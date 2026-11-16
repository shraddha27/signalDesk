"""PostgreSQL-backed ingestion worker with leased claims and bounded retries."""

import logging
import os
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import (
    INGEST_INBOX_DIR,
    INGEST_LEASE_SECONDS,
    INGEST_MAX_ATTEMPTS,
    INGEST_POLL_SECONDS,
    INGEST_RETRY_BASE_SECONDS,
    INGEST_RETRY_MAX_SECONDS,
)
from app.db import SessionLocal, engine
from app.ingestion import process_ingestion
from app.ingestion_queue import enqueue_inbox_files
from app.models import Base, IngestionJob, IngestionWorkItem

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_worker_schema() -> None:
    """Create missing tables before querying the durable queue."""
    Base.metadata.create_all(bind=engine)


def claim_work_item(db: Session, worker_id: str) -> IngestionWorkItem | None:
    """Claim the oldest ready or lease-expired item without blocking peers."""
    now = _now()
    task = db.scalars(
        select(IngestionWorkItem)
        .join(IngestionJob, IngestionJob.id == IngestionWorkItem.job_id)
        .where(
            IngestionJob.status.not_in(("completed", "failed")),
            IngestionWorkItem.attempts < INGEST_MAX_ATTEMPTS,
            IngestionWorkItem.next_attempt_at <= now,
            or_(
                IngestionWorkItem.lease_until.is_(None),
                IngestionWorkItem.lease_until <= now,
            ),
        )
        .order_by(IngestionWorkItem.id)
        .limit(1)
        .with_for_update(skip_locked=True, of=IngestionWorkItem)
    ).first()
    if task is None:
        return None

    task.attempts += 1
    task.worker_id = worker_id
    task.lease_until = now + timedelta(seconds=INGEST_LEASE_SECONDS)
    job = db.get(IngestionJob, task.job_id)
    if job is None:
        raise RuntimeError(f"Work item {task.id} references a missing job.")
    job.status = "processing"
    job.finished_at = None
    db.commit()
    db.refresh(task)
    return task


def record_failure(
    db: Session,
    task_id: int,
    worker_id: str,
    error: Exception,
) -> None:
    """Schedule an exponential-backoff retry or mark the job terminally failed."""
    task = db.get(IngestionWorkItem, task_id)
    if task is None:
        raise RuntimeError(f"Work item {task_id} no longer exists.")
    if task.worker_id != worker_id:
        logger.warning("Ignoring failure from worker without lease for task %s", task_id)
        return

    message = f"{type(error).__name__}: {error}"[:4000]
    job = db.get(IngestionJob, task.job_id)
    if job is None:
        raise RuntimeError(f"Work item {task_id} references a missing job.")
    if job.status == "completed":
        task.completed_at = _now()
        task.worker_id = None
        task.lease_until = None
        db.commit()
        return
    task.last_error = message
    task.worker_id = None
    task.lease_until = None
    job.error = message
    if task.attempts >= INGEST_MAX_ATTEMPTS:
        job.status = "failed"
        job.finished_at = _now()
    else:
        delay = min(
            INGEST_RETRY_BASE_SECONDS * (2 ** (task.attempts - 1)),
            INGEST_RETRY_MAX_SECONDS,
        )
        task.next_attempt_at = _now() + timedelta(seconds=delay)
        job.status = "queued"
        job.finished_at = None
    db.commit()


def complete_work_item(db: Session, task_id: int, worker_id: str) -> str:
    """Mark a successfully processed item complete and return its source path."""
    task = db.get(IngestionWorkItem, task_id)
    if task is None or task.worker_id != worker_id:
        raise RuntimeError(f"Worker {worker_id} no longer owns task {task_id}.")
    task.completed_at = _now()
    task.worker_id = None
    task.lease_until = None
    db.commit()
    return task.source_path


def _reconcile_completed(db: Session) -> list[str]:
    """Close the crash window between job completion and work-item completion."""
    tasks = db.scalars(
        select(IngestionWorkItem)
        .join(IngestionJob, IngestionJob.id == IngestionWorkItem.job_id)
        .where(
            IngestionJob.status == "completed",
            IngestionWorkItem.completed_at.is_(None),
            or_(
                IngestionWorkItem.lease_until.is_(None),
                IngestionWorkItem.lease_until <= _now(),
            ),
        )
        .with_for_update(skip_locked=True, of=IngestionWorkItem)
    ).all()
    paths = [task.source_path for task in tasks]
    for task in tasks:
        task.completed_at = _now()
        task.worker_id = None
        task.lease_until = None
    if tasks:
        db.commit()
    return paths


def _fail_expired_final_attempts(db: Session) -> None:
    """Finalize work abandoned after its final lease expired."""
    now = _now()
    tasks = db.scalars(
        select(IngestionWorkItem)
        .join(IngestionJob, IngestionJob.id == IngestionWorkItem.job_id)
        .where(
            IngestionWorkItem.attempts >= INGEST_MAX_ATTEMPTS,
            IngestionWorkItem.lease_until <= now,
            IngestionJob.status.not_in(("completed", "failed")),
        )
        .limit(100)
        .with_for_update(skip_locked=True, of=IngestionWorkItem)
    ).all()
    for task in tasks:
        message = task.last_error or "Worker lease expired on the final attempt."
        task.last_error = message
        task.worker_id = None
        task.lease_until = None
        job = db.get(IngestionJob, task.job_id)
        if job is None:
            raise RuntimeError(f"Work item {task.id} references a missing job.")
        job.status = "failed"
        job.error = message
        job.finished_at = now
    if tasks:
        db.commit()


def _remove_completed_source(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        logger.exception("Could not remove completed source file %s", path)


def run_worker() -> None:
    """Continuously enqueue inbox files and process durable work items."""
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    Path(INGEST_INBOX_DIR).mkdir(parents=True, exist_ok=True)
    ensure_worker_schema()
    logger.info("Starting ingestion worker %s", worker_id)

    while True:
        try:
            with SessionLocal() as db:
                completed_sources = _reconcile_completed(db)
                _fail_expired_final_attempts(db)
                enqueue_inbox_files(db, INGEST_INBOX_DIR)
                task = claim_work_item(db, worker_id)
                if task is None:
                    for source_path in completed_sources:
                        _remove_completed_source(source_path)
                    time.sleep(INGEST_POLL_SECONDS)
                    continue
                task_data = (
                    task.id,
                    task.job_id,
                    task.source_path,
                    db.get(IngestionJob, task.job_id).filename,
                )

            task_id, job_id, source_path, filename = task_data
            try:
                process_ingestion(job_id, source_path, filename, task_id, worker_id)
                with SessionLocal() as db:
                    completed_path = complete_work_item(db, task_id, worker_id)
                _remove_completed_source(completed_path)
                logger.info("Completed ingestion job %s", job_id)
            except Exception as error:
                logger.exception("Ingestion job %s failed", job_id)
                with SessionLocal() as db:
                    record_failure(db, task_id, worker_id, error)
        except Exception:
            logger.exception("Ingestion worker loop failed; retrying")
            time.sleep(INGEST_POLL_SECONDS)


if __name__ == "__main__":
    run_worker()
