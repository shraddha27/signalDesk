"""Durable PostgreSQL work-item creation and inbox discovery."""

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ingestion import upload_format
from app.models import IngestionJob, IngestionWorkItem

logger = logging.getLogger(__name__)


def enqueue_ingestion(db: Session, source_path: str, filename: str) -> IngestionJob | None:
    """Atomically create a visible job and its durable work item."""
    normalized_path = str(Path(source_path).resolve())
    job = IngestionJob(filename=filename, status="queued")
    db.add(job)
    db.flush()
    db.add(IngestionWorkItem(job_id=job.id, source_path=normalized_path))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(IngestionWorkItem.id)
            .filter(IngestionWorkItem.source_path == normalized_path)
            .first()
        )
        if existing:
            return None
        raise
    db.refresh(job)
    return job


def enqueue_inbox_files(db: Session, inbox_dir: str) -> int:
    """Enqueue supported files published into the inbox directory."""
    directory = Path(inbox_dir)
    directory.mkdir(parents=True, exist_ok=True)
    candidates: list[tuple[Path, str]] = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            upload_format(path.name)
        except ValueError:
            continue
        candidates.append((path, str(path.resolve())))

    if not candidates:
        return 0

    existing = set(
        db.scalars(
            select(IngestionWorkItem.source_path).where(
                IngestionWorkItem.source_path.in_([item[1] for item in candidates])
            )
        ).all()
    )
    enqueued = 0
    for path, source_path in candidates:
        if source_path in existing:
            continue
        try:
            with db.begin_nested():
                job = IngestionJob(filename=path.name, status="queued")
                db.add(job)
                db.flush()
                db.add(
                    IngestionWorkItem(job_id=job.id, source_path=source_path)
                )
                db.flush()
            enqueued += 1
            logger.info("Queued inbox file %s", path.name)
        except IntegrityError:
            if db.scalar(
                select(IngestionWorkItem.id).where(
                    IngestionWorkItem.source_path == source_path
                )
            ) is None:
                raise
    if enqueued:
        db.commit()
    return enqueued
