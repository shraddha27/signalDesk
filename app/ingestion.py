"""Bounded-memory CSV/JSONL ingestion and account field normalization."""

import csv
import gzip
import hashlib
import importlib
import io
import json
import logging
import re
import time
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

try:
    from compression import zstd as stdlib_zstd
except ImportError:
    stdlib_zstd = None

try:
    third_party_zstd = importlib.import_module("zstandard")
except ImportError:
    third_party_zstd = None

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import (
    INGEST_BATCH_SIZE,
    INGEST_LEASE_SECONDS,
    INGEST_PROFILE_BATCHES,
)
from app.db import SessionLocal
from app.models import Account, IngestionJob, IngestionWorkItem
from app.scoring import parse_employee_count, score_account

logger = logging.getLogger(__name__)

SUPPORTED_SUFFIXES = (
    ".csv",
    ".csv.gz",
    ".jsonl",
    ".jsonl.gz",
    ".ndjson",
    ".ndjson.gz",
    ".csv.zst",
    ".jsonl.zst",
    ".ndjson.zst",
    ".zst",
)
FIELD_ALIASES = {
    "name": ("company_name", "business_name", "organization_name", "company", "name"),
    "domain": ("domain", "website", "company_website", "url", "website_url"),
    "industry": ("industry", "sector", "category"),
    "country": ("country", "country_name", "hq_country", "location_country"),
    "employees": (
        "employee_count",
        "employees",
        "staff_count",
        "number_of_employees",
        "company_size",
    ),
}


def upload_format(filename: str) -> str:
    """Validate the extension and return the input format."""
    lowered = filename.casefold()
    if not any(lowered.endswith(suffix) for suffix in SUPPORTED_SUFFIXES):
        raise ValueError(
            "Upload a .csv, .csv.gz, .csv.zst, .jsonl, or .ndjson file "
            "(optionally compressed with gzip or zstd)."
        )
    return "csv" if lowered.endswith((".csv", ".csv.gz", ".csv.zst")) else "jsonl"


def _open_text(path: str, filename: str):
    """Open compressed or plain-text input without loading it into memory."""
    lowered = filename.casefold()
    if lowered.endswith(".gz"):
        return gzip.open(path, mode="rt", encoding="utf-8-sig", newline="")
    if lowered.endswith(".zst"):
        if stdlib_zstd is not None:
            return stdlib_zstd.open(path, mode="rt", encoding="utf-8-sig", newline="")
        if third_party_zstd is None:
            raise RuntimeError("Zstandard support requires the zstandard package.")
        compressed = open(path, mode="rb")
        reader = third_party_zstd.ZstdDecompressor().stream_reader(compressed)
        return io.TextIOWrapper(reader, encoding="utf-8-sig", newline="")
    return open(path, mode="r", encoding="utf-8-sig", newline="")


def iter_records(path: str, filename: str) -> Iterator[tuple[dict[str, Any] | None, str | None]]:
    """Yield one row at a time; malformed JSONL rows are reported and skipped."""
    input_format = upload_format(filename)
    with _open_text(path, filename) as source:
        if input_format == "csv":
            reader = csv.DictReader(source)
            if not reader.fieldnames:
                raise ValueError("The CSV file is empty or has no header row.")
            for row_number, row in enumerate(reader, start=2):
                if not row or not any(value for value in row.values() if value is not None):
                    continue
                if None in row:
                    yield None, f"CSV row {row_number} has more cells than headers."
                    continue
                yield row, None
            return

        for row_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                yield None, f"JSONL line {row_number}: {error.msg}."
                continue
            if not isinstance(row, dict):
                yield None, f"JSONL line {row_number} is not a JSON object."
                continue
            yield row, None


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _find_value(row: Mapping[str, Any], aliases: tuple[str, ...]) -> Any:
    normalized = {_normalized_key(str(key)): value for key, value in row.items()}
    for alias in aliases:
        if alias in normalized and normalized[alias] not in (None, ""):
            return normalized[alias]
    for key, value in normalized.items():
        if value not in (None, "") and any(alias in key for alias in aliases):
            return value
    return None


def _domain(value: Any) -> str | None:
    if not value:
        return None
    candidate = str(value).strip()
    if "@" in candidate and "://" not in candidate:
        return None
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").casefold().removeprefix("www.")
    return host or None


def _first_host(value: Any) -> str | None:
    candidates = value if isinstance(value, (list, tuple)) else (value,)
    for candidate in candidates:
        host = _domain(candidate)
        if host:
            return host
    return None


def _sanitize_json(value: Any) -> Any:
    """Make nested JSON values safe for PostgreSQL JSONB."""
    if isinstance(value, str):
        return "".join(
            r"\u0000"
            if character == "\x00"
            else "\ufffd"
            if 0xD800 <= ord(character) <= 0xDFFF
            else character
            for character in value
        )
    if isinstance(value, Mapping):
        return {
            _sanitize_json(str(key)): _sanitize_json(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_json(item) for item in value]
    return value


def _shodan_host(row: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Return the host label and stable address for a Shodan service record."""
    host = _first_host(_find_value(row, ("hostnames",)))
    host = host or _first_host(_find_value(row, ("domains",)))
    address = _domain(_find_value(row, ("ip_str",)))
    return host or address, address


def account_payload(
    row: Mapping[str, Any], source_file: str, row_number: int
) -> dict[str, Any]:
    """Map known firmographic columns while retaining every original field."""
    safe_row = {
        _sanitize_json(str(key)): _sanitize_json(value)
        for key, value in row.items()
    }
    attributes = {
        str(key): value
        for key, value in safe_row.items()
        if value is not None and isinstance(value, (str, int, float, bool, list, dict))
    }
    normalized_keys = {_normalized_key(str(key)) for key in safe_row}
    is_shodan_record = bool({"ip_str", "_shodan", "hostnames"} & normalized_keys)
    shodan_host, shodan_address = (
        _shodan_host(safe_row) if is_shodan_record else (None, None)
    )
    raw_name = _find_value(safe_row, FIELD_ALIASES["name"])
    raw_domain = _find_value(safe_row, FIELD_ALIASES["domain"])
    if is_shodan_record:
        raw_name = shodan_host or raw_name
        raw_domain = shodan_host or shodan_address or raw_domain
    industry = _find_value(safe_row, FIELD_ALIASES["industry"])
    location = safe_row.get("location")
    country = (
        location.get("country_name")
        if is_shodan_record and isinstance(location, Mapping)
        else _find_value(safe_row, FIELD_ALIASES["country"])
    )
    employee_count = parse_employee_count(
        _find_value(safe_row, FIELD_ALIASES["employees"])
    )

    domain = _domain(raw_domain)
    name = str(raw_name or domain or f"Imported account {row_number}").strip()
    if is_shodan_record and (shodan_address or shodan_host):
        port = _find_value(safe_row, ("port",))
        account_identity = f"host:{shodan_address or shodan_host}|port:{port or ''}"
        if port is not None:
            name = f"{name} (port {port})"
    elif domain:
        account_identity = f"domain:{domain}"
    elif raw_name:
        account_identity = f"name:{name.casefold()}|country:{str(country or '').casefold()}"
    else:
        # Keep records without identity columns distinct across files and row positions.
        account_identity = f"row:{source_file}:{row_number}"
    account_key = hashlib.sha256(account_identity.encode("utf-8")).hexdigest()

    score, tier, signals = score_account(
        attributes,
        industry=str(industry) if industry is not None else None,
        employee_count=employee_count,
    )
    return {
        "account_key": account_key,
        "name": name[:500],
        "domain": domain[:500] if domain else None,
        "industry": str(industry)[:300] if industry is not None else None,
        "country": str(country)[:200] if country is not None else None,
        "employee_count": employee_count,
        "score": score,
        "tier": tier,
        "signals": signals,
        "attributes": attributes,
        "source_file": source_file[:500],
        "updated_at": datetime.now(timezone.utc),
    }


def _deduplicate_batch(batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the latest row for each account key within a database batch."""
    latest_by_key: dict[str, dict[str, Any]] = {}
    for account in batch:
        latest_by_key[account["account_key"]] = account
    return list(latest_by_key.values())


def _save_batch(db: Session, batch: list[dict[str, Any]]) -> None:
    """Upsert each account once per batch so repeated endpoints update safely."""
    unique_batch = _deduplicate_batch(batch)
    statement = insert(Account).values(unique_batch)
    update_fields = {
        field: getattr(statement.excluded, field)
        for field in unique_batch[0]
        if field not in {"account_key"}
    }
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[Account.account_key],
            set_=update_fields,
        )
    )


def _update_job(
    db: Session,
    job_id: int,
    processed: int,
    skipped: int,
    status: str | None = None,
    error: str | None = None,
    task_id: int | None = None,
    worker_id: str | None = None,
) -> None:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise RuntimeError(f"Ingestion job {job_id} no longer exists.")
    job.rows_processed = processed
    job.rows_skipped = skipped
    if status:
        job.status = status
    job.error = error[:4000] if error else None
    if status in {"completed", "failed"}:
        job.finished_at = datetime.now(timezone.utc)
    elif status == "processing":
        job.finished_at = None
    if task_id is not None and worker_id is not None:
        task = db.get(IngestionWorkItem, task_id)
        if task is None or task.worker_id != worker_id:
            raise RuntimeError(f"Worker {worker_id} no longer owns task {task_id}.")
        task.lease_until = datetime.now(timezone.utc) + timedelta(
            seconds=INGEST_LEASE_SECONDS
        )
    db.commit()


def process_ingestion(
    job_id: int,
    path: str,
    filename: str,
    task_id: int,
    worker_id: str,
) -> None:
    """Process a durable work item in bounded batches and persist progress."""
    db = SessionLocal()
    processed = 0
    skipped = 0
    first_error: str | None = None
    last_heartbeat = time.monotonic()
    profile_started = time.perf_counter()
    profile_rows = 0
    profile_processed = 0
    profile_skipped = 0
    profile_batches = 0
    read_parse_seconds = 0.0
    map_score_seconds = 0.0
    database_seconds = 0.0

    def log_profile() -> None:
        nonlocal profile_started, profile_rows, profile_processed
        nonlocal profile_skipped, profile_batches
        nonlocal read_parse_seconds, map_score_seconds, database_seconds
        elapsed = time.perf_counter() - profile_started
        if elapsed <= 0 or profile_rows == 0:
            return
        logger.info(
            "Ingestion profile job=%s interval_rows=%s processed=%s skipped=%s "
            "batches=%s elapsed_seconds=%.2f rows_per_second=%.1f "
            "read_decompress_parse_seconds=%.2f map_score_seconds=%.2f "
            "database_write_commit_seconds=%.2f",
            job_id,
            profile_rows,
            profile_processed,
            profile_skipped,
            profile_batches,
            elapsed,
            profile_rows / elapsed,
            read_parse_seconds,
            map_score_seconds,
            database_seconds,
        )
        profile_started = time.perf_counter()
        profile_rows = 0
        profile_processed = 0
        profile_skipped = 0
        profile_batches = 0
        read_parse_seconds = 0.0
        map_score_seconds = 0.0
        database_seconds = 0.0

    try:
        _update_job(
            db,
            job_id,
            processed,
            skipped,
            status="processing",
            task_id=task_id,
            worker_id=worker_id,
        )
        batch: list[dict[str, Any]] = []
        records = iter_records(path, filename)
        row_number = 0
        while True:
            read_started = time.perf_counter()
            try:
                row, error = next(records)
            except StopIteration:
                read_parse_seconds += time.perf_counter() - read_started
                break
            read_parse_seconds += time.perf_counter() - read_started
            row_number += 1
            profile_rows += 1
            if error:
                skipped += 1
                profile_skipped += 1
                first_error = first_error or error
            elif row is not None:
                mapping_started = time.perf_counter()
                batch.append(account_payload(row, filename, row_number))
                map_score_seconds += time.perf_counter() - mapping_started
                if len(batch) >= INGEST_BATCH_SIZE:
                    database_started = time.perf_counter()
                    _save_batch(db, batch)
                    processed += len(batch)
                    profile_processed += len(batch)
                    batch.clear()
                    _update_job(
                        db,
                        job_id,
                        processed,
                        skipped,
                        error=first_error,
                        task_id=task_id,
                        worker_id=worker_id,
                    )
                    database_seconds += time.perf_counter() - database_started
                    last_heartbeat = time.monotonic()
                    profile_batches += 1
                    if (
                        INGEST_PROFILE_BATCHES > 0
                        and profile_batches >= INGEST_PROFILE_BATCHES
                    ):
                        log_profile()
            if time.monotonic() - last_heartbeat >= INGEST_LEASE_SECONDS / 3:
                database_started = time.perf_counter()
                _update_job(
                    db,
                    job_id,
                    processed,
                    skipped,
                    error=first_error,
                    task_id=task_id,
                    worker_id=worker_id,
                )
                database_seconds += time.perf_counter() - database_started
                last_heartbeat = time.monotonic()
        if batch:
            database_started = time.perf_counter()
            _save_batch(db, batch)
            processed += len(batch)
            profile_processed += len(batch)
            profile_batches += 1
        _update_job(
            db,
            job_id,
            processed,
            skipped,
            status="completed",
            error=first_error,
            task_id=task_id,
            worker_id=worker_id,
        )
        if batch:
            database_seconds += time.perf_counter() - database_started
        if INGEST_PROFILE_BATCHES > 0:
            log_profile()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
