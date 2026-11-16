import gzip
import importlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

try:
    zstd = importlib.import_module("compression.zstd")
except ImportError:
    zstd = importlib.import_module("zstandard")

from app import ingestion as ingestion_module
from app.ingestion import _deduplicate_batch, account_payload, iter_records, upload_format
from app.config import INGEST_MAX_ATTEMPTS
from app.models import Base, IngestionJob, IngestionWorkItem
from app.ingestion_queue import enqueue_ingestion, enqueue_inbox_files
from app import worker as ingestion_worker
from app.worker import claim_work_item, record_failure


def test_worker_startup_creates_missing_queue_schema(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'worker-startup.db'}")
    monkeypatch.setattr(ingestion_worker, "engine", engine)

    ingestion_worker.ensure_worker_schema()

    assert "ingestion_work_items" in inspect(engine).get_table_names()
    engine.dispose()


def test_ingestion_logs_timing_profiles_by_batch(tmp_path, monkeypatch, caplog):
    source = tmp_path / "profile.jsonl"
    source.write_text(
        '{"company":"First"}\n{"company":"Second"}\n',
        encoding="utf-8",
    )
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        job = IngestionJob(filename=source.name, status="queued")
        db.add(job)
        db.flush()
        task = IngestionWorkItem(
            job_id=job.id,
            source_path=str(source),
            worker_id="profile-worker",
        )
        db.add(task)
        db.commit()
        job_id, task_id = job.id, task.id

    monkeypatch.setattr(ingestion_module, "SessionLocal", lambda: Session(engine))
    monkeypatch.setattr(ingestion_module, "INGEST_BATCH_SIZE", 1)
    monkeypatch.setattr(ingestion_module, "INGEST_PROFILE_BATCHES", 1)
    monkeypatch.setattr(ingestion_module, "_save_batch", lambda db, batch: None)

    with caplog.at_level(logging.INFO, logger="app.ingestion"):
        ingestion_module.process_ingestion(
            job_id, str(source), source.name, task_id, "profile-worker"
        )

    assert "Ingestion profile job=" in caplog.text
    assert "read_decompress_parse_seconds=" in caplog.text
    assert "map_score_seconds=" in caplog.text
    assert "database_write_commit_seconds=" in caplog.text

    with Session(engine) as db:
        assert db.get(IngestionJob, job_id).rows_processed == 2
        assert db.get(IngestionJob, job_id).status == "completed"
    engine.dispose()


def test_supported_compressed_formats():
    assert upload_format("accounts.csv.gz") == "csv"
    assert upload_format("accounts.ndjson") == "jsonl"
    assert upload_format("shodan.jsonl.zst") == "jsonl"
    assert upload_format("b2_download_file_by_id.zst") == "jsonl"

    try:
        upload_format("accounts.xlsx")
    except ValueError as error:
        assert "Upload a" in str(error)
    else:
        raise AssertionError("Unsupported file types must be rejected.")


def test_csv_stream_maps_company_fields_and_keeps_source_fields(tmp_path):
    source = tmp_path / "companies.csv.gz"
    with gzip.open(source, "wt", encoding="utf-8") as file:
        file.write("Company Name,Website,Industry,Employees,Description\n")
        file.write(
            "Example Health,https://www.example.org,Healthcare,201-500,"
            "Security incident disclosed\n"
        )

    rows = list(iter_records(str(source), source.name))
    assert rows == [
        (
            {
                "Company Name": "Example Health",
                "Website": "https://www.example.org",
                "Industry": "Healthcare",
                "Employees": "201-500",
                "Description": "Security incident disclosed",
            },
            None,
        )
    ]

    account = account_payload(rows[0][0], source.name, 1)
    assert account["name"] == "Example Health"
    assert account["domain"] == "example.org"
    assert account["employee_count"] == 201
    assert account["attributes"]["Description"] == "Security incident disclosed"
    assert account["score"] > 0


def test_jsonl_skips_bad_lines_with_a_specific_error(tmp_path):
    source = tmp_path / "accounts.jsonl"
    source.write_text('{"company":"One"}\nnot-json\n[]\n', encoding="utf-8")

    rows = list(iter_records(str(source), source.name))

    assert rows[0] == ({"company": "One"}, None)
    assert rows[1][0] is None
    assert "JSONL line 2" in rows[1][1]
    assert rows[2][0] is None
    assert "not a JSON object" in rows[2][1]


def test_zstd_jsonl_stream_maps_shodan_host_and_keeps_source_fields(tmp_path):
    source = tmp_path / "shodan.jsonl.zst"
    records = (
        '{"ip_str":"203.0.113.8","hostnames":["web.example.org"],'
        '"domains":["example.org"],"port":443,"transport":"tcp",'
        '"location":{"country_name":"Exampleland"},"vulns":{"CVE-2026-1234":{}}}\n'
    )
    content = records.encode("utf-8")
    compressed = (
        zstd.compress(content)
        if hasattr(zstd, "compress")
        else zstd.ZstdCompressor().compress(content)
    )
    source.write_bytes(compressed)

    rows = list(iter_records(str(source), source.name))

    assert rows == [
        (
            {
                "ip_str": "203.0.113.8",
                "hostnames": ["web.example.org"],
                "domains": ["example.org"],
                "port": 443,
                "transport": "tcp",
                "location": {"country_name": "Exampleland"},
                "vulns": {"CVE-2026-1234": {}},
            },
            None,
        )
    ]
    account = account_payload(rows[0][0], source.name, 1)
    assert account["name"] == "web.example.org (port 443)"
    assert account["domain"] == "web.example.org"
    assert account["country"] == "Exampleland"
    assert account["attributes"]["ip_str"] == "203.0.113.8"
    other_port = account_payload(
        {**rows[0][0], "port": 80}, source.name, 2
    )
    assert other_port["account_key"] != account["account_key"]


def test_shodan_hostnames_are_mapped_when_ip_string_is_missing():
    account = account_payload(
        {
            "_shodan": {"module": "https"},
            "domains": ["hyperquake.com"],
            "hostnames": ["static.staging.honeywell.tools.hyperquake.com"],
            "port": 443,
        },
        "shodan.jsonl.zst",
        1,
    )

    assert account["name"] == "static.staging.honeywell.tools.hyperquake.com (port 443)"
    assert account["domain"] == "static.staging.honeywell.tools.hyperquake.com"


def test_account_payload_escapes_nul_characters_in_nested_source_data():
    account = account_payload(
        {
            "_shodan": {"module": "https"},
            "ip_str": "203.0.113.8",
            "port": 443,
            "data": "response\x00payload",
            "nested": {"field\x00name": "nested\x00value"},
        },
        "shodan.jsonl.zst",
        1,
    )

    assert account["attributes"]["data"] == r"response\u0000payload"
    assert account["attributes"]["nested"] == {
        r"field\u0000name": r"nested\u0000value"
    }


def test_account_payload_replaces_unpaired_surrogates_in_nested_source_data():
    account = account_payload(
        {
            "_shodan": {"module": "https"},
            "ip_str": "203.0.113.8",
            "port": 443,
            "data": "response\udd04payload",
            "nested": {"field\ud800name": "nested\udc00value"},
        },
        "shodan.jsonl.zst",
        1,
    )

    assert account["attributes"]["data"] == "response\ufffdpayload"
    assert account["attributes"]["nested"] == {
        "field\ufffdname": "nested\ufffdvalue"
    }


def test_batch_deduplication_keeps_the_latest_endpoint_observation():
    first = {"account_key": "endpoint-1", "name": "First observation"}
    other = {"account_key": "endpoint-2", "name": "Other endpoint"}
    latest = {"account_key": "endpoint-1", "name": "Latest observation"}

    assert _deduplicate_batch([first, other, latest]) == [latest, other]


def test_durable_queue_enqueue_is_idempotent_and_retries_keep_the_source(tmp_path):
    source = tmp_path / "accounts.jsonl"
    source.write_text('{"company":"Example"}\n', encoding="utf-8")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        job = enqueue_ingestion(db, str(source), source.name)
        assert job is not None
        assert enqueue_ingestion(db, str(source), source.name) is None

        task = claim_work_item(db, "worker-test")
        assert task is not None
        assert task.job_id == job.id
        assert task.attempts == 1

        record_failure(db, task.id, "worker-test", ValueError("temporary failure"))

        saved_job = db.get(IngestionJob, job.id)
        saved_task = db.scalar(
            select(IngestionWorkItem).where(IngestionWorkItem.job_id == job.id)
        )
        assert saved_job.status == "queued"
        assert saved_job.error == "ValueError: temporary failure"
        assert saved_task.attempts == 1
        assert saved_task.lease_until is None
        assert source.exists()
        assert claim_work_item(db, "worker-test") is None

    engine.dispose()


def test_inbox_enqueues_ready_supported_files_in_a_batch(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "one.jsonl").write_text('{"company":"One"}\n', encoding="utf-8")
    (inbox / "two.csv.gz").write_bytes(b"not parsed until the worker runs")
    (inbox / "partial.jsonl.part").write_text("partial", encoding="utf-8")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        assert enqueue_inbox_files(db, str(inbox)) == 2
        assert enqueue_inbox_files(db, str(inbox)) == 0
        assert len(db.scalars(select(IngestionWorkItem)).all()) == 2
        assert len(db.scalars(select(IngestionJob)).all()) == 2

    engine.dispose()


def test_worker_reclaims_an_expired_lease_after_restart(tmp_path):
    source = tmp_path / "restart.jsonl"
    source.write_text('{"company":"Example"}\n', encoding="utf-8")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        job = enqueue_ingestion(db, str(source), source.name)
        task = db.scalar(
            select(IngestionWorkItem).where(IngestionWorkItem.job_id == job.id)
        )
        task.attempts = 1
        task.worker_id = "stopped-worker"
        task.lease_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        job.status = "processing"
        db.commit()

        recovered = claim_work_item(db, "replacement-worker")

        assert recovered is not None
        assert recovered.id == task.id
        assert recovered.attempts == 2
        assert recovered.worker_id == "replacement-worker"
        assert source.exists()

    engine.dispose()


def test_worker_stops_retrying_after_the_configured_attempt_limit(tmp_path):
    source = tmp_path / "terminal.jsonl"
    source.write_text('{"company":"Example"}\n', encoding="utf-8")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        job = enqueue_ingestion(db, str(source), source.name)
        task = db.scalar(
            select(IngestionWorkItem).where(IngestionWorkItem.job_id == job.id)
        )
        task.attempts = INGEST_MAX_ATTEMPTS - 1
        db.commit()

        claimed = claim_work_item(db, "last-worker")
        record_failure(db, claimed.id, "last-worker", ValueError("permanent failure"))

        assert db.get(IngestionJob, job.id).status == "failed"
        assert claimed.attempts == INGEST_MAX_ATTEMPTS
        assert source.exists()

    engine.dispose()
