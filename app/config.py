"""Small environment-based settings module for the API and worker."""

import os
import tempfile


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://sales:sales@localhost:5432/sales_intelligence",
)
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(16 * 1024**3)))
UPLOAD_TEMP_DIR = os.getenv("UPLOAD_TEMP_DIR")
INGEST_BATCH_SIZE = int(os.getenv("INGEST_BATCH_SIZE", "1000"))
INGEST_PROFILE_BATCHES = int(os.getenv("INGEST_PROFILE_BATCHES", "10"))
INGEST_INBOX_DIR = os.getenv(
    "INGEST_INBOX_DIR",
    os.path.join(UPLOAD_TEMP_DIR or tempfile.gettempdir(), "inbox"),
)
INGEST_POLL_SECONDS = float(os.getenv("INGEST_POLL_SECONDS", "2"))
INGEST_LEASE_SECONDS = int(os.getenv("INGEST_LEASE_SECONDS", "1800"))
INGEST_MAX_ATTEMPTS = int(os.getenv("INGEST_MAX_ATTEMPTS", "5"))
INGEST_RETRY_BASE_SECONDS = int(os.getenv("INGEST_RETRY_BASE_SECONDS", "30"))
INGEST_RETRY_MAX_SECONDS = int(os.getenv("INGEST_RETRY_MAX_SECONDS", "1800"))
LOGFIRE_TOKEN = os.getenv("LOGFIRE_TOKEN")
