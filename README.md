# SignalDesk — AI Sales Intelligence MVP

SignalDesk is a FastAPI and PostgreSQL prototype for finding and prioritizing companies that may need cybersecurity support. It focuses on explainable evidence from company data, rather than generated outreach or opaque AI scores.

## Run locally with Docker

From this directory, run:

```powershell
docker compose up --build
```

Then open `http://localhost:8000`. The first launch creates the database tables. Import a `.csv`, `.csv.gz`, `.csv.zst`, `.jsonl`, `.ndjson`, or `.zst` file from the dashboard. CSV and JSONL files may be compressed with gzip or zstd; a generic `.zst` file is treated as JSONL.

The included `data/sample_accounts.csv` is fictional and can be imported to try the workflow. It is not part of the task dataset.

## Render free demo

The root `render.yaml` deploys a small demo using a free Render web service and free Render Postgres in Singapore. Select **New > Blueprint** in Render and connect this repository. Demo mode seeds the fictional `data/sample_accounts.csv` once and disables uploads. It is for demonstrating account search and scoring only; it cannot ingest the 16 GB Shodan file or run the separate worker.

Render's free web service sleeps after inactivity and has ephemeral local storage. Its free Postgres database is limited to 1 GB and expires after 30 days. This public demo has no login, so it only uses fictional sample data. Do not upload real customer or prospect data. The full upload/worker pipeline requires a paid hosting design with durable shared/object storage and access control.

## What it does

- Uploads large files to disk in chunks; CSV and JSONL rows are parsed one at a time and written in database batches.
- Keeps each row's original fields in PostgreSQL JSONB and maps common company name, domain, industry, country, and employee-count columns.
- Maps Shodan records to host accounts, using the hostname/domain and IP address, with one account per scanned IP/port endpoint. Repeated imports refresh that endpoint.
- Ranks accounts with a deterministic 0–100 heuristic and shows the field/value evidence behind each score.
- Filters and searches accounts and reports import progress, processed rows, skipped rows, and parsing errors.

The score is an account-prioritization heuristic, not a probability of purchase. Incident, exposure, security hiring, compliance, industry, company-size, and Shodan evidence are visible in the account detail. Shodan signals distinguish severity-rated CVEs, known-exploited and ransomware-associated CVEs, Shodan-verified findings, end-of-life product tags, sensitive public services (such as databases and remote administration), legacy TLS support, and expired certificates. Ordinary public web ports are weak signals; cloud/CDN attribution is down-weighted, and honeypot records are excluded from prospect scoring. Shodan's `org` and `isp` fields describe network ownership and may identify a hosting provider rather than the company; confirm hostname ownership before prospecting. A Shodan observation is a lead to verify, not proof that a company is compromised or that a reported vulnerability is exploitable.

## Typed agent runs and observability

The API uses Pydantic request/response contracts, including the account-planning endpoints:

- `POST /api/agents/account-plans` with `{"account_id": 1, "goal": "Prioritize a thoughtful first touch."}` creates a proposed plan.
- `GET /api/agent-runs/{run_id}` reads the validated plan and saved tool trace.
- `POST /api/agent-runs/{run_id}/approval` with `{"decision": "approve"}` or `{"decision": "reject"}` records the human checkpoint. A decision cannot be changed.
- `POST /api/agent-runs/{run_id}/replay` revalidates the recorded tool inputs and outputs without re-running tools or making external calls.

The initial runtime uses three deterministic, locally executed tools: load an account, analyze its signals, and draft a next-step recommendation. The loop has a hard three-tool-call budget; tool arguments and results are validated with Pydantic and every call is stored in the trace. The runtime does not call an LLM, send account data to a provider, or send outreach. This keeps the prototype inspectable while providing an integration point for a future model-backed planner.

FastAPI request spans are instrumented with Logfire. Set `LOGFIRE_TOKEN` to enable export to your Logfire project; without it, exporting is disabled. Request query/body values are excluded from span attributes, and only validation error locations/types are retained. The agent span records run/account identifiers and step budget, not account names or raw evidence.

The approval routes are a prototype workflow, not an authenticated approval system. Add authentication and reviewer authorization before exposing them outside a trusted environment.

## Data and ingestion notes

The Shodan dataset is a large zstd-compressed newline-delimited JSON file. Upload it directly through the dashboard; ingestion decompresses and parses it as a stream rather than unpacking it to a second full-size file. Shodan records are keyed by IP and port so separate observed services remain distinct. The `vulns` field includes useful metadata such as CVSS, `kev`, `ransomware_campaign`, and `verified`; tags can identify `eol-product`, `honeypot`, `cloud`, `cdn`, and certificate hints. TLS version lists distinguish enabled protocols from disabled ones (prefixed with `-`). Scoring uses these as ranked, explainable clues and treats ordinary web exposure and uncertain ownership cautiously.

Unrecognized input columns are retained; NUL characters are escaped and unpaired Unicode surrogates are replaced so PostgreSQL JSONB can store the source fields. Field mapping is best-effort for common company fields, and the scoring rules are intentionally conservative and auditable. Review the mapped fields and observed evidence against the real dataset before relying on its ranking. A single top-level JSON array and archive formats other than gzip and zstd are not supported.

Uploads are copied to a shared disk volume and the API atomically creates an ingestion job and PostgreSQL work item. Separate worker containers claim work with `FOR UPDATE SKIP LOCKED`; leases allow another worker to recover work after a crash. Workers process bounded batches, renew their leases during long scans, and retry failures with capped exponential backoff. Account writes are upserts, so a retry after a worker restart is safe. Source files are removed only after successful processing; exhausted failures retain their source file and error for operator review. `Base.metadata.create_all()` adds the new work-item table to an existing database; it does not migrate unrelated schema changes.

Workers emit a low-overhead profiling summary every `INGEST_PROFILE_BATCHES` batches (default 10), separating read/decompress/JSON-parse time, mapping/scoring time, and database-write/commit time. Set the value to `0` to disable these summaries. View them with `docker compose logs -f worker`.

For bulk arrivals, write files into the shared `uploads/inbox` directory (the host path is configured by `SIGNALDESK_UPLOAD_DIR`) using a temporary, unsupported extension, then atomically rename each finished file to a supported `.csv`, `.jsonl`, `.ndjson`, or `.zst` filename. Workers discover and enqueue those files automatically. Multiple workers can safely scan the inbox; unique source paths prevent duplicate jobs. Run more workers with `docker compose up --build --scale worker=4`. The API upload endpoint remains available for individual files and enforces `MAX_UPLOAD_BYTES`; bulk inbox files should be subject to equivalent controls in the producer and host storage.

The Compose setup uses a local shared disk volume, so it is limited by that disk's capacity and availability and is not a complete object-storage or multi-region production design. For thousands of large monthly files, provision and monitor sufficient durable storage, database capacity, worker throughput, backups, retention, and dead-letter operations. PostgreSQL is the durable queue; no Snowflake service is used.

## Run tests

With the project's Python dependencies installed:

```powershell
python -m pytest
```

The focused unit tests cover score explanations, priority caps, compressed CSV and zstd JSONL parsing, Shodan host mapping, invalid JSONL records, durable queue creation and retries, typed agent tool calls, approval transitions, and trace replay validation. Start PostgreSQL with Docker Compose to exercise the complete upload-to-dashboard workflow.

## API

- `GET /api/health`
- `GET /api/overview`
- `GET /api/accounts?q=&industry=&tier=&min_score=&sort=&limit=&offset=`
- `GET /api/accounts/{account_id}`
- `POST /api/ingestions` with multipart field `file`
- `GET /api/ingestions`
- `GET /api/ingestions/{job_id}`
- `POST /api/agents/account-plans`
- `GET /api/agent-runs/{run_id}`
- `POST /api/agent-runs/{run_id}/approval`
- `POST /api/agent-runs/{run_id}/replay`
- `GET /docs` for the interactive OpenAPI docs
