"""FastAPI routes and static dashboard for the sales intelligence MVP."""

import os
import tempfile
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.agent_runtime import AccountAgentRuntime, build_account_plan
from app.config import MAX_UPLOAD_BYTES, UPLOAD_TEMP_DIR
from app.db import engine, get_db
from app.ingestion import upload_format
from app.ingestion_queue import enqueue_ingestion
from app.models import Account, AgentRun, Base, IngestionJob
from app.observability import instrument_app
from app.schemas import (
    AccountListResponse,
    AccountResponse,
    AgentPlanRequest,
    AgentReplayResponse,
    AgentRunResponse,
    ApprovalRequest,
    HealthResponse,
    IngestionListResponse,
    IngestionResponse,
    OverviewResponse,
)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """Create the MVP schema when the API starts."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SignalDesk",
    description="Explainable account prioritization for cybersecurity sales teams.",
    version="1.0.0",
    lifespan=lifespan,
)
instrument_app(app)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health", response_model=HealthResponse)
def health() -> dict[str, str]:
    return {"status": "ok"}


def _account_json(account: Account) -> dict[str, Any]:
    return {
        "id": account.id,
        "name": account.name,
        "domain": account.domain,
        "industry": account.industry,
        "country": account.country,
        "employee_count": account.employee_count,
        "score": account.score,
        "tier": account.tier,
        "signals": account.signals or [],
        "attributes": account.attributes or {},
        "source_file": account.source_file,
        "updated_at": account.updated_at.isoformat() if account.updated_at else None,
    }


def _job_json(job: IngestionJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "filename": job.filename,
        "status": job.status,
        "rows_processed": job.rows_processed,
        "rows_skipped": job.rows_skipped,
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@app.get("/api/overview", response_model=OverviewResponse)
def overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    stats = db.execute(
        select(
            func.count(Account.id).label("total"),
            func.count(Account.id)
            .filter(Account.tier == "high")
            .label("high_priority"),
            func.avg(Account.score).label("average_score"),
        )
    ).one()
    active_jobs = db.scalar(
        select(func.count(IngestionJob.id)).where(
            IngestionJob.status.in_(("queued", "processing"))
        )
    ) or 0
    industries = db.scalars(
        select(Account.industry)
        .where(Account.industry.is_not(None), Account.industry != "")
        .distinct()
        .order_by(Account.industry)
        .limit(100)
    ).all()
    return {
        "total_accounts": stats.total or 0,
        "high_priority_accounts": stats.high_priority or 0,
        "active_ingestions": active_jobs,
        "average_score": round(float(stats.average_score or 0), 1),
        "industries": industries,
    }


@app.get("/api/accounts", response_model=AccountListResponse)
def list_accounts(
    q: str | None = None,
    industry: str | None = None,
    tier: str | None = Query(default=None, pattern="^(high|medium|low)$"),
    min_score: int = Query(default=0, ge=0, le=100),
    sort: str = Query(default="score", pattern="^(score|name|updated_at)$"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    filters = [Account.score >= min_score]
    if q:
        search = f"%{q.strip()}%"
        filters.append(
            or_(
                Account.name.ilike(search),
                Account.domain.ilike(search),
                Account.industry.ilike(search),
            )
        )
    if industry:
        filters.append(Account.industry == industry)
    if tier:
        filters.append(Account.tier == tier)

    total = db.scalar(select(func.count(Account.id)).where(*filters)) or 0
    sort_column = {
        "score": Account.score.desc(),
        "name": Account.name.asc(),
        "updated_at": Account.updated_at.desc(),
    }[sort]
    accounts = db.scalars(
        select(Account)
        .where(*filters)
        .order_by(sort_column, Account.name.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    return {"items": [_account_json(account) for account in accounts], "total": total}


@app.get("/api/accounts/{account_id}", response_model=AccountResponse)
def account_detail(account_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    account = db.get(Account, account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    return _account_json(account)


@app.get("/api/ingestions", response_model=IngestionListResponse)
def list_ingestions(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    jobs = db.scalars(
        select(IngestionJob).order_by(IngestionJob.created_at.desc()).limit(limit)
    ).all()
    return {"items": [_job_json(job) for job in jobs]}


@app.post("/api/ingestions", status_code=202, response_model=IngestionResponse)
async def upload_ingestion(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    filename = Path(file.filename or "accounts.csv").name
    try:
        upload_format(filename)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    temp_dir = UPLOAD_TEMP_DIR or tempfile.gettempdir()
    os.makedirs(temp_dir, exist_ok=True)
    temp_path: str | None = None
    byte_count = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="signaldesk-", suffix=".upload", dir=temp_dir, delete=False
        ) as target:
            temp_path = target.name
            while chunk := await file.read(1024 * 1024):
                byte_count += len(chunk)
                if byte_count > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds the {MAX_UPLOAD_BYTES:,}-byte upload limit.",
                    )
                target.write(chunk)
        if byte_count == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")

        job = enqueue_ingestion(db, temp_path, filename)
        if job is None:
            raise RuntimeError("The newly uploaded file path is already queued.")
        return _job_json(job)
    except HTTPException:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    finally:
        await file.close()


@app.get("/api/ingestions/{job_id}", response_model=IngestionResponse)
def get_ingestion(job_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Ingestion job not found.")
    return _job_json(job)


def _agent_run_json(run: AgentRun) -> AgentRunResponse:
    return AgentRunResponse(
        id=run.id,
        parent_run_id=run.parent_run_id,
        status=run.status,
        input=run.input_data,
        plan=run.plan_data,
        trace=run.trace_data,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


@app.post("/api/agents/account-plans", response_model=AgentRunResponse, status_code=201)
def create_account_plan(
    request: AgentPlanRequest, db: Session = Depends(get_db)
) -> AgentRunResponse:
    try:
        run = build_account_plan(db, request)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    return _agent_run_json(run)


@app.get("/api/agent-runs/{run_id}", response_model=AgentRunResponse)
def get_agent_run(run_id: int, db: Session = Depends(get_db)) -> AgentRunResponse:
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found.")
    return _agent_run_json(run)


@app.post("/api/agent-runs/{run_id}/approval", response_model=AgentRunResponse)
def decide_agent_run(
    run_id: int,
    request: ApprovalRequest,
    db: Session = Depends(get_db),
) -> AgentRunResponse:
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found.")
    if run.status != "pending_approval":
        raise HTTPException(
            status_code=409,
            detail=f"Agent run is already {run.status}; approval cannot be changed.",
        )

    decision_status = "approved" if request.decision == "approve" else "rejected"
    trace = list(run.trace_data)
    last_step = max((event["step"] for event in trace), default=0)
    trace.append(
        {
            "step": last_step + 1,
            "event": decision_status,
            "input": {"decision": request.decision},
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    result = db.execute(
        update(AgentRun)
        .where(
            AgentRun.id == run_id,
            AgentRun.status == "pending_approval",
        )
        .values(status=decision_status, trace_data=trace)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Agent run was already decided by another request.",
        )
    db.commit()
    db.refresh(run)
    return _agent_run_json(run)


@app.post("/api/agent-runs/{run_id}/replay", response_model=AgentReplayResponse)
def replay_agent_run(run_id: int, db: Session = Depends(get_db)) -> AgentReplayResponse:
    run = db.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found.")
    try:
        trace = AccountAgentRuntime(db).replay(run)
    except (ValueError, LookupError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return AgentReplayResponse(
        run_id=run.id,
        status=run.status,
        replay_verified=True,
        trace=trace,
    )
