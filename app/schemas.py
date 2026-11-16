"""Validated API contracts shared by routes, tools, and agent traces."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt


class APIModel(BaseModel):
    """Allow responses to be built from either ORM rows or typed values."""

    model_config = ConfigDict(from_attributes=True)


class Signal(BaseModel):
    category: str
    title: str
    points: int = Field(ge=0, le=100)
    evidence: str


class AccountResponse(APIModel):
    id: int
    name: str
    domain: str | None
    industry: str | None
    country: str | None
    employee_count: int | None
    score: float
    tier: Literal["high", "medium", "low"]
    signals: list[Signal]
    attributes: dict[str, Any]
    source_file: str
    updated_at: datetime | None


class AccountListResponse(BaseModel):
    items: list[AccountResponse]
    total: int = Field(ge=0)


class OverviewResponse(BaseModel):
    total_accounts: int = Field(ge=0)
    high_priority_accounts: int = Field(ge=0)
    active_ingestions: int = Field(ge=0)
    average_score: float = Field(ge=0, le=100)
    industries: list[str]


class HealthResponse(BaseModel):
    status: Literal["ok"]


class IngestionResponse(APIModel):
    id: int
    filename: str
    status: Literal["queued", "processing", "completed", "failed"]
    rows_processed: int = Field(ge=0)
    rows_skipped: int = Field(ge=0)
    error: str | None
    created_at: datetime | None
    finished_at: datetime | None


class IngestionListResponse(BaseModel):
    items: list[IngestionResponse]


class AgentPlanRequest(BaseModel):
    account_id: PositiveInt
    goal: str = Field(
        default="Prioritize a thoughtful first sales touch.",
        min_length=1,
        max_length=500,
    )


class AccountContext(BaseModel):
    account_id: PositiveInt
    name: str
    domain: str | None
    industry: str | None
    country: str | None
    employee_count: int | None
    score: float = Field(ge=0, le=100)
    tier: Literal["high", "medium", "low"]
    signals: list[Signal]


class SignalAnalysis(BaseModel):
    account_id: PositiveInt
    urgency_signals: list[Signal]
    fit_signals: list[Signal]
    evidence_summary: str
    evidence_available: bool


class AgentPlanOutput(BaseModel):
    account_id: PositiveInt
    plan_summary: str
    recommended_action: str
    rationale: str
    evidence: list[Signal]
    requires_human_review: Literal[True] = True


class AgentTraceEvent(BaseModel):
    step: int = Field(ge=1)
    event: Literal[
        "tool_started",
        "tool_completed",
        "checkpoint_created",
        "approved",
        "rejected",
    ]
    tool: str | None = None
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] | None = None
    occurred_at: datetime


class AgentRunResponse(BaseModel):
    id: int
    parent_run_id: int | None
    status: Literal["pending_approval", "approved", "rejected"]
    input: AgentPlanRequest
    plan: AgentPlanOutput
    trace: list[AgentTraceEvent]
    created_at: datetime | None
    updated_at: datetime | None


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "reject"]


class AgentReplayResponse(BaseModel):
    run_id: int
    status: Literal["pending_approval", "approved", "rejected"]
    replay_verified: bool
    trace: list[AgentTraceEvent]
