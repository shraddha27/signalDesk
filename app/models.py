"""PostgreSQL tables for account records and ingestion progress."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSON_DOCUMENT = JSON().with_variant(JSONB, "postgresql")


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        Index("ix_accounts_score", "score"),
        Index("ix_accounts_industry", "industry"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_key: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(500), index=True)
    domain: Mapped[str | None] = mapped_column(String(500), nullable=True)
    industry: Mapped[str | None] = mapped_column(String(300), nullable=True)
    country: Mapped[str | None] = mapped_column(String(200), nullable=True)
    employee_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0)
    tier: Mapped[str] = mapped_column(String(20), default="low")
    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON_DOCUMENT, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, default=dict)
    source_file: Mapped[str] = mapped_column(String(500))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (Index("ix_ingestion_jobs_created_at", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    rows_processed: Mapped[int] = mapped_column(Integer, default=0)
    rows_skipped: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class IngestionWorkItem(Base):
    __tablename__ = "ingestion_work_items"
    __table_args__ = (
        Index("ix_ingestion_work_items_ready", "next_attempt_at", "lease_until"),
        Index("ix_ingestion_work_items_completed_at", "completed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(
        ForeignKey("ingestion_jobs.id"), unique=True, index=True
    )
    source_path: Mapped[str] = mapped_column(String(2048), unique=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    worker_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AgentRun(Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        Index("ix_agent_runs_created_at", "created_at"),
        Index("ix_agent_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    parent_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("agent_runs.id"), nullable=True
    )
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending_approval")
    input_data: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)
    plan_data: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT)
    trace_data: Mapped[list[dict[str, Any]]] = mapped_column(JSON_DOCUMENT)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
