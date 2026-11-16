from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.agent_runtime import AccountAgentRuntime, build_account_plan
from app.main import decide_agent_run, replay_agent_run
from app.models import Account, AgentRun, Base
from app.schemas import AgentPlanRequest, AgentReplayResponse, ApprovalRequest


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            Account(
                account_key="northstar",
                name="Northstar Health",
                domain="northstar.example",
                industry="Healthcare",
                country="US",
                employee_count=420,
                score=70,
                tier="high",
                signals=[
                    {
                        "category": "incident",
                        "title": "Recent security incident",
                        "points": 35,
                        "evidence": "news: disclosed a ransomware incident",
                    },
                    {
                        "category": "compliance",
                        "title": "Regulatory exposure",
                        "points": 10,
                        "evidence": "certifications: HIPAA",
                    },
                ],
                attributes={"news": "disclosed a ransomware incident"},
                source_file="companies.csv",
                updated_at=datetime.now(timezone.utc),
            )
        )
        session.commit()
        yield session


def test_agent_tools_validate_output_and_create_a_human_checkpoint(db):
    run = build_account_plan(
        db,
        AgentPlanRequest(account_id=1, goal="Prioritize a thoughtful first touch."),
    )

    assert run.status == "pending_approval"
    assert run.account_id == 1
    assert run.plan_data["requires_human_review"] is True
    assert "ransomware" in run.plan_data["evidence"][0]["evidence"]
    assert [event["tool"] for event in run.trace_data if event["event"] == "tool_completed"] == [
        "load_account",
        "analyze_signals",
        "draft_action",
    ]
    assert run.trace_data[-1]["event"] == "checkpoint_created"


def test_approval_is_recorded_and_cannot_be_changed(db):
    run = build_account_plan(db, AgentPlanRequest(account_id=1))

    approved = decide_agent_run(
        run.id, ApprovalRequest(decision="approve"), db=db
    )

    assert approved.status == "approved"
    assert approved.trace[-1].event == "approved"
    with pytest.raises(HTTPException) as error:
        decide_agent_run(run.id, ApprovalRequest(decision="reject"), db=db)
    assert error.value.status_code == 409


def test_trace_replay_validates_saved_inputs_and_outputs(db):
    run = build_account_plan(db, AgentPlanRequest(account_id=1))

    replay = replay_agent_run(run.id, db=db)

    assert isinstance(replay, AgentReplayResponse)
    assert replay.replay_verified is True
    assert len(replay.trace) == 7
    approved = decide_agent_run(run.id, ApprovalRequest(decision="approve"), db=db)
    assert replay_agent_run(run.id, db=db).status == approved.status


def test_runtime_rejects_a_tool_budget_that_cannot_finish_the_workflow(db):
    with pytest.raises(ValueError, match="between 1 and 3"):
        AccountAgentRuntime(db, max_steps=4)

    with pytest.raises(RuntimeError, match="step budget"):
        AccountAgentRuntime(db, max_steps=2).create_run(
            AgentPlanRequest(account_id=1)
        )
    assert db.query(AgentRun).count() == 0


def test_replay_rejects_corrupted_tool_output(db):
    run = build_account_plan(db, AgentPlanRequest(account_id=1))
    trace = list(run.trace_data)
    trace[1] = {
        **trace[1],
        "output": {**trace[1]["output"], "tier": "urgent"},
    }
    run.trace_data = trace
    db.commit()
    db.refresh(run)

    with pytest.raises(ValueError):
        AccountAgentRuntime(db).replay(run)


def test_plan_for_unknown_account_is_an_explicit_failure(db):
    with pytest.raises(LookupError, match="Account 99"):
        build_account_plan(db, AgentPlanRequest(account_id=99))

    assert db.query(AgentRun).count() == 0
