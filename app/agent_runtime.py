"""Bounded, typed tool runtime for explainable account-planning workflows."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

import logfire
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models import Account, AgentRun
from app.schemas import (
    AccountContext,
    AgentPlanOutput,
    AgentPlanRequest,
    AgentTraceEvent,
    Signal,
    SignalAnalysis,
)

MAX_AGENT_STEPS = 3

InputModel = TypeVar("InputModel", bound=BaseModel)
OutputModel = TypeVar("OutputModel", bound=BaseModel)


class LoadAccountInput(BaseModel):
    account_id: int


class AnalyzeSignalsInput(BaseModel):
    account: AccountContext


class DraftActionInput(BaseModel):
    account: AccountContext
    analysis: SignalAnalysis
    goal: str


@dataclass(frozen=True)
class ToolDefinition(Generic[InputModel, OutputModel]):
    name: str
    input_model: type[InputModel]
    output_model: type[OutputModel]
    handler: Callable[[InputModel], OutputModel]


class AccountAgentRuntime:
    """Execute a fixed, inspectable tool loop and persist a human checkpoint."""

    def __init__(self, db: Session, max_steps: int = MAX_AGENT_STEPS) -> None:
        if not 1 <= max_steps <= MAX_AGENT_STEPS:
            raise ValueError(f"max_steps must be between 1 and {MAX_AGENT_STEPS}.")
        self.db = db
        self.max_steps = max_steps
        self.tools: dict[str, ToolDefinition[Any, Any]] = {
            "load_account": ToolDefinition(
                name="load_account",
                input_model=LoadAccountInput,
                output_model=AccountContext,
                handler=self._load_account,
            ),
            "analyze_signals": ToolDefinition(
                name="analyze_signals",
                input_model=AnalyzeSignalsInput,
                output_model=SignalAnalysis,
                handler=self._analyze_signals,
            ),
            "draft_action": ToolDefinition(
                name="draft_action",
                input_model=DraftActionInput,
                output_model=AgentPlanOutput,
                handler=self._draft_action,
            ),
        }

    def _load_account(self, request: LoadAccountInput) -> AccountContext:
        account = self.db.get(Account, request.account_id)
        if account is None:
            raise LookupError(f"Account {request.account_id} was not found.")
        return AccountContext(
            account_id=account.id,
            name=account.name,
            domain=account.domain,
            industry=account.industry,
            country=account.country,
            employee_count=account.employee_count,
            score=account.score,
            tier=account.tier,
            signals=[Signal.model_validate(signal) for signal in account.signals or []],
        )

    @staticmethod
    def _analyze_signals(request: AnalyzeSignalsInput) -> SignalAnalysis:
        urgency_categories = {"incident", "exposure"}
        urgency = [
            signal
            for signal in request.account.signals
            if signal.category in urgency_categories
        ]
        fit = [
            signal
            for signal in request.account.signals
            if signal.category not in urgency_categories
        ]
        all_signals = urgency + fit
        summary = (
            "; ".join(signal.evidence for signal in all_signals)
            if all_signals
            else "No matched risk or fit signals were found in the supplied account data."
        )
        return SignalAnalysis(
            account_id=request.account.account_id,
            urgency_signals=urgency,
            fit_signals=fit,
            evidence_summary=summary,
            evidence_available=bool(all_signals),
        )

    @staticmethod
    def _draft_action(request: DraftActionInput) -> AgentPlanOutput:
        evidence = request.analysis.urgency_signals or request.analysis.fit_signals
        if request.analysis.urgency_signals:
            action = "Review the cited incident or exposure evidence, then ask a timely, non-presumptive discovery question."
            summary = "Prioritize a human-reviewed, evidence-led first touch."
        elif request.analysis.evidence_available:
            action = "Verify the cited fit signal and company context before choosing an outreach angle."
            summary = "Research account fit before personalizing outreach."
        else:
            action = "Research the account using approved sources before claiming a cybersecurity need."
            summary = "Gather evidence before prioritizing outreach."

        return AgentPlanOutput(
            account_id=request.account.account_id,
            plan_summary=summary,
            recommended_action=action,
            rationale=(
                f"Requested goal: {request.goal} "
                f"Evidence review: {request.analysis.evidence_summary}"
            ),
            evidence=evidence,
        )

    def _next_tool(
        self,
        request: AgentPlanRequest,
        account: AccountContext | None,
        analysis: SignalAnalysis | None,
        plan: AgentPlanOutput | None,
    ) -> tuple[str, dict[str, Any]] | None:
        if account is None:
            return "load_account", {"account_id": request.account_id}
        if analysis is None:
            return "analyze_signals", {"account": account.model_dump(mode="json")}
        if plan is None:
            return (
                "draft_action",
                {
                    "account": account.model_dump(mode="json"),
                    "analysis": analysis.model_dump(mode="json"),
                    "goal": request.goal,
                },
            )
        return None

    def _invoke(
        self, tool_name: str, raw_input: dict[str, Any]
    ) -> tuple[BaseModel, dict[str, Any]]:
        tool = self.tools.get(tool_name)
        if tool is None:
            raise ValueError(f"Unregistered agent tool: {tool_name}.")
        tool_input = tool.input_model.model_validate(raw_input)
        result = tool.handler(tool_input)
        validated_result = tool.output_model.model_validate(result)
        json_output = json.loads(validated_result.model_dump_json())
        return validated_result, json_output

    def create_run(
        self, request: AgentPlanRequest, parent_run_id: int | None = None
    ) -> AgentRun:
        account: AccountContext | None = None
        analysis: SignalAnalysis | None = None
        plan: AgentPlanOutput | None = None
        trace: list[AgentTraceEvent] = []
        iteration = 0

        # A hard step budget prevents accidental unbounded tool loops.
        with logfire.span(
            "agent.account_plan",
            account_id=request.account_id,
            max_steps=self.max_steps,
        ):
            while iteration < self.max_steps:
                next_tool = self._next_tool(request, account, analysis, plan)
                if next_tool is None:
                    break
                tool_name, tool_input = next_tool
                iteration += 1
                trace.append(
                    AgentTraceEvent(
                        step=iteration,
                        event="tool_started",
                        tool=tool_name,
                        input=tool_input,
                        occurred_at=datetime.now(timezone.utc),
                    )
                )
                result, output = self._invoke(tool_name, tool_input)
                trace.append(
                    AgentTraceEvent(
                        step=iteration,
                        event="tool_completed",
                        tool=tool_name,
                        input=tool_input,
                        output=output,
                        occurred_at=datetime.now(timezone.utc),
                    )
                )
                if tool_name == "load_account":
                    account = AccountContext.model_validate(result)
                elif tool_name == "analyze_signals":
                    analysis = SignalAnalysis.model_validate(result)
                else:
                    plan = AgentPlanOutput.model_validate(result)

        if plan is None:
            raise RuntimeError("The agent reached its step budget without a complete plan.")

        trace.append(
            AgentTraceEvent(
                step=iteration + 1,
                event="checkpoint_created",
                input={"required": True, "reason": "Review the evidence and plan before action."},
                occurred_at=datetime.now(timezone.utc),
            )
        )
        run = AgentRun(
            parent_run_id=parent_run_id,
            account_id=request.account_id,
            status="pending_approval",
            input_data=request.model_dump(mode="json"),
            plan_data=json.loads(plan.model_dump_json()),
            trace_data=[json.loads(event.model_dump_json()) for event in trace],
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        logfire.info(
            "Agent plan created",
            run_id=run.id,
            account_id=request.account_id,
            tool_steps=iteration,
            status=run.status,
        )
        return run

    def replay(self, run: AgentRun) -> list[AgentTraceEvent]:
        """Validate a saved trace against registered tool schemas without side effects."""
        AgentPlanRequest.model_validate(run.input_data)
        AgentPlanOutput.model_validate(run.plan_data)
        replayed: list[AgentTraceEvent] = []
        for raw_event in run.trace_data:
            event = AgentTraceEvent.model_validate(raw_event)
            if event.event == "tool_completed":
                if event.tool is None or event.output is None:
                    raise ValueError("Completed tool trace is missing its tool or output.")
                tool = self.tools.get(event.tool)
                if tool is None:
                    raise ValueError(f"Trace contains unregistered tool {event.tool}.")
                tool.input_model.model_validate(event.input)
                tool.output_model.model_validate(event.output)
            replayed.append(event)

        tool_events = [
            event
            for event in replayed
            if event.event in {"tool_started", "tool_completed"}
        ]
        if len(tool_events) != MAX_AGENT_STEPS * 2:
            raise ValueError("Trace does not contain the complete bounded tool sequence.")
        expected_tools = ["load_account", "analyze_signals", "draft_action"]
        for index, expected_tool in enumerate(expected_tools):
            started, completed = tool_events[index * 2 : index * 2 + 2]
            if (
                started.event != "tool_started"
                or completed.event != "tool_completed"
                or started.step != index + 1
                or completed.step != index + 1
                or started.tool != expected_tool
                or completed.tool != expected_tool
                or started.input != completed.input
            ):
                raise ValueError("Trace tool ordering or arguments are inconsistent.")

        checkpoint_index = next(
            (
                index
                for index, event in enumerate(replayed)
                if event.event == "checkpoint_created"
            ),
            None,
        )
        expected_checkpoint_index = (
            len(replayed) - 1 if run.status == "pending_approval" else len(replayed) - 2
        )
        if checkpoint_index != expected_checkpoint_index:
            raise ValueError("Trace is missing its final human checkpoint.")
        if run.status != "pending_approval" and replayed[-1].event != run.status:
            raise ValueError("Trace decision does not match the saved run status.")
        return replayed


def build_account_plan(
    db: Session, request: AgentPlanRequest, parent_run_id: int | None = None
) -> AgentRun:
    """Create one traced plan run using the bounded account runtime."""
    return AccountAgentRuntime(db).create_run(request, parent_run_id=parent_run_id)
