"""
orchestrator.py
───────────────
Core agentic pipeline server. Receives a user task, runs the planning loop,
invokes tools, and returns the final result.

This is the primary attack surface evaluated in:
  Ikhidero, P. O. (2026). An Empirical Evaluation of Attack and Defense Dynamics in
  Enterprise Agentic LLM Pipelines. Zenodo. [DOI to be assigned]
"""

import logging
import time
import uuid
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.agent.planner import Planner
from src.agent.context_manager import ContextManager
from src.defenses.input_screener import InputScreener
from src.defenses.goal_verifier import GoalVerifier
from src.defenses.output_validator import OutputValidator
from src.defenses.hitl_gate import HITLGate
from src.tools.retrieval_tool import RetrievalTool
from src.tools.code_exec_tool import CodeExecTool
from src.tools.api_call_tool import APICallTool

logger = logging.getLogger(__name__)

app = FastAPI(title="Agentic LLM Security Research Pipeline", version="1.0.0")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Request / Response Models ──────────────────────────────────────────────────

class TaskRequest(BaseModel):
    task: str
    session_id: str | None = None
    defense_profile: str = "layered"  # baseline | individual | layered


class TaskResponse(BaseModel):
    session_id: str
    task: str
    result: str
    steps_taken: int
    execution_time_ms: float
    defense_events: list[dict]
    tool_call_log: list[dict]
    status: str  # completed | halted_by_defense | max_steps_reached | error


# ── Pipeline Initialization ────────────────────────────────────────────────────

pipeline_cfg = load_config("configs/pipeline_config.yaml")
defense_cfg  = load_config("configs/defense_config.yaml")

tools = {
    "retrieval": RetrievalTool(pipeline_cfg["tools"]["retrieval"]),
    "code_exec": CodeExecTool(pipeline_cfg["tools"]["code_execution"]),
    "api_call":  APICallTool(pipeline_cfg["tools"]["api_call"]),
}

planner       = Planner(pipeline_cfg["agent"])
context_mgr   = ContextManager(pipeline_cfg["memory"])
input_screener  = InputScreener(defense_cfg["input_screener"])
goal_verifier   = GoalVerifier(defense_cfg["goal_verifier"])
output_validator = OutputValidator(defense_cfg["output_validator"])
hitl_gate       = HITLGate(defense_cfg["hitl_gate"])


# ── Main Endpoint ──────────────────────────────────────────────────────────────

@app.post("/run", response_model=TaskResponse)
async def run_task(request: TaskRequest) -> TaskResponse:
    session_id = request.session_id or str(uuid.uuid4())
    start_time = time.time()
    defense_events: list[dict] = []
    tool_call_log: list[dict] = []
    status = "completed"

    logger.info(f"[{session_id}] Task received: {request.task[:100]}")

    # ── Step 0: Screen incoming task ──────────────────────────────────────────
    if defense_cfg["input_screener"]["enabled"]:
        screen_result = input_screener.screen(request.task)
        if screen_result["flagged"]:
            defense_events.append({"step": 0, "defense": "input_screener",
                                   "event": "injection_detected_in_user_input",
                                   "detail": screen_result})
            if defense_cfg["input_screener"]["block_on_detection"]:
                raise HTTPException(status_code=400,
                    detail="Input rejected: potential injection pattern detected.")

    # ── Initialize context ────────────────────────────────────────────────────
    context = context_mgr.initialize(session_id, request.task)
    original_goal = request.task

    # ── Agentic execution loop ────────────────────────────────────────────────
    max_steps = pipeline_cfg["agent"]["max_steps"]

    for step in range(1, max_steps + 1):
        logger.info(f"[{session_id}] Step {step}/{max_steps}")

        # Plan next action
        plan = planner.plan(context)

        if plan["action"] == "FINISH":
            break

        # ── Goal consistency check ────────────────────────────────────────────
        if defense_cfg["goal_verifier"]["enabled"]:
            gv_result = goal_verifier.verify(original_goal, plan, context)
            if not gv_result["consistent"]:
                defense_events.append({"step": step, "defense": "goal_verifier",
                                       "event": "goal_inconsistency_detected",
                                       "planned_action": plan["action"],
                                       "consistency_score": gv_result["score"]})
                if defense_cfg["goal_verifier"]["halt_on_inconsistency"]:
                    status = "halted_by_defense"
                    break

        # ── HITL gate for high-consequence actions ────────────────────────────
        if defense_cfg["hitl_gate"]["enabled"]:
            hitl_result = hitl_gate.check(plan)
            if hitl_result["requires_confirmation"]:
                approved = await hitl_gate.request_confirmation(session_id, plan)
                if not approved:
                    defense_events.append({"step": step, "defense": "hitl_gate",
                                           "event": "action_rejected_by_human",
                                           "action": plan["action"]})
                    status = "halted_by_defense"
                    break

        # ── Execute tool ──────────────────────────────────────────────────────
        tool_name  = plan.get("tool")
        tool_input = plan.get("tool_input", {})

        if tool_name not in tools:
            logger.warning(f"[{session_id}] Unknown tool requested: {tool_name}")
            context = context_mgr.update(context, step, plan, {"error": "unknown tool"})
            continue

        tool_start = time.time()
        try:
            tool_output = tools[tool_name].execute(tool_input)
        except Exception as exc:
            logger.error(f"[{session_id}] Tool {tool_name} raised: {exc}")
            tool_output = {"error": str(exc)}

        tool_latency = (time.time() - tool_start) * 1000
        tool_call_log.append({"step": step, "tool": tool_name,
                               "input": tool_input, "output": tool_output,
                               "latency_ms": round(tool_latency, 2)})

        # ── Screen tool output before injecting into context ──────────────────
        if (defense_cfg["input_screener"]["enabled"]
                and defense_cfg["input_screener"]["screen_retrieved_content"]):
            raw_output = str(tool_output)
            screen_result = input_screener.screen(raw_output)
            if screen_result["flagged"]:
                defense_events.append({"step": step, "defense": "input_screener",
                                       "event": "injection_detected_in_tool_output",
                                       "tool": tool_name,
                                       "detail": screen_result})
                if defense_cfg["input_screener"]["block_on_detection"]:
                    tool_output = {"content": "[CONTENT BLOCKED: injection pattern detected]",
                                   "blocked": True}

        # Update context with isolated tool output
        context = context_mgr.update(context, step, plan, tool_output)

    else:
        status = "max_steps_reached"

    # ── Generate final output ─────────────────────────────────────────────────
    final_result = planner.finalize(context)

    # ── Validate final output ─────────────────────────────────────────────────
    if defense_cfg["output_validator"]["enabled"]:
        ov_result = output_validator.validate(final_result)
        if ov_result["violation_detected"]:
            defense_events.append({"step": "final", "defense": "output_validator",
                                   "event": "output_violation_detected",
                                   "categories": ov_result["categories"]})
            if defense_cfg["output_validator"]["block_on_violation"]:
                final_result = "[OUTPUT BLOCKED: policy violation detected in model response]"
                status = "halted_by_defense"

    elapsed_ms = (time.time() - start_time) * 1000
    logger.info(f"[{session_id}] Completed in {elapsed_ms:.0f}ms | status={status}")

    return TaskResponse(
        session_id=session_id,
        task=request.task,
        result=final_result,
        steps_taken=step,
        execution_time_ms=round(elapsed_ms, 2),
        defense_events=defense_events,
        tool_call_log=tool_call_log,
        status=status,
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "version": "1.0.0"}
