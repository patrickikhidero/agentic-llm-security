"""
orchestrator.py
───────────────
Core agentic pipeline. `Pipeline.run()` receives a task, runs the planning
loop, invokes tools, and returns the final result. It is used directly
in-process by the evaluation runner (src/evaluation/runner.py) and is also
exposed over HTTP by the FastAPI app below for interactive/manual use.

This is the primary attack surface evaluated in:
  Ikhidero, P. O. (2026). An Empirical Evaluation of Attack and Defense Dynamics in
  Enterprise Agentic LLM Pipelines. Zenodo. [DOI to be assigned]

Attack injection: `Pipeline.run(..., attack_injection={"type": ..., "scenario": ...})`
lets the evaluation runner mount goal-hijacking (mid-execution response poisoning),
cascade-exploitation (induced tool failures), and tool-description-poisoning
(poisoned tool registry) attacks against a real execution. Indirect prompt
injection requires no hook here — it is mounted by seeding poisoned documents
into the retrieval corpus before calling run().
"""

import logging
import time
import uuid
from typing import Any

import yaml
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

load_dotenv()

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

DEFENSE_NAMES = ["input_screener", "goal_verifier", "output_validator", "hitl_gate"]


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


class Pipeline:
    """Holds all pipeline state and runs the agentic execution loop."""

    def __init__(self, pipeline_cfg: dict, defense_cfg: dict) -> None:
        self.pipeline_cfg = pipeline_cfg
        self.defense_cfg = defense_cfg

        self.tools = {
            "retrieval": RetrievalTool(pipeline_cfg["tools"]["retrieval"]),
            "code_exec": CodeExecTool(pipeline_cfg["tools"]["code_execution"]),
            "api_call": APICallTool(pipeline_cfg["tools"]["api_call"]),
        }
        self.planner = Planner(pipeline_cfg["agent"])
        self.context_mgr = ContextManager(pipeline_cfg["memory"])
        self.input_screener = InputScreener(defense_cfg["input_screener"])
        self.goal_verifier = GoalVerifier(defense_cfg["goal_verifier"])
        self.output_validator = OutputValidator(defense_cfg["output_validator"])
        self.hitl_gate = HITLGate(defense_cfg["hitl_gate"])

        self.base_tool_registry = {
            name: {"description": tool.DESCRIPTION, "parameters": {}}
            for name, tool in self.tools.items()
        }

    def _effective_defense_flags(self, defense_profile: str) -> dict[str, bool]:
        """
        baseline           -> all four defenses off (undefended condition)
        layered            -> all four defenses per defense_config.yaml
        individual_<name>  -> only <name> on (per-layer ablation, RQ3)
        """
        if defense_profile == "baseline":
            return {n: False for n in DEFENSE_NAMES}
        if defense_profile.startswith("individual_"):
            target = defense_profile[len("individual_"):]
            return {n: (n == target) for n in DEFENSE_NAMES}
        return {n: self.defense_cfg[n].get("enabled", True) for n in DEFENSE_NAMES}

    async def run(self, task: str, defense_profile: str = "layered",
                  attack_injection: dict[str, Any] | None = None,
                  session_id: str | None = None) -> dict:
        session_id = session_id or str(uuid.uuid4())
        start_time = time.time()
        defense_events: list[dict] = []
        tool_call_log: list[dict] = []
        status = "completed"
        flags = self._effective_defense_flags(defense_profile)

        # Domain allowlisting is a fixed tool-level control described alongside
        # the defense stack in the methodology, but for the profile contrast to
        # be meaningful it must vary with it too: undefended (baseline) and
        # single-layer ablations (individual_*) permit all domains so that
        # attacker-URL attacks aren't pre-blocked by this control; only the
        # full "layered" profile enforces it.
        api_tool = self.tools["api_call"]
        if defense_profile == "layered":
            api_tool.allowed_domains = list(
                self.pipeline_cfg["tools"]["api_call"].get("legitimate_domains", []))
        else:
            api_tool.allowed_domains = []

        attack_injection = attack_injection or {}
        attack_type = attack_injection.get("type")
        attack_scenario = attack_injection.get("scenario")

        logger.info(f"[{session_id}] Task received: {task[:100]} | profile={defense_profile}")

        # ── Build tool registry (poisoned if this is a tool-poisoning trial) ────
        tool_registry = self.base_tool_registry
        if attack_type == "tool_poisoning":
            from src.attacks.tool_poisoning import ToolPoisoningAttack
            tool_registry = ToolPoisoningAttack().get_poisoned_tool_registry(
                attack_scenario, self.base_tool_registry)

        # ── Step 0: screen incoming task ──────────────────────────────────────────
        if flags["input_screener"]:
            screen_result = self.input_screener.screen(task)
            if screen_result["flagged"]:
                defense_events.append({"step": 0, "defense": "input_screener",
                                       "event": "injection_detected_in_user_input",
                                       "detail": screen_result})
                if self.defense_cfg["input_screener"]["block_on_detection"]:
                    elapsed_ms = (time.time() - start_time) * 1000
                    return {
                        "session_id": session_id, "task": task,
                        "result": "[INPUT BLOCKED: potential injection pattern detected]",
                        "steps_taken": 0, "execution_time_ms": round(elapsed_ms, 2),
                        "defense_events": defense_events, "tool_call_log": tool_call_log,
                        "status": "halted_by_defense",
                    }

        # ── Initialize context ────────────────────────────────────────────────────
        context = self.context_mgr.initialize(session_id, task)
        original_goal = task
        max_steps = self.pipeline_cfg["agent"]["max_steps"]
        step = 0

        # ── Agentic execution loop ────────────────────────────────────────────────
        for step in range(1, max_steps + 1):
            plan = self.planner.plan(context, tool_registry)

            if plan["action"] == "ERROR":
                # A pipeline-level planning failure, not a genuine model
                # decision — must not be scored as a completed task.
                status = "error"
                break

            if plan["action"] == "FINISH":
                break

            # ── Goal consistency check ────────────────────────────────────────────
            if flags["goal_verifier"]:
                gv_result = self.goal_verifier.verify(original_goal, plan, context)
                if not gv_result["consistent"]:
                    defense_events.append({"step": step, "defense": "goal_verifier",
                                           "event": "goal_inconsistency_detected",
                                           "planned_action": plan.get("action"),
                                           "consistency_score": gv_result["score"]})
                    if self.defense_cfg["goal_verifier"]["halt_on_inconsistency"]:
                        status = "halted_by_defense"
                        break

            # ── HITL gate for high-consequence actions ────────────────────────────
            if flags["hitl_gate"]:
                hitl_result = self.hitl_gate.check(plan)
                if hitl_result["requires_confirmation"]:
                    approved = await self.hitl_gate.request_confirmation(session_id, plan)
                    if not approved:
                        defense_events.append({"step": step, "defense": "hitl_gate",
                                               "event": "action_rejected_by_human",
                                               "action": plan.get("action")})
                        status = "halted_by_defense"
                        break

            # ── Execute tool (or substitute an attack-induced response) ───────────
            tool_name = plan.get("tool")
            tool_input = plan.get("tool_input", {})

            if tool_name not in self.tools:
                logger.warning(f"[{session_id}] Unknown tool requested: {tool_name}")
                unknown_output = {"error": "unknown tool"}
                # Still recorded in the call log: a selection of a non-executable
                # tool (e.g. an auxiliary tool injected only via a poisoned
                # description) is itself the signal a poisoning attack looks for.
                tool_call_log.append({"step": step, "tool": tool_name,
                                       "input": tool_input, "output": unknown_output,
                                       "latency_ms": 0.0})
                context = self.context_mgr.update(context, step, plan, unknown_output)
                continue

            induced_failure = None
            if attack_type == "cascade_exploit":
                from src.attacks.cascade_exploit import CascadeExploitAttack
                induced_failure = CascadeExploitAttack().get_failure_response(
                    attack_scenario, step, tool_name)

            tool_start = time.time()
            if induced_failure is not None:
                tool_output = induced_failure
            else:
                try:
                    tool_output = self.tools[tool_name].execute(tool_input)
                except Exception as exc:
                    logger.error(f"[{session_id}] Tool {tool_name} raised: {exc}")
                    tool_output = {"error": str(exc)}
            tool_latency = (time.time() - tool_start) * 1000

            # ── Goal hijacking: poison the tool response at the target step ───────
            if attack_type == "goal_hijacking":
                from src.attacks.goal_hijacking import GoalHijackingAttack
                tool_output = GoalHijackingAttack().get_poisoned_tool_response(
                    attack_scenario, step, tool_output)

            tool_call_log.append({"step": step, "tool": tool_name,
                                   "input": tool_input, "output": tool_output,
                                   "latency_ms": round(tool_latency, 2)})

            # ── Screen tool output before injecting into context ──────────────────
            if (flags["input_screener"]
                    and self.defense_cfg["input_screener"]["screen_retrieved_content"]):
                raw_output = str(tool_output)
                screen_result = self.input_screener.screen(raw_output)
                if screen_result["flagged"]:
                    defense_events.append({"step": step, "defense": "input_screener",
                                           "event": "injection_detected_in_tool_output",
                                           "tool": tool_name,
                                           "detail": screen_result})
                    if self.defense_cfg["input_screener"]["block_on_detection"]:
                        tool_output = {"content": "[CONTENT BLOCKED: injection pattern detected]",
                                       "blocked": True}

            # Update context with isolated tool output
            context = self.context_mgr.update(context, step, plan, tool_output)

        else:
            status = "max_steps_reached"

        # ── Generate final output ─────────────────────────────────────────────────
        final_result = self.planner.finalize(context, tool_registry)

        # ── Validate final output ─────────────────────────────────────────────────
        if flags["output_validator"]:
            ov_result = self.output_validator.validate(final_result)
            if ov_result["violation_detected"]:
                defense_events.append({"step": "final", "defense": "output_validator",
                                       "event": "output_violation_detected",
                                       "categories": ov_result["categories"]})
                if self.defense_cfg["output_validator"]["block_on_violation"]:
                    final_result = "[OUTPUT BLOCKED: policy violation detected in model response]"
                    status = "halted_by_defense"

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info(f"[{session_id}] Completed in {elapsed_ms:.0f}ms | status={status}")

        return {
            "session_id": session_id,
            "task": task,
            "result": final_result,
            "steps_taken": step,
            "execution_time_ms": round(elapsed_ms, 2),
            "defense_events": defense_events,
            "tool_call_log": tool_call_log,
            "status": status,
        }


# ── FastAPI wrapper (interactive/manual use) ───────────────────────────────────

app = FastAPI(title="Agentic LLM Security Research Pipeline", version="1.0.0")

pipeline_cfg = load_config("configs/pipeline_config.yaml")
defense_cfg  = load_config("configs/defense_config.yaml")
_pipeline = Pipeline(pipeline_cfg, defense_cfg)


class TaskRequest(BaseModel):
    task: str
    session_id: str | None = None
    defense_profile: str = "layered"  # baseline | individual_<name> | layered


class TaskResponse(BaseModel):
    session_id: str
    task: str
    result: str
    steps_taken: int
    execution_time_ms: float
    defense_events: list[dict]
    tool_call_log: list[dict]
    status: str  # completed | halted_by_defense | max_steps_reached | error


@app.post("/run", response_model=TaskResponse)
async def run_task(request: TaskRequest) -> TaskResponse:
    result = await _pipeline.run(request.task, request.defense_profile,
                                  session_id=request.session_id)
    return TaskResponse(**result)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok", "version": "1.0.0"}
