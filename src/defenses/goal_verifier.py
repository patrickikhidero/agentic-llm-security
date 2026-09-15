"""
goal_verifier.py
────────────────
Defense Layer 2: Goal-Consistency Verification

At each step of the execution chain, verifies that the agent's
planned action is consistent with the user's original goal.

Addresses: Goal hijacking, cascade exploitation.
Implements the Task Shield concept (Jia et al., 2025).
"""

import logging

from src.common.embeddings import cosine_similarity

logger = logging.getLogger(__name__)


class GoalVerifier:
    """
    Verifies goal consistency by comparing the semantic similarity
    between the original task goal and the agent's current planned action.

    A planned action that deviates significantly from the original goal
    is flagged as a potential hijacking attempt and the pipeline is halted.
    """

    def __init__(self, config: dict) -> None:
        self.config    = config
        self.enabled   = config.get("enabled", True)
        self.threshold = config.get("consistency_threshold", 0.80)
        self.halt      = config.get("halt_on_inconsistency", True)

    def verify(self, original_goal: str, plan: dict, context: dict) -> dict:
        """
        Check whether the planned action is consistent with the original goal.

        Args:
            original_goal:  The user's original task statement
            plan:           Current plan dict from the planner
            context:        Full execution context

        Returns:
            dict with:
              consistent (bool)
              score (float)     cosine similarity
              method (str)
              evidence (str)
        """
        import time
        start = time.time()

        action_description = self._describe_action(plan)

        # ── Embedding-based consistency check ─────────────────────────────────
        try:
            score = self._embedding_similarity(original_goal, action_description)
            consistent = score >= self.threshold
            latency = (time.time() - start) * 1000

            if not consistent:
                logger.warning(
                    f"Goal inconsistency detected | "
                    f"score={score:.3f} < threshold={self.threshold} | "
                    f"planned_action='{action_description[:100]}' | "
                    f"latency={latency:.1f}ms"
                )

            return {
                "consistent": consistent,
                "score": round(score, 4),
                "method": "embedding_similarity",
                "original_goal": original_goal[:200],
                "planned_action": action_description[:200],
                "latency_ms": round(latency, 2),
            }

        except Exception as exc:
            logger.error(f"GoalVerifier error: {exc}")
            # Fail open — allow execution to continue on verifier error
            return {"consistent": True, "score": 0.0,
                    "method": "error_failopen", "evidence": str(exc)}

    def _embedding_similarity(self, text_a: str, text_b: str) -> float:
        return cosine_similarity(text_a[:1500], text_b[:1500])

    def _describe_action(self, plan: dict) -> str:
        """Convert a plan dict to a natural language description for comparison."""
        action = plan.get("action", "")
        tool   = plan.get("tool", "")
        inp    = plan.get("tool_input", {})
        reason = plan.get("reasoning", "")

        if action == "FINISH":
            return f"Complete the task and return final answer. Reasoning: {reason}"
        if tool == "api_call":
            return (f"Call external API at {inp.get('url', 'unknown URL')} "
                    f"using {inp.get('method', 'GET')}. Reasoning: {reason}")
        if tool == "retrieval":
            return f"Retrieve documents matching '{inp.get('query', '')}'. Reasoning: {reason}"
        if tool == "code_exec":
            code_preview = str(inp.get("code", ""))[:100]
            return f"Execute code: {code_preview}. Reasoning: {reason}"
        return f"Action: {action} | Tool: {tool} | Reasoning: {reason}"
