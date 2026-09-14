"""
context_manager.py
──────────────────
Manages the agent's context window across execution steps.
Enforces structural separation between trusted instructions and
untrusted tool outputs — a core principle of the defense architecture
described in Ikhidero (2026).
"""

import logging

logger = logging.getLogger(__name__)


class ContextManager:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.max_tokens = config.get("max_context_tokens", 8000)
        self.session_persistence = config.get("session_persistence", False)
        self._sessions: dict[str, dict] = {}

    def initialize(self, session_id: str, task: str) -> dict:
        """Create a fresh context for a new task execution."""
        context = {
            "session_id": session_id,
            "original_task": task,
            "history": [],       # List of {step, plan, tool, output}
            "token_count": 0,
        }
        if self.session_persistence:
            self._sessions[session_id] = context
        logger.debug(f"Context initialized for session {session_id}")
        return context

    def update(self, context: dict, step: int,
               plan: dict, tool_output: dict) -> dict:
        """
        Append a completed step to the context history.
        Tool outputs are stored separately from planning instructions
        to preserve the structural separation principle.
        """
        entry = {
            "step": step,
            "plan": plan,
            "tool": plan.get("tool", "none"),
            "output": tool_output,
            # Flag output as untrusted — never promoted to instruction level
            "output_trusted": False,
        }
        context["history"].append(entry)
        context["token_count"] = self._estimate_tokens(context)

        # Trim oldest entries if context window is approaching limit
        while context["token_count"] > self.max_tokens and len(context["history"]) > 1:
            removed = context["history"].pop(0)
            logger.debug(f"Trimmed step {removed['step']} from context to manage window size")
            context["token_count"] = self._estimate_tokens(context)

        return context

    def get(self, session_id: str) -> dict | None:
        return self._sessions.get(session_id)

    def _estimate_tokens(self, context: dict) -> int:
        """Rough token estimate: 1 token ≈ 4 characters."""
        import json
        raw = json.dumps(context)
        return len(raw) // 4
