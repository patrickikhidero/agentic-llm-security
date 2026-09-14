"""
hitl_gate.py
────────────
Defense Layer 4: Human-in-the-Loop Confirmation Gate

Intercepts high-consequence or irreversible actions before the agent
executes them and requires explicit human approval.

Addresses: Goal hijacking (prevents execution of attacker goal),
           privilege escalation (blocks unauthorized write operations).

In experiment mode, auto-approval can be simulated for baseline comparison.
"""

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Actions that require human confirmation before execution
HIGH_CONSEQUENCE_ACTIONS = {
    "api_post_request":              "POST request to external API",
    "api_put_request":               "PUT request to external API",
    "api_delete_request":            "DELETE request to external API",
    "code_execution_with_file_write":"Code execution that writes to filesystem",
    "any_action_on_regulated_data":  "Action involving PHI or regulated data",
}


class HITLGate:
    """
    Human-in-the-loop gate that intercepts high-consequence actions.

    In production: sends confirmation request to a human operator
    and waits for approval (with timeout).

    In experiment mode: uses auto_approve_policy to simulate human
    decisions for controlled evaluation of defense effectiveness.
    """

    def __init__(self, config: dict) -> None:
        self.config           = config
        self.enabled          = config.get("enabled", False)
        self.require_for      = config.get("require_confirmation_for", [])
        self.auto_reads       = config.get("auto_approve_reads", True)
        self.timeout          = config.get("confirmation_timeout_seconds", 60)
        # Experiment-only: simulated human decision policy
        # "always_approve" | "always_deny" | "deny_attacker_urls"
        self.experiment_policy = config.get("experiment_policy", "deny_attacker_urls")

    def check(self, plan: dict) -> dict:
        """
        Determine whether the planned action requires human confirmation.

        Returns:
            dict with:
              requires_confirmation (bool)
              reason (str)
              action_class (str)
        """
        if not self.enabled:
            return {"requires_confirmation": False, "reason": "HITL disabled"}

        tool   = plan.get("tool", "")
        inp    = plan.get("tool_input", {})
        method = inp.get("method", "GET").upper()

        # Read-only API calls can be auto-approved
        if tool == "api_call" and method == "GET" and self.auto_reads:
            return {"requires_confirmation": False,
                    "reason": "Read-only API call auto-approved"}

        # Check write API methods
        if tool == "api_call" and method in ("POST", "PUT", "DELETE", "PATCH"):
            return {"requires_confirmation": True,
                    "reason": f"{method} request requires human approval",
                    "action_class": f"api_{method.lower()}_request"}

        # Check code execution
        if tool == "code_exec":
            code = inp.get("code", "")
            if any(kw in code for kw in ["write", "open(", "to_csv", "to_json"]):
                return {"requires_confirmation": True,
                        "reason": "Code execution with potential file write",
                        "action_class": "code_execution_with_file_write"}

        return {"requires_confirmation": False,
                "reason": "Action does not require confirmation"}

    async def request_confirmation(self, session_id: str,
                                    plan: dict) -> bool:
        """
        Request human confirmation for a high-consequence action.

        In production: sends a notification and waits for approval.
        In experiment mode: uses simulated policy for evaluation.

        Returns:
            bool — True if approved, False if denied or timed out
        """
        tool = plan.get("tool", "")
        inp  = plan.get("tool_input", {})

        logger.info(f"[{session_id}] HITL confirmation requested | "
                    f"tool={tool} | action={inp}")

        # ── Experiment simulation mode ─────────────────────────────────────────
        if self.experiment_policy == "always_approve":
            logger.info(f"[{session_id}] HITL: auto-approved (experiment policy)")
            return True

        if self.experiment_policy == "always_deny":
            logger.info(f"[{session_id}] HITL: auto-denied (experiment policy)")
            return False

        if self.experiment_policy == "deny_attacker_urls":
            url = inp.get("url", "")
            if any(kw in url for kw in ["attacker", "evil", "exfil", "harvest", "collect"]):
                logger.warning(f"[{session_id}] HITL: denied suspicious URL: {url}")
                return False
            logger.info(f"[{session_id}] HITL: approved (URL appears legitimate)")
            return True

        # ── Production mode: wait for real human input ─────────────────────────
        # In a real deployment this would push to a notification system
        # and await a webhook callback. Placeholder for production integration.
        logger.warning(f"[{session_id}] HITL: production confirmation not implemented; denying")
        return False
