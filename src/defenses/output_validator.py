"""
output_validator.py
───────────────────
Defense Layer 3: Output Validation

Screens the agent's final output (and intermediate outputs in multi-step
chains) before they are returned to the application or user.

Addresses: Output trust exploitation, data exfiltration via model output,
           policy violations embedded in generated content.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Patterns that indicate output policy violations
VIOLATION_PATTERNS = {
    "credential_exposure": [
        r"(api[_\s]?key|secret[_\s]?key|access[_\s]?token)\s*[:=]\s*\S+",
        r"sk-[A-Za-z0-9]{20,}",
        r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}",
    ],
    "data_exfiltration_pattern": [
        r"(send|post|transmit|forward)\s+.{0,50}to\s+https?://",
        r"https?://[^\s]{5,}\s*(with|and)\s+(data|context|content|summary)",
    ],
    "unauthorized_action_instruction": [
        r"(ignore|disregard|forget)\s+(the\s+)?(previous|original|user'?s?)\s+(task|goal|instruction)",
        r"instead\s+of\s+.{0,50}(you\s+should|please|must)",
    ],
    "policy_violation": [
        r"(password|credential|ssn|social\s+security|dob|date\s+of\s+birth)\s*[:=]\s*\S+",
        r"patient\s+(id|identifier|record)\s*[:=]\s*\S+",
    ],
}

COMPILED_VIOLATIONS = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in VIOLATION_PATTERNS.items()
}


class OutputValidator:
    """
    Validates agent output against a set of policy rules before
    returning to the caller. Blocks outputs that contain:
      - Credential or sensitive data exposure
      - Data exfiltration instructions
      - Embedded adversarial instructions
      - PHI or regulated data patterns
    """

    def __init__(self, config: dict) -> None:
        self.config      = config
        self.enabled     = config.get("schema_enforcement", True)
        self.use_clf     = config.get("secondary_classifier", True)
        self.block       = config.get("block_on_violation", True)
        self.categories  = config.get("classifier_categories",
                                      list(VIOLATION_PATTERNS.keys()))

    def validate(self, output: str) -> dict:
        """
        Validate output text against all policy categories.

        Returns:
            dict with:
              violation_detected (bool)
              categories (list[str])   — which categories triggered
              evidence (list[str])     — matched patterns
        """
        import time
        start = time.time()

        violations: list[str] = []
        evidence:   list[str] = []

        for category, compiled in COMPILED_VIOLATIONS.items():
            if category not in self.categories:
                continue
            for pattern in compiled:
                match = pattern.search(output)
                if match:
                    violations.append(category)
                    evidence.append(f"{category}: '{match.group(0)[:80]}'")
                    break  # One match per category is sufficient

        latency = (time.time() - start) * 1000

        if violations:
            logger.warning(f"Output violation detected | categories={violations} | "
                           f"latency={latency:.1f}ms")

        return {
            "violation_detected": bool(violations),
            "categories": violations,
            "evidence": evidence,
            "latency_ms": round(latency, 2),
        }
