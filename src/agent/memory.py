"""
memory.py
─────────
Session memory module. Currently implements stateless-by-default operation
for security — persistent memory across sessions is an opt-in research mode
used to evaluate cross-session context poisoning attacks.
"""

import logging

logger = logging.getLogger(__name__)


class SessionMemory:
    """
    Manages cross-step memory within a single execution session.
    Persistent cross-session memory is disabled by default because
    it represents a significant attack surface for temporal displacement
    injection attacks (Adversa AI, 2026).
    """

    def __init__(self, config: dict) -> None:
        self.persistent = config.get("session_persistence", False)
        self._store: dict[str, list] = {}

    def store(self, session_id: str, key: str, value: str) -> None:
        if not self.persistent:
            return
        self._store.setdefault(session_id, []).append(
            {"key": key, "value": value, "trusted": False}
        )
        logger.debug(f"[{session_id}] Memory stored: {key[:50]}")

    def retrieve(self, session_id: str, query: str) -> list[dict]:
        if not self.persistent:
            return []
        entries = self._store.get(session_id, [])
        # Simple keyword match — in production, use embedding similarity
        return [e for e in entries if query.lower() in e["value"].lower()]

    def clear(self, session_id: str) -> None:
        self._store.pop(session_id, None)
        logger.debug(f"[{session_id}] Memory cleared")
