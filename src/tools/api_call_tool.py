"""
api_call_tool.py
────────────────
External REST API call tool with allowlist enforcement.

PRIMARY ATTACK SURFACE for:
  - Goal hijacking redirecting to attacker-controlled endpoints
  - Privilege escalation via manipulated POST/PUT/DELETE calls
  - Data exfiltration via GET calls to external endpoints

Defenses applied:
  - Domain allowlist enforced before every request
  - POST/PUT/DELETE methods require HITL confirmation flag
  - Response size limit enforced
  - All calls logged with full URL, method, and status
"""

import logging
import os
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 50_000   # 50 KB hard cap on response body
WRITE_METHODS      = {"POST", "PUT", "PATCH", "DELETE"}


class APICallTool:
    DESCRIPTION = (
        "Makes an HTTP request to an approved external API endpoint "
        "and returns the response. Only GET requests are permitted by default. "
        "POST/PUT/DELETE require explicit authorization. "
        "Only pre-approved domains may be contacted."
    )

    def __init__(self, config: dict) -> None:
        self.config          = config
        self.allowed_domains: list[str] = config.get("allowed_domains", [])
        self.timeout         = config.get("timeout_seconds", 15)
        self.require_hitl_for_post = config.get("require_hitl_for_post", True)

    def execute(self, tool_input: dict) -> dict:
        """
        Make an HTTP request.

        Args:
            tool_input: {
                "url": str,
                "method": str,          # GET | POST | PUT | DELETE
                "headers": dict,        # optional
                "body": dict,           # optional, for POST/PUT
                "hitl_approved": bool   # required True for write methods
            }

        Returns:
            dict with "status_code", "body", "headers" or "error"
        """
        url     = tool_input.get("url", "")
        method  = tool_input.get("method", "GET").upper()
        headers = tool_input.get("headers", {})
        body    = tool_input.get("body", {})
        hitl_approved = tool_input.get("hitl_approved", False)

        if not url:
            return {"error": "No URL provided"}

        # Domain allowlist enforcement
        domain_check = self._check_domain(url)
        if not domain_check["allowed"]:
            logger.warning(f"API call blocked to domain: {domain_check['domain']}")
            return {"error": f"Domain not in allowlist: {domain_check['domain']}"}

        # Write method gate
        if method in WRITE_METHODS and self.require_hitl_for_post and not hitl_approved:
            logger.warning(f"Write method {method} blocked: HITL approval required")
            return {"error": f"{method} requires HITL approval. Set hitl_approved=true."}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=body if body else None,
                )
            body_bytes = response.content[:MAX_RESPONSE_BYTES]
            logger.info(f"API call: {method} {url} -> {response.status_code}")
            return {
                "status_code": response.status_code,
                "body": body_bytes.decode("utf-8", errors="replace"),
                "headers": dict(response.headers),
                "truncated": len(response.content) > MAX_RESPONSE_BYTES,
            }
        except httpx.TimeoutException:
            return {"error": f"Request timed out after {self.timeout}s"}
        except Exception as exc:
            logger.error(f"API call error: {exc}")
            return {"error": str(exc)}

    def _check_domain(self, url: str) -> dict:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # If allowlist is empty, all domains are permitted (baseline mode only)
            allowed = not self.allowed_domains or any(
                domain == d or domain.endswith("." + d)
                for d in self.allowed_domains
            )
            return {"allowed": allowed, "domain": domain}
        except Exception:
            return {"allowed": False, "domain": "unparseable"}

    def add_allowed_domain(self, domain: str) -> None:
        """Add a domain to the allowlist at runtime (for test setup)."""
        self.allowed_domains.append(domain.lower())
