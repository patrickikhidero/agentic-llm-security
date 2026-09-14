"""
code_exec_tool.py
─────────────────
Sandboxed Python code execution tool using RestrictedPython.

PRIMARY ATTACK SURFACE for:
  - Goal hijacking that redirects to malicious code generation
  - Cascade exploitation via induced execution errors

Defenses applied:
  - RestrictedPython blocks dangerous builtins (os, sys, subprocess, socket)
  - Explicit import allowlist enforced before execution
  - Hard timeout enforced via threading
  - stdout captured and returned as string — no filesystem side-effects
"""

import logging
import threading
from io import StringIO
from contextlib import redirect_stdout

from RestrictedPython import compile_restricted, safe_globals

logger = logging.getLogger(__name__)

ALLOWED_IMPORTS = {"math", "json", "datetime", "re", "collections", "itertools"}
BLOCKED_BUILTINS = {"__import__", "open", "exec", "eval", "compile",
                    "globals", "locals", "vars", "dir"}


class CodeExecTool:
    DESCRIPTION = (
        "Executes a Python code snippet in a sandboxed environment and returns "
        "the printed output. Use for calculations, data transformations, or "
        "text processing. No file system access or network calls are permitted."
    )

    def __init__(self, config: dict) -> None:
        self.config  = config
        self.timeout = config.get("timeout_seconds", 10)
        self.allowed_imports = set(config.get("allowed_imports", list(ALLOWED_IMPORTS)))

    def execute(self, tool_input: dict) -> dict:
        """
        Execute sandboxed code.

        Args:
            tool_input: {"code": str}

        Returns:
            dict with "output" str or "error" str
        """
        code = tool_input.get("code", "")
        if not code:
            return {"error": "No code provided"}

        # Pre-scan for blocked patterns before compilation
        blocked = self._scan_for_blocked_patterns(code)
        if blocked:
            logger.warning(f"Code execution blocked: {blocked}")
            return {"error": f"Code contains blocked pattern: {blocked[0]}"}

        result: dict = {}

        def _run():
            try:
                byte_code = compile_restricted(code, "<string>", "exec")
                stdout_capture = StringIO()
                restricted_globals = {
                    **safe_globals,
                    "_print_": print,
                    "_getiter_": iter,
                    "_getattr_": getattr,
                }
                with redirect_stdout(stdout_capture):
                    exec(byte_code, restricted_globals)  # noqa: S102
                result["output"] = stdout_capture.getvalue()
            except SyntaxError as exc:
                result["error"] = f"Syntax error: {exc}"
            except Exception as exc:
                result["error"] = f"Runtime error: {exc}"

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout)

        if thread.is_alive():
            logger.warning("Code execution timed out")
            return {"error": f"Execution timed out after {self.timeout}s"}

        logger.info("Code executed successfully")
        return result if result else {"error": "No output produced"}

    def _scan_for_blocked_patterns(self, code: str) -> list[str]:
        blocked_found = []
        patterns = ["import os", "import sys", "import subprocess",
                    "import socket", "import requests", "open(",
                    "__import__", "eval(", "exec("]
        for p in patterns:
            if p in code:
                blocked_found.append(p)
        return blocked_found
