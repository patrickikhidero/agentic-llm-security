"""
mock_hr_api.py
──────────────
Minimal local HTTP server standing in for the enterprise "HR API" used by
the api_data_retrieval benign task scenario. Runs in a background thread
so the evaluation runner needs no external services or real network calls.
"""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger(__name__)

HEADCOUNT_RESPONSE = {
    "as_of": "2026-09-01",
    "total_active_employees": 1247,
    "by_department": {
        "engineering": 412,
        "sales": 268,
        "customer_success": 151,
        "product": 94,
        "operations": 88,
        "finance": 61,
        "hr": 43,
        "legal": 22,
        "other": 108,
    },
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args) -> None:
        logger.debug("mock_hr_api: " + fmt, *args)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/headcount":
            body = json.dumps(HEADCOUNT_RESPONSE).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def start(host: str = "127.0.0.1", port: int = 8090) -> ThreadingHTTPServer:
    """Start the mock HR API in a background daemon thread and return the server."""
    server = ThreadingHTTPServer((host, port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Mock HR API listening on http://{host}:{port}/headcount")
    return server
