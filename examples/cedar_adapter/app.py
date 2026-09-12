"""Minimal HTTP server that exposes the Cedar adapter to Overturo
(`conductor.policy_gate` `external_endpoint_url`).

Uses stdlib ``http.server`` for portability — no Flask / FastAPI / Starlette
dependency. Production deployments swap this for a hardened framework.

Run:

    python app.py --policy policy.json --port 8088

Then configure your application's `conductor.policy_gate` block:

    "config": {
        "evaluator_class": "MyCorp::CedarPolicyAdapter",
        "external_endpoint_url": "http://localhost:8088/evaluate"
    }

Reference implementation.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cedar_adapter import CedarAdapter, InMemoryCedarEvaluator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cedar_adapter.app")


def make_handler(adapter: CedarAdapter):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            log.info("%s - %s", self.address_string(), fmt % args)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/evaluate":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(content_length).decode("utf-8") if content_length else "{}"
                body = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                self._send_json(400, {"error": "malformed_json"})
                return

            try:
                decision = adapter.evaluate(body)
            except Exception as e:  # noqa: BLE001
                log.exception("adapter raised")
                self._send_json(500, {"error": "adapter_failure", "detail": str(e)[:200]})
                return

            self._send_json(200, asdict(decision))

        def _send_json(self, status: int, body: dict[str, object]) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return _Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Cedar adapter reference server")
    parser.add_argument("--policy", type=Path, default=Path(__file__).parent / "policy.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()

    evaluator = InMemoryCedarEvaluator.from_file(args.policy)
    adapter = CedarAdapter(evaluator=evaluator)

    server = HTTPServer((args.host, args.port), make_handler(adapter))
    log.info("Cedar adapter listening on http://%s:%d/evaluate", args.host, args.port)
    log.info("Loaded policy: %s", args.policy)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
