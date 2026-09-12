"""Recorded API exchanges, keyed by operationId.

Each recording was made against the real API and validated against the
published OpenAPI document, so a response built from one is what the client
will actually see. Ids, timestamps and tokens are placeholders
(``<PREFIX_ID:n>``, ``2026-01-01T00:00:00Z``, ``<TOKEN>``).

The shared corpus is read when this package sits next to it; the public mirror
carries the vendored copy under tests/fixtures/api_responses. ``OVERTURO_API_CORPUS_DIR``
overrides the location (used to prove the vendored copy is self-contained).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import httpx

SHARED = Path(__file__).resolve().parents[2] / "shared" / "conformance" / "api_responses"
VENDORED = Path(__file__).resolve().parent / "fixtures" / "api_responses"
PLACEHOLDER = re.compile(r"<[A-Z_]+(?::[^>]*)?>")


def corpus_dir() -> Path:
    override = os.environ.get("OVERTURO_API_CORPUS_DIR")
    if override:
        return Path(override)
    return SHARED if SHARED.is_dir() else VENDORED


def corpus_exchange(operation_id: str, step: str | None = None) -> dict[str, Any]:
    name = f"{operation_id}.{step}.json" if step else f"{operation_id}.json"
    return json.loads((corpus_dir() / name).read_text())


def corpus_body(operation_id: str, step: str | None = None) -> Any:
    return corpus_exchange(operation_id, step)["response"]["body"]


def corpus_response(operation_id: str, step: str | None = None) -> httpx.Response:
    response = corpus_exchange(operation_id, step)["response"]
    body = response.get("body")
    if body is None:
        return httpx.Response(response["status"], headers=response.get("headers", {}))
    return httpx.Response(response["status"], json=body, headers=response.get("headers", {}))


def corpus_url_regex(base: str, operation_id: str, step: str | None = None) -> str:
    """The recorded path with every placeholder widened to one path segment; query left free."""
    path = re.escape(base + corpus_exchange(operation_id, step)["request"]["path"])
    return "^" + PLACEHOLDER.sub("[^/?]+", path) + r"(\?.*)?$"


def corpus_route(router: Any, operation_id: str, base: str, step: str | None = None) -> Any:
    """Register the recording on a respx router (or the respx module) and return the route."""
    request = corpus_exchange(operation_id, step)["request"]
    route = router.route(
        method=request["method"], url__regex=corpus_url_regex(base, operation_id, step)
    )
    return route.mock(return_value=corpus_response(operation_id, step))
