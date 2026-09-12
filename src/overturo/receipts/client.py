"""authority record client methods.

Wire endpoints:

    GET  /api/v1/authorization_receipts/:id   (audit:verify scope)
    POST /api/v1/disclosure_receipts          (disclosures:write scope)

The 404 contract is parity-preserving by design: unknown, foreign, and
non-authority ids are indistinguishable — never disambiguated
client-side. The two endpoints' 422 shapes differ (the read uses
``{"error": "<code>", "reason": ...}``, the mint uses ``{"error":
"<message>", "code": "<code>"}``); both surface as
:class:`~overturo.errors.OverturoValidationError` with ``reason_code``
carrying the machine code.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..errors import (
    OverturoApiError,
    OverturoNetworkError,
    OverturoRateLimited,
    OverturoServerError,
    OverturoTimeoutError,
    OverturoUnauthorized,
    OverturoValidationError,
)

__all__ = [
    "create_disclosure_receipt",
    "retrieve_authorization_receipt",
]


def retrieve_authorization_receipt(
    *,
    base_url: str,
    api_token: str,
    record_id: str,
    flavor: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Fetch a durable authorization record (``audit:verify`` scope).

    ``flavor=None``/``"canonical"`` returns the wrapped document's inner
    dict; ``"signed"`` returns the bare envelope (hand it to
    :func:`overturo.verify_record`); ``"dpv"`` returns the JSON-LD dict
    (the body is JSON despite the ``application/ld+json`` content type).
    Typed refusals raise :class:`OverturoValidationError` with
    ``reason_code`` in {"unknown_flavor", "not_signable",
    "dpv_unavailable"}.
    """
    params = {"flavor": flavor} if flavor else None
    body = _request(
        "GET",
        f"{base_url.rstrip('/')}/api/v1/authorization_receipts/{record_id}",
        api_token=api_token,
        params=params,
        timeout=timeout,
    )
    if flavor in (None, "canonical"):
        inner = body.get("authorization_receipt")
        return inner if isinstance(inner, dict) else body
    return body


def create_disclosure_receipt(
    *,
    base_url: str,
    api_token: str,
    flow_id: str,
    agent_id: str,
    disclosed_at: str,
    locale: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Mint an operator-declared disclosure receipt (``disclosures:write``).

    Returns ``{"record_id": ..., "record": ...}``. Mint-only by design —
    the operator disclosure log page is the read side. Typed refusals
    raise :class:`OverturoValidationError` with ``reason_code`` in
    {"agent_not_disclosed", "invalid_disclosed_at", "purposes_missing"}.
    """
    payload: dict[str, Any] = {
        "flow_id": flow_id,
        "agent_id": agent_id,
        "disclosed_at": disclosed_at,
    }
    if locale is not None:
        payload["locale"] = locale
    body = _request(
        "POST",
        f"{base_url.rstrip('/')}/api/v1/disclosure_receipts",
        api_token=api_token,
        json_body=payload,
        timeout=timeout,
    )
    inner = body.get("disclosure_receipt")
    return inner if isinstance(inner, dict) else body


# ── internals ──────────────────────────────────────────────────────────


def _request(
    method: str,
    url: str,
    *,
    api_token: str,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float,
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}
    try:
        response = httpx.request(
            method, url, params=params, json=json_body, headers=headers, timeout=timeout
        )
    except httpx.TimeoutException as e:
        raise OverturoTimeoutError(message=str(e)) from e
    except httpx.HTTPError as e:
        raise OverturoNetworkError(message=str(e)) from e

    if response.status_code >= 200 and response.status_code < 300:
        parsed = _parse_json(response)
        if not isinstance(parsed, dict):
            raise OverturoApiError(
                message="expected a JSON object body", http_status=response.status_code
            )
        return parsed

    _raise_for(response)
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_json(response: httpx.Response) -> Any:
    # Content-type-agnostic on purpose: the dpv flavor responds with
    # application/ld+json and the body is JSON.
    try:
        return json.loads(response.text)
    except json.JSONDecodeError:
        return None


def _raise_for(response: httpx.Response) -> None:
    status = response.status_code
    body = _parse_json(response)
    body = body if isinstance(body, dict) else {}
    message = str(body.get("error") or f"HTTP {status}")

    if status == 401:
        raise OverturoUnauthorized(message=message, http_status=status)
    if status == 403:
        raise OverturoUnauthorized(message=message, http_status=status, reason_code="missing_scope")
    if status == 422:
        raise OverturoValidationError(
            message=message,
            http_status=status,
            reason_code=str(body.get("code") or body.get("error") or ""),
            detail=body.get("reason") or body.get("error"),
        )
    if status == 429:
        raise OverturoRateLimited(message=message, http_status=status)
    if status >= 500:
        raise OverturoServerError(message=message, http_status=status)
    raise OverturoApiError(message=message, http_status=status)
