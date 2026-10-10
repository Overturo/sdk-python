"""Meetings — the organisation's side of meeting consent.

A meeting is the unit of record: it has a window (``scheduled_at`` /
``ends_at``), a platform identity, a cancellation, and participant rows that
carry each person's decision per purpose.

Wire endpoints (API token bearer, the application's admin scope)::

    GET    /api/v1/applications/:application_id/meeting_consents
    POST   /api/v1/applications/:application_id/meeting_consents
    GET    /api/v1/applications/:application_id/meeting_consents/:id
    PATCH  /api/v1/applications/:application_id/meeting_consents/:id
    DELETE /api/v1/applications/:application_id/meeting_consents/:id   (cancel)
    GET    /api/v1/applications/:application_id/meeting_consents/:id/participants

Every function has a synchronous form and an ``*_async`` twin. The
participant pair (a participant's own status / withdrawal) lives in the
browser SDK, where the session token is.
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
    "list_meetings",
    "list_meetings_async",
    "create_meeting",
    "create_meeting_async",
    "retrieve_meeting",
    "retrieve_meeting_async",
    "update_meeting",
    "update_meeting_async",
    "cancel_meeting",
    "cancel_meeting_async",
    "list_participants",
    "list_participants_async",
]

_UPDATE_FIELDS = ("title", "scheduled_at", "duration_minutes", "platform", "external_meeting_id")
_CREATE_FIELDS = (
    "template",
    "title",
    "description",
    "scheduled_at",
    "duration_minutes",
    "platform",
    "external_meeting_id",
    "agent_ids",
)


# ── sync ───────────────────────────────────────────────────────────────


def list_meetings(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    page: int | None = None,
    per_page: int | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """The application's meetings, newest first (``{"meeting_consents": [...], "pagination": {...}}``)."""
    params = {k: str(v) for k, v in {"page": page, "per_page": per_page}.items() if v is not None}
    return _request(
        "GET",
        _collection_url(base_url, application_id),
        api_token=api_token,
        params=params or None,
        timeout=timeout,
    )


def create_meeting(
    *, base_url: str, api_token: str, application_id: str, timeout: float = 10.0, **fields: Any
) -> dict[str, Any]:
    """Create a meeting and its consent flow; answers ``{"meeting_consent": {...}, "consent_link": ...}``.

    Accepted fields: template, title, description, scheduled_at (ISO 8601),
    duration_minutes (defaults to 60 server-side), platform,
    external_meeting_id, agent_ids.
    """
    return _request(
        "POST",
        _collection_url(base_url, application_id),
        api_token=api_token,
        json_body=_pick(fields, _CREATE_FIELDS),
        timeout=timeout,
    )


def retrieve_meeting(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    return _request(
        "GET",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        timeout=timeout,
    )


def update_meeting(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    meeting_id: str,
    timeout: float = 10.0,
    **fields: Any,
) -> dict[str, Any]:
    """Rename or reschedule (title, scheduled_at, duration_minutes, platform, external_meeting_id)."""
    return _request(
        "PATCH",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        json_body=_pick(fields, _UPDATE_FIELDS),
        timeout=timeout,
    )


def cancel_meeting(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> None:
    """Cancel the meeting (participants are told; the record stays)."""
    _request(
        "DELETE",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        timeout=timeout,
        expect_body=False,
    )


def list_participants(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    """The meeting's participants with their decision per purpose."""
    return _request(
        "GET",
        f"{_member_url(base_url, application_id, meeting_id)}/participants",
        api_token=api_token,
        timeout=timeout,
    )


# ── async ──────────────────────────────────────────────────────────────


async def list_meetings_async(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    page: int | None = None,
    per_page: int | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    params = {k: str(v) for k, v in {"page": page, "per_page": per_page}.items() if v is not None}
    return await _request_async(
        "GET",
        _collection_url(base_url, application_id),
        api_token=api_token,
        params=params or None,
        timeout=timeout,
    )


async def create_meeting_async(
    *, base_url: str, api_token: str, application_id: str, timeout: float = 10.0, **fields: Any
) -> dict[str, Any]:
    return await _request_async(
        "POST",
        _collection_url(base_url, application_id),
        api_token=api_token,
        json_body=_pick(fields, _CREATE_FIELDS),
        timeout=timeout,
    )


async def retrieve_meeting_async(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    return await _request_async(
        "GET",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        timeout=timeout,
    )


async def update_meeting_async(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    meeting_id: str,
    timeout: float = 10.0,
    **fields: Any,
) -> dict[str, Any]:
    return await _request_async(
        "PATCH",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        json_body=_pick(fields, _UPDATE_FIELDS),
        timeout=timeout,
    )


async def cancel_meeting_async(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> None:
    await _request_async(
        "DELETE",
        _member_url(base_url, application_id, meeting_id),
        api_token=api_token,
        timeout=timeout,
        expect_body=False,
    )


async def list_participants_async(
    *, base_url: str, api_token: str, application_id: str, meeting_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    return await _request_async(
        "GET",
        f"{_member_url(base_url, application_id, meeting_id)}/participants",
        api_token=api_token,
        timeout=timeout,
    )


# ── internals ──────────────────────────────────────────────────────────


def _collection_url(base_url: str, application_id: str) -> str:
    if not application_id:
        raise OverturoValidationError(message="application_id is required")
    return f"{base_url.rstrip('/')}/api/v1/applications/{application_id}/meeting_consents"


def _member_url(base_url: str, application_id: str, meeting_id: str) -> str:
    if not meeting_id:
        raise OverturoValidationError(message="meeting_id is required")
    return f"{_collection_url(base_url, application_id)}/{meeting_id}"


def _pick(fields: dict[str, Any], allowed: tuple[str, ...]) -> dict[str, Any]:
    unknown = set(fields) - set(allowed)
    if unknown:
        raise OverturoValidationError(message=f"unknown field(s): {', '.join(sorted(unknown))}")
    return {k: v for k, v in fields.items() if v is not None}


def _headers(api_token: str, json_body: Any) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    return headers


def _request(
    method: str,
    url: str,
    *,
    api_token: str,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float,
    expect_body: bool = True,
) -> dict[str, Any]:
    try:
        response = httpx.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=_headers(api_token, json_body),
            timeout=timeout,
        )
    except httpx.TimeoutException as e:
        raise OverturoTimeoutError(message=str(e)) from e
    except httpx.HTTPError as e:
        raise OverturoNetworkError(message=str(e)) from e
    return _handle(response, expect_body=expect_body)


async def _request_async(
    method: str,
    url: str,
    *,
    api_token: str,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float,
    expect_body: bool = True,
) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.request(
                method, url, params=params, json=json_body, headers=_headers(api_token, json_body)
            )
    except httpx.TimeoutException as e:
        raise OverturoTimeoutError(message=str(e)) from e
    except httpx.HTTPError as e:
        raise OverturoNetworkError(message=str(e)) from e
    return _handle(response, expect_body=expect_body)


def _handle(response: httpx.Response, *, expect_body: bool) -> dict[str, Any]:
    if 200 <= response.status_code < 300:
        if not expect_body:
            return {}
        parsed = _parse_json(response)
        if not isinstance(parsed, dict):
            raise OverturoApiError(
                message="expected a JSON object body", http_status=response.status_code
            )
        return parsed

    _raise_for(response)
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_json(response: httpx.Response) -> Any:
    try:
        return json.loads(response.text)
    except json.JSONDecodeError:
        return None


def _raise_for(response: httpx.Response) -> None:
    status = response.status_code
    body = _parse_json(response)
    body = body if isinstance(body, dict) else {}
    message = str(body.get("error") or f"HTTP {status}")
    code = body.get("code")

    if status == 401:
        raise OverturoUnauthorized(message=message, http_status=status)
    if status == 403:
        raise OverturoUnauthorized(message=message, http_status=status, reason_code="missing_scope")
    if status == 404:
        raise OverturoApiError(
            message=message, http_status=status, reason_code=str(code or "not_found")
        )
    if status in (409, 422):
        raise OverturoValidationError(
            message=message,
            http_status=status,
            reason_code=str(code or body.get("error") or ""),
            detail=body.get("error"),
        )
    if status == 429:
        raise OverturoRateLimited(message=message, http_status=status)
    if status >= 500:
        raise OverturoServerError(message=message, http_status=status)
    raise OverturoApiError(message=message, http_status=status)
