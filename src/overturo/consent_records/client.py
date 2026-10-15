"""Consent records — the organisation records a consent it captured itself.

Wire endpoints (API token bearer)::

    POST /api/v1/consent_records                        create (capture + commit)
    GET  /api/v1/consent_records/:id                    read
    POST /api/v1/consent_records/imports                batch import (dry run available)
    GET  /api/v1/consent_records/imports/:import_id     import status + per-row outcomes
    GET  /api/v1/applications/:application_id/consent_status?subject[email]=…   status by subject reference

Every function has a synchronous form and an ``*_async`` twin. The transport
(headers, error mapping, retries) is the one the meetings client uses.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from ..errors import OverturoValidationError
from ..meetings.client import _request, _request_async

__all__ = [
    "create_record",
    "create_record_async",
    "retrieve_record",
    "retrieve_record_async",
    "commit_capture",
    "import_records",
    "import_records_async",
    "retrieve_import",
    "retrieve_import_async",
    "status",
    "status_async",
]

_CREATE_FIELDS = (
    "flow_id",
    "subject",
    "decisions",
    "captured_at",
    "idempotency_key",
    "notice_hash",
    "locale",
    "suppress_receipt",
    "client_facts",
)


def _records_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/api/v1/consent_records"


def _create_body(fields: dict[str, Any]) -> dict[str, Any]:
    body = {k: v for k, v in fields.items() if k in _CREATE_FIELDS and v is not None}
    if not body.get("flow_id"):
        raise OverturoValidationError(message="flow_id is required")
    if not isinstance(body.get("subject"), dict) or not body["subject"].get("email"):
        raise OverturoValidationError(message="subject.email is required")
    if not isinstance(body.get("decisions"), dict) or not body["decisions"]:
        raise OverturoValidationError(message="decisions must name at least one purpose")
    return body


def _import_body(
    flow_id: str, records: list[dict[str, Any]], dry_run: bool, send_receipts: bool
) -> dict[str, Any]:
    if not flow_id:
        raise OverturoValidationError(message="flow_id is required")
    if not isinstance(records, list) or not records:
        raise OverturoValidationError(message="records must be a non-empty list")
    return {
        "flow_id": flow_id,
        "records": records,
        "dry_run": dry_run,
        "send_receipts": send_receipts,
    }


def _status_url(base_url: str, application_id: str) -> str:
    if not application_id:
        raise OverturoValidationError(message="application_id is required")
    return f"{base_url.rstrip('/')}/api/v1/applications/{quote(application_id, safe='')}/consent_status"


def _status_params(email: str | None, external_id: str | None) -> dict[str, str]:
    if not email and not external_id:
        raise OverturoValidationError(message="email or external_id is required")
    params: dict[str, str] = {}
    if email:
        params["subject[email]"] = email
    if external_id:
        params["subject[external_id]"] = external_id
    return params


def create_record(
    *, base_url: str, api_token: str, timeout: float = 10.0, **fields: Any
) -> dict[str, Any]:
    """Record a consent you captured: creates, binds the subject, commits and freezes the receipt.

    Fields: flow_id, subject ({email, external_id}), decisions ({purpose: {decision,
    default_checked, mandatory}}), captured_at, idempotency_key, notice_hash,
    locale, suppress_receipt, client_facts. Answers ``{"consent_record": {...}}``.
    """
    return _request(
        "POST",
        _records_url(base_url),
        api_token=api_token,
        json_body=_create_body(fields),
        timeout=timeout,
    )


def commit_capture(
    *,
    base_url: str,
    api_token: str,
    token: str,
    subject: dict[str, str] | None = None,
    suppress_receipt: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """201 — commit a capture your form's snippet minted.

    ``POST /api/v1/decisions/{token}/authorize`` with the application
    credential: names the person your server knows (``subject``: ``email`` and
    optionally ``external_id``) and may suppress the receipt email. Answers the
    decision with its ``record_id`` and ``channel``. A publishable key cannot
    commit (403 ``publishable_key_cannot_commit``).
    """
    if not token:
        raise OverturoValidationError(message="token is required")
    body: dict[str, Any] = {}
    if subject:
        body["subject"] = subject
    if suppress_receipt:
        body["suppress_receipt"] = True
    return _request(
        "POST",
        f"{base_url.rstrip('/')}/api/v1/decisions/{quote(token, safe='')}/authorize",
        api_token=api_token,
        json_body=body,
        timeout=timeout,
    )


def retrieve_record(
    *, base_url: str, api_token: str, record_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    if not record_id:
        raise OverturoValidationError(message="record_id is required")
    return _request(
        "GET",
        f"{_records_url(base_url)}/{quote(record_id, safe='')}",
        api_token=api_token,
        timeout=timeout,
    )


def import_records(
    *,
    base_url: str,
    api_token: str,
    flow_id: str,
    records: list[dict[str, Any]],
    dry_run: bool = False,
    send_receipts: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Import consents you already hold (at most 5000 rows). Answers ``{"import": {...}}``."""
    return _request(
        "POST",
        f"{_records_url(base_url)}/imports",
        api_token=api_token,
        json_body=_import_body(flow_id, records, dry_run, send_receipts),
        timeout=timeout,
    )


def retrieve_import(
    *, base_url: str, api_token: str, import_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    if not import_id:
        raise OverturoValidationError(message="import_id is required")
    return _request(
        "GET",
        f"{_records_url(base_url)}/imports/{quote(import_id, safe='')}",
        api_token=api_token,
        timeout=timeout,
    )


def status(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    email: str | None = None,
    external_id: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """The per-purpose consent status for a subject reference (email or your identifier)."""
    return _request(
        "GET",
        _status_url(base_url, application_id),
        api_token=api_token,
        params=_status_params(email, external_id),
        timeout=timeout,
    )


async def create_record_async(
    *, base_url: str, api_token: str, timeout: float = 10.0, **fields: Any
) -> dict[str, Any]:
    return await _request_async(
        "POST",
        _records_url(base_url),
        api_token=api_token,
        json_body=_create_body(fields),
        timeout=timeout,
    )


async def retrieve_record_async(
    *, base_url: str, api_token: str, record_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    if not record_id:
        raise OverturoValidationError(message="record_id is required")
    return await _request_async(
        "GET",
        f"{_records_url(base_url)}/{quote(record_id, safe='')}",
        api_token=api_token,
        timeout=timeout,
    )


async def import_records_async(
    *,
    base_url: str,
    api_token: str,
    flow_id: str,
    records: list[dict[str, Any]],
    dry_run: bool = False,
    send_receipts: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    return await _request_async(
        "POST",
        f"{_records_url(base_url)}/imports",
        api_token=api_token,
        json_body=_import_body(flow_id, records, dry_run, send_receipts),
        timeout=timeout,
    )


async def retrieve_import_async(
    *, base_url: str, api_token: str, import_id: str, timeout: float = 10.0
) -> dict[str, Any]:
    if not import_id:
        raise OverturoValidationError(message="import_id is required")
    return await _request_async(
        "GET",
        f"{_records_url(base_url)}/imports/{quote(import_id, safe='')}",
        api_token=api_token,
        timeout=timeout,
    )


async def status_async(
    *,
    base_url: str,
    api_token: str,
    application_id: str,
    email: str | None = None,
    external_id: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    return await _request_async(
        "GET",
        _status_url(base_url, application_id),
        api_token=api_token,
        params=_status_params(email, external_id),
        timeout=timeout,
    )
