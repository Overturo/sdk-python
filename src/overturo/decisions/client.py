"""backend helpers for minting and tracking approval-decision
sessions tied to an OAP escalation.

Two flavours:
  - **One-shot**: :func:`url_for`, :func:`token_for`, :func:`poll_status`
    (sync wrappers thin over the underlying ``OverturoOversight`` async
    client).
  - **Long-poll**: :func:`subscribe` (async generator) and
    :func:`subscribe_sync` (sync iterator wrapper).

Wire endpoints:

    POST /api/v1/decisions
    GET  /api/v1/decisions/:session_token
    GET  /api/v1/decisions/by-escalation/:escalation_prefix_id/wait

"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator, Coroutine, Iterator
from typing import Any, TypeVar, cast

import httpx

from ..errors import (
    OverturoApiError,
    OverturoNetworkError,
    OverturoTimeoutError,
    OverturoValidationError,
)
from ..models import DecisionStatus, DecisionToken, FlowDisclosures

_T = TypeVar("_T")

__all__ = [
    "url_for",
    "token_for",
    "poll_status",
    "discover",
    "subscribe",
    "subscribe_sync",
    "DEFAULT_TIMEOUT_S",
    "SERVER_HOLD_S",
]

DEFAULT_TIMEOUT_S = 300.0  # overall client wait budget for subscribe()
SERVER_HOLD_S = 30.0  # server-side max single-request hold
_LONG_POLL_HTTP_TIMEOUT_S = SERVER_HOLD_S + 5.0
_MIN_BACKOFF_S = 0.5
_DEFAULT_RETRY_AFTER_S = 1.0


def _decisions_base(client: Any) -> str:
    """Build the ``/api/v1/decisions`` base URL from the client's
    discovery-document base URL."""
    base = client._discovery._base_url.rstrip("/")
    return f"{base}/api/v1/decisions"


# ── one-shot helpers ───────────────────────────────────────────────────


def url_for(
    client: Any,
    *,
    escalation_id: str,
    mode: str = "redirect",
    embed_origin: str | None = None,
) -> str:
    """Mint a decision session for the escalation and return its URL.

    Convenience wrapper over :func:`token_for` — returns only the
    ``decision_url`` (the full URL including its session_token query
    string). Backends that need the session_token separately (to poll)
    should call :func:`token_for` directly.

    Synchronous: spins up a private event loop via ``asyncio.run``. If
    already inside an async context, call ``token_for_async`` /
    ``poll_status_async`` instead (see :func:`subscribe`).
    """
    token = token_for(
        client,
        escalation_id=escalation_id,
        mode=mode,
        embed_origin=embed_origin,
    )
    return token.decision_url


def token_for(
    client: Any,
    *,
    escalation_id: str,
    mode: str = "redirect",
    embed_origin: str | None = None,
) -> DecisionToken:
    """Mint a decision session and return the full DecisionToken.

    POSTs to ``/api/v1/decisions`` with the escalation_id; the server
    returns a fresh session_token + URLs.
    """
    return _run_sync(
        _token_for_async(
            client,
            escalation_id=escalation_id,
            mode=mode,
            embed_origin=embed_origin,
        )
    )


def poll_status(client: Any, *, session_token: str) -> DecisionStatus:
    """One-shot status check. Returns the current DecisionStatus.

    Use :func:`subscribe` / :func:`subscribe_sync` for long-poll.
    """
    return _run_sync(_poll_status_async(client, session_token=session_token))


def discover(
    base_url: str,
    *,
    flow_id: str,
    publishable_key: str,
    locale: str | None = None,
    timeout: float = 10.0,
) -> FlowDisclosures:
    """pre-flight disclosure discovery.

    ``GET /api/v1/decisions/flows/{flow_id}/disclosures`` — returns what the
    decision screen would present for a consent flow (purposes, fields, steps,
    the action label, expiry, application branding) BEFORE any session exists,
    in public vocabulary and the requested ``locale``.

    Publishable-key authenticated: ``publishable_key`` (``pk_live_…`` /
    ``pk_test_…``) is an embed-safe, per-application credential passed
    explicitly rather than via client config — this endpoint ignores any bearer
    token, so the publishable key is the only credential that matters. Standalone
    (takes ``base_url``, not a client) for the same reason.

    An unknown / foreign / non-consent flow answers a uniform 404
    (:class:`~overturo.errors.OverturoApiError`, ``http_status=404``).

    :raises OverturoValidationError: if ``flow_id`` or ``publishable_key`` is
        empty (parity with the JS/Node/Ruby clients — fail before the network).
    """
    # Validate before the network, matching the other three clients (a blank
    # flow_id would otherwise produce a confusing server 404, and a None
    # publishable_key a bare httpx TypeError rather than a typed SDK error).
    if not flow_id:
        raise OverturoValidationError(message="flow_id is required")
    if not publishable_key:
        raise OverturoValidationError(message="publishable_key is required")

    url = f"{base_url.rstrip('/')}/api/v1/decisions/flows/{flow_id}/disclosures"
    params = {"locale": locale} if locale else None
    headers = {"X-Publishable-Key": publishable_key, "Accept": "application/json"}

    try:
        response = httpx.get(url, params=params, headers=headers, timeout=timeout)
    except httpx.TimeoutException as e:
        raise OverturoTimeoutError(message=f"Discovery request to {url} timed out: {e}") from e
    except httpx.HTTPError as e:
        raise OverturoNetworkError(message=f"Discovery network error on {url}: {e}") from e

    if not (200 <= response.status_code < 300):
        body: Any = {}
        try:
            body = response.json()
        except ValueError:
            body = {}
        error = body.get("error") if isinstance(body, dict) else None
        error = error if isinstance(error, dict) else {}
        raise OverturoApiError(
            message=error.get("message", f"HTTP {response.status_code} on {url}"),
            http_status=response.status_code,
            reason_code=error.get("code"),
            request_id=response.headers.get("x-request-id"),
        )

    # Guard the success body: a non-JSON or envelope-less 200 (a proxy/gateway
    # misconfig — the server itself is fail-closed) becomes a typed error, never
    # a bare JSONDecodeError/KeyError that escapes `except OverturoError`.
    try:
        envelope = response.json()
    except ValueError as e:
        raise OverturoApiError(
            message=f"Malformed discovery response (not JSON) from {url}: {e}",
            http_status=response.status_code,
        ) from e
    if not isinstance(envelope, dict) or "flow" not in envelope:
        raise OverturoApiError(
            message=f"Malformed discovery response (missing 'flow') from {url}",
            http_status=response.status_code,
        )
    # The guard above proves envelope is a dict with a "flow" key; json() is Any,
    # so cast to the declared return type (the shape is the server's contract).
    return cast(FlowDisclosures, envelope["flow"])


# ── long-poll generators ───────────────────────────────────────────────


async def subscribe(
    client: Any,
    *,
    escalation_id: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> AsyncGenerator[DecisionStatus, None]:
    """Async generator that yields a DecisionStatus on every server
    return — terminal or interim (`wait_again: true`).

    Stops yielding once :meth:`DecisionStatus.is_terminal` is true, or
    when the overall ``timeout_s`` budget expires (whichever comes
    first). On budget exhaustion the generator simply returns without
    raising — the caller's existing ``async for`` loop falls through.

    Concurrency model:
      - Server holds for ~30 s; client uses ~35 s httpx timeout.
      - On a `wait_again: true` response, the loop re-issues immediately.
      - On a 429 or 5xx, the loop honours ``retry_after`` (if returned by
        the SDK error) before retrying.
    """
    deadline = time.monotonic() + timeout_s
    base = _decisions_base(client)
    url = f"{base}/by-escalation/{escalation_id}/wait"

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return

        raw = await client._http.long_poll_get(
            url, timeout=min(_LONG_POLL_HTTP_TIMEOUT_S, remaining + 5.0)
        )
        status = DecisionStatus.from_response(raw)
        yield status
        if status.is_terminal():
            return

        # Server returned `wait_again: true` — fall through and re-poll.
        # If the server suggested retry_after, honour it (rate-limit hint).
        if status.retry_after is not None:
            await asyncio.sleep(max(_MIN_BACKOFF_S, float(status.retry_after)))


def subscribe_sync(
    client: Any,
    *,
    escalation_id: str,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Iterator[DecisionStatus]:
    """Synchronous iterator wrapper over :func:`subscribe`.

    Iterates the async generator on a private event loop, yielding each
    DecisionStatus to the sync caller. Each ``__next__`` blocks until
    the next yield (or the iterator returns).

    Refuses to run if the caller is already inside an event loop —
    sync wrappers can't safely drive a private loop concurrent with the
    host one. In that case use ``async for`` on :func:`subscribe`
    directly.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "subscribe_sync() called from within a running event loop. "
            "Use `async for` on subscribe() instead."
        )

    loop = asyncio.new_event_loop()
    agen: AsyncGenerator[DecisionStatus, None] | None = None
    try:
        agen = subscribe(client, escalation_id=escalation_id, timeout_s=timeout_s)
        while True:
            try:
                status = loop.run_until_complete(agen.__anext__())
            except StopAsyncIteration:
                return
            yield status
    finally:
        if agen is not None:
            try:
                loop.run_until_complete(agen.aclose())
            except Exception:
                pass
        loop.close()


# ── async building blocks ──────────────────────────────────────────────


async def _token_for_async(
    client: Any,
    *,
    escalation_id: str,
    mode: str,
    embed_origin: str | None,
) -> DecisionToken:
    body: dict[str, Any] = {"escalation_id": escalation_id, "mode": mode}
    if embed_origin is not None:
        body["embed_origin"] = embed_origin
    raw: dict[str, Any] = await client._http.post_json(_decisions_base(client), body)
    return DecisionToken.from_response(raw)


async def _poll_status_async(client: Any, *, session_token: str) -> DecisionStatus:
    if not session_token:
        raise ValueError("session_token is required (a pending long-poll envelope carries none)")
    url = f"{_decisions_base(client)}/{session_token}"
    raw: dict[str, Any] = await client._http.get_json(url)
    return DecisionStatus.from_response(raw)


# ── sync runner ────────────────────────────────────────────────────────


def _run_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to completion on a private event loop.

    Mirrors the pattern used by ``OverturoOversight.attest_sync`` —
    refuses to nest inside an existing loop so we don't dead-lock.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError(
        "decisions helper called from within a running event loop. "
        "Use the async form (_token_for_async / _poll_status_async) "
        "or call subscribe() directly via `async for`."
    )
