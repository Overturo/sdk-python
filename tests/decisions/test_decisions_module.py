"""decisions module unit coverage."""

from __future__ import annotations

import json

import pytest
import respx

from overturo import (
    DecisionStatus,
    DecisionToken,
    OverturoOversight,
    decisions,
)
from overturo.errors import OverturoValidationError
from tests.corpus import corpus_route

BASE = "https://overturo.test"
DISCOVERY_URL = f"{BASE}/.well-known/openid-configuration"
DECISIONS_URL = f"{BASE}/api/v1/decisions"


def _discovery_doc() -> dict:
    return {
        "issuer": "https://overturo.us",
        "oap_protocol_versions_supported": ["1.0"],
        "oversight_attestation_endpoint": f"{BASE}/api/v1/oap/attestations",
        "oversight_attestation_heartbeat_endpoint": f"{BASE}/api/v1/oap/attestations/heartbeat",
        "oversight_escalation_endpoint": f"{BASE}/api/v1/oap/escalations",
        "oversight_revocation_endpoint": f"{BASE}/api/v1/oap/revocations",
    }


@pytest.fixture
async def client_and_router():
    with respx.mock(assert_all_called=False) as router:
        router.get(DISCOVERY_URL).respond(200, json=_discovery_doc())
        client = await OverturoOversight.create(
            base_url=BASE,
            token="tat_dev_xxx",
            touchpoint_id="tp_dev_yyy",
            heartbeat_enabled=False,
        )
        yield client, router
        await client.close()


# ── token_for ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_token_for_posts_and_returns_decision_token(client_and_router):
    client, router = client_and_router
    # The recorded create exchange (a consent session; the envelope is kind-agnostic).
    route = corpus_route(router, "Decisions_create", BASE)

    token = await decisions._token_for_async(
        client, escalation_id="esc_dev_abc", mode="redirect", embed_origin=None
    )
    assert isinstance(token, DecisionToken)
    assert token.session_token == "<TOKEN>"
    assert token.kind == "consent"
    assert token.mode == "redirect"

    body = json.loads(route.calls[0].request.content)
    assert body == {"escalation_id": "esc_dev_abc", "mode": "redirect"}


@pytest.mark.asyncio
async def test_token_for_passes_embed_origin_when_supplied(client_and_router):
    client, router = client_and_router
    route = router.post(DECISIONS_URL).respond(
        201,
        json={
            "session_token": "ds_y_tok",
            "decision_url": f"{BASE}/decisions/ds_y?token=ds_y_tok",
            "embed_url": f"{BASE}/decisions/ds_y/embed",
            "kind": "approval",
            "mode": "embed",
            "expires_at": "2099-01-01T00:00:00Z",
        },
    )

    await decisions._token_for_async(
        client,
        escalation_id="esc_dev_abc",
        mode="embed",
        embed_origin="https://partner.example",
    )
    body = json.loads(route.calls[0].request.content)
    assert body == {
        "escalation_id": "esc_dev_abc",
        "mode": "embed",
        "embed_origin": "https://partner.example",
    }


# ── poll_status ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_poll_status_returns_the_recorded_status(client_and_router):
    client, router = client_and_router
    # The recorded status exchange: a pending session is not terminal.
    corpus_route(router, "Decisions_show", BASE)

    status = await decisions._poll_status_async(client, session_token="ds_x_tok")
    assert isinstance(status, DecisionStatus)
    assert status.status == "pending"
    assert not status.is_terminal()


@pytest.mark.asyncio
async def test_poll_status_propagates_404_as_validation_error(client_and_router):
    client, router = client_and_router
    router.get(f"{DECISIONS_URL}/ds_missing").respond(
        404,
        json={
            "error": {
                "reason_code": "decision_session_not_found",
                "message": "no such session",
            }
        },
    )
    with pytest.raises(OverturoValidationError):
        await decisions._poll_status_async(client, session_token="ds_missing")


# ── subscribe (async long-poll) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_subscribe_loops_until_terminal(client_and_router):
    client, router = client_and_router
    wait_url = f"{DECISIONS_URL}/by-escalation/esc_dev_abc/wait"
    responses = [
        {
            "session_token": "ds_x",
            "status": "pending",
            "decision": None,
            "wait_again": True,
        },
        {
            "session_token": "ds_x",
            "status": "approved",
            "decision": {"approved_by": "user_a"},
            "wait_again": False,
        },
    ]
    call_idx = {"i": 0}

    def _handler(request):
        i = call_idx["i"]
        call_idx["i"] += 1
        import httpx as _h

        return _h.Response(200, json=responses[min(i, len(responses) - 1)])

    router.get(wait_url).mock(side_effect=_handler)

    seen: list[DecisionStatus] = []
    async for status in decisions.subscribe(client, escalation_id="esc_dev_abc", timeout_s=5.0):
        seen.append(status)

    assert len(seen) == 2
    assert seen[0].status == "pending"
    assert seen[0].wait_again is True
    assert seen[1].status == "approved"
    assert seen[1].is_terminal()


@pytest.mark.asyncio
async def test_subscribe_exits_on_timeout_without_yielding(client_and_router):
    """If the overall deadline passes before any response, the
    generator should return cleanly without yielding."""
    client, _router = client_and_router
    # No mock for the wait endpoint → bail out before deadline by
    # forcing timeout_s=0 (deadline is in the past on first loop pass).
    seen: list[DecisionStatus] = []
    async for status in decisions.subscribe(client, escalation_id="esc_dev_abc", timeout_s=0.0):
        seen.append(status)
    assert seen == []


@pytest.mark.asyncio
async def test_subscribe_honors_retry_after_hint(client_and_router):
    """When the server returns wait_again with `retry_after`, the
    subscribe loop must sleep that long before re-polling."""
    import asyncio as _asyncio

    client, router = client_and_router
    wait_url = f"{DECISIONS_URL}/by-escalation/esc_dev_abc/wait"

    call_idx = {"i": 0}

    def _handler(_request):
        i = call_idx["i"]
        call_idx["i"] += 1
        import httpx as _h

        if i == 0:
            # Interim response with a rate-limit hint.
            return _h.Response(
                200,
                json={
                    "session_token": "ds_x",
                    "status": "pending",
                    "decision": None,
                    "wait_again": True,
                    "retry_after": 2,
                },
            )
        return _h.Response(
            200,
            json={
                "session_token": "ds_x",
                "status": "approved",
                "decision": {"by": "user_a"},
                "wait_again": False,
            },
        )

    router.get(wait_url).mock(side_effect=_handler)

    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    seen = []
    # Patch asyncio.sleep on the decisions module's local binding.
    real_sleep = _asyncio.sleep
    decisions.client.asyncio.sleep = fake_sleep  # type: ignore[attr-defined]
    try:
        async for status in decisions.subscribe(
            client, escalation_id="esc_dev_abc", timeout_s=10.0
        ):
            seen.append(status)
    finally:
        decisions.client.asyncio.sleep = real_sleep  # type: ignore[attr-defined]

    assert len(seen) == 2
    assert seen[0].retry_after == 2
    # We should have slept ≥ retry_after (2.0) before re-polling.
    assert any(s >= 2.0 for s in sleeps), f"expected a 2s+ sleep, got {sleeps!r}"


def test_url_for_returns_decision_url():
    """url_for is a thin wrapper over token_for — mock the async path
    and verify the URL flows through."""
    from unittest.mock import patch

    fake_token = decisions.DecisionToken(
        session_token="ds_x_secret",
        decision_url="https://x.example/decisions/ds_x?token=ds_x_secret",
        embed_url="https://x.example/decisions/ds_x/embed",
        kind="approval",
        mode="redirect",
        expires_at="2099-01-01T00:00:00Z",
    )

    async def _stub(client, **_):
        return fake_token

    with patch.object(decisions.client, "_token_for_async", side_effect=_stub):
        url = decisions.url_for(object(), escalation_id="esc_dev_abc")

    assert url == fake_token.decision_url


def test_subscribe_sync_iterates_to_terminal_status():
    """Cover the sync iterator wrapper — drive `subscribe()` on a
    private loop and confirm it yields each DecisionStatus.

    No running event loop in this sync test, so the inside-loop guard
    is skipped naturally.
    """

    statuses = [
        decisions.DecisionStatus(
            session_token="ds_x", status="pending", decision=None, wait_again=True
        ),
        decisions.DecisionStatus(
            session_token="ds_x",
            status="approved",
            decision={"by": "u"},
            wait_again=False,
        ),
    ]
    call_idx = {"i": 0}

    async def fake_long_poll_get(*_args, **_kwargs):
        i = call_idx["i"]
        call_idx["i"] += 1
        s = statuses[min(i, len(statuses) - 1)]
        return {
            "session_token": s.session_token,
            "status": s.status,
            "decision": s.decision,
            "wait_again": s.wait_again,
        }

    # Build a bare client stand-in with just the attributes subscribe touches.
    class _StubDiscovery:
        _base_url = "https://overturo.test"

    class _StubHttp:
        long_poll_get = staticmethod(fake_long_poll_get)

    class _StubClient:
        _discovery = _StubDiscovery()
        _http = _StubHttp()

    seen = list(decisions.subscribe_sync(_StubClient(), escalation_id="esc_dev_abc", timeout_s=5.0))

    assert len(seen) == 2
    assert seen[0].is_terminal() is False
    assert seen[1].is_terminal() is True


def test_subscribe_sync_refuses_inside_running_loop():
    """If called from within a running loop, it must raise rather
    than silently dead-lock."""
    import asyncio as _asyncio

    async def _try():
        with pytest.raises(RuntimeError, match="running event loop"):
            list(decisions.subscribe_sync(object(), escalation_id="esc_x"))

    _asyncio.run(_try())
