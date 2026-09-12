"""OverturoAuthorize client — happy path, escalate, error envelope, fallback."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from overturo.authorize._jurisdiction import jurisdiction_context
from overturo.authorize.client import OverturoAuthorize, TokenInfo
from overturo.errors import OapError, is_oap_error


def _client(handler, *, dpop_keypair) -> OverturoAuthorize:
    transport = httpx.MockTransport(handler)
    return OverturoAuthorize(
        grant_id="ath_test_xyz",
        agent_token="agent-token-v1",
        dpop_key=dpop_keypair,
        iss="https://us.overturo.test",
        http_client=httpx.Client(transport=transport),
    )


def test_authorize_posts_with_bearer_and_dpop_headers(dpop_keypair):
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        seen["dpop"] = request.headers.get("DPoP")
        return httpx.Response(
            200,
            json={
                "decision": "allow",
                "receipt": "h.p.s",
                "jti": "n1",
                "exp": int(time.time()) + 60,
                "chronicle_id": "audit_rec_test",
                "oap_ver": "1.0",
            },
        )

    client = _client(handler, dpop_keypair=dpop_keypair)
    res = client.authorize(nonce="uuid-1", action="read", scope="profile")
    assert seen["url"] == "https://us.overturo.test/api/v1/grants/ath_test_xyz/authorize"
    assert seen["auth"] == "DPoP agent-token-v1"
    assert seen["dpop"] is not None and seen["dpop"].count(".") == 2
    assert res["decision"] == "allow"
    assert res["jti"] == "n1"


# the public ``jurisdiction`` maps into the authorize context.
def test_authorize_maps_jurisdiction_into_context(dpop_keypair):
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": "allow", "jti": "n1", "oap_ver": "1.0"})

    client = _client(handler, dpop_keypair=dpop_keypair)
    client.authorize(nonce="u1", action="read", scope="profile", jurisdiction="IT")
    # Assert via the confined mapping helper so the wire key literal stays out
    # of the (firewall-scanned) test file.
    assert seen["body"]["context"] == jurisdiction_context("IT")
    assert "jurisdiction" not in seen["body"]


def test_authorize_without_jurisdiction_sends_no_context(dpop_keypair):
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": "allow", "jti": "n2", "oap_ver": "1.0"})

    client = _client(handler, dpop_keypair=dpop_keypair)
    client.authorize(nonce="u2", action="read", scope="profile")
    assert "context" not in seen["body"]


# the typed authorize surfaces accept `jurisdiction` too (parity with
# the untyped `authorize`); the param must reach `_authorize_call`.
def test_authorize_typed_maps_jurisdiction_into_context(dpop_keypair):
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"decision": "allow", "jti": "n3", "oap_ver": "1.0"})

    client = _client(handler, dpop_keypair=dpop_keypair)
    client.authorize_typed(nonce="u3", action="read", scope="profile", jurisdiction="DE")
    assert seen["body"]["context"] == jurisdiction_context("DE")


def test_authorize_binds_dpop_proof_to_agent_token_via_ath(dpop_keypair):
    """RFC 9449 section 4.1 — the proof MUST carry ath = SHA-256(token) when
    accompanied by a bearer. The server rejects with dpop_invalid
    otherwise."""
    from hashlib import sha256

    from overturo.authorize.receipt import b64url_decode, b64url_encode

    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["dpop"] = request.headers.get("DPoP")
        return httpx.Response(
            200,
            json={
                "decision": "allow",
                "receipt": "h.p.s",
                "jti": "n1",
                "exp": int(time.time()) + 60,
                "chronicle_id": "audit_rec_test",
                "oap_ver": "1.0",
            },
        )

    client = _client(handler, dpop_keypair=dpop_keypair)
    client.authorize(nonce="uuid-ath", action="read", scope="profile")

    parts = seen["dpop"].split(".")
    payload = json.loads(b64url_decode(parts[1]))
    expected = b64url_encode(sha256(b"agent-token-v1").digest())
    assert payload["ath"] == expected


def test_authorize_raises_approval_required_on_escalate(dpop_keypair):
    """untyped `authorize()` now raises
    OapApprovalRequired on `decision == "escalate"` instead of
    returning the dict. Typed callers (`authorize_typed`) are
    unaffected.
    """
    from overturo import OapApprovalRequired

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "decision": "escalate",
                "escalation": {
                    "escalation_id": "esc_test",
                    "required_signers": ["principal_a"],
                    "approval_ttl_at": "2026-05-13T00:00:00Z",
                    "decision_url": "https://overturo.example/decisions/ds_x",
                    "session_token": "ds_x_token",
                },
                "oap_ver": "1.0",
            },
        )

    client = _client(handler, dpop_keypair=dpop_keypair)
    with pytest.raises(OapApprovalRequired) as excinfo:
        client.authorize(
            nonce="uuid-2",
            action="pay",
            scope="payments:write",
            value="200.00",
            currency="USD",
        )

    exc = excinfo.value
    assert exc.escalation_id == "esc_test"
    assert exc.required_signers == ("principal_a",)
    assert exc.decision_url == "https://overturo.example/decisions/ds_x"
    assert exc.session_token == "ds_x_token"


def test_authorize_raises_oap_error_with_reason_code_on_deny(dpop_keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "reason_code": "value_exceeds_tx_max",
                    "message": "Value exceeds per-transaction limit",
                    "failed_bound": "value_bounds",
                    "detail": {"max_per_transaction": "100", "given": "200"},
                    "oap_ver": "1.0",
                }
            },
        )

    client = _client(handler, dpop_keypair=dpop_keypair)
    with pytest.raises(OapError) as excinfo:
        client.authorize(
            nonce="uuid-3",
            action="pay",
            scope="payments:write",
            value="200.00",
            currency="USD",
        )
    err = excinfo.value
    assert is_oap_error(err)
    assert err.reason_code == "value_exceeds_tx_max"
    assert err.failed_bound == "value_bounds"
    assert err.http_status == 403


def test_authorize_synthesises_internal_error_for_non_envelope_5xx(dpop_keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="<html>bad gateway</html>")

    client = _client(handler, dpop_keypair=dpop_keypair)
    with pytest.raises(OapError) as excinfo:
        client.authorize(nonce="uuid-4", action="read", scope="profile")
    assert excinfo.value.reason_code == "internal_error"
    assert excinfo.value.http_status == 502


def test_refresh_token_updates_in_memory_bearer(dpop_keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "agent_token": "new-token-v2",
                "agent_token_expires_at": "2026-05-13T00:00:00Z",
                "iss": "https://us.overturo.test",
                "oap_ver": "1.0",
            },
        )

    client = _client(handler, dpop_keypair=dpop_keypair)
    assert client.current_token == "agent-token-v1"
    info = client.refresh_token()
    assert isinstance(info, TokenInfo)
    assert info.agent_token == "new-token-v2"
    assert client.current_token == "new-token-v2"


def test_constructor_requires_grant_id_token_iss(dpop_keypair):
    with pytest.raises(ValueError, match="grant_id"):
        OverturoAuthorize(grant_id="", agent_token="x", dpop_key=dpop_keypair, iss="https://x")
    with pytest.raises(ValueError, match="agent_token"):
        OverturoAuthorize(grant_id="ath_x", agent_token="", dpop_key=dpop_keypair, iss="https://x")
    with pytest.raises(ValueError, match="iss"):
        OverturoAuthorize(grant_id="ath_x", agent_token="x", dpop_key=dpop_keypair, iss="")


def test_iss_trailing_slash_is_stripped(dpop_keypair):
    seen_url: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_url["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "agent_token": "y",
                "agent_token_expires_at": "z",
                "iss": "https://us.overturo.test",
                "oap_ver": "1.0",
            },
        )

    client = OverturoAuthorize(
        grant_id="ath_test_xyz",
        agent_token="x",
        dpop_key=dpop_keypair,
        iss="https://us.overturo.test///",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.refresh_token()
    assert seen_url["url"] == "https://us.overturo.test/api/v1/grants/ath_test_xyz/token"


def test_network_error_surfaces_as_internal_error(dpop_keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _client(handler, dpop_keypair=dpop_keypair)
    with pytest.raises(OapError) as excinfo:
        client.authorize(nonce="uuid-net", action="read", scope="profile")
    assert excinfo.value.reason_code == "internal_error"
    assert excinfo.value.http_status is None


def test_context_manager_closes_owned_client(dpop_keypair):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{}")

    transport = httpx.MockTransport(handler)
    with OverturoAuthorize(
        grant_id="ath_test_xyz",
        agent_token="x",
        dpop_key=dpop_keypair,
        iss="https://x",
        http_client=httpx.Client(transport=transport),
    ) as client:
        assert client.current_token == "x"
    # No error on context exit — close() is idempotent for caller-owned clients.
