"""untyped `authorize()` raises `OapApprovalRequired`."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from overturo import (
    DpopKeyPair,
    OapApprovalRequired,
    OverturoAuthorize,
)
from overturo.models import OverturoDecision


@pytest.fixture
def client() -> OverturoAuthorize:
    return OverturoAuthorize(
        grant_id="ath_us_grant",
        agent_token="agent_token_x",
        dpop_key=DpopKeyPair.generate(),
        iss="https://overturo.example",
    )


def test_untyped_authorize_raises_on_escalate(client: OverturoAuthorize) -> None:
    escalate_response = {
        "decision": "escalate",
        "mode": "conductor",
        "request_id": "req_x",
        "escalation": {
            "escalation_id": "esc_dev_abc",
            "required_signers": ["user_a"],
            "approval_ttl_at": "2099-01-01T00:00:00Z",
            "decision_url": "https://overturo.example/decisions/ds_x",
            "session_token": "ds_x_token",
        },
    }
    with patch.object(client, "_signed_request", return_value=escalate_response):
        with pytest.raises(OapApprovalRequired) as exc_info:
            client.authorize(nonce="n", action="a", scope="s")

    exc = exc_info.value
    assert exc.escalation_id == "esc_dev_abc"
    assert exc.required_signers == ("user_a",)
    assert exc.decision_url == "https://overturo.example/decisions/ds_x"
    assert exc.session_token == "ds_x_token"
    assert exc.reason_code == "approval_required"


def test_typed_authorize_returns_unchanged_on_escalate(
    client: OverturoAuthorize,
) -> None:
    """Regression — the typed paths must NOT raise; they continue to
    return an OverturoDecision with .decision == 'escalate'."""
    escalate_response = {
        "decision": "escalate",
        "mode": "conductor",
        "request_id": "req_x",
        "overturo_decision_schema_version": "1.0.0",
        "escalation": {
            "escalation_id": "esc_dev_abc",
            "required_signers": ["user_a"],
            "approval_ttl_at": "2099-01-01T00:00:00Z",
            "decision_url": "https://overturo.example/decisions/ds_x",
            "session_token": "ds_x_token",
        },
    }
    with patch.object(client, "_authorize_call", return_value=escalate_response):
        result = client.authorize_typed(nonce="n", action="a", scope="s")

    assert isinstance(result, OverturoDecision)
    assert result.decision == "escalate"
    assert result.escalation is not None
    assert result.escalation.escalation_id == "esc_dev_abc"
    # new fields populated on OverturoEscalation too.
    assert result.escalation.decision_url == "https://overturo.example/decisions/ds_x"
    assert result.escalation.session_token == "ds_x_token"


def test_untyped_authorize_allow_returns_dict(client: OverturoAuthorize) -> None:
    """Regression — allow path still returns the dict."""
    allow_response = {
        "decision": "allow",
        "mode": "conductor",
        "request_id": "req_x",
    }
    with patch.object(client, "_signed_request", return_value=allow_response):
        result = client.authorize(nonce="n", action="a", scope="s")

    assert result == allow_response


def test_authorize_raises_on_4xx_approval_required_envelope(client: OverturoAuthorize) -> None:
    """When a future server emits `approval_required` as a 4xx error
    envelope (rather than a 200 with `decision: escalate`), the
    standard `_parse` path must route it to OapApprovalRequired with
    the same redacted-by-default behaviour."""
    import httpx

    envelope_response = httpx.Response(
        409,
        json={
            "error": {
                "reason_code": "approval_required",
                "message": "Approval required for action",
                "request_id": "req_y",
                "escalation": {
                    "escalation_id": "esc_dev_xyz",
                    "required_signers": ["principal_b"],
                    "approval_ttl_at": "2099-01-01T00:00:00Z",
                    "decision_url": "https://x/decisions/ds_y?token=abc",
                    "session_token": "abc",
                },
            }
        },
    )
    with patch.object(
        client._http,
        "request",
        return_value=envelope_response,
    ):
        with pytest.raises(OapApprovalRequired) as exc_info:
            client.authorize(nonce="n", action="a", scope="s")

    exc = exc_info.value
    assert exc.escalation_id == "esc_dev_xyz"
    assert exc.http_status == 409
    assert exc.required_signers == ("principal_b",)
    assert exc.session_token == "abc"
    assert exc.decision_url == "https://x/decisions/ds_y?token=abc"
    assert exc.request_id == "req_y"


def test_overturo_escalation_repr_redacts_url_and_token() -> None:
    """OverturoEscalation now carries the same credential-bearing fields
    as the OapApprovalRequired exception; its __repr__ must redact both
    so passing the typed result through `logger.info(result.escalation)`
    cannot leak the bearer token."""
    from overturo.models import OverturoEscalation

    e = OverturoEscalation(
        escalation_id="esc_dev_abc",
        required_signers=("user_a",),
        approval_ttl_at="2099-01-01T00:00:00Z",
        decision_url="https://x.example/decisions/ds_x?token=ds_x_secret",
        session_token="ds_x_secret",
    )
    r = repr(e)
    assert "<redacted>" in r
    assert "ds_x_secret" not in r
    assert "?token=" not in r
    # Non-credential fields are fine to log.
    assert "esc_dev_abc" in r
    assert "user_a" in r


def test_overturo_escalation_repr_shows_none_for_missing_fields() -> None:
    """When an older server didn't populate the new fields, the
    repr should say 'None' rather than redacted (no leak to hide)."""
    from overturo.models import OverturoEscalation

    e = OverturoEscalation(
        escalation_id="esc_dev_abc",
        required_signers=(),
        approval_ttl_at="2099-01-01T00:00:00Z",
    )
    r = repr(e)
    assert "decision_url=None" in r
    assert "session_token=None" in r
    assert "<redacted>" not in r


def test_overturo_escalation_optional_fields_default_none() -> None:
    """Older servers won't include decision_url / session_token."""
    from overturo.models import _parse_escalation

    esc = _parse_escalation(
        {
            "escalation_id": "esc_x",
            "required_signers": ["user_a"],
            "approval_ttl_at": "2099-01-01T00:00:00Z",
        }
    )
    assert esc.decision_url is None
    assert esc.session_token is None
