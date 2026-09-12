"""vendored `_shared.py` correctness + redaction.

Same body lives at `oversight-py/tests/unit/test_shared.py`.
"""

from __future__ import annotations

from overturo.models import (
    DecisionStatus,
    DecisionToken,
    Escalation,
)


def test_escalation_from_envelope() -> None:
    e = Escalation.from_envelope(
        {
            "escalation_id": "esc_dev_abc",
            "required_signers": ["user_a", "user_b"],
            "approval_ttl_at": "2099-01-01T00:00:00Z",
            "decision_url": "https://overturo.example/decisions/ds_x",
            "session_token": "ds_x_token",
        }
    )
    assert e.escalation_id == "esc_dev_abc"
    assert e.required_signers == ("user_a", "user_b")
    assert e.approval_ttl_at == "2099-01-01T00:00:00Z"
    assert e.decision_url == "https://overturo.example/decisions/ds_x"
    assert e.session_token == "ds_x_token"


def test_escalation_from_envelope_optional_fields_default_none() -> None:
    """Older servers don't include decision_url / session_token."""
    e = Escalation.from_envelope(
        {
            "escalation_id": "esc_x",
            "required_signers": [],
            "approval_ttl_at": "2099-01-01T00:00:00Z",
        }
    )
    assert e.decision_url is None
    assert e.session_token is None


def test_escalation_repr_redacts_session_token() -> None:
    e = Escalation(
        escalation_id="esc_x",
        required_signers=(),
        approval_ttl_at="2099-01-01T00:00:00Z",
        decision_url="https://x/y",
        session_token="supersecret",
    )
    r = repr(e)
    assert "supersecret" not in r
    assert "<redacted>" in r


def test_decision_status_is_terminal() -> None:
    pending = DecisionStatus(session_token="x", status="pending", decision=None, wait_again=True)
    assert not pending.is_terminal()

    approved = DecisionStatus(session_token="x", status="approved", decision={}, wait_again=False)
    assert approved.is_terminal()


def test_decision_status_repr_redacts_token() -> None:
    s = DecisionStatus(
        session_token="ds_x_secret",
        status="pending",
        decision=None,
        wait_again=True,
    )
    assert "ds_x_secret" not in repr(s)
    assert "<redacted>" in repr(s)


def test_decision_token_repr_redacts_url_and_token() -> None:
    t = DecisionToken.from_response(
        {
            "session_token": "ds_x_secret",
            "decision_url": "https://overturo.example/decisions/ds_x?token=secret",
            "embed_url": "https://overturo.example/decisions/ds_x/embed",
            "kind": "approval",
            "mode": "redirect",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    )
    r = repr(t)
    assert "<redacted>" in r
    assert "ds_x_secret" not in r
    assert "?token=" not in r
    # Non-credential fields are fine to log
    assert "'approval'" in r
    assert "'redirect'" in r
