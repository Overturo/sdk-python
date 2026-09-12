"""`OapApprovalRequired` dispatch + redaction."""

from __future__ import annotations

from overturo.errors import (
    OapApprovalRequired,
    OapAuthorizationDenied,
    OapError,
)


def _envelope() -> dict:
    return {
        "error": {
            "reason_code": "approval_required",
            "message": "Approval required for action",
            "request_id": "req_x",
            "escalation": {
                "escalation_id": "esc_dev_abc",
                "required_signers": ["user_a"],
                "approval_ttl_at": "2099-01-01T00:00:00Z",
                "decision_url": "https://overturo.example/decisions/ds_x?token=ds_x_token",
                "session_token": "ds_x_token",
            },
        }
    }


def test_dispatch_routes_to_approval_required() -> None:
    exc = OapError.from_envelope(_envelope(), status=409)
    assert isinstance(exc, OapApprovalRequired)
    assert exc.escalation_id == "esc_dev_abc"
    assert exc.required_signers == ("user_a",)
    assert exc.approval_ttl_at == "2099-01-01T00:00:00Z"
    assert exc.decision_url == "https://overturo.example/decisions/ds_x?token=ds_x_token"
    assert exc.session_token == "ds_x_token"
    assert exc.http_status == 409
    assert exc.request_id == "req_x"


def test_str_does_not_leak_token_or_url() -> None:
    exc = OapError.from_envelope(_envelope(), status=409)
    s = str(exc)
    assert "ds_x_token" not in s
    assert "decisions/ds_x" not in s
    assert "esc_dev_abc" in s  # escalation_id is OK to log


def test_repr_redacts_credentials() -> None:
    exc = OapError.from_envelope(_envelope(), status=409)
    r = repr(exc)
    assert "<redacted>" in r
    assert "ds_x_token" not in r
    assert "decisions/ds_x" not in r
    assert "esc_dev_abc" in r


def test_existing_dispatch_unaffected() -> None:
    """Regression — category dispatch still routes correctly."""
    exc = OapError.from_envelope(
        {
            "error": {
                "reason_code": "auth_denied",
                "message": "Token expired",
                "denial_category": "authorization_denied",
            }
        },
        status=401,
    )
    assert isinstance(exc, OapAuthorizationDenied)
    assert not isinstance(exc, OapApprovalRequired)


def test_missing_escalation_block_defaults_to_empty() -> None:
    """Older servers might emit the reason code without the
    nested escalation. The exception should still construct."""
    exc = OapError.from_envelope(
        {"error": {"reason_code": "approval_required", "message": "x"}},
        status=409,
    )
    assert isinstance(exc, OapApprovalRequired)
    assert exc.escalation_id == ""
    assert exc.required_signers == ()
    assert exc.decision_url == ""
    assert exc.session_token == ""


def test_re_exported_from_package() -> None:
    from overturo import OapApprovalRequired as Reexported

    assert Reexported is OapApprovalRequired
