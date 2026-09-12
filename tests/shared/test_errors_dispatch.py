"""Consolidation regression: the unified error tree must produce
identical class routing to the pre-consolidation dispatch.

"""

from __future__ import annotations

import pytest

from overturo.errors import (
    OapApprovalRequired,
    OapAuthorizationDenied,
    OapDispatchError,
    OapError,
    OapEscalationDenied,
    OapIntentDenied,
    OapSequenceDenied,
    OapTrajectoryDenied,
    OapWrongRegion,
    OverturoApiError,
    OverturoError,
    OverturoRateLimited,
)

# ─── Reason-code dispatch ──────────────────


@pytest.mark.parametrize(
    "reason_code,expected_cls",
    [
        ("sequence_prohibited", OapSequenceDenied),
        ("sequence_missing_predecessor", OapSequenceDenied),
        ("escalation_denied", OapEscalationDenied),
        ("dispatch_error", OapDispatchError),
        ("wrong_region", OapWrongRegion),
        ("approval_required", OapApprovalRequired),
    ],
)
def test_reason_code_dispatch(reason_code, expected_cls):
    envelope = {"error": {"reason_code": reason_code, "message": "x"}}
    if reason_code == "approval_required":
        envelope["error"]["escalation"] = {
            "escalation_id": "esc_test",
            "required_signers": ["alice"],
            "approval_ttl_at": "2026-06-10T12:00:00Z",
        }
    err = OapError.from_envelope(envelope, status=403)
    assert type(err) is expected_cls


@pytest.mark.parametrize(
    "category,expected_cls",
    [
        ("authorization_denied", OapAuthorizationDenied),
        ("intent_denied", OapIntentDenied),
        ("trajectory_denied", OapTrajectoryDenied),
    ],
)
def test_category_dispatch(category, expected_cls):
    envelope = {
        "error": {
            "reason_code": "x",
            "denial_category": category,
            "message": "y",
        }
    }
    err = OapError.from_envelope(envelope, status=403)
    assert type(err) is expected_cls


def test_unknown_reason_code_falls_through_to_oap_error():
    """Unknown reason + no category = bare OapError."""
    envelope = {"error": {"reason_code": "unknown_thing", "message": "x"}}
    err = OapError.from_envelope(envelope, status=500)
    assert type(err) is OapError


# ─── Sub-tree membership (unification invariant) ─────────────


def test_oap_error_is_overturo_error():
    """The unification's key invariant."""
    err = OapError(reason_code="x", message="y")
    assert isinstance(err, OverturoError)


def test_transport_error_is_overturo_error():
    err = OverturoApiError(message="500")
    assert isinstance(err, OverturoError)


def test_protocol_and_transport_dont_cross_catch():
    """Both root under OverturoError, but neither extends the other."""
    oap = OapError(reason_code="x", message="y")
    transport = OverturoApiError(message="500")
    assert not isinstance(oap, OverturoApiError)
    assert not isinstance(transport, OapError)


def test_approval_required_repr_redacts_token():
    """Security checkpoint — preserved."""
    err = OapApprovalRequired(
        reason_code="approval_required",
        message="needs approval",
        session_token="sk_secret",
        decision_url="https://x.example?token=sk_secret",
        escalation_id="esc_test",
    )
    assert "sk_secret" not in repr(err)
    assert "<redacted>" in repr(err)


def test_approval_required_str_redacts_token():
    """__str__ also redacted."""
    err = OapApprovalRequired(
        reason_code="approval_required",
        message="needs approval",
        session_token="sk_secret",
        decision_url="https://x.example?token=sk_secret",
        escalation_id="esc_test",
    )
    assert "sk_secret" not in str(err)


# ─── Dataclass-inheritance hazard smoke tests (r2 addition) ────────
# OverturoError has 1 effective field (message) + 4 defaults;
# OapError extends and adds 6 defaulted; OapApprovalRequired adds 5
# more defaulted. Dataclass inheritance rules require non-default
# fields before default ones — this layout satisfies that, but
# regressions are easy to introduce.


def test_overturo_error_constructs_positionally():
    """Single positional arg (message) works — back-compat with
    existing OverturoError(message='x') call sites."""
    err = OverturoError("network failure")
    assert err.message == "network failure"
    assert err.http_status is None


def test_overturo_error_constructs_by_keyword():
    err = OverturoError(message="x", http_status=500, reason_code="x")
    assert err.http_status == 500


def test_oap_error_inherits_root_fields():
    err = OapError(
        message="denied",
        reason_code="authorization_denied",
        denial_category="authorization_denied",
        failed_bound="time_bound",
    )
    assert err.message == "denied"
    assert err.failed_bound == "time_bound"


def test_oap_approval_required_inherits_full_chain():
    """Constructor accepts both OapError fields AND its own added fields."""
    err = OapApprovalRequired(
        message="needs approval",
        reason_code="approval_required",
        http_status=409,
        decision_url="https://x.example",
        session_token="secret",
        escalation_id="esc_1",
        required_signers=("alice", "bob"),
    )
    assert isinstance(err, OapError)
    assert isinstance(err, OverturoError)
    assert err.required_signers == ("alice", "bob")


def test_rate_limited_carries_retry_after():
    """OverturoRateLimited adds retry_after_seconds without breaking parent."""
    err = OverturoRateLimited(message="429", retry_after_seconds=30)
    assert err.retry_after_seconds == 30
    assert isinstance(err, OverturoApiError)
    assert isinstance(err, OverturoError)


# ─── Closed-enum source-of-truth invariant (conformance hook) ────────────


def test_reason_code_table_is_complete():
    """Sanity: every key in _REASON_CODE_TO_CLASS routes to an OapError subclass."""
    from overturo.errors import _REASON_CODE_TO_CLASS

    for code, cls in _REASON_CODE_TO_CLASS.items():
        assert issubclass(cls, OapError), f"{code} → {cls.__name__} is not an OapError subclass"


def test_category_table_routes_only_to_oap_error_subclasses():
    from overturo.errors import _CATEGORY_TO_CLASS

    for cat, cls in _CATEGORY_TO_CLASS.items():
        assert issubclass(cls, OapError), (
            f"category {cat} → {cls.__name__} is not an OapError subclass"
        )
