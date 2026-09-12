"""typed-error additions.

Asserts the reason_code → exception dispatch picks the right subclass
for the three new error classes shipped in v1.1.0.
"""

from __future__ import annotations

from overturo import (
    OapDispatchError,
    OapError,
    OapEscalationDenied,
    OapWrongRegion,
)


def _envelope(reason_code: str, http_status: int) -> dict:
    return {
        "error": {
            "reason_code": reason_code,
            "message": f"test message for {reason_code}",
            "detail": {},
            "denial_category": None,
        }
    }


def test_escalation_denied_dispatch() -> None:
    err = OapError.from_envelope(_envelope("escalation_denied", 403), status=403)
    assert isinstance(err, OapEscalationDenied)
    assert err.reason_code == "escalation_denied"


def test_dispatch_error_dispatch() -> None:
    err = OapError.from_envelope(_envelope("dispatch_error", 500), status=500)
    assert isinstance(err, OapDispatchError)
    assert err.reason_code == "dispatch_error"


def test_wrong_region_dispatch() -> None:
    err = OapError.from_envelope(_envelope("wrong_region", 403), status=403)
    assert isinstance(err, OapWrongRegion)
    assert err.reason_code == "wrong_region"


def test_unknown_reason_code_falls_through_to_OapError() -> None:
    err = OapError.from_envelope(_envelope("future_unseen_reason", 500), status=500)
    # Falls through reason-code dispatch + denial_category dispatch → base
    assert isinstance(err, OapError)
    assert not isinstance(err, (OapEscalationDenied, OapDispatchError, OapWrongRegion))
