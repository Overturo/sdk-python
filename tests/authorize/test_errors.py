"""OapError.from_envelope dispatch coverage."""

from __future__ import annotations

import pytest

from overturo.errors import (
    OapAuthorizationDenied,
    OapError,
    OapIntentDenied,
    OapSequenceDenied,
    OapTrajectoryDenied,
    is_oap_error,
)


def _envelope(**fields):
    base = {
        "reason_code": "validation_failed",
        "message": "demo",
        "oap_ver": "1.0",
    }
    base.update(fields)
    return {"error": base}


class TestFromEnvelope:
    def test_dispatches_authorization_denied(self):
        err = OapError.from_envelope(
            _envelope(
                reason_code="dpop_invalid",
                denial_category="authorization_denied",
                cascade_step=1,
            ),
            status=401,
        )
        assert isinstance(err, OapAuthorizationDenied)
        assert isinstance(err, OapError)
        assert is_oap_error(err)
        assert err.denial_category == "authorization_denied"
        assert err.cascade_step == 1
        assert err.http_status == 401

    def test_dispatches_intent_denied(self):
        err = OapError.from_envelope(
            _envelope(
                reason_code="action_not_allowed",
                denial_category="intent_denied",
                cascade_step=7,
            ),
            status=403,
        )
        assert isinstance(err, OapIntentDenied)
        assert err.denial_category == "intent_denied"
        assert err.cascade_step == 7

    def test_dispatches_trajectory_denied(self):
        err = OapError.from_envelope(
            _envelope(
                reason_code="value_exceeds_tx_max",
                denial_category="trajectory_denied",
                cascade_step=10,
            ),
            status=403,
        )
        assert isinstance(err, OapTrajectoryDenied)
        # NOT the sequence subclass — reason code distinguishes.
        assert not isinstance(err, OapSequenceDenied)

    def test_falls_back_to_base_on_absent_category(self):
        err = OapError.from_envelope(_envelope(reason_code="validation_failed"), status=422)
        assert type(err) is OapError
        assert not isinstance(err, OapAuthorizationDenied)
        assert not isinstance(err, OapIntentDenied)
        assert not isinstance(err, OapTrajectoryDenied)
        assert err.denial_category is None

    # ── sequence dispatch precedence ──────────────
    @pytest.mark.parametrize("reason_code", ["sequence_prohibited", "sequence_missing_predecessor"])
    def test_sequence_reason_codes_dispatch_to_sequence_subclass(self, reason_code):
        err = OapError.from_envelope(
            _envelope(
                reason_code=reason_code,
                denial_category="trajectory_denied",
                cascade_step=13,
            ),
            status=403,
        )
        assert isinstance(err, OapSequenceDenied)
        # The subclass remains catchable as the broader trajectory
        # category and as the base OapError.
        assert isinstance(err, OapTrajectoryDenied)
        assert isinstance(err, OapError)

    def test_non_sequence_trajectory_does_not_downgrade_to_sequence(self):
        err = OapError.from_envelope(
            _envelope(
                reason_code="value_exceeds_tx_max",
                denial_category="trajectory_denied",
                cascade_step=10,
            ),
            status=403,
        )
        assert isinstance(err, OapTrajectoryDenied)
        assert not isinstance(err, OapSequenceDenied)

    def test_tolerates_missing_cascade_step(self):
        # The server may suppress cascade_step after the threshold.
        err = OapError.from_envelope(
            _envelope(
                reason_code="sequence_prohibited",
                denial_category="trajectory_denied",
                # no cascade_step
            ),
            status=403,
        )
        assert isinstance(err, OapSequenceDenied)
        assert err.cascade_step is None
