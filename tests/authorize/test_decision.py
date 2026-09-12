"""parse_decision unit tests.

Mirrors the TypeScript decision.test.ts suite. Same fixture matrix to
keep cross-SDK behaviour parity-testable.
"""

from __future__ import annotations

from typing import Any

import pytest

from overturo import (
    OverturoBlockInvocation,
    OverturoDecision,
    OverturoDecisionMalformed,
    OverturoReceipt,
    parse_decision,
)

BASE_ALLOW: dict[str, Any] = {
    "decision": "allow",
    "mode": "conductor",
    "request_id": "req_abc",
    "overturo_decision_schema_version": "1.0.0",
}


def test_minimal_allow_parses() -> None:
    d = parse_decision(BASE_ALLOW)
    assert d.decision == "allow"
    assert d.mode == "conductor"
    assert d.request_id == "req_abc"
    assert d.block_invocations == ()


def test_passthrough_fields_ignored_silently() -> None:
    # `iss` and `oap_ver` are wire-additive; the parser preserves the
    # OverturoDecision-shape fields only.
    payload = {**BASE_ALLOW, "iss": "https://eu.example.com", "oap_ver": "1.0"}
    d = parse_decision(payload)
    assert d.decision == "allow"


def test_block_invocations_parsed_with_optional_fields() -> None:
    d = parse_decision(
        {
            **BASE_ALLOW,
            "block_invocations": [
                {
                    "position": 7,
                    "block_slug": "conductor.policy_gate",
                    "decision": "pass",
                    "latency_ms": 1.5,
                    "evaluator_class": "BuiltinEvaluator",
                },
                {
                    "position": 10,
                    "block_slug": "conductor.budget_governor",
                    "decision": "pass",
                    "latency_ms": 2.0,
                    "evaluator_class": "BuiltinEvaluator",
                    "cache_outcome": "hit",
                },
            ],
        }
    )
    assert len(d.block_invocations) == 2
    assert isinstance(d.block_invocations[0], OverturoBlockInvocation)
    assert d.block_invocations[0].position == 7
    assert d.block_invocations[1].cache_outcome == "hit"


def test_escalation_parsed() -> None:
    d = parse_decision(
        {
            **BASE_ALLOW,
            "decision": "escalate",
            "escalation": {
                "escalation_id": "esc_abc",
                "required_signers": ["principal"],
                "approval_ttl_at": "2026-12-31T00:00:00Z",
            },
        }
    )
    assert d.escalation is not None
    assert d.escalation.escalation_id == "esc_abc"
    assert d.escalation.required_signers == ("principal",)


def test_receipt_as_string_wrapped() -> None:
    d = parse_decision(
        {
            **BASE_ALLOW,
            "receipt": "eyJ.AAA.BBB",
            "receipt_jti": "jti_1",
            "iat": 1700000000,
            "exp": 1700003600,
        }
    )
    assert isinstance(d.receipt, OverturoReceipt)
    assert d.receipt.jwt == "eyJ.AAA.BBB"
    assert d.receipt.jti == "jti_1"


def test_receipt_as_object() -> None:
    d = parse_decision(
        {
            **BASE_ALLOW,
            "receipt": {"jwt": "eyJ.AAA.BBB", "jti": "jti_2", "iat": 1700000000, "exp": 1700003600},
        }
    )
    assert d.receipt is not None
    assert d.receipt.jti == "jti_2"


def test_missing_mode_defaults_to_conductor() -> None:
    """Server may omit mode on the deny path when touchpoint is
    unresolved (audit fix). The parser
    must default to 'conductor' rather than rejecting the payload."""
    payload = {k: v for k, v in BASE_ALLOW.items() if k != "mode"}
    d = parse_decision(payload)
    assert d.mode == "conductor"


# ── Malformed inputs ──────────────────────────────────────────────────


def test_rejects_missing_decision() -> None:
    payload = {k: v for k, v in BASE_ALLOW.items() if k != "decision"}
    with pytest.raises(OverturoDecisionMalformed, match="missing required field"):
        parse_decision(payload)


def test_rejects_unknown_decision_value() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="unknown decision: 'maybe'"):
        parse_decision({**BASE_ALLOW, "decision": "maybe"})


def test_rejects_unknown_mode() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="unknown mode: 'trust'"):
        parse_decision({**BASE_ALLOW, "mode": "trust"})


def test_rejects_v2x_schema_version() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="not 1.x compatible"):
        parse_decision({**BASE_ALLOW, "overturo_decision_schema_version": "2.0.0"})


def test_rejects_unknown_block_invocation_decision() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="unknown block_invocation.decision"):
        parse_decision(
            {
                **BASE_ALLOW,
                "block_invocations": [
                    {
                        "position": 7,
                        "block_slug": "x",
                        "decision": "ALLOWED",
                        "latency_ms": 1,
                        "evaluator_class": "Y",
                    }
                ],
            }
        )


def test_rejects_non_array_block_invocations() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="block_invocations must be a list"):
        parse_decision({**BASE_ALLOW, "block_invocations": "lots"})


def test_rejects_receipt_of_wrong_type() -> None:
    with pytest.raises(OverturoDecisionMalformed, match="receipt must be object or string"):
        parse_decision({**BASE_ALLOW, "receipt": 42})


def test_OverturoDecision_is_frozen_dataclass() -> None:
    d = parse_decision(BASE_ALLOW)
    assert isinstance(d, OverturoDecision)
    with pytest.raises((AttributeError, Exception)):
        d.decision = "deny"  # type: ignore[misc]
