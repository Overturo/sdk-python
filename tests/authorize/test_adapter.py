"""OverturoDecisionAdapter ABC tests."""

from __future__ import annotations

from typing import Any

import pytest

from overturo import OverturoDecision, OverturoDecisionAdapter


def test_adapter_cannot_be_instantiated_directly() -> None:
    with pytest.raises(TypeError, match="abstract"):
        OverturoDecisionAdapter()  # type: ignore[abstract]


def test_subclass_must_implement_evaluate() -> None:
    class IncompleteAdapter(OverturoDecisionAdapter):
        pass

    with pytest.raises(TypeError, match="evaluate"):
        IncompleteAdapter()  # type: ignore[abstract]


def test_subclass_with_evaluate_instantiates() -> None:
    class MinimalAdapter(OverturoDecisionAdapter):
        def evaluate(self, request: dict[str, Any]) -> OverturoDecision:
            return OverturoDecision(
                decision="allow",
                mode="conductor",
                request_id="req_test",
                overturo_decision_schema_version="1.0.0",
            )

    adapter = MinimalAdapter()
    result = adapter.evaluate({"action": "read"})
    assert result.decision == "allow"
    assert result.request_id == "req_test"
