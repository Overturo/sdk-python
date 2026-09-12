"""Cedar-style policy adapter — reference implementation.

Implements :class:`OverturoDecisionAdapter` against a fixture-driven
in-memory policy evaluator that mirrors Cedar's `(principal, action,
resource, context)` shape. Production deployments swap the
``InMemoryCedarEvaluator`` for the real ``cedar-policy`` package
(see README, "Cedar swap").

Reference implementation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# SDK imports — try the installed package first (production path).
# Fall back to loading the models module directly so the example and its
# smoke test run without an editable install and without httpx (which the
# SDK's HTTP clients import but the adapter does not need).
try:
    from overturo.authorize.adapter import OverturoDecisionAdapter
    from overturo.models import OverturoDecision
except ImportError:
    import importlib.util
    import sys as _sys

    _SDK_SRC = Path(__file__).resolve().parents[2] / "src" / "overturo"

    def _load_standalone(module_name: str, filename: str):
        spec = importlib.util.spec_from_file_location(module_name, str(_SDK_SRC / filename))
        mod = importlib.util.module_from_spec(spec)
        _sys.modules[module_name] = mod  # dataclasses need the module registered
        spec.loader.exec_module(mod)
        return mod

    _models_mod = _load_standalone("overturo_models_standalone", "models.py")
    OverturoDecision = _models_mod.OverturoDecision

    # OverturoDecisionAdapter is a one-method ABC — restate locally instead
    # of importing the package (which would pull in the HTTP clients).
    from abc import ABC, abstractmethod

    class OverturoDecisionAdapter(ABC):  # type: ignore[no-redef]
        @abstractmethod
        def evaluate(self, request: dict[str, Any]) -> OverturoDecision: ...


# ── In-memory policy evaluator ─────────────────────────────────────


@dataclass(frozen=True)
class _PolicyRule:
    name: str
    effect: str  # "permit" | "forbid"
    principal: dict[str, Any] | None
    action: str | None
    resource: dict[str, Any] | None
    context: dict[str, Any] | None


@dataclass(frozen=True)
class PolicyEvaluation:
    effect: str  # "permit" | "forbid"
    matched_rule: str | None


class InMemoryCedarEvaluator:
    """Loads a JSON policy fixture and evaluates Cedar-style rules.

    Mirrors Cedar's semantics in the small: rules are checked in order,
    first match wins. Rules without explicit matchers (None) act as
    wildcards. Customers replace this class with a real Cedar engine
    invocation.
    """

    def __init__(self, rules: list[_PolicyRule]) -> None:
        self._rules = rules

    @classmethod
    def from_file(cls, path: str | Path) -> "InMemoryCedarEvaluator":
        data = json.loads(Path(path).read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InMemoryCedarEvaluator":
        rules = [
            _PolicyRule(
                name=r["name"],
                effect=r["effect"],
                principal=r.get("principal"),
                action=r.get("action"),
                resource=r.get("resource"),
                context=r.get("context"),
            )
            for r in data.get("rules", [])
        ]
        return cls(rules)

    def evaluate(
        self,
        *,
        principal: dict[str, Any],
        action: str,
        resource: dict[str, Any],
        context: dict[str, Any],
    ) -> PolicyEvaluation:
        for rule in self._rules:
            if not self._matches_principal(rule, principal):
                continue
            if rule.action is not None and rule.action != action:
                continue
            if not self._matches_resource(rule, resource):
                continue
            if not self._matches_context(rule, context):
                continue
            return PolicyEvaluation(effect=rule.effect, matched_rule=rule.name)
        return PolicyEvaluation(effect="forbid", matched_rule=None)

    @staticmethod
    def _matches_principal(rule: _PolicyRule, principal: dict[str, Any]) -> bool:
        if rule.principal is None:
            return True
        expected_type = rule.principal.get("type")
        if expected_type and expected_type != principal.get("type"):
            return False
        return True

    @staticmethod
    def _matches_resource(rule: _PolicyRule, resource: dict[str, Any]) -> bool:
        if rule.resource is None:
            return True
        scope_in = rule.resource.get("scope_in")
        if scope_in is not None:
            requested_scope = resource.get("scope")
            if requested_scope not in scope_in:
                return False
        return True

    @staticmethod
    def _matches_context(rule: _PolicyRule, context: dict[str, Any]) -> bool:
        if rule.context is None:
            return True
        value_gt = rule.context.get("value_gt")
        if value_gt is not None:
            try:
                actual_value = float(context.get("value") or 0)
            except (TypeError, ValueError):
                return False
            if actual_value <= value_gt:
                return False
        return True


# ── Adapter ────────────────────────────────────────────────────────


class CedarAdapter(OverturoDecisionAdapter):
    """Bridges an OAP authorize request to the in-memory Cedar evaluator.

    Returns an :class:`OverturoDecision` matching the wire shape the
    server expects from a `conductor.policy_gate` external endpoint.

    Not a `@dataclass` — the request_id counter is a plain int we mutate
    in place. (A frozen dataclass + ABC subclass combo also produces
    awkward semantics around abstract-method enforcement; plain class
    is clearer.)
    """

    def __init__(
        self,
        *,
        evaluator: InMemoryCedarEvaluator,
        request_id_prefix: str = "cedar",
    ) -> None:
        self.evaluator = evaluator
        self.request_id_prefix = request_id_prefix
        self._counter = 0

    def evaluate(self, request: dict[str, Any]) -> OverturoDecision:
        # Map OAP request → Cedar-shaped (principal, action, resource, context).
        principal = {"type": "User", "id": request.get("counterparty") or "anonymous"}
        action = str(request.get("action", "")).lower()
        resource = {"scope": str(request.get("scope", ""))}
        context = {
            "value": request.get("value"),
            "currency": request.get("currency"),
            "nonce": request.get("nonce"),
        }

        result = self.evaluator.evaluate(
            principal=principal, action=action, resource=resource, context=context,
        )

        self._counter += 1
        request_id = f"{self.request_id_prefix}_{self._counter:08d}"

        if result.effect == "permit":
            return OverturoDecision(
                decision="allow",
                mode="conductor",
                request_id=request_id,
                overturo_decision_schema_version="1.0.0",
                decision_latency_ms=0.5,
            )
        return OverturoDecision(
            decision="deny",
            mode="conductor",
            request_id=request_id,
            overturo_decision_schema_version="1.0.0",
            reason_code="action_not_allowed" if action != "read" else "scope_not_covered",
            denial_category="intent_denied",
            cascade_step=7,
            failed_bound="action_bounds" if action != "read" else "scope_bounds",
        )
