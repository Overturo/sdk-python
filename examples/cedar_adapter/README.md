# Cedar adapter — reference implementation

A reference `OverturoDecisionAdapter` implementation that bridges a
Cedar-style policy evaluator to the
policy-gate
external-endpoint contract.

**See [`EXAMPLE_DISCLAIMER.md`](./EXAMPLE_DISCLAIMER.md) first** — this
is not a supported integration.

## Files

| File | Purpose |
|---|---|
| `cedar_adapter.py` | `CedarAdapter` + `InMemoryCedarEvaluator` |
| `policy.json` | Example policy fixture (Cedar-style rules in JSON) |
| `app.py` | Stdlib HTTP server exposing `/evaluate` |
| `tests/test_cedar_adapter.py` | Smoke tests against the fixture policy |

## Quick start

```bash
cd lib/sdk/overturo-py
PYTHONPATH=src:examples/cedar_adapter python examples/cedar_adapter/app.py
```

Server listens on `http://127.0.0.1:8088/evaluate`. Send a POST with the
OAP authorize request body shape:

```bash
curl -s -X POST http://127.0.0.1:8088/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"nonce":"n1","action":"read","scope":"profile"}'
```

Response is an `OverturoDecision` JSON object (allow / deny shape per
the v1.0.0 schema).

## Wiring into an application

```ruby
# In your composition_manifest:
"blocks" => {
  "policy_gate" => {
    "slug" => "conductor.policy_gate",
    "surface" => "infrastructure",
    "version" => "1.0.0",
    "config" => {
      "fail_open" => false,
      "evaluator_class" => "MyCorp::CedarPolicyAdapter",
      "external_endpoint_url" => "http://localhost:8088/evaluate"
    }
  }
}
```

(The `MyCorp::CedarPolicyAdapter` Ruby class wraps the HTTP client that
calls this endpoint and conforms to the
`BuildingBlocks::Conductor::PolicyGateContract`. Out of scope for this
example.)

## Cedar swap

The in-memory `InMemoryCedarEvaluator` mirrors Cedar's
`(principal, action, resource, context)` shape but is **not** a Cedar
parser. To use the real engine:

```python
import cedar_policy  # pip install cedar-policy

class CedarBackedEvaluator:
    def __init__(self, policies_text: str, entities_text: str = "[]"):
        self._policies = cedar_policy.PolicySet.from_str(policies_text)
        self._entities = cedar_policy.Entities.from_str(entities_text)

    def evaluate(self, *, principal, action, resource, context):
        req = cedar_policy.Request(
            principal=f'User::"{principal["id"]}"',
            action=f'Action::"{action}"',
            resource=f'Resource::"{resource["scope"]}"',
            context=context,
        )
        decision = cedar_policy.Authorizer().is_authorized(
            req, self._policies, self._entities
        )
        return PolicyEvaluation(
            effect="permit" if decision.allowed else "forbid",
            matched_rule=next(iter(decision.diagnostics.reason), None),
        )
```

Then replace `InMemoryCedarEvaluator` with `CedarBackedEvaluator` in
`app.py`. The `CedarAdapter` class itself does not change — it only
depends on the `PolicyEvaluation` protocol.

## Tests

```bash
cd lib/sdk/overturo-py
PYTHONPATH=src:examples/cedar_adapter python examples/cedar_adapter/tests/test_cedar_adapter.py
```
