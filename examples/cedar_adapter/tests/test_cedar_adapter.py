"""Smoke tests for the Cedar adapter example.

Standalone-runnable (no pytest dep). Exits non-zero on failure so it can
be wired into CI shell pipelines.

    python tests/test_cedar_adapter.py

Reference implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Resolve paths regardless of CWD.
HERE = Path(__file__).parent
EXAMPLE_DIR = HERE.parent

# Make both the SDK src and the example dir importable.
sys.path.insert(0, str(EXAMPLE_DIR.parent.parent / "src"))
sys.path.insert(0, str(EXAMPLE_DIR))

from cedar_adapter import CedarAdapter, InMemoryCedarEvaluator  # noqa: E402


def _adapter() -> CedarAdapter:
    evaluator = InMemoryCedarEvaluator.from_file(EXAMPLE_DIR / "policy.json")
    return CedarAdapter(evaluator=evaluator)


def test_read_profile_allowed() -> None:
    adapter = _adapter()
    d = adapter.evaluate({"nonce": "n1", "action": "read", "scope": "profile"})
    assert d.decision == "allow", d
    assert d.mode == "conductor"
    assert d.overturo_decision_schema_version == "1.0.0"
    assert d.request_id.startswith("cedar_")


def test_write_default_allowed() -> None:
    adapter = _adapter()
    d = adapter.evaluate({"nonce": "n2", "action": "write", "scope": "data:write"})
    assert d.decision == "allow", d


def test_high_value_write_forbidden() -> None:
    adapter = _adapter()
    d = adapter.evaluate(
        {"nonce": "n3", "action": "write", "scope": "data:write", "value": "1500"}
    )
    assert d.decision == "deny", d
    assert d.reason_code == "action_not_allowed"
    assert d.cascade_step == 7


def test_unknown_scope_read_forbidden() -> None:
    adapter = _adapter()
    # `read` requires scope ∈ {openid, profile, email}; "secrets" falls
    # through every rule → default forbid.
    d = adapter.evaluate({"nonce": "n4", "action": "read", "scope": "secrets"})
    assert d.decision == "deny", d
    assert d.reason_code == "scope_not_covered"


def test_request_id_counter_increments() -> None:
    adapter = _adapter()
    a = adapter.evaluate({"nonce": "n5", "action": "read", "scope": "profile"})
    b = adapter.evaluate({"nonce": "n6", "action": "read", "scope": "profile"})
    assert a.request_id != b.request_id, (a.request_id, b.request_id)


def test_write_at_boundary_value_allowed() -> None:
    """Parity with OPA example: value_gt=1000, so value=1000 (NOT >)
    must fall through the high_value rule and match write_default_allowed.
    Boundary regression gate matching `__tests__/opa_adapter_example.test.ts`."""
    adapter = _adapter()
    d = adapter.evaluate(
        {"nonce": "n7", "action": "write", "scope": "data:write", "value": "1000"}
    )
    assert d.decision == "allow", d


def main() -> int:
    tests = [
        test_read_profile_allowed,
        test_write_default_allowed,
        test_high_value_write_forbidden,
        test_unknown_scope_read_forbidden,
        test_request_id_counter_increments,
        test_write_at_boundary_value_allowed,
    ]
    failures: list[tuple[str, str]] = []
    for t in tests:
        try:
            t()
            print(f"  OK  {t.__name__}")
        except AssertionError as e:
            failures.append((t.__name__, str(e)))
            print(f"  FAIL  {t.__name__}: {e}")
    if failures:
        print(f"\n{len(failures)} of {len(tests)} smoke tests failed")
        return 1
    print(f"\n{len(tests)} smoke tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
