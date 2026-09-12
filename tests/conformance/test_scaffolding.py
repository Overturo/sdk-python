"""
Conformance harness scaffolding spec.

Confirms that the harness wires up correctly without requiring a
live Overturo server. A later release will replace this with the
full contract suite.
"""
import re

import pytest

from overturo import (
    OverturoOversight,
    ReceiptInvalid,
    evidence_digest,
    verify_receipt,
)

from .conftest import is_offline


def test_imports_resolve():
    """SDK + verify modules import together cleanly."""
    assert OverturoOversight is not None
    assert callable(verify_receipt)
    assert callable(evidence_digest)
    assert ReceiptInvalid is not None


def test_evidence_digest_shape():
    """`evidence_digest` returns 64 hex chars matching the server's regex."""
    digest = evidence_digest({"a": 1}, {"b": 2})
    assert re.fullmatch(r"[a-f0-9]{64}", digest)


@pytest.mark.skipif(is_offline(), reason="requires OVERTURO_BASE_URL")
def test_ov10_contract_suite_placeholder(env):
    """Placeholder slot for the contract suite."""
    # The contract suite will fill in:
    #   - attestation lifecycle
    #   - idempotency
    #   - sequence-gap detection
    #   - escalation flow
    #   - revocation propagation
    #   - receipt verification
    #   - token rotation
    assert env.base_url.startswith("http")
