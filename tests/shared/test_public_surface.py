"""every symbol in `overturo.__init__.py` must be
importable and non-None.

"""

from __future__ import annotations

import overturo

_EXPECTED_TOP_LEVEL_SYMBOLS = (
    # Versions
    "__version__",
    # Subpackage namespaces
    "decisions",
    # Authorize
    "OverturoAuthorize",
    "OverturoDecisionAdapter",
    "OverturoChronicleStream",
    "DpopKeyPair",
    "access_token_hash",
    "jwk_thumbprint",
    "sign_dpop_proof",
    "peek_receipt",
    # Oversight
    "OverturoOversight",
    "Decision",
    "IssRole",
    "LegalBasis",
    "LogLevel",
    "OversightConfig",
    "RevocationReason",
    "RevocationScope",
    "TrustWeight",
    "ISS_ROLES",
    "ISS_ROLE_TO_TRUST_WEIGHT",
    "evidence_digest",
    # Models
    "OverturoDecision",
    "OverturoEscalation",
    "OverturoReceipt",
    "OverturoBlockInvocation",
    "OverturoDecisionMalformed",
    "parse_decision",
    "TokenInfo",
    "JwksKey",
    "PeekedReceipt",
    "Escalation",
    "DecisionToken",
    "DecisionStatus",
    "AttestResult",
    "EscalateResult",
    "RevokeResult",
    "VerifiedReceipt",
    # Errors
    "OverturoError",
    "OverturoConfigError",
    "OverturoNetworkError",
    "OverturoTimeoutError",
    "OverturoApiError",
    "OverturoUnauthorized",
    "OverturoRateLimited",
    "OverturoServerError",
    "OverturoValidationError",
    "ReceiptInvalid",
    "OapError",
    "OapAuthorizationDenied",
    "OapIntentDenied",
    "OapTrajectoryDenied",
    "OapSequenceDenied",
    "OapEscalationDenied",
    "OapDispatchError",
    "OapWrongRegion",
    "OapApprovalRequired",
    "is_oap_error",
    # Verify
    "verify_receipt",
    "verify_receipt_offline",
    "JwksCache",
)


def test_every_top_level_symbol_importable():
    for name in _EXPECTED_TOP_LEVEL_SYMBOLS:
        assert hasattr(overturo, name), f"missing top-level: {name}"
        assert getattr(overturo, name) is not None, f"None at top-level: {name}"


def test_namespaced_imports():
    """Namespaced imports work alongside flat imports."""
    from overturo.authorize import OverturoAuthorize
    from overturo.decisions import poll_status, subscribe, url_for
    from overturo.oversight import OverturoOversight

    assert OverturoAuthorize is not None
    assert OverturoOversight is not None
    assert url_for is not None
    assert poll_status is not None
    assert subscribe is not None


def test_version_string():
    # Parity with pyproject.toml, not a pinned
    # literal: the version is declared twice (pyproject + __init__), and
    # a literal here made a bump a three-file edit with no cross-check.
    import re
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    declared = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.MULTILINE)
    assert declared is not None, "no version in pyproject.toml"
    assert overturo.__version__ == declared.group(1)


def test_legacy_module_paths_removed():
    """Old `overturo_authorize` / `overturo_oversight` namespaces are gone."""
    import importlib

    for legacy in ("overturo_authorize", "overturo_oversight"):
        try:
            importlib.import_module(legacy)
        except ModuleNotFoundError:
            continue
        raise AssertionError(f"legacy module still importable: {legacy}")
