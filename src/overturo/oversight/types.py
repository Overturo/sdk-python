"""
public types.

Closed-enum vocabularies mirror server-side constants:
  - Decision           ← Oap::Attestation::DECISIONS
  - LegalBasis         ← Oap::Attestation::LEGAL_BASES
  - RevocationScope    ← Oap::Revocation::SCOPES
  - RevocationReason   ← Oap::Revocation::REASONS
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

Decision = Literal["allow", "deny", "escalate"]

LegalBasis = Literal[
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
]

RevocationScope = Literal["attestation", "agent_class", "touchpoint"]

RevocationReason = Literal[
    "compliance_failure",
    "security_incident",
    "data_subject_request",
    "policy_change",
    "other",
]

IssRole = Literal["authorizer", "witness", "approval_url_signer"]

TrustWeight = Literal["strong", "witness_only", "approval_url"]

LogLevel = Literal["silent", "warn", "info", "debug"]


# Constructor / `create()` configuration is passed as kwargs; this
# dataclass mainly exists for `repr` + test fixtures.
@dataclass
class OversightConfig:
    base_url: str
    token: str
    touchpoint_id: str
    token_provider: Callable[[], str | Awaitable[str]] | None = None
    heartbeat_enabled: bool = True
    heartbeat_cadence_seconds: int = 60
    start_sequence: int = 1
    on_sequence_update: Callable[[int], None | Awaitable[None]] | None = None
    max_retries: int = 3
    timeout_seconds: float = 30.0
    log_level: LogLevel = "warn"


# AttestResult, EscalateResult, RevokeResult, VerifiedReceipt
# moved to overturo.models (cross-cutting result types). Re-exported here
# for back-compat with `from overturo.oversight.types import …`.
from ..models import (  # noqa: E402, F401
    AttestResult,
    EscalateResult,
    RevokeResult,
    VerifiedReceipt,
)


@dataclass
class ResolvedEndpoints:
    attestation: str
    heartbeat: str
    escalation: str
    revocation: str
