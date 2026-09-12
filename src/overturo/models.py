"""Cross-cutting dataclasses for the overturo SDK.

Lives at the top level so `overturo.authorize` and `overturo.oversight`
can import from a single source. Replaces the vendored `_shared.py`
and absorbs the dataclasses from authorize's `decision.py` + the
cross-cutting result types from oversight's `types.py`.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

__all__ = [
    # needs-approval shared shapes
    "DecisionKind",
    "DecisionMode",
    "DecisionStatusLiteral",
    "Escalation",
    "DecisionToken",
    "DecisionStatus",
    # 189 pre-flight disclosure discovery (TypedDicts)
    "FlowDisclosures",
    "FlowDisclosureFlow",
    "FlowDisclosureApplication",
    "FlowDisclosurePurpose",
    "FlowDisclosureFieldEntry",
    "FlowDisclosureStep",
    "FlowDisclosurePresentation",
    "FlowDisclosureExpiry",
    "FlowDisclosureLocale",
    "FlowDisclosureMechanism",
    "FlowDisclosureLegalBasis",
    "FlowDisclosureButtonMode",
    # Authorize decision envelope
    "OverturoBlockInvocation",
    "OverturoEscalation",
    "OverturoReceipt",
    "OverturoDecision",
    "OverturoDecisionMalformed",
    "parse_decision",
    # Authorize client ancillary
    "TokenInfo",
    "JwksKey",
    "PeekedReceipt",
    "OfflineVerifyResult",
    # Oversight cross-cutting result types
    "AttestResult",
    "EscalateResult",
    "RevokeResult",
    "VerifiedReceipt",
]


# ══════════════════════════════════════════════════════════════════════
# Section 1 — needs-approval shared dataclasses
# (formerly vendored as _shared.py in both packages)
# ══════════════════════════════════════════════════════════════════════

DecisionKind = Literal["consent", "approval"]
DecisionMode = Literal["embed", "popup", "redirect"]
DecisionStatusLiteral = Literal[
    "pending",
    "in_progress",
    "approved",
    "denied",
    "countered",
    "expired",
    "cancelled",
]


@dataclass(frozen=True)
class Escalation:
    """Extended escalation shape used by the needs-approval path.

        Mirrors ``OverturoEscalation`` in authorize's ``decision.py`` but
        adds the optional ``decision_url`` + ``session_token`` that the
        server populates when escalating an in-flight authorize() call
    .
    """

    escalation_id: str
    required_signers: tuple[str, ...]
    approval_ttl_at: str
    decision_url: str | None = None
    session_token: str | None = None

    @classmethod
    def from_envelope(cls, raw: dict[str, Any]) -> Escalation:
        return cls(
            escalation_id=str(raw["escalation_id"]),
            required_signers=tuple(raw.get("required_signers", ())),
            approval_ttl_at=str(raw["approval_ttl_at"]),
            decision_url=raw.get("decision_url"),
            session_token=raw.get("session_token"),
        )

    def __repr__(self) -> str:
        token_repr = "<redacted>" if self.session_token else "None"
        url_repr = "<redacted>" if self.decision_url else "None"
        return (
            f"Escalation(escalation_id={self.escalation_id!r}, "
            f"required_signers={self.required_signers!r}, "
            f"approval_ttl_at={self.approval_ttl_at!r}, "
            f"decision_url={url_repr}, "
            f"session_token={token_repr})"
        )


@dataclass(frozen=True)
class DecisionToken:
    """Server-minted session token for a decision flow.

    Returned by ``POST /api/v1/decisions``; consumed by oversight's
    ``decisions.token_for()`` helper. Both ``decision_url`` and
    ``embed_url`` carry the ``session_token`` in their query strings
    — they are bearer credentials and must not be logged.
    """

    session_token: str
    decision_url: str
    embed_url: str
    kind: DecisionKind
    mode: DecisionMode
    expires_at: str

    @classmethod
    def from_response(cls, raw: dict[str, Any]) -> DecisionToken:
        # The API wraps the token under ``decision`` and names the validity
        # bound ``deadline_at``; both shapes are accepted.
        data = raw["decision"] if isinstance(raw.get("decision"), dict) else raw
        return cls(
            session_token=str(data["session_token"]),
            decision_url=str(data["decision_url"]),
            embed_url=str(data["embed_url"]),
            kind=data["kind"],
            mode=data["mode"],
            expires_at=str(data.get("expires_at") or data.get("deadline_at") or ""),
        )

    def __repr__(self) -> str:
        return (
            f"DecisionToken(session_token=<redacted>, "
            f"decision_url=<redacted>, embed_url=<redacted>, "
            f"kind={self.kind!r}, mode={self.mode!r}, "
            f"expires_at={self.expires_at!r})"
        )


@dataclass(frozen=True)
class DecisionStatus:
    """Result of ``GET /api/v1/decisions/:session_token`` (one-shot)
    or ``GET /api/v1/decisions/by-escalation/:id/wait`` (long-poll).
    """

    session_token: str | None
    status: DecisionStatusLiteral
    decision: dict[str, Any] | None
    wait_again: bool
    retry_after: int | None = None

    @classmethod
    def from_response(cls, raw: dict[str, Any]) -> DecisionStatus:
        # ``GET /decisions/:token`` wraps the status under ``decision``; the
        # long-poll envelope is flat and omits ``session_token`` while pending.
        data = (
            raw["decision"]
            if "status" not in raw and isinstance(raw.get("decision"), dict)
            else raw
        )
        return cls(
            session_token=(str(data["session_token"]) if data.get("session_token") else None),
            status=data["status"],
            decision=data.get("decision") if isinstance(data.get("decision"), dict) else None,
            wait_again=bool(data.get("wait_again", False)),
            retry_after=data.get("retry_after"),
        )

    def is_terminal(self) -> bool:
        return self.status in (
            "approved",
            "denied",
            "countered",
            "expired",
            "cancelled",
        )

    def __repr__(self) -> str:
        return (
            f"DecisionStatus(session_token=<redacted>, "
            f"status={self.status!r}, wait_again={self.wait_again}, "
            f"retry_after={self.retry_after})"
        )


# ══════════════════════════════════════════════════════════════════════
# Section 1b — 189 pre-flight disclosure discovery
# ══════════════════════════════════════════════════════════════════════
#
# TypedDicts, not dataclasses: discover() returns the parsed JSON dict
# verbatim (this server client does not transform keys), and a passthrough
# JSON object IS a TypedDict at type-check time. Mirrors
# config/schemas/decisions/discovery/v1/disclosure_inventory.json exactly.

FlowDisclosureMechanism = Literal["explicit", "informed", "opt_out", "documented", "delegated"]
FlowDisclosureLegalBasis = Literal[
    "consent",
    "contract",
    "legitimate_interest",
    "legal_obligation",
    "vital_interest",
    "public_task",
]
FlowDisclosureButtonMode = Literal[
    "accept", "acknowledge", "authorize", "connect", "continue", "share", "sign_in", "verify"
]


class FlowDisclosureFlow(TypedDict):
    id: str
    name: str
    version: int
    kind: Literal["consent"]


class FlowDisclosureApplication(TypedDict):
    name: str
    primary_color: str | None
    logo_url: str | None


class FlowDisclosurePurpose(TypedDict):
    name: str
    label: str
    description: str | None
    mechanism: FlowDisclosureMechanism
    legal_basis: FlowDisclosureLegalBasis
    required: bool
    data_labels: list[str]


class FlowDisclosureFieldEntry(TypedDict):
    name: str
    label: str
    field_type: str
    required: bool
    section: Literal["input", "obligation", "proof"]
    completed_by: Literal["principal", "application", "both"]


class FlowDisclosureStep(TypedDict):
    key: str
    title: str


class FlowDisclosurePresentation(TypedDict):
    button_mode: FlowDisclosureButtonMode
    display_label: str


class FlowDisclosureExpiry(TypedDict):
    consent_duration_days: int | None


class FlowDisclosureLocale(TypedDict):
    requested: Literal["params", "header", "default"]
    resolved: str
    fallback: Literal["en"]


class FlowDisclosures(TypedDict):
    schema: str
    flow: FlowDisclosureFlow
    application: FlowDisclosureApplication
    purposes: list[FlowDisclosurePurpose]
    fields: list[FlowDisclosureFieldEntry]
    steps: list[FlowDisclosureStep]
    presentation: FlowDisclosurePresentation
    outcomes: list[Literal["granted", "denied"]]
    expiry: FlowDisclosureExpiry
    locale: FlowDisclosureLocale
    revision: str


# ══════════════════════════════════════════════════════════════════════
# Section 2 — Authorize decision envelope
# (was authorize-py/decision.py)
# ══════════════════════════════════════════════════════════════════════

_ALLOWED_DECISION = frozenset({"allow", "deny", "escalate"})
_ALLOWED_MODE = frozenset({"conductor", "oversight", "hybrid"})
_ALLOWED_BLOCK_DECISION = frozenset({"pass", "deny", "escalate", "dispatch_error"})


class OverturoDecisionMalformed(ValueError):
    """Raised when a server response does not conform to the
    OverturoDecision v1.0.0 schema. SDK-side guard against server
    drift."""


@dataclass(frozen=True)
class OverturoBlockInvocation:
    position: int
    block_slug: str
    decision: Literal["pass", "deny", "escalate", "dispatch_error"]
    latency_ms: float
    evaluator_class: str
    policy_engine: str | None = None
    cache_outcome: Literal["hit"] | None = None
    reason_code: str | None = None
    failed_bound: str | None = None


@dataclass(frozen=True)
class OverturoEscalation:
    escalation_id: str
    required_signers: tuple[str, ...]
    approval_ttl_at: str
    # server-minted; None on pre-1.2.0 servers.
    decision_url: str | None = None
    session_token: str | None = None

    def __repr__(self) -> str:
        token_repr = "<redacted>" if self.session_token else "None"
        url_repr = "<redacted>" if self.decision_url else "None"
        return (
            f"OverturoEscalation(escalation_id={self.escalation_id!r}, "
            f"required_signers={self.required_signers!r}, "
            f"approval_ttl_at={self.approval_ttl_at!r}, "
            f"decision_url={url_repr}, session_token={token_repr})"
        )


@dataclass(frozen=True)
class OverturoReceipt:
    jwt: str
    jti: str
    iat: int
    exp: int


@dataclass(frozen=True)
class OverturoDecision:
    decision: Literal["allow", "deny", "escalate"]
    mode: Literal["conductor", "oversight", "hybrid"]
    request_id: str
    overturo_decision_schema_version: str
    reason_code: str | None = None
    denial_category: str | None = None
    cascade_step: int | None = None
    failed_bound: str | None = None
    block_invocations: tuple[OverturoBlockInvocation, ...] = field(default_factory=tuple)
    escalation: OverturoEscalation | None = None
    receipt: OverturoReceipt | None = None
    decision_latency_ms: float | None = None
    chronicle_id: str | None = None


def _require(d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise OverturoDecisionMalformed(f"missing required field: {key!r}")
    return d[key]


def _parse_block_invocation(raw: dict[str, Any]) -> OverturoBlockInvocation:
    decision = raw.get("decision")
    if decision not in _ALLOWED_BLOCK_DECISION:
        raise OverturoDecisionMalformed(f"unknown block_invocation.decision: {decision!r}")
    return OverturoBlockInvocation(
        position=int(_require(raw, "position")),
        block_slug=str(_require(raw, "block_slug")),
        decision=decision,
        latency_ms=float(_require(raw, "latency_ms")),
        evaluator_class=str(_require(raw, "evaluator_class")),
        policy_engine=raw.get("policy_engine"),
        cache_outcome=raw.get("cache_outcome"),
        reason_code=raw.get("reason_code"),
        failed_bound=raw.get("failed_bound"),
    )


def _parse_escalation(raw: dict[str, Any]) -> OverturoEscalation:
    return OverturoEscalation(
        escalation_id=str(_require(raw, "escalation_id")),
        required_signers=tuple(raw.get("required_signers", ())),
        approval_ttl_at=str(_require(raw, "approval_ttl_at")),
        decision_url=raw.get("decision_url"),
        session_token=raw.get("session_token"),
    )


def _parse_receipt(payload: dict[str, Any]) -> OverturoReceipt | None:
    # Server returns receipt JWT as a String at the top level; SDK
    # wraps into an object alongside receipt_jti/iat/exp. We also accept
    # a pre-wrapped object form (used by the cross-SDK conformance
    # corpus where every fixture is canonical).
    raw = payload.get("receipt")
    if raw is None:
        return None
    if isinstance(raw, dict):
        return OverturoReceipt(
            jwt=str(_require(raw, "jwt")),
            jti=str(_require(raw, "jti")),
            iat=int(_require(raw, "iat")),
            exp=int(_require(raw, "exp")),
        )
    if isinstance(raw, str):
        return OverturoReceipt(
            jwt=raw,
            jti=str(payload.get("receipt_jti", "")),
            iat=int(payload.get("iat", 0)),
            exp=int(payload.get("exp", 0)),
        )
    raise OverturoDecisionMalformed(f"receipt must be object or string; got {type(raw).__name__}")


def parse_decision(payload: dict[str, Any]) -> OverturoDecision:
    """Parse a wire response body into :class:`OverturoDecision`.

    Raises :class:`OverturoDecisionMalformed` on any schema violation.
    Tolerates extra top-level fields (the wire response carries
    ``iss``, ``oap_ver``, etc. alongside the OverturoDecision shape).
    """
    decision = _require(payload, "decision")
    if decision not in _ALLOWED_DECISION:
        raise OverturoDecisionMalformed(f"unknown decision: {decision!r}")

    mode = payload.get("mode", "conductor")
    if mode not in _ALLOWED_MODE:
        raise OverturoDecisionMalformed(f"unknown mode: {mode!r}")

    version = payload.get("overturo_decision_schema_version", "1.0.0")
    if not isinstance(version, str) or not version.startswith("1."):
        raise OverturoDecisionMalformed(f"schema version not 1.x compatible: {version!r}")

    raw_invocations = payload.get("block_invocations") or ()
    if not isinstance(raw_invocations, (list, tuple)):
        raise OverturoDecisionMalformed(
            f"block_invocations must be a list; got {type(raw_invocations).__name__}"
        )
    invocations = tuple(_parse_block_invocation(r) for r in raw_invocations)

    raw_escalation = payload.get("escalation")
    escalation = _parse_escalation(raw_escalation) if isinstance(raw_escalation, dict) else None

    return OverturoDecision(
        decision=decision,
        mode=mode,
        request_id=str(payload.get("request_id", "")),
        overturo_decision_schema_version=version,
        reason_code=payload.get("reason_code"),
        denial_category=payload.get("denial_category"),
        cascade_step=payload.get("cascade_step"),
        failed_bound=payload.get("failed_bound"),
        block_invocations=invocations,
        escalation=escalation,
        receipt=_parse_receipt(payload),
        decision_latency_ms=payload.get("decision_latency_ms"),
        chronicle_id=payload.get("chronicle_id"),
    )


# ══════════════════════════════════════════════════════════════════════
# Section 3 — Authorize client ancillary types
# (TokenInfo from authorize-py/client.py; JwksKey + OfflineVerifyResult
# from authorize-py/verify.py; PeekedReceipt from authorize-py/receipt.py)
# ══════════════════════════════════════════════════════════════════════


@dataclass
class TokenInfo:
    agent_token: str
    agent_token_expires_at: str
    iss: str
    oap_ver: str


@dataclass
class JwksKey:
    """Minimal JWK shape for an Ed25519 public key."""

    kid: str
    x: str  # base64url-encoded 32-byte raw public key
    kty: str = "OKP"
    crv: str = "Ed25519"


@dataclass
class OfflineVerifyResult:
    valid: bool
    claims: dict[str, Any] | None = None
    reason_code: str | None = None


@dataclass
class PeekedReceipt:
    """Result of a structural decode. Mirrors the JS SDK's peekReceipt
    return shape so cross-language users see the same vocabulary."""

    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes


# ══════════════════════════════════════════════════════════════════════
# Section 4 — Oversight cross-cutting result types
# (was oversight-py/types.py; the closed-enum literals — Decision,
# LegalBasis, IssRole, TrustWeight, RevocationScope, RevocationReason,
# LogLevel, OversightConfig — stay in overturo/oversight/types.py.)
# ══════════════════════════════════════════════════════════════════════

# Local aliases needed for the result-type fields below. The Literal
# vocabularies themselves live in overturo/oversight/types.py; we re-
# declare them here as type aliases to keep this file independent of
# the subpackage import order.
_Decision = Literal["allow", "deny", "escalate"]
_IssRole = Literal["authorizer", "witness", "approval_url_signer"]
_TrustWeight = Literal["strong", "witness_only", "approval_url"]
_RevocationScope = Literal["attestation", "agent_class", "touchpoint"]


@dataclass
class AttestResult:
    attestation_id: str
    received_at: str
    sequence_number: int
    decision: _Decision
    receipt: str | None
    idempotent_replay: bool


@dataclass
class EscalateResult:
    escalation_id: str
    attestation_id: str
    approval_url: str
    context_class: str
    status: str
    idempotent_replay: bool


@dataclass
class RevokeResult:
    revocation_id: str
    scope: _RevocationScope
    affected_attestation_count: int
    triggered_at: str
    estimated_propagation_complete_at: str
    idempotent_replay: bool


@dataclass
class VerifiedReceipt:
    iss: str
    iat: int
    iss_role: _IssRole
    trust_weight: _TrustWeight
    # Optional standard claims
    exp: int | None = None
    jti: str | None = None
    sub: str | None = None
    aud: str | None = None
    # Overturo-specific claims (forward-compat preserves arbitrary extras)
    extra: dict[str, Any] = field(default_factory=dict)
