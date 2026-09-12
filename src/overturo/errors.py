"""Unified error tree for the overturo SDK.

Single root `OverturoError` with two sub-trees:

- Transport family: `OverturoConfigError`, `OverturoNetworkError`,
  `OverturoApiError`, etc.
  (was `overturo-oversight-py/errors.py`)

- OAP protocol family: `OapError` + 8 typed subclasses
  (was `overturo-authorize-py/errors.py`)

The `_REASON_CODE_TO_CLASS` dispatch table is the closed-enum source of
truth that the conformance suite hashes.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    # Root
    "OverturoError",
    # Transport family
    "OverturoConfigError",
    "OverturoNetworkError",
    "OverturoTimeoutError",
    "OverturoApiError",
    "OverturoUnauthorized",
    "OverturoRateLimited",
    "OverturoServerError",
    "OverturoValidationError",
    "ReceiptInvalid",
    "RecordInvalid",
    # OAP protocol family
    "OapError",
    "OapAuthorizationDenied",
    "OapIntentDenied",
    "OapTrajectoryDenied",
    "OapSequenceDenied",
    "OapEscalationDenied",
    "OapDispatchError",
    "OapWrongRegion",
    "OapApprovalRequired",
    "OapDenialCategory",
    # Helpers
    "is_oap_error",
]


# ══════════════════════════════════════════════════════════════════════
# ROOT
# ══════════════════════════════════════════════════════════════════════


@dataclass
class OverturoError(Exception):
    """Single root for every SDK-raised error.

    Carries the 5 transport-common fields. Subclasses extend with
    family-specific fields (OapError adds 6; OverturoRateLimited adds
    retry_after_seconds; ReceiptInvalid adds code).
    """

    message: str = ""
    http_status: int | None = None
    reason_code: str | None = None
    detail: Any = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"http_status={self.http_status}, "
            f"reason_code={self.reason_code!r})"
        )


# ══════════════════════════════════════════════════════════════════════
# Transport family
# (was overturo-oversight-py/errors.py — preserved sub-tree)
# ══════════════════════════════════════════════════════════════════════


@dataclass
class OverturoConfigError(OverturoError):
    """Constructor / config validation failure."""


@dataclass
class OverturoNetworkError(OverturoError):
    """TCP / TLS / DNS failure."""


@dataclass
class OverturoTimeoutError(OverturoNetworkError):
    """Request exceeded the configured timeout."""


@dataclass
class OverturoApiError(OverturoError):
    """Any non-2xx the SDK doesn't have a dedicated subclass for."""


@dataclass
class OverturoUnauthorized(OverturoApiError):
    """token rotation retry exhausted."""


@dataclass
class OverturoRateLimited(OverturoApiError):
    """max retries exhausted."""

    retry_after_seconds: int | None = None


@dataclass
class OverturoServerError(OverturoApiError):
    """5xx — max retries exhausted."""


@dataclass
class OverturoValidationError(OverturoError):
    """4xx other than 401/429."""


class ReceiptInvalid(OverturoError):
    """`verify_receipt` rejection. `code` discriminator.

    Constructor signature kept as ``(code, message)`` for back-compat
    with the oversight v0.2 API. Not a dataclass — the positional
    ordering (code first) differs from OverturoError's (message first),
    so an explicit __init__ is the cleanest expression.
    """

    def __init__(
        self,
        code: str,
        message: str = "",
        *,
        http_status: int | None = None,
        reason_code: str | None = None,
        detail: Any = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            http_status=http_status,
            reason_code=reason_code,
            detail=detail,
            request_id=request_id,
        )
        self.code = code


class RecordInvalid(OverturoError):
    """`verify_record` rejection. `code` discriminator.

    One class per artifact: `ReceiptInvalid` is the runtime receipt (a
    JWT), `RecordInvalid` is the durable signed record export (a JSON
    envelope with a detached signature over canonical bytes). The code
    strings are the shared cross-language vocabulary — identical to the
    TS `RecordInvalidCode` union and the corpus manifest's `expect`
    values: malformed_envelope, unsupported_algorithm,
    unsupported_canonicalization, no_key_source, unknown_key_version,
    key_mismatch, key_discovery_failed, signature_failed,
    manifest_hash_mismatch, malformed_manifest.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message=message, reason_code=code)
        self.code = code


# ══════════════════════════════════════════════════════════════════════
# OAP protocol family
# (was overturo-authorize-py/errors.py — preserved sub-tree)
# ══════════════════════════════════════════════════════════════════════

OapDenialCategory = Literal[
    "authorization_denied",
    "intent_denied",
    "trajectory_denied",
]


@dataclass
class OapError(OverturoError):
    """OAP-protocol failure. Adds 6 protocol-specific fields on top
    of OverturoError.

    Carries the canonical envelope fields plus the HTTP status for
    transport-level pattern matching (429 retry vs 403 deny).
    The wire adds ``denial_category`` and ``cascade_step``; both
    are present on cascade-relevant denials and absent on validation
    / conflict / internal errors.
    """

    failed_bound: str | None = None
    denial_category: OapDenialCategory | None = None
    cascade_step: int | None = None
    negotiable: bool = False
    negotiate_url: str | None = None
    documentation_url: str | None = None

    def __str__(self) -> str:
        return f"{self.reason_code}: {self.message}"

    @classmethod
    def from_envelope(cls, envelope: dict[str, Any], status: int | None = None) -> OapError:
        """Build the most-specific subclass for the envelope.

        Reason-code dispatch takes precedence over the category
        dispatch so the most specific subclass wins. Sequence denials
        sequence denials are trajectory_denied but get their own
        subclass to enable ``except OapSequenceDenied`` catches.

        Non-cascade errors return a bare ``OapError``.
        """
        err = envelope.get("error", {}) or {}
        reason_code = err.get("reason_code", "internal_error")
        category = err.get("denial_category")
        target = _REASON_CODE_TO_CLASS.get(reason_code) or _CATEGORY_TO_CLASS.get(
            category, OapError
        )
        # let subclasses with nested envelope
        # shapes (e.g. OapApprovalRequired.escalation) take over.
        if target is not OapError and "from_envelope" in target.__dict__:
            return target.from_envelope(envelope, status)
        return target(
            reason_code=reason_code,
            message=err.get("message", "Unknown OAP error"),
            http_status=status,
            detail=err.get("detail"),
            failed_bound=err.get("failed_bound"),
            denial_category=category,
            cascade_step=err.get("cascade_step"),
            request_id=err.get("request_id"),
            negotiable=bool(err.get("negotiable", False)),
            negotiate_url=err.get("negotiate_url"),
            documentation_url=err.get("documentation_url"),
        )


@dataclass
class OapAuthorizationDenied(OapError):
    """denial_category == "authorization_denied"."""


@dataclass
class OapIntentDenied(OapError):
    """denial_category == "intent_denied"."""


@dataclass
class OapTrajectoryDenied(OapError):
    """denial_category == "trajectory_denied"."""


@dataclass
class OapSequenceDenied(OapTrajectoryDenied):
    """sequence_bounds violation."""


@dataclass
class OapEscalationDenied(OapError):
    """synchronous
    HumanApproval evaluator denied an escalation in-call."""


@dataclass
class OapDispatchError(OapError):
    """cascade dispatcher wrapped a non-Oap
    exception. HTTP 500."""


@dataclass
class OapWrongRegion(OapError):
    """caller landed on a non-home region.
    HTTP 403."""


@dataclass
class OapApprovalRequired(OapError):
    """the server returned ``decision == "escalate"`` from
    the untyped :meth:`OverturoAuthorize.authorize` path. Raised so
    that callers using the simple dict-returning surface get a fail-
    fast signal instead of a silently-incomplete decision they could
    mistake for an allow.

    Reason code on the wire: ``approval_required``.

    Field semantics:
        decision_url: full URL the principal opens to approve/deny.
            Includes ``session_token`` in its query string — **never log**.
        session_token: bearer credential — **never log**.
        approval_ttl_at: ISO-8601 string.
        escalation_id: prefix_id of the escalation.
        required_signers: tuple of principal IDs who can approve.

    The typed ``authorize_typed()`` / ``authorize_with_decomposition()``
    paths do **not** raise this exception; they return an
    ``OverturoDecision`` with ``.decision == "escalate"`` and a populated
    ``.escalation`` field.
    """

    decision_url: str = ""
    session_token: str = ""
    approval_ttl_at: str = ""
    escalation_id: str = ""
    required_signers: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_envelope(
        cls, envelope: dict[str, Any], status: int | None = None
    ) -> OapApprovalRequired:
        err = envelope.get("error", {}) or {}
        esc = err.get("escalation", {}) or {}
        return cls(
            reason_code=err.get("reason_code", "approval_required"),
            message=err.get("message", "Approval required"),
            http_status=status,
            detail=err.get("detail"),
            request_id=err.get("request_id"),
            decision_url=str(esc.get("decision_url", "")),
            session_token=str(esc.get("session_token", "")),
            approval_ttl_at=str(esc.get("approval_ttl_at", "")),
            escalation_id=str(esc.get("escalation_id", "")),
            required_signers=tuple(esc.get("required_signers", ())),
        )

    def __str__(self) -> str:
        # NEVER include session_token or decision_url in __str__ —
        # logs and traceback messages must be safe to ship to disk.
        return f"approval_required: escalation_id={self.escalation_id}"

    def __repr__(self) -> str:
        return (
            f"OapApprovalRequired(escalation_id={self.escalation_id!r}, "
            f"approval_ttl_at={self.approval_ttl_at!r}, "
            f"required_signers={self.required_signers!r}, "
            f"decision_url=<redacted>, session_token=<redacted>)"
        )


# ══════════════════════════════════════════════════════════════════════
# Dispatch tables (closed-enum source of truth for conformance)
# ══════════════════════════════════════════════════════════════════════

_CATEGORY_TO_CLASS: dict[str | None, type[OapError]] = {
    "authorization_denied": OapAuthorizationDenied,
    "intent_denied": OapIntentDenied,
    "trajectory_denied": OapTrajectoryDenied,
}

_REASON_CODE_TO_CLASS: dict[str, type[OapError]] = {
    "sequence_prohibited": OapSequenceDenied,
    "sequence_missing_predecessor": OapSequenceDenied,
    "escalation_denied": OapEscalationDenied,
    "dispatch_error": OapDispatchError,
    "wrong_region": OapWrongRegion,
    "approval_required": OapApprovalRequired,
}


def is_oap_error(exc: BaseException) -> bool:
    """Type guard for callers using a single ``except`` block over
    many exception types."""
    return isinstance(exc, OapError)
