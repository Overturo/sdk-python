"""durable signed-record verification.

Verifies the record export served with ``?flavor=signed``: a JSON
envelope ``{receipt, signature}`` where ``signature.value`` is a
detached Ed25519 signature over the ``overturo-jcs-1`` canonical bytes
of the ``receipt`` member alone.

``overturo-jcs-1`` is NOT RFC 8785 — it is the five published rules
(Receipt Interop & Verification guide): object keys deep-sorted
bytewise, array order preserved, compact separators, non-ASCII raw,
values serialized as the platform serializes them. ``json.dumps(...,
sort_keys=True, ensure_ascii=False, separators=(",", ":"))`` matches
Ruby's canonicalize + JSON.generate for every value the platform
emits: Python's parse→dump normalizes number lexemes exactly as the
Ruby signer's own parse→generate does (5.0 stays "5.0"), so parsed
``dict`` input is exact here — unlike JavaScript, where the raw-text
path is mandatory. ``sort_keys`` compares code points, identical to
bytewise order for all BMP keys; the shared corpus is the drift gate.

Exports are stateless — each export signs with the region's
then-current key and historical keys stay published — so verification
resolves the stamped ``key_version`` against a published key set
(``published_keys``), never blindly trusting the envelope's own key
copy. ``allow_embedded_key=True`` is the explicit, weaker opt-in:
internal consistency, not issuance. Fetching the key-discovery
document is the caller's two lines of httpx (the TS sibling's
``fetchKeyDiscovery`` convenience is deliberately absent — this SDK
already ships an HTTP client the caller controls).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import RecordInvalid

__all__ = [
    "CANONICALIZATION",
    "VerifiedRecord",
    "canonical_bytes",
    "manifest_content_hash",
    "verify_manifest_pin",
    "verify_record",
]

CANONICALIZATION = "overturo-jcs-1"

_REQUIRED_SIGNATURE_MEMBERS = (
    "algorithm",
    "canonicalization",
    "region",
    "key_version",
    "value",
    "public_key",
)


@dataclass
class VerifiedRecord:
    receipt: dict[str, Any]
    record_type: str | None
    region: str
    key_version: str
    key_source: str  # "supplied" | "embedded"


def canonical_bytes(value: Any) -> bytes:
    """``overturo-jcs-1`` canonical bytes of a JSON value."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def verify_record(
    envelope: str | bytes | dict[str, Any],
    *,
    published_keys: dict[str, str] | None = None,
    allow_embedded_key: bool = False,
) -> VerifiedRecord:
    """Verify a signed record export against published keys.

    ``published_keys`` maps key_version ("us-1") to the standard-base64
    raw 32-byte public key — e.g. the ``keys`` list of the region's
    key-discovery document, reshaped. Raises :class:`RecordInvalid`
    with a typed ``code`` on every refusal.
    """
    parsed = _parse_envelope(envelope)
    receipt, signature = parsed

    if signature["algorithm"] != "Ed25519":
        raise RecordInvalid(
            "unsupported_algorithm",
            f'signature.algorithm must be "Ed25519"; got {signature["algorithm"]!r}',
        )
    if signature["canonicalization"] != CANONICALIZATION:
        raise RecordInvalid(
            "unsupported_canonicalization",
            f'signature.canonicalization must be "{CANONICALIZATION}"; '
            f"got {signature['canonicalization']!r}",
        )

    key_version = signature["key_version"]
    embedded_b64 = signature["public_key"]

    if published_keys is not None:
        published_b64 = published_keys.get(key_version)
        if published_b64 is None:
            raise RecordInvalid(
                "unknown_key_version",
                f"key_version {key_version} not in the supplied published key set",
            )
        if _b64decode(published_b64, "published key") != _b64decode(
            embedded_b64, "signature.public_key"
        ):
            raise RecordInvalid(
                "key_mismatch",
                f"envelope's embedded public_key disagrees with the published key for {key_version}",
            )
        key_bytes = _b64decode(published_b64, "published key")
        key_source = "supplied"
    elif allow_embedded_key:
        key_bytes = _b64decode(embedded_b64, "signature.public_key")
        key_source = "embedded"
    else:
        raise RecordInvalid(
            "no_key_source",
            "no key source: pass published_keys or explicitly opt into allow_embedded_key "
            "(embedded-only proves internal consistency, not issuance)",
        )

    signature_bytes = _b64decode(signature["value"], "signature.value")
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            signature_bytes, canonical_bytes(receipt)
        )
    except InvalidSignature:
        raise RecordInvalid("signature_failed", "Ed25519 signature verification failed") from None
    except ValueError as e:
        raise RecordInvalid(
            "signature_failed", f"public key is not a valid raw Ed25519 key: {e}"
        ) from None

    record = receipt.get("record")
    record_type = record.get("record_type") if isinstance(record, dict) else None

    return VerifiedRecord(
        receipt=receipt,
        record_type=record_type if isinstance(record_type, str) else None,
        region=signature["region"],
        key_version=key_version,
        key_source=key_source,
    )


def manifest_content_hash(content: Any) -> str:
    """``"sha256:<hex>"`` over the overturo-jcs-1 canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes(content)).hexdigest()


def verify_manifest_pin(pin: dict[str, Any], published_manifest: dict[str, Any]) -> str:
    """Recompute the published manifest's content hash against a record's pin.

    Returns the recomputed hash on success; raises
    :class:`RecordInvalid` ("manifest_hash_mismatch") when the
    published content does not hash to the pinned value.
    """
    pin_hash = pin.get("hash")
    if not isinstance(pin_hash, str) or not pin_hash.startswith("sha256:"):
        raise RecordInvalid("malformed_manifest", "pin.hash must be a sha256:<hex> string")
    if not isinstance(published_manifest, dict) or "content" not in published_manifest:
        raise RecordInvalid("malformed_manifest", "published manifest must carry `content`")
    recomputed = manifest_content_hash(published_manifest["content"])
    if recomputed != pin_hash:
        raise RecordInvalid(
            "manifest_hash_mismatch",
            f"published content hashes to {recomputed}, but the record pins {pin_hash}",
        )
    return recomputed


# ── internals ──────────────────────────────────────────────────────────


def _parse_envelope(
    envelope: str | bytes | dict[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    if isinstance(envelope, (str, bytes)):
        try:
            envelope = json.loads(envelope)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise RecordInvalid(
                "malformed_envelope",
                "input is not valid JSON — a dot-separated JWT string is the runtime "
                "receipt; verify it with verify_receipt",
            ) from None
    if not isinstance(envelope, dict):
        raise RecordInvalid(
            "malformed_envelope",
            "signed record must be a JSON object with `receipt` and `signature` members",
        )
    receipt = envelope.get("receipt")
    signature = envelope.get("signature")
    if not isinstance(receipt, dict):
        raise RecordInvalid("malformed_envelope", "envelope missing `receipt` object")
    if not isinstance(signature, dict):
        raise RecordInvalid("malformed_envelope", "envelope missing `signature` object")
    for member in _REQUIRED_SIGNATURE_MEMBERS:
        if not isinstance(signature.get(member), str):
            raise RecordInvalid("malformed_envelope", f"signature.{member} must be a string")
    return receipt, signature


def _b64decode(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise RecordInvalid("malformed_envelope", f"{what} is not standard base64") from None
