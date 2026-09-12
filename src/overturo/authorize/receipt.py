"""Receipt parsing — anonymous decode, no signature verification.

Use `verify_receipt_offline` when authenticity matters.
"""

from __future__ import annotations

import base64
import json

from ..models import PeekedReceipt

__all__ = ["PeekedReceipt", "peek_receipt", "b64url_encode", "b64url_decode"]


def peek_receipt(jwt: str | None) -> PeekedReceipt | None:
    """Decode the three JWT segments without verifying the signature.

    Returns None on any structural failure — never raises. Callers that
    want a typed error build one from the None result.
    """
    if not isinstance(jwt, str):
        return None
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError):
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return PeekedReceipt(
        header=header,
        claims=claims,
        signing_input=signing_input,
        signature=signature,
    )


def b64url_encode(data: bytes) -> str:
    """RFC 7515 section 2 base64url, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """RFC 7515 section 2 base64url decode, padding-tolerant."""
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)
