"""RFC 9449 DPoP proof generation + RFC 7638 JWK thumbprint."""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .receipt import b64url_encode


@dataclass
class DpopKeyPair:
    """Pair of an Ed25519 private key + the JWK its public half exports as.

    Only Ed25519 is supported in v1.0; the JS SDK additionally supports
    P-256 — Python parity comes in 1.1.
    """

    private_key: Ed25519PrivateKey
    public_jwk: dict[str, Any]

    @classmethod
    def generate(cls) -> DpopKeyPair:
        """Create a fresh Ed25519 keypair. Useful in tests; production
        agents should persist the key across restarts so the grant's
        `cnf.jkt` binding holds."""
        priv = Ed25519PrivateKey.generate()
        raw = priv.public_key().public_bytes_raw()
        return cls(
            private_key=priv,
            public_jwk={
                "kty": "OKP",
                "crv": "Ed25519",
                "x": b64url_encode(raw),
            },
        )


def sign_dpop_proof(
    keypair: DpopKeyPair,
    *,
    htm: str,
    htu: str,
    iat: int | None = None,
    jti: str | None = None,
    access_token: str | None = None,
) -> str:
    """Sign a DPoP proof JWT. Returns the compact JWS string.

    When ``access_token`` is supplied, the proof carries the RFC 9449
    section 4.1 ``ath`` claim — required by the server-side verifier whenever
    the request also presents a bearer token. The ``OverturoAuthorize``
    client wires this automatically; bare callers must pass it
    themselves when they send the proof alongside a bearer token.
    """

    crv = keypair.public_jwk.get("crv")
    if crv != "Ed25519":
        raise ValueError(
            f"Unsupported DPoP key curve: {crv}. v1.0 Python SDK only supports Ed25519."
        )

    header = {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": keypair.public_jwk}
    payload: dict[str, Any] = {
        "htm": htm.upper(),
        "htu": _normalise_htu(htu),
        "iat": iat if iat is not None else int(time.time()),
        "jti": jti if jti is not None else b64url_encode(secrets.token_bytes(16)),
    }
    if access_token is not None:
        payload["ath"] = access_token_hash(access_token)

    header_b64 = b64url_encode(_jcs(header))
    payload_b64 = b64url_encode(_jcs(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = keypair.private_key.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def access_token_hash(access_token: str) -> str:
    """RFC 9449 section 4.1 access token hash (``ath``).

    SHA-256 of the raw access token bytes, base64url-encoded with no
    padding. The server-side verifier rejects with
    ``dpop_invalid: "missing ath"`` whenever a bearer + DPoP proof
    reach an endpoint without it.
    """
    return b64url_encode(sha256(access_token.encode("utf-8")).digest())


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 section 3 SHA-256 thumbprint over the canonical member subset
    for the JWK's key type. Returned as base64url with no padding —
    matches the platform's `agent_dpop_jkt` field."""
    kty = jwk.get("kty")
    if kty == "OKP":
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]},
            separators=(",", ":"),
            sort_keys=False,
        )
    elif kty == "EC":
        canonical = json.dumps(
            {
                "crv": jwk["crv"],
                "kty": "EC",
                "x": jwk["x"],
                "y": jwk["y"],
            },
            separators=(",", ":"),
            sort_keys=False,
        )
    else:
        raise ValueError(f"jwk_thumbprint: unsupported kty {kty!r}")
    return b64url_encode(sha256(canonical.encode("utf-8")).digest())


def _normalise_htu(url: str) -> str:
    """Strip query string + fragment per RFC 9449 section 4.2."""
    try:
        parts = urlparse(url)
        return urlunparse((parts.scheme, parts.netloc, parts.path, "", "", ""))
    except ValueError:
        return url


def _jcs(obj: dict[str, Any]) -> bytes:
    """Minimal JCS-compatible encoder — same shape JS uses (compact JSON,
    insertion-order keys). The platform doesn't require RFC 8785 here
    because the DPoP payload is round-tripped through verify-by-key, not
    re-canonicalised on the server side."""
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")
