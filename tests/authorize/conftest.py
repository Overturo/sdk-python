"""Shared fixtures — keypair generation + receipt builder used across the
verify and dpop test modules."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from overturo.authorize.dpop import DpopKeyPair
from overturo.authorize.receipt import b64url_encode
from overturo.verify import JwksKey, raw_ed25519_to_jwk


@pytest.fixture(scope="session")
def signing_keypair() -> tuple[Ed25519PrivateKey, JwksKey]:
    """A session-wide Ed25519 keypair plus the matching JwksKey."""
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes_raw()
    jwks_entry = raw_ed25519_to_jwk("oap-test-v1", b64url_encode(raw))
    return priv, jwks_entry


@pytest.fixture(scope="session")
def dpop_keypair() -> DpopKeyPair:
    """A session-wide DPoP keypair for client/dpop specs."""
    return DpopKeyPair.generate()


def make_receipt(
    private_key: Ed25519PrivateKey,
    *,
    kid: str = "oap-test-v1",
    audience: str = "did:web:cp.example",
    issuer: str = "https://us.overturo.test",
    iat: int | None = None,
    exp: int | None = None,
    oap_ver: str = "1.0",
    overrides: dict[str, Any] | None = None,
    header_overrides: dict[str, Any] | None = None,
) -> str:
    """Build a signed oap+jwt receipt with sensible defaults."""
    now = int(time.time())
    header = {"alg": "EdDSA", "typ": "oap+jwt", "kid": kid}
    if header_overrides:
        header.update(header_overrides)
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "iat": iat or now - 5,
        "exp": exp or now + 60,
        "jti": f"n_{now}",
        "oap_ver": oap_ver,
        "grant_id": "ath_test_xyz",
        "action": "read",
        "scope": "profile",
        "context_hash": "0" * 64,
        "chronicle_id": "audit_rec_test_xyz",
        "single_use": True,
    }
    if overrides:
        claims.update(overrides)
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig = private_key.sign(signing_input)
    return f"{header_b64}.{claims_b64}.{b64url_encode(sig)}"
