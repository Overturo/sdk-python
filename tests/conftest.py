"""
Shared fixtures: Ed25519 keypair + JWKS + signed-JWT helper.

The verify-receipt + JWKS tests sign their own JWTs against a fresh
keypair generated once per pytest session.
"""

from __future__ import annotations

import base64
import json
import sys
import time
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class Fixture:
    private_key: Ed25519PrivateKey
    jwks: dict
    kid: str


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="session")
def fixture() -> Fixture:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = "test-key-1"
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(public_bytes),
                "kid": kid,
                "alg": "EdDSA",
            }
        ]
    }
    return Fixture(private_key=private_key, jwks=jwks, kid=kid)


@pytest.fixture
def sign_jwt(fixture: Fixture):
    def _sign(payload: dict[str, Any], *, kid: str | None = None) -> str:
        header = {"alg": "EdDSA", "typ": "JWT", "kid": kid or fixture.kid}
        header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signed_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = fixture.private_key.sign(signed_input)
        signature_b64 = _b64url(signature)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    return _sign


@pytest.fixture
def sample_payload():
    def _build(**overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": "https://overturo.us",
            "iss_role": "witness",
            "sub": "att_dev_test123",
            "aud": "tp_dev_test456",
            "iat": now,
            "exp": now + 3600,
            "jti": "jti-test-1",
            "oap_ver": "1.0",
            "decision": "allow",
            "legal_basis": "consent",
        }
        for key, value in overrides.items():
            if value is None and key in payload:
                payload.pop(key)
            else:
                payload[key] = value
        return payload

    return _build


# Reset the verify-module JWKS cache between every test so spies + URL
# bookkeeping don't bleed across cases.
@pytest.fixture(autouse=True)
def reset_jwks_cache():
    sys.modules.setdefault(
        "_reset_jwks_cache_loaded",
        __import__("overturo.verify", fromlist=["_reset_jwks_cache"]),
    )
    from overturo.verify import _reset_jwks_cache

    _reset_jwks_cache()
    yield
    _reset_jwks_cache()
