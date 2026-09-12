"""Offline receipt verification — round-trip + every failure mode."""

from __future__ import annotations

import time

import pytest

from overturo.authorize.receipt import b64url_decode, b64url_encode
from overturo.verify import (
    raw_ed25519_to_jwk,
    verify_receipt_offline,
)
from tests.authorize.conftest import make_receipt

AUDIENCE = "did:web:cp.example"
ISSUER = "https://us.overturo.test"


def test_accepts_fresh_receipt(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv)
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.valid is True
    assert result.reason_code is None
    assert result.claims["jti"]


def test_rejects_malformed(signing_keypair):
    _, jwk = signing_keypair
    result = verify_receipt_offline(
        "garbage", audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk]
    )
    assert result.valid is False
    assert result.reason_code == "malformed"


def test_rejects_invalid_alg(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv, header_overrides={"alg": "RS256"})
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.reason_code == "invalid_alg"


def test_rejects_invalid_typ(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv, header_overrides={"typ": "jwt"})
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.reason_code == "invalid_typ"


def test_rejects_unknown_kid(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv, kid="oap-other-v9")
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.reason_code == "unknown_kid"


def test_rejects_audience_mismatch(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv)
    result = verify_receipt_offline(
        jwt, audience="did:web:wrong.example", accepted_issuers=[ISSUER], jwks=[jwk]
    )
    assert result.reason_code == "invalid_aud"
    assert result.claims is not None  # claims surface even on aud failure


def test_rejects_issuer_mismatch(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv)
    result = verify_receipt_offline(
        jwt,
        audience=AUDIENCE,
        accepted_issuers=["https://other.example"],
        jwks=[jwk],
    )
    assert result.reason_code == "invalid_iss"


def test_rejects_expired_receipt(signing_keypair):
    priv, jwk = signing_keypair
    now = int(time.time())
    jwt = make_receipt(priv, iat=now - 600, exp=now - 120)
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.reason_code == "expired"


def test_rejects_wrong_oap_version(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv, oap_ver="2.0")
    result = verify_receipt_offline(jwt, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk])
    assert result.reason_code == "invalid_version"


def test_rejects_tampered_payload(signing_keypair):
    priv, jwk = signing_keypair
    jwt = make_receipt(priv)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    import json

    claims = json.loads(b64url_decode(payload_b64))
    claims["scope"] = "admin"
    tampered_payload = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    tampered = f"{header_b64}.{tampered_payload}.{sig_b64}"
    result = verify_receipt_offline(
        tampered, audience=AUDIENCE, accepted_issuers=[ISSUER], jwks=[jwk]
    )
    assert result.reason_code == "bad_signature"


def test_raw_ed25519_to_jwk_round_trips(signing_keypair):
    _, jwk = signing_keypair
    rebuilt = raw_ed25519_to_jwk(jwk.kid, jwk.x)
    assert rebuilt.kid == jwk.kid
    assert rebuilt.x.rstrip("=") == jwk.x.rstrip("=")


def test_raw_ed25519_to_jwk_rejects_wrong_length():
    with pytest.raises(ValueError, match="32 bytes"):
        raw_ed25519_to_jwk("kid-1", b64url_encode(b"\x00" * 10))
