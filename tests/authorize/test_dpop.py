"""DPoP proof generation + JWK thumbprint."""

from __future__ import annotations

import json

import pytest

from overturo.authorize.dpop import (
    DpopKeyPair,
    jwk_thumbprint,
    sign_dpop_proof,
)
from overturo.authorize.receipt import b64url_decode


def _payload(proof: str) -> dict:
    parts = proof.split(".")
    return json.loads(b64url_decode(parts[1]))


def _header(proof: str) -> dict:
    parts = proof.split(".")
    return json.loads(b64url_decode(parts[0]))


def test_dpop_keypair_generate_produces_okp_ed25519():
    kp = DpopKeyPair.generate()
    assert kp.public_jwk == {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": kp.public_jwk["x"],
    }


def test_sign_dpop_proof_emits_typ_alg_jwk(dpop_keypair):
    proof = sign_dpop_proof(
        dpop_keypair,
        htm="post",
        htu="https://us.overturo.com/api/v1/grants/ath_us_x/authorize",
    )
    header = _header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "EdDSA"
    assert header["jwk"]["crv"] == "Ed25519"


def test_dpop_normalises_htu_strips_query_and_fragment(dpop_keypair):
    proof = sign_dpop_proof(
        dpop_keypair,
        htm="GET",
        htu="https://us.overturo.com/api/v1/grants/ath_us_x?leak=secret#frag",
    )
    payload = _payload(proof)
    assert payload["htu"] == "https://us.overturo.com/api/v1/grants/ath_us_x"
    assert payload["htm"] == "GET"


def test_dpop_auto_generates_unique_jti(dpop_keypair):
    a = _payload(sign_dpop_proof(dpop_keypair, htm="POST", htu="https://x/"))
    b = _payload(sign_dpop_proof(dpop_keypair, htm="POST", htu="https://x/"))
    assert a["jti"] != b["jti"]


def test_dpop_emits_ath_when_access_token_supplied(dpop_keypair):
    from hashlib import sha256

    from overturo.authorize.receipt import b64url_encode

    proof = sign_dpop_proof(
        dpop_keypair,
        htm="POST",
        htu="https://us.overturo.com/api/v1/grants/x/authorize",
        access_token="agent-token-v1",
    )
    payload = _payload(proof)
    expected = b64url_encode(sha256(b"agent-token-v1").digest())
    assert payload["ath"] == expected


def test_dpop_omits_ath_when_access_token_absent(dpop_keypair):
    proof = sign_dpop_proof(
        dpop_keypair,
        htm="POST",
        htu="https://us.overturo.com/api/v1/grants/x/authorize",
    )
    assert "ath" not in _payload(proof)


def test_dpop_signature_verifies_under_public_key(dpop_keypair):
    proof = sign_dpop_proof(dpop_keypair, htm="POST", htu="https://us.overturo.com/x")
    header_b64, payload_b64, sig_b64 = proof.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = b64url_decode(sig_b64)

    # Verifying with the matching public key must succeed.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_raw = dpop_keypair.private_key.public_key().public_bytes_raw()
    Ed25519PublicKey.from_public_bytes(public_raw).verify(sig, signing_input)

    # An unrelated key MUST NOT verify the same signature.
    from cryptography.exceptions import InvalidSignature

    other = DpopKeyPair.generate()
    other_raw = other.private_key.public_key().public_bytes_raw()
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(other_raw).verify(sig, signing_input)


def test_sign_rejects_non_ed25519_curve(dpop_keypair):
    bogus = DpopKeyPair(
        private_key=dpop_keypair.private_key,
        public_jwk={"kty": "EC", "crv": "P-384"},
    )
    with pytest.raises(ValueError, match="Unsupported DPoP key curve"):
        sign_dpop_proof(bogus, htm="POST", htu="https://x/")


def test_jwk_thumbprint_is_deterministic(dpop_keypair):
    a = jwk_thumbprint(dpop_keypair.public_jwk)
    b = jwk_thumbprint(dpop_keypair.public_jwk)
    assert a == b
    assert all(c.isalnum() or c in "-_" for c in a)


def test_jwk_thumbprint_differs_per_key():
    a = jwk_thumbprint(DpopKeyPair.generate().public_jwk)
    b = jwk_thumbprint(DpopKeyPair.generate().public_jwk)
    assert a != b


def test_jwk_thumbprint_supports_p256():
    jwk = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}
    assert isinstance(jwk_thumbprint(jwk), str)


def test_jwk_thumbprint_rejects_unsupported_kty():
    with pytest.raises(ValueError, match="unsupported kty"):
        jwk_thumbprint({"kty": "RSA", "n": "x", "e": "AQAB"})
