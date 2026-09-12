"""verify_receipt unit coverage."""

import base64
import json
import time

import pytest

from overturo import ReceiptInvalid, verify_receipt

# ── happy paths ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_witness_role_yields_witness_only(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss_role="witness"))
    result = await verify_receipt(jwt, jwks=fixture.jwks)
    assert result.iss_role == "witness"
    assert result.trust_weight == "witness_only"
    assert result.iss == "https://overturo.us"


@pytest.mark.asyncio
async def test_authorizer_role_yields_strong(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss_role="authorizer"))
    result = await verify_receipt(jwt, jwks=fixture.jwks)
    assert result.iss_role == "authorizer"
    assert result.trust_weight == "strong"


@pytest.mark.asyncio
async def test_approval_url_signer_yields_approval_url(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss_role="approval_url_signer"))
    result = await verify_receipt(jwt, jwks=fixture.jwks)
    assert result.iss_role == "approval_url_signer"
    assert result.trust_weight == "approval_url"


# ── iss_role validation ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_iss_role_raises(fixture, sign_jwt, sample_payload):
    payload = sample_payload(iss_role=None)
    jwt = sign_jwt(payload)
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "missing_iss_role"


@pytest.mark.asyncio
async def test_unknown_iss_role_raises(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss_role="rogue_role"))
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "unknown_iss_role"


# ── signature verification ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_tampered_signature_fails(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload())
    parts = jwt.split(".")
    # Replace the entire signature with all-A's (decodes to non-matching 64-byte sig).
    tampered = f"{parts[0]}.{parts[1]}.{'A' * 86}"
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(tampered, jwks=fixture.jwks)
    assert exc.value.code in ("signature_failed", "malformed_jwt")


@pytest.mark.asyncio
async def test_unknown_kid_raises(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(), kid="rotated-key")
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "unknown_kid"


@pytest.mark.asyncio
async def test_unsupported_algorithm_raises(fixture, sample_payload):
    # Hand-build a JWT with alg=HS256
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "x"}).encode())
        .rstrip(b"=")
        .decode("ascii")
    )
    payload = (
        base64.urlsafe_b64encode(json.dumps(sample_payload()).encode()).rstrip(b"=").decode("ascii")
    )
    jwt = f"{header}.{payload}.AAAA"

    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "unsupported_algorithm"


# ── temporal claims ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_expired_receipt_raises(fixture, sign_jwt, sample_payload):
    past = int(time.time()) - 4000
    jwt = sign_jwt(sample_payload(iat=past, exp=past + 60))
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "expired"


@pytest.mark.asyncio
async def test_admits_recently_expired_within_clock_skew(fixture, sign_jwt, sample_payload):
    now = int(time.time())
    jwt = sign_jwt(sample_payload(iat=now - 100, exp=now - 10))
    result = await verify_receipt(jwt, jwks=fixture.jwks, clock_skew_seconds=60)
    assert result.iss_role == "witness"


@pytest.mark.asyncio
async def test_future_issued_raises(fixture, sign_jwt, sample_payload):
    future = int(time.time()) + 10_000
    jwt = sign_jwt(sample_payload(iat=future, exp=future + 3600))
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks)
    assert exc.value.code == "future_issued"


# ── structural ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_malformed_jwt_raises(fixture):
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt("not.a.complete.jwt", jwks=fixture.jwks)
    assert exc.value.code == "malformed_jwt"


@pytest.mark.asyncio
async def test_requires_either_jwks_or_jwks_url(sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload())
    with pytest.raises(ReceiptInvalid):
        await verify_receipt(jwt)


# ── forward-compat ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_preserves_unknown_claims_in_extra(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(custom_field="future-value", nested={"a": 1}))
    result = await verify_receipt(jwt, jwks=fixture.jwks)
    assert result.extra.get("custom_field") == "future-value"
    assert result.extra.get("nested") == {"a": 1}


# ── G8 — issuer + audience validation ─────────────────────────────


@pytest.mark.asyncio
async def test_g8_admits_matching_expected_issuer(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss="https://overturo.us"))
    result = await verify_receipt(jwt, jwks=fixture.jwks, expected_issuer="https://overturo.us")
    assert result.iss == "https://overturo.us"


@pytest.mark.asyncio
async def test_g8_rejects_unmatched_expected_issuer(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss="https://overturo.us"))
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks, expected_issuer="https://overturo.eu")
    assert exc.value.code == "issuer_not_allowed"


@pytest.mark.asyncio
async def test_g8_accepts_array_of_expected_issuers(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss="https://overturo.us"))
    result = await verify_receipt(
        jwt,
        jwks=fixture.jwks,
        expected_issuer=["https://overturo.eu", "https://overturo.us"],
    )
    assert result.iss == "https://overturo.us"


@pytest.mark.asyncio
async def test_g8_admits_matching_audience(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(aud="tp_dev_xyz"))
    result = await verify_receipt(jwt, jwks=fixture.jwks, audience="tp_dev_xyz")
    assert result.aud == "tp_dev_xyz"


@pytest.mark.asyncio
async def test_g8_rejects_unmatched_audience(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(aud="tp_dev_other"))
    with pytest.raises(ReceiptInvalid) as exc:
        await verify_receipt(jwt, jwks=fixture.jwks, audience="tp_dev_xyz")
    assert exc.value.code == "audience_mismatch"


@pytest.mark.asyncio
async def test_g8_back_compat_omits_validation(fixture, sign_jwt, sample_payload):
    jwt = sign_jwt(sample_payload(iss="https://rogue.example"))
    result = await verify_receipt(jwt, jwks=fixture.jwks)
    assert result.iss == "https://rogue.example"
