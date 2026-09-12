"""Receipt parsing — base64url round-trip + peek_receipt structural cases."""

from __future__ import annotations

import json

from overturo.authorize.receipt import (
    b64url_decode,
    b64url_encode,
    peek_receipt,
)


def test_base64url_round_trips_arbitrary_bytes() -> None:
    blob = bytes(range(256))
    assert b64url_decode(b64url_encode(blob)) == blob


def test_base64url_has_no_padding() -> None:
    assert "=" not in b64url_encode(b"ab")


def test_base64url_is_url_safe() -> None:
    encoded = b64url_encode(b"\xfb\xff\xff")
    assert "+" not in encoded
    assert "/" not in encoded
    assert "-" in encoded or "_" in encoded


def test_peek_receipt_returns_header_claims_signature() -> None:
    header = {"alg": "EdDSA", "typ": "oap+jwt", "kid": "oap-us-v1"}
    claims = {"iss": "https://us.overturo.com", "aud": "did:web:cp.example", "jti": "n1"}
    h_b64 = b64url_encode(json.dumps(header).encode())
    c_b64 = b64url_encode(json.dumps(claims).encode())
    sig_b64 = b64url_encode(b"\x01\x02\x03")
    peeked = peek_receipt(f"{h_b64}.{c_b64}.{sig_b64}")

    assert peeked is not None
    assert peeked.header["kid"] == "oap-us-v1"
    assert peeked.claims["jti"] == "n1"
    assert peeked.signing_input == f"{h_b64}.{c_b64}".encode("ascii")
    assert peeked.signature == b"\x01\x02\x03"


def test_peek_receipt_returns_none_for_non_jwt_input() -> None:
    assert peek_receipt("not-a-jwt") is None
    assert peek_receipt("") is None
    assert peek_receipt("a.b") is None


def test_peek_receipt_returns_none_for_non_string_input() -> None:
    assert peek_receipt(None) is None
    assert peek_receipt(123) is None  # type: ignore[arg-type]


def test_peek_receipt_returns_none_when_segment_is_not_json() -> None:
    bad_payload = b64url_encode(b"{not-json")
    assert peek_receipt(f"aaa.{bad_payload}.bbb") is None
