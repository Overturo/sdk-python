"""unit coverage for verify_record's key resolution and
typed refusals (the corpus test covers the byte-exactness matrix)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from overturo import RecordInvalid, verify_manifest_pin, verify_record

# The shared corpus when this package sits next to it; the vendored copy otherwise.
SHARED_CORPUS = Path(__file__).resolve().parents[3] / "shared" / "conformance" / "signed_records"
CORPUS_DIR = (
    SHARED_CORPUS
    if SHARED_CORPUS.is_dir()
    else Path(__file__).resolve().parents[1] / "fixtures" / "signed_records"
)

PUBLISHED_KEYS: dict[str, str] = json.loads((CORPUS_DIR / "manifest.json").read_text())[
    "published_keys"
]


def valid_envelope() -> dict:
    return json.loads((CORPUS_DIR / "authorization_record_valid.json").read_text())


def code_of(fn) -> str:
    with pytest.raises(RecordInvalid) as excinfo:
        fn()
    return excinfo.value.code


def test_supplied_keys_mode() -> None:
    verified = verify_record(valid_envelope(), published_keys=PUBLISHED_KEYS)
    assert verified.key_source == "supplied"
    assert verified.region == "us"


def test_embedded_only_requires_opt_in() -> None:
    assert code_of(lambda: verify_record(valid_envelope())) == "no_key_source"
    verified = verify_record(valid_envelope(), allow_embedded_key=True)
    assert verified.key_source == "embedded"


def test_supplied_keys_take_precedence_over_embedded() -> None:
    verified = verify_record(
        valid_envelope(), published_keys=PUBLISHED_KEYS, allow_embedded_key=True
    )
    assert verified.key_source == "supplied"


def test_wrong_algorithm_tag() -> None:
    envelope = valid_envelope()
    envelope["signature"]["algorithm"] = "RS256"
    assert (
        code_of(lambda: verify_record(envelope, allow_embedded_key=True)) == "unsupported_algorithm"
    )


def test_wrong_canonicalization_tag() -> None:
    envelope = valid_envelope()
    envelope["signature"]["canonicalization"] = "rfc8785"
    assert (
        code_of(lambda: verify_record(envelope, allow_embedded_key=True))
        == "unsupported_canonicalization"
    )


def test_truncated_envelope_shapes() -> None:
    assert code_of(lambda: verify_record({})) == "malformed_envelope"
    assert code_of(lambda: verify_record({"receipt": {}})) == "malformed_envelope"
    assert (
        code_of(lambda: verify_record({"receipt": {}, "signature": {"algorithm": "Ed25519"}}))
        == "malformed_envelope"
    )
    assert code_of(lambda: verify_record([])) == "malformed_envelope"  # type: ignore[arg-type]


def test_jwt_string_is_a_typed_cross_artifact_refusal() -> None:
    assert code_of(lambda: verify_record("eyJh.eyJi.c2ln")) == "malformed_envelope"


def test_non_base64_signature_material() -> None:
    envelope = valid_envelope()
    envelope["signature"]["value"] = "!!not-base64!!"
    assert code_of(lambda: verify_record(envelope, allow_embedded_key=True)) == "malformed_envelope"


def test_malformed_manifest_pin() -> None:
    assert (
        code_of(lambda: verify_manifest_pin({"hash": "md5:nope"}, {"content": {}}))
        == "malformed_manifest"
    )
    assert (
        code_of(lambda: verify_manifest_pin({"hash": "sha256:" + "0" * 64}, {}))
        == "malformed_manifest"
    )
