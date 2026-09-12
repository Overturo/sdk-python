"""the Python leg of the signed-record conformance corpus.

One fixture set, three legs: the server spec
(spec/conformance/signed_record_corpus_spec.rb) generates and
re-verifies; this suite and the TS suite
(lib/sdk/overturo-verify/tests/signed-record-corpus.test.ts) iterate
the same manifest. A canonicalizer that drifts from the server by one
byte fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from overturo import RecordInvalid, manifest_content_hash, verify_manifest_pin, verify_record

# The shared corpus when this package sits next to it; the vendored copy otherwise.
SHARED_CORPUS = Path(__file__).resolve().parents[3] / "shared" / "conformance" / "signed_records"
CORPUS_DIR = (
    SHARED_CORPUS
    if SHARED_CORPUS.is_dir()
    else Path(__file__).resolve().parents[1] / "fixtures" / "signed_records"
)

MANIFEST = json.loads((CORPUS_DIR / "manifest.json").read_text())
PUBLISHED_KEYS: dict[str, str] = MANIFEST["published_keys"]


def read_fixture(name: str) -> dict:
    return json.loads((CORPUS_DIR / name).read_text())


def test_corpus_schema() -> None:
    assert MANIFEST["schema"] == "overturo-signed-record-corpus/1"
    assert len(MANIFEST["cases"]) >= 9


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=[c["fixture"] for c in MANIFEST["cases"]])
def test_corpus_case(case: dict) -> None:
    expect = case["expect"]
    document = read_fixture(case["fixture"])

    if expect == "valid":
        verified = verify_record(document, published_keys=PUBLISHED_KEYS)
        assert verified.key_source == "supplied"
        assert verified.key_version == case["key_version"]
        if case.get("record_type"):
            assert verified.record_type == case["record_type"]
    elif expect in ("signature_failed", "key_mismatch", "unknown_key_version"):
        with pytest.raises(RecordInvalid) as excinfo:
            verify_record(document, published_keys=PUBLISHED_KEYS)
        assert excinfo.value.code == expect
    elif expect == "manifest_valid":
        recomputed = verify_manifest_pin(
            {"reference": "corpus/manifest/v1", "hash": document["content_hash"]},
            {"content": document["content"]},
        )
        assert recomputed == document["content_hash"]
        assert manifest_content_hash(document["content"]) == document["content_hash"]
    elif expect == "manifest_hash_mismatch":
        with pytest.raises(RecordInvalid) as excinfo:
            verify_manifest_pin(
                {"reference": "corpus/manifest/v1", "hash": document["content_hash"]},
                {"content": document["content"]},
            )
        assert excinfo.value.code == "manifest_hash_mismatch"
    else:
        raise AssertionError(f"unknown corpus expectation {expect!r} — extend this suite")


def test_raw_text_input_verifies_identically() -> None:
    raw = (CORPUS_DIR / "authorization_record_valid.json").read_text()
    verified = verify_record(raw, published_keys=PUBLISHED_KEYS)
    assert verified.record_type == "authorization_record"
    # Python round-trips number lexemes ("5.0" stays "5.0"), so parsed
    # dict input is exact too — asserted by the parametrized cases.


def test_tampered_fails_in_embedded_only_mode_too() -> None:
    with pytest.raises(RecordInvalid) as excinfo:
        verify_record(read_fixture("tampered_receipt.json"), allow_embedded_key=True)
    assert excinfo.value.code == "signature_failed"
