"""the in-process retrieve→verify round-trip.

Python is the language where the full chain is importable in one
process: the receipts client retrieves the signed flavor and
`overturo.verify_record` verifies it offline. The served body is a real
corpus fixture (server-generated), so this is the designed pair working
end-to-end against production-shaped bytes.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from overturo import verify_record
from overturo.receipts import retrieve_authorization_receipt

# The shared corpus when this package sits next to it; the vendored copy otherwise.
SHARED_CORPUS = Path(__file__).resolve().parents[3] / "shared" / "conformance" / "signed_records"
CORPUS_DIR = (
    SHARED_CORPUS
    if SHARED_CORPUS.is_dir()
    else Path(__file__).resolve().parents[1] / "fixtures" / "signed_records"
)

BASE = "https://overturo.example"


@respx.mock
def test_retrieve_signed_then_verify_offline() -> None:
    raw = (CORPUS_DIR / "authorization_record_valid.json").read_text()
    published_keys = json.loads((CORPUS_DIR / "manifest.json").read_text())["published_keys"]

    respx.get(f"{BASE}/api/v1/authorization_receipts/acc_123", params={"flavor": "signed"}).mock(
        return_value=httpx.Response(200, text=raw, headers={"content-type": "application/json"})
    )

    envelope = retrieve_authorization_receipt(
        base_url=BASE, api_token="tok", record_id="acc_123", flavor="signed"
    )
    verified = verify_record(envelope, published_keys=published_keys)

    assert verified.record_type == "authorization_record"
    assert verified.key_source == "supplied"
    assert verified.key_version == "us-1"
