"""receipts client: flavor matrix, both 422 shapes, scopes, 404."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from overturo.errors import OverturoUnauthorized, OverturoValidationError
from overturo.receipts import create_disclosure_receipt, retrieve_authorization_receipt
from tests.corpus import corpus_body, corpus_route

BASE = "https://overturo.example"

# The recorded exchange the real API produced (validated against the published document).
CANONICAL_BODY = corpus_body("AuthorizationReceipts_show")

SIGNED_ENVELOPE = corpus_body("AuthorizationReceipts_show", step="signed")


@respx.mock
def test_canonical_default_unwraps_and_sends_no_flavor() -> None:
    route = corpus_route(respx, "AuthorizationReceipts_show", BASE)

    doc = retrieve_authorization_receipt(base_url=BASE, api_token="tok", record_id="acc_123")

    assert doc["record"]["record_type"] == "authorization_record"
    assert doc["record"]["record_id"] == "<PREFIX_ID:1>"
    request = route.calls.last.request
    assert "flavor" not in str(request.url)
    assert request.headers["authorization"] == "Bearer tok"


@respx.mock
def test_signed_flavor_returns_bare_envelope() -> None:
    corpus_route(respx, "AuthorizationReceipts_show", BASE, step="signed")

    envelope = retrieve_authorization_receipt(
        base_url=BASE, api_token="tok", record_id="acc_123", flavor="signed"
    )

    assert set(envelope.keys()) == {"receipt", "signature"}
    assert envelope["signature"]["canonicalization"] == "overturo-jcs-1"


@respx.mock
def test_dpv_flavor_parses_ld_json() -> None:
    dpv = {"@context": {"dpv": "https://w3id.org/dpv#"}, "@type": "dpv:ConsentRecord"}
    respx.get(f"{BASE}/api/v1/authorization_receipts/acc_123", params={"flavor": "dpv"}).mock(
        return_value=httpx.Response(
            200, text=json.dumps(dpv), headers={"content-type": "application/ld+json"}
        )
    )

    doc = retrieve_authorization_receipt(
        base_url=BASE, api_token="tok", record_id="acc_123", flavor="dpv"
    )

    assert doc["@type"] == "dpv:ConsentRecord"


@respx.mock
@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"error": "unknown_flavor"}, "unknown_flavor"),
        ({"error": "not_signable", "reason": "no frozen snapshot"}, "not_signable"),
        ({"error": "dpv_unavailable", "reason": "no PII slice"}, "dpv_unavailable"),
    ],
)
def test_read_422_shape_surfaces_reason_code(body: dict, code: str) -> None:
    respx.get(f"{BASE}/api/v1/authorization_receipts/acc_123", params={"flavor": "x"}).mock(
        return_value=httpx.Response(422, json=body)
    )

    with pytest.raises(OverturoValidationError) as excinfo:
        retrieve_authorization_receipt(
            base_url=BASE, api_token="tok", record_id="acc_123", flavor="x"
        )
    assert excinfo.value.reason_code == code


@respx.mock
def test_missing_scope_403() -> None:
    respx.get(f"{BASE}/api/v1/authorization_receipts/acc_123").mock(
        return_value=httpx.Response(403, json={"error": "Requires audit:verify scope"})
    )

    with pytest.raises(OverturoUnauthorized) as excinfo:
        retrieve_authorization_receipt(base_url=BASE, api_token="tok", record_id="acc_123")
    assert excinfo.value.reason_code == "missing_scope"
    assert "audit:verify" in excinfo.value.message


@respx.mock
def test_parity_preserving_404() -> None:
    from overturo.errors import OverturoApiError

    respx.get(f"{BASE}/api/v1/authorization_receipts/acc_nope").mock(
        return_value=httpx.Response(404, json={"error": "Authorization record not found"})
    )

    with pytest.raises(OverturoApiError) as excinfo:
        retrieve_authorization_receipt(base_url=BASE, api_token="tok", record_id="acc_nope")
    assert excinfo.value.http_status == 404


@respx.mock
def test_mint_posts_closed_payload_and_unwraps() -> None:
    route = corpus_route(respx, "DisclosureReceipts_create", BASE)

    receipt = create_disclosure_receipt(
        base_url=BASE,
        api_token="tok",
        flow_id="acc_flow1",
        agent_id="agt_1",
        disclosed_at="2026-08-06T10:00:00Z",
        locale="en",
    )

    assert receipt["record_id"] == "<PREFIX_ID:3>"
    sent = json.loads(route.calls.last.request.content)
    assert sent == {
        "flow_id": "acc_flow1",
        "agent_id": "agt_1",
        "disclosed_at": "2026-08-06T10:00:00Z",
        "locale": "en",
    }


@respx.mock
def test_mint_422_shape_surfaces_reason_code() -> None:
    respx.post(f"{BASE}/api/v1/disclosure_receipts").mock(
        return_value=httpx.Response(
            422,
            json={
                "error": "the named flow does not disclose this agent",
                "code": "agent_not_disclosed",
            },
        )
    )

    with pytest.raises(OverturoValidationError) as excinfo:
        create_disclosure_receipt(
            base_url=BASE,
            api_token="tok",
            flow_id="acc_flow1",
            agent_id="agt_other",
            disclosed_at="2026-08-06T10:00:00Z",
        )
    assert excinfo.value.reason_code == "agent_not_disclosed"
    assert "does not disclose" in excinfo.value.message
