"""Wire-level integration suite for overturo-authorize.

Boots no servers — assumes an Overturo instance is reachable at $BASE_URL
(default http://localhost:5000) with the OAP feature flag enabled.

If the server is unreachable every test is skipped, so the suite is
safe to include in the default pytest run.

Run explicitly:

    INTEGRATION=true pytest integration/

This is the harness whose absence allowed the DPoP `ath` bug to ship
in Sprint 4 — every test exercises the real wire format end-to-end.
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

from overturo import (
    OapError,
    OverturoAuthorize,
    is_oap_error,
    peek_receipt,
    verify_receipt_offline,
)
from overturo.verify import raw_ed25519_to_jwk

from .scenario import IntegrationFixture, load_oap_scenario

# Skip the entire module if the suite isn't explicitly opted into AND
# the server isn't reachable. With INTEGRATION=true the module runs
# unconditionally — a failed scenario load surfaces as a real error
# (which is what you want in CI).
RUN_INTEGRATION = os.environ.get("INTEGRATION") == "true"


@pytest.fixture(scope="module")
def fixture() -> IntegrationFixture:
    f = load_oap_scenario()
    if f is None:
        if RUN_INTEGRATION:
            pytest.fail(
                "INTEGRATION=true but Overturo server at $BASE_URL is unreachable"
            )
        pytest.skip("No Overturo server at $BASE_URL — run `bin/dev` to enable")
    return f


@pytest.fixture(scope="module")
def jwks(fixture: IntegrationFixture):
    response = httpx.get(f"{fixture.base_url}/.well-known/jwks.json", timeout=5.0)
    response.raise_for_status()
    body = response.json()
    return [raw_ed25519_to_jwk(k["kid"], k["x"]) for k in body["keys"]]


def _client(fixture: IntegrationFixture) -> OverturoAuthorize:
    return OverturoAuthorize(
        grant_id=fixture.contract["grant"]["prefix_id"],
        agent_token=fixture.contract["agent_token"],
        dpop_key=fixture.dpop_key,
        iss=fixture.contract["iss"],
        api_base_url=fixture.contract["api_base_url"],
    )


def test_seed_contract_carries_required_fields(fixture):
    c = fixture.contract
    assert c["grant"]["prefix_id"].startswith("ath_")
    assert c["counterparty"]["bearer_token"].startswith("cpt_")
    assert c["agent_token"].count(".") == 2
    assert c["iss"].startswith(("http://", "https://"))
    assert c["api_base_url"].startswith(("http://", "https://"))


def test_authorize_round_trip_against_live_server(fixture):
    """Proves the Sprint-4 DPoP `ath` fix — without it this 401s."""
    client = _client(fixture)
    result = client.authorize(
        nonce=str(uuid.uuid4()), action="read", scope="profile"
    )
    assert result["decision"] == "allow"
    assert result["receipt"].count(".") == 2
    assert result["chronicle_id"].startswith("audit_rec_")


def test_receipts_verify_offline_against_live_jwks(fixture, jwks):
    client = _client(fixture)
    result = client.authorize(
        nonce=str(uuid.uuid4()),
        action="read",
        scope="profile",
        counterparty=fixture.contract["counterparty"]["identifier"],
    )
    assert result["decision"] == "allow"

    verified = verify_receipt_offline(
        result["receipt"],
        audience=fixture.contract["counterparty"]["identifier"],
        accepted_issuers=[fixture.contract["iss"]],
        jwks=jwks,
    )
    assert verified.valid is True
    assert verified.claims["grant_id"] == fixture.contract["grant"]["prefix_id"]


def test_scope_not_covered_surfaces_as_oap_error(fixture):
    client = _client(fixture)
    with pytest.raises(OapError) as excinfo:
        client.authorize(
            nonce=str(uuid.uuid4()),
            action="read",
            scope="admin",  # grant only allows profile + email
        )
    assert is_oap_error(excinfo.value)
    assert excinfo.value.reason_code == "scope_not_covered"
    assert excinfo.value.http_status == 403


def test_action_not_allowed_surfaces_as_oap_error(fixture):
    client = _client(fixture)
    with pytest.raises(OapError) as excinfo:
        client.authorize(
            nonce=str(uuid.uuid4()), action="delete", scope="profile"
        )
    assert excinfo.value.reason_code == "action_not_allowed"


def test_nonce_replay_is_rejected(fixture):
    client = _client(fixture)
    nonce = str(uuid.uuid4())
    first = client.authorize(nonce=nonce, action="read", scope="profile")
    assert first["decision"] == "allow"

    with pytest.raises(OapError) as excinfo:
        client.authorize(nonce=nonce, action="read", scope="profile")
    assert excinfo.value.reason_code == "nonce_replay"


def test_decode_endpoint_accepts_receipt_anonymously(fixture):
    client = _client(fixture)
    result = client.authorize(
        nonce=str(uuid.uuid4()), action="read", scope="profile"
    )
    assert result["decision"] == "allow"

    decoded = httpx.post(
        f"{fixture.base_url}/.well-known/overturo-decode",
        json={"receipt": result["receipt"]},
        timeout=5.0,
    ).json()
    assert decoded["structurally_valid"] is True
    assert decoded["signature_valid"] is True
    assert decoded["claims_preview"]["jti"] == result["jti"]


def test_peek_receipt_matches_server_decode(fixture):
    client = _client(fixture)
    result = client.authorize(
        nonce=str(uuid.uuid4()), action="read", scope="profile"
    )
    assert result["decision"] == "allow"

    peeked = peek_receipt(result["receipt"])
    assert peeked is not None
    assert peeked.claims["iss"] == fixture.contract["iss"]
    assert peeked.claims["grant_id"] == fixture.contract["grant"]["prefix_id"]
    assert peeked.header["typ"] == "oap+jwt"
