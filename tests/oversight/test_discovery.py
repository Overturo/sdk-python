"""Discovery unit coverage."""

import httpx
import pytest
import respx

from overturo.errors import OverturoConfigError, OverturoNetworkError
from overturo.oversight.discovery import Discovery

BASE = "https://overturo.test"
DISCOVERY_URL = f"{BASE}/.well-known/openid-configuration"


def _discovery_doc(**overrides):
    doc = {
        "issuer": "https://overturo.us",
        "oap_protocol_versions_supported": ["1.0"],
        "oversight_attestation_endpoint": f"{BASE}/api/v1/oap/attestations",
        "oversight_attestation_heartbeat_endpoint": f"{BASE}/api/v1/oap/attestations/heartbeat",
        "oversight_escalation_endpoint": f"{BASE}/api/v1/oap/escalations",
        "oversight_revocation_endpoint": f"{BASE}/api/v1/oap/revocations",
        "oversight_attestation_decisions_supported": ["allow", "deny", "escalate"],
        "oversight_attestation_legal_bases_supported": ["consent", "contract"],
        "oversight_revocation_scopes_supported": ["attestation", "agent_class", "touchpoint"],
        "oversight_revocation_reasons_supported": ["security_incident", "policy_change"],
    }
    doc.update(overrides)
    return doc


@pytest.mark.asyncio
@respx.mock
async def test_fetches_discovery_document():
    respx.get(DISCOVERY_URL).respond(200, json=_discovery_doc())
    d = await Discovery.fetch(BASE)
    assert d.endpoints.attestation == f"{BASE}/api/v1/oap/attestations"
    assert d.endpoints.escalation == f"{BASE}/api/v1/oap/escalations"
    assert d.endpoints.heartbeat == f"{BASE}/api/v1/oap/attestations/heartbeat"
    assert d.endpoints.revocation == f"{BASE}/api/v1/oap/revocations"


@pytest.mark.asyncio
@respx.mock
async def test_caches_closed_enum_vocabularies():
    respx.get(DISCOVERY_URL).respond(200, json=_discovery_doc())
    d = await Discovery.fetch(BASE)
    assert d.supported_decisions == ("allow", "deny", "escalate")
    assert d.supported_legal_bases == ("consent", "contract")
    assert d.supported_revocation_scopes == ("attestation", "agent_class", "touchpoint")


@pytest.mark.asyncio
@respx.mock
async def test_rejects_when_required_oap_version_missing():
    respx.get(DISCOVERY_URL).respond(
        200, json=_discovery_doc(oap_protocol_versions_supported=["2.0"])
    )
    with pytest.raises(OverturoConfigError):
        await Discovery.fetch(BASE, required_oap_version="1.0")


@pytest.mark.asyncio
@respx.mock
async def test_rejects_when_required_endpoint_missing():
    doc = _discovery_doc()
    del doc["oversight_attestation_endpoint"]
    respx.get(DISCOVERY_URL).respond(200, json=doc)
    with pytest.raises(OverturoConfigError):
        await Discovery.fetch(BASE)


@pytest.mark.asyncio
@respx.mock
async def test_raises_network_error_on_non_2xx():
    respx.get(DISCOVERY_URL).respond(503, json={})
    with pytest.raises(OverturoNetworkError):
        await Discovery.fetch(BASE)


@pytest.mark.asyncio
@respx.mock
async def test_raises_network_error_on_transport_failure():
    respx.get(DISCOVERY_URL).mock(side_effect=httpx.ConnectError("ECONNREFUSED"))
    with pytest.raises(OverturoNetworkError):
        await Discovery.fetch(BASE)
