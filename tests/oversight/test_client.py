"""OverturoOversight orchestration coverage."""

import json

import pytest
import respx

from overturo import OverturoOversight
from overturo.errors import OverturoConfigError

BASE = "https://overturo.test"
DISCOVERY_URL = f"{BASE}/.well-known/openid-configuration"


def _discovery_doc():
    return {
        "issuer": "https://overturo.us",
        "oap_protocol_versions_supported": ["1.0"],
        "oversight_attestation_endpoint": f"{BASE}/api/v1/oap/attestations",
        "oversight_attestation_heartbeat_endpoint": f"{BASE}/api/v1/oap/attestations/heartbeat",
        "oversight_escalation_endpoint": f"{BASE}/api/v1/oap/escalations",
        "oversight_revocation_endpoint": f"{BASE}/api/v1/oap/revocations",
        "oversight_attestation_decisions_supported": ["allow", "deny", "escalate"],
        "oversight_attestation_legal_bases_supported": [
            "consent",
            "contract",
            "legitimate_interests",
        ],
        "oversight_revocation_scopes_supported": ["attestation", "agent_class", "touchpoint"],
        "oversight_revocation_reasons_supported": ["security_incident", "policy_change"],
    }


@pytest.fixture
async def client_no_heartbeat():
    """Builds a client with heartbeat disabled + mocked discovery."""
    with respx.mock(assert_all_called=False) as mock_router:
        mock_router.get(DISCOVERY_URL).respond(200, json=_discovery_doc())
        client = await OverturoOversight.create(
            base_url=BASE,
            token="tat_dev_xxx",
            touchpoint_id="tp_dev_yyy",
            heartbeat_enabled=False,
        )
        yield client, mock_router
        await client.close()


# ── config validation ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_requires_base_url():
    with pytest.raises(OverturoConfigError):
        await OverturoOversight.create(
            base_url="", token="t", touchpoint_id="tp", heartbeat_enabled=False
        )


@pytest.mark.asyncio
async def test_create_requires_token():
    with pytest.raises(OverturoConfigError):
        await OverturoOversight.create(
            base_url=BASE, token="", touchpoint_id="tp", heartbeat_enabled=False
        )


@pytest.mark.asyncio
async def test_create_requires_touchpoint_id():
    with pytest.raises(OverturoConfigError):
        await OverturoOversight.create(
            base_url=BASE, token="t", touchpoint_id="", heartbeat_enabled=False
        )


@pytest.mark.asyncio
async def test_create_rejects_non_http_base_url():
    with pytest.raises(OverturoConfigError):
        await OverturoOversight.create(
            base_url="file:///etc",
            token="t",
            touchpoint_id="tp",
            heartbeat_enabled=False,
        )


# ── attest happy path ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_attest_posts_body_and_returns_parsed_result(client_no_heartbeat):
    client, router = client_no_heartbeat
    attest_route = router.post(f"{BASE}/api/v1/oap/attestations").respond(
        201,
        json={
            "attestation": {
                "id": "att_dev_xyz",
                "received_at": "2026-06-01T12:00:00.001Z",
                "sequence_number": 1,
                "decision": "allow",
            },
            "receipt": "eyJhbGc.eyJjbGFpbXM.signature",
        },
    )

    result = await client.attest(
        agent_class="data_export_agent",
        action_class="mcp_tool_call",
        decision="allow",
        legal_basis="consent",
        context={"policy_ref": "p"},
        evidence_digest="a" * 64,
    )

    assert result.attestation_id == "att_dev_xyz"
    assert result.receipt == "eyJhbGc.eyJjbGFpbXM.signature"
    assert result.idempotent_replay is False

    request_body = json.loads(attest_route.calls[0].request.content)
    assert request_body["agent_class"] == "data_export_agent"
    assert request_body["action_class"] == "mcp_tool_call"
    assert request_body["decision"] == "allow"
    assert request_body["legal_basis"] == "consent"
    assert request_body["touchpoint_id"] == "tp_dev_yyy"
    assert request_body["sequence_number"] == 1


@pytest.mark.asyncio
async def test_attest_invokes_on_sequence_update():
    captured: list[int] = []
    with respx.mock(assert_all_called=False) as router:
        router.get(DISCOVERY_URL).respond(200, json=_discovery_doc())
        router.post(f"{BASE}/api/v1/oap/attestations").respond(
            201,
            json={
                "attestation": {
                    "id": "x",
                    "received_at": "t",
                    "sequence_number": 5,
                    "decision": "allow",
                },
                "receipt": None,
            },
        )

        async def on_update(seq: int) -> None:
            captured.append(seq)

        client = await OverturoOversight.create(
            base_url=BASE,
            token="tat_dev_xxx",
            touchpoint_id="tp_dev_yyy",
            heartbeat_enabled=False,
            start_sequence=5,
            on_sequence_update=on_update,
        )

        await client.attest(
            agent_class="x",
            action_class="y",
            decision="allow",
            legal_basis="consent",
            context={},
            evidence_digest="a" * 64,
        )
        await client.close()

    assert captured == [5]


# ── client-side validation ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_attest_rejects_unsupported_decision_before_wire(client_no_heartbeat):
    client, _ = client_no_heartbeat
    with pytest.raises(OverturoConfigError):
        await client.attest(
            agent_class="x",
            action_class="y",
            decision="rogue",  # type: ignore[arg-type]
            legal_basis="consent",
            context={},
            evidence_digest="a" * 64,
        )


@pytest.mark.asyncio
async def test_attest_rejects_unsupported_legal_basis_before_wire(client_no_heartbeat):
    client, _ = client_no_heartbeat
    with pytest.raises(OverturoConfigError):
        await client.attest(
            agent_class="x",
            action_class="y",
            decision="allow",
            legal_basis="rogue",  # type: ignore[arg-type]
            context={},
            evidence_digest="a" * 64,
        )


# ── revoke ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_posts_body_and_returns_parsed_result(client_no_heartbeat):
    client, router = client_no_heartbeat
    revoke_route = router.post(f"{BASE}/api/v1/oap/revocations").respond(
        201,
        json={
            "revocation": {
                "id": "rev_dev_xyz",
                "scope": "agent_class",
                "affected_attestation_count": 7,
                "triggered_at": "2026-06-01T12:00:00.001Z",
                "estimated_propagation_complete_at": "2026-06-01T12:00:30.001Z",
            }
        },
    )

    result = await client.revoke(
        scope="agent_class",
        agent_class="data_export_agent",
        reason="security_incident",
        idempotency_key="k1",
    )

    assert result.revocation_id == "rev_dev_xyz"
    assert result.affected_attestation_count == 7

    request = revoke_route.calls[0].request
    assert request.headers["Idempotency-Key"] == "k1"


@pytest.mark.asyncio
async def test_revoke_rejects_unsupported_scope(client_no_heartbeat):
    client, _ = client_no_heartbeat
    with pytest.raises(OverturoConfigError):
        await client.revoke(scope="rogue", reason="security_incident")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_revoke_rejects_unsupported_reason(client_no_heartbeat):
    client, _ = client_no_heartbeat
    with pytest.raises(OverturoConfigError):
        await client.revoke(scope="touchpoint", reason="rogue")  # type: ignore[arg-type]
