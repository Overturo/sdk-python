"""Seed loader for the OAP journey scenario.

Hits the Overturo server's /internal/scenarios/seed endpoint and reconstructs
the matching DPoP keypair so the integration suite can sign real proofs
against the live OAP service. Returns None when the server is unreachable
so tests can skip gracefully.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from overturo.authorize.dpop import DpopKeyPair
from overturo.authorize.receipt import b64url_decode, b64url_encode

BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")
SCENARIO_NAME = "journeys/oap_agent_workflow"


@dataclass
class IntegrationFixture:
    base_url: str
    contract: dict[str, Any]
    dpop_key: DpopKeyPair


def load_oap_scenario() -> IntegrationFixture | None:
    """Seed the scenario and rebuild the DPoP keypair, or None on
    connection failure (server not running)."""
    try:
        response = httpx.post(
            f"{BASE_URL}/internal/scenarios/seed",
            json={"scenario": SCENARIO_NAME},
            headers={"X-Scenario-Engine": "true"},
            timeout=5.0,
        )
    except httpx.RequestError:
        return None

    if not response.is_success:
        raise RuntimeError(
            f"scenario seed failed: HTTP {response.status_code} {response.text[:200]}"
        )

    payload = response.json()
    contract = payload["data"]
    dpop_key = _rebuild_dpop_key(contract["dpop"]["private_seed_b64url"])
    return IntegrationFixture(base_url=BASE_URL, contract=contract, dpop_key=dpop_key)


def _rebuild_dpop_key(seed_b64url: str) -> DpopKeyPair:
    seed = b64url_decode(seed_b64url)
    if len(seed) != 32:
        raise ValueError(
            f"OAP scenario emitted a non-Ed25519 seed (got {len(seed)} bytes)"
        )
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw = priv.public_key().public_bytes_raw()
    return DpopKeyPair(
        private_key=priv,
        public_jwk={
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url_encode(pub_raw),
        },
    )
