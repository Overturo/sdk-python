"""
discovery-document client.

Fetches `/.well-known/openid-configuration` on `create()` and caches:
  - `oversight_*_endpoint` URLs
  - `oap_protocol_versions_supported` (asserted against SDK version)
  - Closed-enum vocabularies for client-side validation
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..errors import OverturoConfigError, OverturoNetworkError
from .types import ResolvedEndpoints

DEFAULT_CACHE_TTL_SECONDS = 3600  # 1 hour


@dataclass
class Discovery:
    endpoints: ResolvedEndpoints
    supported_decisions: tuple[str, ...]
    supported_legal_bases: tuple[str, ...]
    supported_revocation_scopes: tuple[str, ...]
    supported_revocation_reasons: tuple[str, ...]
    supported_oap_versions: tuple[str, ...]
    _base_url: str = ""
    _fetched_at: float = field(default_factory=time.time)

    @classmethod
    async def fetch(
        cls,
        base_url: str,
        required_oap_version: str = "1.0",
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> Discovery:
        url = _join_url(base_url, "/.well-known/openid-configuration")

        owns_client = http_client is None
        if owns_client:
            http_client = httpx.AsyncClient(timeout=10.0)
        try:
            response = await http_client.get(url)
        except httpx.HTTPError as e:
            raise OverturoNetworkError(f"Discovery fetch failed: {e}") from e
        finally:
            if owns_client and http_client is not None:
                await http_client.aclose()

        if response.status_code >= 400:
            raise OverturoNetworkError(f"Discovery fetch returned HTTP {response.status_code}")

        try:
            doc = response.json()
        except ValueError as e:
            raise OverturoNetworkError(f"Discovery response is not valid JSON: {e}") from e

        supported_versions = tuple(doc.get("oap_protocol_versions_supported", []) or [])
        if required_oap_version not in supported_versions:
            raise OverturoConfigError(
                f"Server does NOT support OAP version {required_oap_version}; "
                f"advertised: {list(supported_versions)!r}",
            )

        endpoints = ResolvedEndpoints(
            attestation=_assert_url(doc, "oversight_attestation_endpoint"),
            heartbeat=_assert_url(doc, "oversight_attestation_heartbeat_endpoint"),
            escalation=_assert_url(doc, "oversight_escalation_endpoint"),
            revocation=_assert_url(doc, "oversight_revocation_endpoint"),
        )

        return cls(
            endpoints=endpoints,
            supported_decisions=tuple(
                doc.get("oversight_attestation_decisions_supported")
                or ("allow", "deny", "escalate")
            ),
            supported_legal_bases=tuple(
                doc.get("oversight_attestation_legal_bases_supported")
                or (
                    "consent",
                    "contract",
                    "legal_obligation",
                    "vital_interests",
                    "public_task",
                    "legitimate_interests",
                )
            ),
            supported_revocation_scopes=tuple(
                doc.get("oversight_revocation_scopes_supported")
                or ("attestation", "agent_class", "touchpoint")
            ),
            supported_revocation_reasons=tuple(
                doc.get("oversight_revocation_reasons_supported")
                or (
                    "compliance_failure",
                    "security_incident",
                    "data_subject_request",
                    "policy_change",
                    "other",
                )
            ),
            supported_oap_versions=supported_versions,
            _base_url=base_url,
            _fetched_at=time.time(),
        )

    @property
    def is_stale(self) -> bool:
        return time.time() - self._fetched_at > DEFAULT_CACHE_TTL_SECONDS

    async def refresh(self, http_client: httpx.AsyncClient | None = None) -> Discovery:
        return await Discovery.fetch(self._base_url, http_client=http_client)


def _assert_url(doc: dict[str, Any], key: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or not value:
        raise OverturoConfigError(
            f"Discovery document missing required field: {key}. Does the server support oversight?",
        )
    return value


def _join_url(base: str, path: str) -> str:
    return base.rstrip("/") + path
