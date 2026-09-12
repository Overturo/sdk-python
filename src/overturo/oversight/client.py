"""
main SDK class.

Orchestrates Discovery + TokenManager + SequenceManager +
HeartbeatManager + HttpClient. `create()` is an async classmethod
because the discovery fetch is async.

Sync wrappers (`attest_sync`, `escalate_sync`, `revoke_sync`,
`close_sync`) are provided for non-async callers via `asyncio.run`
on a fresh event loop. These do NOT keep a heartbeat task running —
sync hosts must invoke the heartbeat manually.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .._http import HttpClient
from .._logger import Logger
from ..errors import OverturoConfigError
from .discovery import Discovery
from .heartbeat import HeartbeatManager
from .sequence import SequenceManager
from .token import TokenManager
from .types import (
    AttestResult,
    Decision,
    EscalateResult,
    LegalBasis,
    RevocationReason,
    RevocationScope,
    RevokeResult,
)

SDK_DEFAULT_OAP_VERSION = "1.0"


class OverturoOversight:
    def __init__(
        self,
        *,
        http: HttpClient,
        discovery: Discovery,
        tokens: TokenManager,
        sequence: SequenceManager,
        heartbeat: HeartbeatManager | None,
        logger: Logger,
        touchpoint_id: str,
    ) -> None:
        self._http = http
        self._discovery = discovery
        self._tokens = tokens
        self._sequence = sequence
        self._heartbeat = heartbeat
        self._logger = logger
        self._touchpoint_id = touchpoint_id

    # ── factory ────────────────────────────────────────────────────

    @classmethod
    async def create(
        cls,
        *,
        base_url: str,
        token: str,
        touchpoint_id: str,
        token_provider: Callable[[], str | Awaitable[str]] | None = None,
        heartbeat_enabled: bool = True,
        heartbeat_cadence_seconds: float = 60.0,
        start_sequence: int | None = None,
        on_sequence_update: Callable[[int], None | Awaitable[None]] | None = None,
        max_retries: int = 3,
        timeout_seconds: float = 30.0,
        log_level: str = "warn",
        http_client: httpx.AsyncClient | None = None,
        required_oap_version: str = SDK_DEFAULT_OAP_VERSION,
    ) -> OverturoOversight:
        _validate_config(base_url=base_url, token=token, touchpoint_id=touchpoint_id)

        logger = Logger(log_level)
        tokens = TokenManager(token, token_provider)
        discovery = await Discovery.fetch(base_url, required_oap_version, http_client=http_client)

        # Track ownership explicitly: when the caller passes a client,
        # they own it (we won't aclose() it on close()).
        owns_client = http_client is None
        if http_client is None:
            http_client = httpx.AsyncClient(timeout=timeout_seconds)

        http = HttpClient(
            tokens,
            logger,
            client=http_client,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            owns_client=owns_client,
        )

        if start_sequence is None:
            logger.warn(
                "Constructed without `start_sequence`; SDK will begin at sequence_number=1. "
                "Pass the persisted value from your durable store to avoid "
                "`attestation.gap_detected` on restart."
            )
        sequence = SequenceManager(start_sequence or 1, on_sequence_update)

        heartbeat: HeartbeatManager | None = None
        if heartbeat_enabled:
            heartbeat = HeartbeatManager(
                http, discovery.endpoints.heartbeat, heartbeat_cadence_seconds, logger
            )
            heartbeat.start()

        return cls(
            http=http,
            discovery=discovery,
            tokens=tokens,
            sequence=sequence,
            heartbeat=heartbeat,
            logger=logger,
            touchpoint_id=touchpoint_id,
        )

    # ── public methods ─────────────────────────────────────────────

    async def attest(
        self,
        *,
        agent_class: str,
        action_class: str,
        decision: Decision,
        legal_basis: LegalBasis,
        context: dict[str, Any],
        evidence_digest: str,
        attestation_id: str | None = None,
        decided_at: str | None = None,
    ) -> AttestResult:
        self._assert_decision_supported(decision)
        self._assert_legal_basis_supported(legal_basis)
        self._assert_evidence_digest_format(evidence_digest)

        seq = self._sequence.next()
        body = {
            "attestation_id": attestation_id or f"att-sdk-oversight-{uuid.uuid4()}",
            "touchpoint_id": self._touchpoint_id,
            "agent_class": agent_class,
            "action_class": action_class,
            "decision": decision,
            "decided_at": decided_at or dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            "sequence_number": seq,
            "legal_basis": legal_basis,
            "evidence_digest": evidence_digest,
            "context": context,
        }

        response = await self._http.post_json(self._discovery.endpoints.attestation, body)
        await self._sequence.persist(seq)

        a = response.get("attestation", {})
        return AttestResult(
            attestation_id=a.get("id", ""),
            received_at=a.get("received_at", ""),
            sequence_number=int(a.get("sequence_number", seq)),
            decision=a.get("decision", decision),
            receipt=response.get("receipt"),
            idempotent_replay=bool(a.get("idempotent_replay", False)),
        )

    async def escalate(
        self,
        *,
        agent_class: str,
        action_class: str,
        legal_basis: LegalBasis,
        context: dict[str, Any],
        evidence_digest: str,
        proposed_action: dict[str, Any],
        approval_ttl_hours: float | None = None,
        required_signers: list[str] | None = None,
        idempotency_key: str | None = None,
    ) -> EscalateResult:
        attest_result = await self.attest(
            agent_class=agent_class,
            action_class=action_class,
            decision="escalate",
            legal_basis=legal_basis,
            context=context,
            evidence_digest=evidence_digest,
        )

        body: dict[str, Any] = {
            "attestation_id": attest_result.attestation_id,
            "touchpoint_id": self._touchpoint_id,
            "context_class": action_class,
            "proposed_action": proposed_action,
        }
        if approval_ttl_hours is not None:
            body["approval_ttl_hours"] = approval_ttl_hours
        if required_signers is not None:
            body["required_signers"] = required_signers

        extra_headers: dict[str, str] = {}
        if idempotency_key:
            extra_headers["Idempotency-Key"] = idempotency_key

        response = await self._http.post_json(
            self._discovery.endpoints.escalation, body, extra_headers=extra_headers
        )
        e = response.get("escalation", {})
        return EscalateResult(
            escalation_id=e.get("id", ""),
            attestation_id=attest_result.attestation_id,
            approval_url=e.get("approval_url", ""),
            context_class=e.get("context_class", action_class),
            status=e.get("status", ""),
            idempotent_replay=bool(e.get("idempotent_replay", False)),
        )

    async def revoke(
        self,
        *,
        scope: RevocationScope,
        reason: RevocationReason,
        agent_class: str | None = None,
        attestation_id: str | None = None,
        reason_detail: str | None = None,
        idempotency_key: str | None = None,
    ) -> RevokeResult:
        self._assert_revocation_scope_supported(scope)
        self._assert_revocation_reason_supported(reason)

        body: dict[str, Any] = {
            "scope": scope,
            "touchpoint_id": self._touchpoint_id,
            "reason": reason,
        }
        if agent_class is not None:
            body["agent_class"] = agent_class
        if attestation_id is not None:
            body["attestation_id"] = attestation_id
        if reason_detail is not None:
            body["reason_detail"] = reason_detail

        extra_headers: dict[str, str] = {}
        if idempotency_key:
            extra_headers["Idempotency-Key"] = idempotency_key

        response = await self._http.post_json(
            self._discovery.endpoints.revocation, body, extra_headers=extra_headers
        )
        r = response.get("revocation", {})
        return RevokeResult(
            revocation_id=r.get("id", ""),
            scope=r.get("scope", scope),
            affected_attestation_count=int(r.get("affected_attestation_count", 0)),
            triggered_at=r.get("triggered_at", ""),
            estimated_propagation_complete_at=r.get("estimated_propagation_complete_at", ""),
            idempotent_replay=bool(r.get("idempotent_replay", False)),
        )

    async def close(self) -> None:
        if self._heartbeat is not None:
            await self._heartbeat.stop()
        await self._http.close()

    # ── sync wrappers ──────────────────────────────────────────────

    def attest_sync(self, **kwargs: Any) -> AttestResult:
        return asyncio.run(self.attest(**kwargs))

    def escalate_sync(self, **kwargs: Any) -> EscalateResult:
        return asyncio.run(self.escalate(**kwargs))

    def revoke_sync(self, **kwargs: Any) -> RevokeResult:
        return asyncio.run(self.revoke(**kwargs))

    def close_sync(self) -> None:
        asyncio.run(self.close())

    # ── internals ──────────────────────────────────────────────────

    def _assert_decision_supported(self, d: str) -> None:
        if d not in self._discovery.supported_decisions:
            raise OverturoConfigError(
                f"Unsupported decision {d!r}; server advertises {list(self._discovery.supported_decisions)!r}"
            )

    # G10 — client-side validate the digest format BEFORE hitting the
    # wire. The server's attestation model validates /^[a-f0-9]{64}$/;
    # catching it here lets the caller see "did I forget to call
    # `evidence_digest()`?" instead of a 422 round-trip.
    _EVIDENCE_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")

    def _assert_evidence_digest_format(self, d: str) -> None:
        if not isinstance(d, str) or not self._EVIDENCE_DIGEST_PATTERN.match(d):
            raise OverturoConfigError(
                "evidence_digest must be 64 lowercase hex chars (SHA-256). "
                "Use the `evidence_digest(input, output)` helper from "
                "`overturo` to compute it correctly."
            )

    def _assert_legal_basis_supported(self, lb: str) -> None:
        if lb not in self._discovery.supported_legal_bases:
            raise OverturoConfigError(
                f"Unsupported legal_basis {lb!r}; server advertises {list(self._discovery.supported_legal_bases)!r}"
            )

    def _assert_revocation_scope_supported(self, s: str) -> None:
        if s not in self._discovery.supported_revocation_scopes:
            raise OverturoConfigError(
                f"Unsupported revocation scope {s!r}; server advertises {list(self._discovery.supported_revocation_scopes)!r}"
            )

    def _assert_revocation_reason_supported(self, r: str) -> None:
        if r not in self._discovery.supported_revocation_reasons:
            raise OverturoConfigError(
                f"Unsupported revocation reason {r!r}; server advertises {list(self._discovery.supported_revocation_reasons)!r}"
            )


def _validate_config(*, base_url: str, token: str, touchpoint_id: str) -> None:
    if not base_url:
        raise OverturoConfigError("base_url is required")
    if not token:
        raise OverturoConfigError("token is required")
    if not touchpoint_id:
        raise OverturoConfigError("touchpoint_id is required")
    if not base_url.startswith("http"):
        raise OverturoConfigError(f"base_url must start with http(s)://; got {base_url}")
