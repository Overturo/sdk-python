"""High-level OAP authorize client."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx

from ..errors import OapApprovalRequired, OapError
from ..models import TokenInfo
from ._jurisdiction import jurisdiction_context
from .dpop import DpopKeyPair, sign_dpop_proof

if TYPE_CHECKING:
    # Imported lazily inside the methods that need it at runtime so the
    # SDK's import graph stays acyclic; bring it in for type-checking
    # so the return annotations on `authorize_typed` /
    # `authorize_with_decomposition` resolve.
    from ..models import OverturoDecision


class OverturoAuthorize:
    """Synchronous OAP authorize client.

    For async callers, swap `httpx.Client` for `httpx.AsyncClient` and
    `await` the request methods — the OAP wire calls have no
    server-streamed bodies, so the sync surface is sufficient for the
    common case.

    Args:
        grant_id: OAP grant prefix_id (e.g. ``ath_us_AbC123…``).
        agent_token: Bearer token returned at grant creation.
        dpop_key: Long-lived DPoP keypair bound to the grant.
        iss: Regional issuer base URL (no trailing slash needed).
        http_client: Optional custom httpx.Client (for retries / mocks /
            shared connection pools).
        timeout: Request timeout in seconds (default 5).
    """

    def __init__(
        self,
        *,
        grant_id: str,
        agent_token: str,
        dpop_key: DpopKeyPair,
        iss: str,
        api_base_url: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        if not grant_id:
            raise ValueError("OverturoAuthorize: grant_id is required")
        if not agent_token:
            raise ValueError("OverturoAuthorize: agent_token is required")
        if not iss:
            raise ValueError("OverturoAuthorize: iss is required")

        self._grant_id = grant_id
        self._agent_token = agent_token
        self._dpop_key = dpop_key
        self._iss = iss.rstrip("/")
        # In production iss is also the API host; tests against a local
        # server pass an explicit api_base_url so the receipt's iss
        # claim and the actual HTTP origin can diverge.
        self._api_base_url = (api_base_url or iss).rstrip("/")
        self._timeout = timeout
        self._own_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)

    def authorize(
        self,
        *,
        nonce: str,
        action: str,
        scope: str,
        value: str | None = None,
        currency: str | None = None,
        counterparty: str | None = None,
        context: dict[str, Any] | None = None,
        jurisdiction: str | None = None,
    ) -> dict[str, Any]:
        """Submit an authorize request.

        Returns the JSON-decoded response body on ``allow``. Raises
        :class:`OapError` (or a typed subclass) on deny / 4xx / 5xx.

        **v1.2.0 behaviour change:** when the server returns
        ``decision == "escalate"``, this method now raises
        :class:`OapApprovalRequired` instead of returning the dict. The
        exception carries ``decision_url`` + ``session_token`` so the
        backend can deliver the approval link to the principal through
        whatever channel it owns. Callers needing the previous return
        shape should migrate to :meth:`authorize_typed`, which returns
        an :class:`OverturoDecision` (with ``.decision == "escalate"``)
        on the same wire response.
        """
        url = f"{self._api_base_url}/api/v1/grants/{self._grant_id}/authorize"
        payload: dict[str, Any] = {"nonce": nonce, "action": action, "scope": scope}
        if value is not None:
            payload["value"] = value
        if currency is not None:
            payload["currency"] = currency
        if counterparty is not None:
            payload["counterparty"] = counterparty
        # map the public ``jurisdiction`` onto the authorize context.
        if jurisdiction is not None:
            payload["context"] = jurisdiction_context(jurisdiction, context)
        elif context is not None:
            payload["context"] = context

        raw = self._signed_request("POST", url, json_body=payload)
        if isinstance(raw, dict) and raw.get("decision") == "escalate":
            envelope = {
                "error": {
                    "reason_code": "approval_required",
                    "message": "Approval required",
                    "escalation": raw.get("escalation", {}) or {},
                }
            }
            raise OapApprovalRequired.from_envelope(envelope, status=None)
        return raw

    # ── typed authorize surfaces ─────

    def authorize_typed(
        self,
        *,
        nonce: str,
        action: str,
        scope: str,
        value: str | None = None,
        currency: str | None = None,
        counterparty: str | None = None,
        context: dict[str, Any] | None = None,
        mode_hint: str | None = None,
        jurisdiction: str | None = None,
    ) -> OverturoDecision:
        """Same as :meth:`authorize` but returns a typed
        :class:`OverturoDecision` instead of an untyped dict.

        Without decomposition: ``decision.block_invocations`` is empty.
        """
        raw = self._authorize_call(
            nonce=nonce,
            action=action,
            scope=scope,
            value=value,
            currency=currency,
            counterparty=counterparty,
            context=context,
            mode_hint=mode_hint,
            decompose=False,
            jurisdiction=jurisdiction,
        )
        from ..models import parse_decision

        return parse_decision(raw)

    def authorize_with_decomposition(
        self,
        *,
        nonce: str,
        action: str,
        scope: str,
        value: str | None = None,
        currency: str | None = None,
        counterparty: str | None = None,
        context: dict[str, Any] | None = None,
        mode_hint: str | None = None,
        jurisdiction: str | None = None,
    ) -> OverturoDecision:
        """Authorize with the ``Overturo-Decomposed: 1`` header set.

        The returned :class:`OverturoDecision` carries the per-position
        ``block_invocations`` tuple in addition to the standard
        allow/escalate/deny fields.
        """
        raw = self._authorize_call(
            nonce=nonce,
            action=action,
            scope=scope,
            value=value,
            currency=currency,
            counterparty=counterparty,
            context=context,
            mode_hint=mode_hint,
            decompose=True,
            jurisdiction=jurisdiction,
        )
        from ..models import parse_decision

        return parse_decision(raw)

    _ALLOWED_MODE_HINTS = frozenset({"conductor", "oversight", "hybrid"})

    def _authorize_call(
        self,
        *,
        nonce: str,
        action: str,
        scope: str,
        value: str | None,
        currency: str | None,
        counterparty: str | None,
        context: dict[str, Any] | None,
        mode_hint: str | None,
        decompose: bool,
        jurisdiction: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self._api_base_url}/api/v1/grants/{self._grant_id}/authorize"
        payload: dict[str, Any] = {"nonce": nonce, "action": action, "scope": scope}
        if value is not None:
            payload["value"] = value
        if currency is not None:
            payload["currency"] = currency
        if counterparty is not None:
            payload["counterparty"] = counterparty
        # map the public ``jurisdiction`` onto the authorize context.
        if jurisdiction is not None:
            payload["context"] = jurisdiction_context(jurisdiction, context)
        elif context is not None:
            payload["context"] = context
        if mode_hint is not None:
            if mode_hint not in self._ALLOWED_MODE_HINTS:
                raise ValueError(f"invalid mode_hint: {mode_hint!r}")
            payload["mode_hint"] = mode_hint
        extra_headers: dict[str, str] = {}
        if decompose:
            extra_headers["Overturo-Decomposed"] = "1"
        return self._signed_request(
            "POST",
            url,
            json_body=payload,
            extra_headers=extra_headers or None,
        )

    def refresh_token(self) -> TokenInfo:
        """Refresh the agent token. Updates the in-memory copy so
        subsequent authorize calls use the fresh token automatically."""
        url = f"{self._api_base_url}/api/v1/grants/{self._grant_id}/token"
        body = self._signed_request("POST", url)
        info = TokenInfo(
            agent_token=body["agent_token"],
            agent_token_expires_at=body["agent_token_expires_at"],
            iss=body.get("iss", self._iss),
            oap_ver=body.get("oap_ver", "1.0"),
        )
        self._agent_token = info.agent_token
        return info

    @property
    def current_token(self) -> str:
        """Read-only view of the current bearer. Useful for log/test
        inspection after a refresh."""
        return self._agent_token

    def close(self) -> None:
        """Close the owned HTTP client. Safe to call twice; no-op when
        the caller supplied their own client."""
        if self._own_client:
            self._http.close()

    def __enter__(self) -> OverturoAuthorize:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ── internals ──────────────────────────────────────────────────

    def _signed_request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        dpop = sign_dpop_proof(
            self._dpop_key,
            htm=method,
            htu=url,
            access_token=self._agent_token,
        )
        headers = {
            "Authorization": f"DPoP {self._agent_token}",
            "DPoP": dpop,
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = self._http.request(
                method,
                url,
                headers=headers,
                params=params,
                content=json.dumps(json_body) if json_body is not None else None,
            )
        except httpx.RequestError as exc:
            raise OapError(
                reason_code="internal_error",
                message=f"Network failure calling {url}: {exc}",
                http_status=None,
            ) from exc

        return self._parse(response)

    @staticmethod
    def _parse(response: httpx.Response) -> dict[str, Any]:
        text = response.text or ""
        if response.is_success:
            return json.loads(text) if text else {}

        try:
            envelope = json.loads(text) if text else {}
        except json.JSONDecodeError:
            envelope = {}

        if isinstance(envelope, dict) and "error" in envelope:
            raise OapError.from_envelope(envelope, status=response.status_code)

        # Non-envelope body (proxy 502, etc.) — synthesise so callers see
        # one consistent exception type.
        raise OapError(
            reason_code="internal_error",
            message=(f"Unexpected HTTP {response.status_code} from OAP authorize endpoint"),
            http_status=response.status_code,
            detail={"body": text[:512]},
        )
