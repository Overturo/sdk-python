"""
HTTP client with retry + `Retry-After`.

Wraps an `httpx.AsyncClient` with:
  - Bearer auth (sourced from `TokenManager`)
  - Exponential backoff on 429 / 5xx (honors `Retry-After` header)
  - One-shot token-rotation retry on 401
  - Per-request timeout
  - SDK error class mapping by HTTP status
"""

from __future__ import annotations

import asyncio
import random
import re
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from ._logger import Logger
from .errors import (
    OverturoApiError,
    OverturoNetworkError,
    OverturoRateLimited,
    OverturoServerError,
    OverturoTimeoutError,
    OverturoUnauthorized,
    OverturoValidationError,
)
from .oversight.token import TokenManager


class HttpClient:
    def __init__(
        self,
        tokens: TokenManager,
        logger: Logger,
        *,
        client: httpx.AsyncClient | None = None,
        max_retries: int = 3,
        timeout_seconds: float = 30.0,
        owns_client: bool | None = None,
    ) -> None:
        """When `owns_client` is None, the SDK takes ownership iff it
        constructed the underlying httpx client (i.e., `client` was
        not supplied). Callers passing a shared `client` should pass
        `owns_client=False` so `close()` doesn't shut down a client
        the host app is still using.
        """
        self._tokens = tokens
        self._logger = logger
        self._max_retries = max_retries
        self._timeout = timeout_seconds
        self._owns_client = (client is None) if owns_client is None else owns_client
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds)

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def post_json(self, url: str, body: Any, extra_headers: dict | None = None) -> dict:
        response = await self._request("POST", url, body=body, extra_headers=extra_headers)
        if response.status_code == 204:
            return {}
        return response.json()

    async def get_json(
        self,
        url: str,
        *,
        params: dict | None = None,
        extra_headers: dict | None = None,
    ) -> dict:
        """GET helper that returns parsed JSON.

        Goes through the standard retry / token-rotation loop so 401 →
        refresh + retry, 429 / 5xx → exponential back-off all work.
        """
        response = await self._request(
            "GET", url, body=None, extra_headers=extra_headers, params=params
        )
        if response.status_code == 204:
            return {}
        return response.json()

    async def long_poll_get(
        self,
        url: str,
        *,
        params: dict | None = None,
        extra_headers: dict | None = None,
        timeout: float = 35.0,
    ) -> dict:
        """long-poll GET with an extended per-request timeout.

        The server holds for up to 30 s; the client must
        allow a few extra seconds for in-flight network + JSON
        serialisation. Bypasses the standard exponential back-off loop
        for 200 responses (a 200 with `wait_again: true` is the
        success case and the caller's outer loop handles re-issue).
        4xx / 5xx still raise the mapped SDK error.
        """
        headers = {
            "Authorization": f"Bearer {self._tokens.current()}",
            "Accept": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = await self._client.request(
                "GET",
                url,
                params=params,
                headers=headers,
                timeout=timeout,
            )
        except httpx.TimeoutException as e:
            raise OverturoTimeoutError(f"Long-poll to {url} timed out: {e}") from e
        except httpx.HTTPError as e:
            raise OverturoNetworkError(f"Long-poll network error on {url}: {e}") from e

        if 200 <= response.status_code < 300:
            if response.status_code == 204:
                return {}
            return response.json()

        raise self._raise_error(response, url)

    async def heartbeat(self, url: str) -> None:
        await self._request("POST", url, body={})

    async def _request(
        self,
        method: str,
        url: str,
        body: Any = None,
        extra_headers: dict | None = None,
        params: dict | None = None,
    ) -> httpx.Response:
        attempt = 0
        token_retried = False

        while True:
            attempt += 1
            try:
                response = await self._send(method, url, body, extra_headers, params)
            except OverturoTimeoutError:
                if attempt > self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            except OverturoNetworkError:
                if attempt > self._max_retries:
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))
                continue

            if 200 <= response.status_code < 300:
                return response

            if response.status_code == 401 and not token_retried:
                rotated = await self._tokens.refresh()
                if rotated:
                    self._logger.info("Token rotated after 401; retrying request once")
                    token_retried = True
                    attempt = 0
                    continue

            if response.status_code == 429 or response.status_code >= 500:
                if attempt > self._max_retries:
                    raise self._raise_error(response, url)
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                wait = retry_after if retry_after is not None else _backoff_seconds(attempt)
                self._logger.warn(
                    f"HTTP {response.status_code} on {url}; backing off {wait:.2f}s "
                    f"(attempt {attempt}/{self._max_retries})"
                )
                await asyncio.sleep(wait)
                continue

            raise self._raise_error(response, url)

    async def _send(
        self,
        method: str,
        url: str,
        body: Any,
        extra_headers: dict | None,
        params: dict | None = None,
    ) -> httpx.Response:
        headers = {
            "Authorization": f"Bearer {self._tokens.current()}",
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        try:
            return await self._client.request(
                method,
                url,
                json=body,
                headers=headers,
                params=params,
            )
        except httpx.TimeoutException as e:
            raise OverturoTimeoutError(f"Request to {url} timed out: {e}") from e
        except httpx.HTTPError as e:
            raise OverturoNetworkError(f"Network error on {url}: {e}") from e

    def _raise_error(self, response: httpx.Response, url: str) -> OverturoApiError:
        request_id = response.headers.get("x-request-id")
        body: dict = {}
        try:
            body = response.json()
        except ValueError:
            pass

        error = body.get("error") if isinstance(body, dict) else None
        reason_code = error.get("reason_code") if isinstance(error, dict) else None
        message = (
            error.get("message")
            if isinstance(error, dict)
            else f"HTTP {response.status_code} on {url}"
        )
        detail = error.get("detail") if isinstance(error, dict) else None

        kwargs = {
            "reason_code": reason_code,
            "detail": detail,
            "request_id": request_id,
        }

        if response.status_code == 401:
            raise OverturoUnauthorized(message, http_status=401, **kwargs)
        if response.status_code in (400, 403, 404, 409, 422):
            raise OverturoValidationError(message, http_status=response.status_code, **kwargs)
        if response.status_code == 429:
            retry_after = _parse_retry_after(response.headers.get("retry-after"))
            raise OverturoRateLimited(
                message,
                retry_after_seconds=int(retry_after) if retry_after is not None else None,
                **kwargs,
            )
        if response.status_code >= 500:
            raise OverturoServerError(message, http_status=response.status_code, **kwargs)
        raise OverturoApiError(message, http_status=response.status_code, **kwargs)


# ── helpers ────────────────────────────────────────────────────────


def _backoff_seconds(attempt: int) -> float:
    base = min(1.0 * 2 ** (attempt - 1), 30.0)
    return base + random.uniform(0, 0.25)


def _parse_retry_after(header: str | None) -> float | None:
    if not header:
        return None
    header = header.strip()
    if re.fullmatch(r"\d+", header):
        return float(header)
    try:
        dt = parsedate_to_datetime(header)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    import datetime as _dt

    now = _dt.datetime.now(tz=dt.tzinfo) if dt.tzinfo else _dt.datetime.now()
    delta = (dt - now).total_seconds()
    return max(0.0, delta)
