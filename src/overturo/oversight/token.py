"""
token-rotation manager.

On 401 the SDK calls `refresh()` to read a new token from either the
configured `token_provider` callback or the `OVERTURO_ATTESTER_TOKEN`
env var. If the value changed, the HTTP client retries the failed
request once. The server's two-slot rotation (24h overlap) makes the gap
invisible when the host app updates env within the overlap window.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Awaitable, Callable


class TokenManager:
    def __init__(
        self,
        initial: str,
        token_provider: Callable[[], str | Awaitable[str]] | None = None,
    ) -> None:
        self._current = initial
        self._provider = token_provider

    def current(self) -> str:
        return self._current

    async def refresh(self) -> bool:
        """Returns True when the token changed (caller should retry once)."""
        if self._provider is not None:
            result = self._provider()
            if inspect.isawaitable(result):
                next_token = await result
            else:
                next_token = result
        else:
            next_token = os.environ.get("OVERTURO_ATTESTER_TOKEN", self._current)

        if next_token == self._current:
            return False
        self._current = next_token
        return True
