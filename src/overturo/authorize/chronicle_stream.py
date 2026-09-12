"""Chronicle stream iterator.

Polls ``GET /api/v1/oap/chronicles`` and yields raw chronicle entries.
Manages cursor advancement and exponential idle back-off.

Usage::

    from overturo import OverturoAuthorize, OverturoChronicleStream

    stream = OverturoChronicleStream(client, event_type_prefix="conductor.")
    for event in stream:
        handle(event)
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any

__all__ = ["OverturoChronicleStream"]


_ALLOWED_PREFIXES = frozenset({"conductor.", "oap."})


class OverturoChronicleStream:
    DEFAULT_POLL = 5.0
    DEFAULT_BACKOFF_MAX = 30.0

    def __init__(
        self,
        client: Any,  # OverturoAuthorize — avoid circular import
        *,
        event_type_prefix: str,
        since: str | None = None,
        poll_interval: float = DEFAULT_POLL,
        max_backoff: float = DEFAULT_BACKOFF_MAX,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if event_type_prefix not in _ALLOWED_PREFIXES:
            raise ValueError(
                f"event_type_prefix must be one of {sorted(_ALLOWED_PREFIXES)}; "
                f"got {event_type_prefix!r}"
            )
        self._client = client
        self._prefix = event_type_prefix
        self._cursor = since
        self._poll_interval = poll_interval
        self._max_backoff = max_backoff
        self._sleep = sleep_fn

    def __iter__(self) -> Iterator[dict[str, Any]]:
        current_interval = self._poll_interval
        while True:
            batch, next_cursor = self._fetch_batch()
            if batch:
                current_interval = self._poll_interval  # reset back-off
                yield from batch
                # Advance after consuming the full batch so a mid-batch
                # break can resume from the last acked cursor.
                self._cursor = next_cursor or self._cursor
            else:
                self._sleep(current_interval)
                current_interval = min(current_interval * 1.5, self._max_backoff)

    def _fetch_batch(self) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, str] = {"event_type_prefix": self._prefix}
        if self._cursor:
            params["since"] = self._cursor
        url = f"{self._client._api_base_url}/api/v1/oap/chronicles"
        body = self._client._signed_request("GET", url, params=params)
        if not isinstance(body, dict):
            return [], None
        events = body.get("events", []) or []
        return list(events), body.get("next_cursor")
