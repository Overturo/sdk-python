"""
heartbeat manager (asyncio).

Spawns a background `asyncio.Task` that ticks every `cadence_seconds`.
Failures log + continue — the server's `attestation.heartbeat_missed`
chronicle event is the operator-side signal.

Threaded fallback for sync callers lives behind `tick_sync()` — the
sync wrapper at `OverturoOversight.attest_sync` doesn't auto-start
heartbeats; sync-only hosts must call `tick_sync()` from their own
scheduler.
"""

from __future__ import annotations

import asyncio

from .._experimental import experimental
from .._http import HttpClient
from .._logger import Logger


class HeartbeatManager:
    @experimental("Heartbeat scheduling API may change before 1.1.")
    def __init__(
        self,
        http: HttpClient,
        heartbeat_url: str,
        cadence_seconds: float,
        logger: Logger,
    ) -> None:
        self._http = http
        self._url = heartbeat_url
        self._cadence = cadence_seconds
        self._logger = logger
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    await self._http.heartbeat(self._url)
                except Exception as e:  # noqa: BLE001
                    self._logger.warn(f"heartbeat tick failed: {type(e).__name__}: {e}")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._cadence)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            return

    async def tick(self) -> None:
        """Manual heartbeat tick (test + sync-caller convenience)."""
        await self._http.heartbeat(self._url)
