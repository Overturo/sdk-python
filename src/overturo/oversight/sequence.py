"""
sequence-number manager.

Tracks an in-memory monotonic counter; emits each new value via
`on_update(seq)` so host apps can durably persist (Redis, file, DB).
Atomic per process — `next()` is sync; caller serialises submission.

On SDK restart: host MUST re-pass the persisted value as
`start_sequence`. Without persistence, restart with the same
(attester, touchpoint) tuple trips the server's `AttestationOutOfOrder` +
`attestation.gap_detected` chronicle row.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from .._experimental import experimental


class SequenceManager:
    @experimental("Sequence-counter manager API may change before 1.1.")
    def __init__(
        self,
        start_sequence: int,
        on_update: Callable[[int], None | Awaitable[None]] | None = None,
    ) -> None:
        if (
            not isinstance(start_sequence, int)
            or isinstance(start_sequence, bool)
            or start_sequence < 1
        ):
            raise ValueError(f"start_sequence must be a positive integer; got {start_sequence!r}")
        self._next = start_sequence
        self._on_update = on_update

    def next(self) -> int:
        value = self._next
        self._next += 1
        return value

    async def persist(self, seq: int) -> None:
        if self._on_update is None:
            return
        result = self._on_update(seq)
        if inspect.isawaitable(result):
            await result

    def peek(self) -> int:
        """Test / debug helper — value of the next `next()` call."""
        return self._next
