"""OverturoChronicleStream tests.

Mocks the SDK client's `_signed_request` to feed deterministic batches;
asserts cursor advancement, back-off engagement, and prefix validation.

PEP 479 note: `StopIteration` raised INSIDE a generator becomes
`RuntimeError` at the consumer. The earlier draft of this suite used
`StopIteration` as a break-out sentinel from `sleep_fn`; that fails
under modern Python. We use a custom `_StopStream` exception instead,
caught explicitly at the consumer.
"""

from __future__ import annotations

from typing import Any

import pytest

from overturo import OverturoChronicleStream


class _StopStream(Exception):
    """Custom break-out sentinel — NOT StopIteration (PEP 479)."""


class _FakeClient:
    """Stand-in for OverturoAuthorize. The stream only touches
    `_signed_request` and `_api_base_url`."""

    def __init__(self, batches: list[tuple[list[dict[str, Any]], str | None]]) -> None:
        self._api_base_url = "http://test"
        self._batches = list(batches)
        self.requests: list[dict[str, str]] = []

    def _signed_request(
        self, method: str, url: str, *, params: dict[str, str] | None = None, **kw: Any
    ) -> dict[str, Any]:
        assert method == "GET"
        assert url == "http://test/api/v1/oap/chronicles"
        self.requests.append(dict(params or {}))
        if not self._batches:
            return {"events": [], "next_cursor": None}
        events, cursor = self._batches.pop(0)
        return {"events": events, "next_cursor": cursor}


def _event(jti: str) -> dict[str, Any]:
    return {"chronicle_id": f"chr_{jti}", "event_type": "conductor.policy_gate.evaluated"}


def test_invalid_prefix_raises_at_construction() -> None:
    client = _FakeClient([])
    with pytest.raises(ValueError, match="event_type_prefix must be one of"):
        OverturoChronicleStream(client, event_type_prefix="attacker.")


def test_yields_events_from_a_single_batch() -> None:
    client = _FakeClient(
        [
            ([_event("a"), _event("b")], "chr_b"),
            ([], None),  # second poll: empty → sleep_fn fires → _StopStream
        ]
    )

    def stop_on_first_sleep(_: float) -> None:
        raise _StopStream

    stream = OverturoChronicleStream(
        client,
        event_type_prefix="conductor.",
        sleep_fn=stop_on_first_sleep,
    )
    yielded: list[dict[str, Any]] = []
    with pytest.raises(_StopStream):
        for event in stream:
            yielded.append(event)

    assert [e["chronicle_id"] for e in yielded] == ["chr_a", "chr_b"]


def test_cursor_advances_between_batches() -> None:
    client = _FakeClient(
        [
            ([_event("a")], "chr_a"),
            ([_event("b")], "chr_b"),
        ]
    )

    yielded: list[dict[str, Any]] = []
    stream = OverturoChronicleStream(client, event_type_prefix="conductor.")
    for event in stream:
        yielded.append(event)
        if len(yielded) >= 2:
            break

    assert len(yielded) == 2
    # Second request must have carried since=chr_a (cursor from first batch).
    assert len(client.requests) >= 2
    assert client.requests[1].get("since") == "chr_a"


def test_idle_backoff_increases() -> None:
    """Empty batches → sleep_fn is called with increasing intervals.
    Capture the first three intervals then abort via _StopStream
    (NOT StopIteration — PEP 479)."""
    client = _FakeClient([])  # always empty
    sleeps: list[float] = []

    def stop_after_three(s: float) -> None:
        sleeps.append(s)
        if len(sleeps) >= 3:
            raise _StopStream

    stream = OverturoChronicleStream(
        client,
        event_type_prefix="conductor.",
        poll_interval=1.0,
        max_backoff=10.0,
        sleep_fn=stop_after_three,
    )
    with pytest.raises(_StopStream):
        for _ in stream:
            pass

    # 1.0 → 1.5 → 2.25 (exponential 1.5x with cap)
    assert sleeps == [1.0, 1.5, 2.25]


def test_initial_cursor_passed_through() -> None:
    client = _FakeClient(
        [
            ([], None),
        ]
    )

    def stop(_: float) -> None:
        raise _StopStream

    stream = OverturoChronicleStream(
        client,
        event_type_prefix="oap.",
        since="chr_start",
        sleep_fn=stop,
    )
    with pytest.raises(_StopStream):
        for _ in stream:
            pass
    assert client.requests[0].get("since") == "chr_start"
    assert client.requests[0].get("event_type_prefix") == "oap."
