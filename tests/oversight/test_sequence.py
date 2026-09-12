"""SequenceManager unit coverage."""

import pytest

from overturo.oversight.sequence import SequenceManager


def test_starts_at_1_by_default_and_increments():
    seq = SequenceManager(1)
    assert seq.next() == 1
    assert seq.next() == 2
    assert seq.next() == 3


def test_respects_non_1_start_sequence():
    seq = SequenceManager(42)
    assert seq.next() == 42
    assert seq.next() == 43


@pytest.mark.asyncio
async def test_invokes_on_update_synchronously():
    captured: list[int] = []
    seq = SequenceManager(1, on_update=lambda s: captured.append(s))
    seq.next()
    await seq.persist(1)
    assert captured == [1]


@pytest.mark.asyncio
async def test_invokes_on_update_async():
    captured: list[int] = []

    async def on_update(s: int) -> None:
        captured.append(s)

    seq = SequenceManager(1, on_update=on_update)
    seq.next()
    await seq.persist(1)
    assert captured == [1]


def test_rejects_zero_or_negative_start_sequence():
    with pytest.raises(ValueError, match="positive integer"):
        SequenceManager(0)
    with pytest.raises(ValueError, match="positive integer"):
        SequenceManager(-1)


def test_rejects_non_integer_start_sequence():
    with pytest.raises(ValueError, match="positive integer"):
        SequenceManager(1.5)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_persist_is_noop_without_on_update():
    seq = SequenceManager(1)
    await seq.persist(1)  # must not raise
