"""@experimental decorator behaviour.

The decorator emits PendingDeprecationWarning the FIRST time a wrapped
callable is invoked per process, then never again. Currently applied to
``HeartbeatManager.__init__`` and ``SequenceManager.__init__``.
"""

from __future__ import annotations

import warnings

import pytest

from overturo._experimental import _SEEN, experimental


@pytest.fixture(autouse=True)
def _reset_seen():
    """Wipe the module-level SEEN set so tests are order-independent."""
    snapshot = set(_SEEN)
    _SEEN.clear()
    yield
    _SEEN.clear()
    _SEEN.update(snapshot)


def test_experimental_emits_pending_deprecation_warning():
    @experimental("test reason")
    def f(x: int) -> int:
        return x + 1

    with pytest.warns(PendingDeprecationWarning, match="test reason"):
        assert f(1) == 2


def test_experimental_emits_only_once():
    @experimental("test reason")
    def f() -> None:
        pass

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        f()
        f()
        f()

    pending = [w for w in captured if issubclass(w.category, PendingDeprecationWarning)]
    assert len(pending) == 1, f"expected 1 warning, got {len(pending)}"


def test_experimental_preserves_return_value_and_signature():
    @experimental("test")
    def add(a: int, b: int) -> int:
        return a + b

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", PendingDeprecationWarning)
        assert add(3, 4) == 7
        assert add.__name__ == "add"


def test_heartbeat_manager_init_is_experimental():
    """HeartbeatManager.__init__ fires the warning on first construction."""
    from unittest.mock import MagicMock

    from overturo.oversight.heartbeat import HeartbeatManager

    with pytest.warns(PendingDeprecationWarning, match="experimental"):
        HeartbeatManager(
            http=MagicMock(),
            heartbeat_url="https://x.example/heartbeat",
            cadence_seconds=60.0,
            logger=MagicMock(),
        )


def test_sequence_manager_init_is_experimental():
    """SequenceManager.__init__ fires the warning on first construction."""
    from overturo.oversight.sequence import SequenceManager

    with pytest.warns(PendingDeprecationWarning, match="experimental"):
        SequenceManager(start_sequence=1)
