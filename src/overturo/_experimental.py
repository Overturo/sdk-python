"""@experimental decorator — marks pre-1.0 stable surfaces.

Emits PendingDeprecationWarning on first access per process per surface,
then never again. Use sparingly — only for surfaces whose API may change
in 1.x.

"""

from __future__ import annotations

import functools
import warnings
from collections.abc import Callable
from typing import TypeVar

_F = TypeVar("_F", bound=Callable[..., object])
_SEEN: set[str] = set()


def experimental(reason: str) -> Callable[[_F], _F]:
    def decorator(fn: _F) -> _F:
        key = f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            if key not in _SEEN:
                _SEEN.add(key)
                warnings.warn(
                    f"{key} is experimental: {reason}. API may change in overturo 1.x.",
                    PendingDeprecationWarning,
                    stacklevel=2,
                )
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
