"""
SDK logger with token redaction.

NEVER emits the bearer token at any log level. Token shape:
`tat_<region>_<base32>`; regex covers all regions.
"""

from __future__ import annotations

import logging
import re
from typing import Any

_LEVELS = {"silent": 0, "warn": 1, "info": 2, "debug": 3}

# Token shape: `tat_<region>_<urlsafe_base64>`.
# `SecureRandom.urlsafe_base64` emits `-` and `_` in the high-entropy
# suffix, so the character class MUST include them — `[A-Za-z0-9]+`
# truncates real tokens at the first `_`/`-`, leaking the suffix.
_TOKEN_PATTERN = re.compile(r"tat_[a-z]+_[A-Za-z0-9_\-]+")


class Logger:
    def __init__(self, level: str = "warn") -> None:
        if level not in _LEVELS:
            raise ValueError(f"unknown log level: {level!r}")
        self._level = level
        self._stdlib = logging.getLogger("overturo")

    def warn(self, message: str, **kwargs: Any) -> None:
        if _LEVELS[self._level] >= _LEVELS["warn"]:
            self._stdlib.warning(_redact(message), **_redact_kwargs(kwargs))

    def info(self, message: str, **kwargs: Any) -> None:
        if _LEVELS[self._level] >= _LEVELS["info"]:
            self._stdlib.info(_redact(message), **_redact_kwargs(kwargs))

    def debug(self, message: str, **kwargs: Any) -> None:
        if _LEVELS[self._level] >= _LEVELS["debug"]:
            self._stdlib.debug(_redact(message), **_redact_kwargs(kwargs))

    @property
    def level(self) -> str:
        return self._level


def _redact(value: str | None) -> str:
    if value is None:
        return ""
    return _TOKEN_PATTERN.sub("tat_<redacted>", value)


def _redact_kwargs(kwargs: dict) -> dict:
    out: dict = {}
    for k, v in kwargs.items():
        out[k] = _scrub(v)
    return out


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value
