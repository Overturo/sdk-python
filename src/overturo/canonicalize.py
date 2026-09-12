"""
RFC 8785 JSON Canonicalization Scheme
(JCS), trimmed for `evidence_digest`.

Covers the surface OPA decision-log records use: objects with string
keys, arrays, strings, numbers, booleans, None. Doesn't (yet) cover
the full RFC 8785 number-normalization corner cases — NaN / ±Infinity
raise; -0 is normalised to 0 by Python's JSON encoder when the input
is already a float, so we accept that.
"""

from __future__ import annotations

import json
import math
from typing import Any


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(
                f"canonicalize: non-finite number {value!r} is not representable in JCS"
            )
        # Use Python's JSON encoder for number → string consistency.
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, str):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, list) or isinstance(value, tuple):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        entries = []
        for key in sorted_keys:
            if not isinstance(key, str):
                raise TypeError(
                    f"canonicalize: dict keys must be strings; got {type(key).__name__}"
                )
            entries.append(f"{json.dumps(key, ensure_ascii=False)}:{canonicalize(value[key])}")
        return "{" + ",".join(entries) + "}"
    raise TypeError(f"canonicalize: unsupported type {type(value).__name__}")
