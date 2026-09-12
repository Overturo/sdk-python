"""
canonical SHA-256 hex digest helper.

Algorithm:
  1. JCS-canonicalise `input_obj`
  2. JCS-canonicalise `output_obj`
  3. Concatenate with `|` separator
  4. SHA-256 over the UTF-8 bytes
  5. Return hex (lowercase)

Matches the server's `evidence_digest` validator (`/\\A[a-f0-9]{64}\\z/`
at app/models/oap/attestation.rb).
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..canonicalize import canonicalize


def evidence_digest(input_obj: Any, output_obj: Any) -> str:
    canonical = f"{canonicalize(input_obj)}|{canonicalize(output_obj)}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
