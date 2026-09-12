"""Needs-approval URL minting and long-poll subscription.

Backend integrators mint approval URLs server-side and deliver them
via custom channels (Slack, email, SMS). The `subscribe` long-poll
generator streams decision-status transitions until terminal.
"""

from ..models import DecisionStatus, DecisionToken, Escalation, FlowDisclosures

# Re-exported for test mocking — `decisions.asyncio.sleep` is the
# canonical monkey-patch target for the poller's backoff loop, and
# the private `_..._async` helpers are mocked by the async-path
# coverage in tests/decisions/. Deliberately omitted from __all__
# so they don't bleed into `from overturo.decisions import *` or
# show up in the public Sphinx surface.
#
# Kept in a separate import block (rather than merged with the
# public names above) so ruff's isort can sort each block by name
# without splitting the comment header — and so a future reviewer
# sees at a glance which names are public vs. test-only.
from .client import (
    _poll_status_async,  # noqa: F401
    _token_for_async,  # noqa: F401
    asyncio,  # noqa: F401
    discover,
    poll_status,
    subscribe,
    subscribe_sync,
    token_for,
    url_for,
)

__all__ = [
    "poll_status",
    "discover",
    "subscribe",
    "subscribe_sync",
    "token_for",
    "url_for",
    # Re-exported from models for convenience (matches the legacy
    # overturo_oversight.decisions surface).
    "DecisionStatus",
    "DecisionToken",
    "Escalation",
    "FlowDisclosures",
]
