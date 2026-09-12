"""Customer decision-engine adapter contract.

Customers hosting an HTTP endpoint that `conductor.policy_gate` calls
via its `external_endpoint_url` config implement this ABC to bridge
their decision engine (Cedar, OPA, in-house) to OverturoDecision.

The SDK provides the type contract; the customer hosts the HTTP server.
Concrete deployment guidance lives in the per-engine example adapters
under ``examples/`` (cedar_adapter, etc).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import OverturoDecision

__all__ = ["OverturoDecisionAdapter"]


class OverturoDecisionAdapter(ABC):
    """Customer adapter shape. Implementations receive a parsed OAP
    authorize request (as a dict matching the wire body shape) and
    return an OverturoDecision.

    Partial decisions are allowed — the SDK fills defaults for any
    unspecified fields when round-tripping back to the wire layer.
    """

    @abstractmethod
    def evaluate(self, request: dict[str, Any]) -> OverturoDecision:
        """Evaluate one OAP authorize request and return a decision."""
