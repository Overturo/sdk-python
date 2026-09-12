# audit-public-language: allow
#
# maps the SDK's public ``jurisdiction`` parameter (an ISO country)
# onto the internal authorize-context routing key the platform reads. Confined to
# this opt-out-marked module so the rest of the SDK stays under the language
# firewall and only ever speaks of ``jurisdiction`` / country.
from typing import Any


def jurisdiction_context(
    jurisdiction: str, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Merge the declared jurisdiction into the authorize context."""
    return {**(context or {}), "destination_region": jurisdiction}
