"""
iss_role → trust_weight mapping.

Closed enum; the server advertises these via
`/.well-known/openid-configuration#iss_roles_supported`. Mismatch
indicates either a wire-protocol version mismatch or a malicious
receipt — fail closed.
"""

from __future__ import annotations

ISS_ROLES: tuple[str, ...] = ("authorizer", "witness", "approval_url_signer")

ISS_ROLE_TO_TRUST_WEIGHT: dict[str, str] = {
    "authorizer": "strong",
    "witness": "witness_only",
    "approval_url_signer": "approval_url",
}


def is_valid_iss_role(value: object) -> bool:
    return isinstance(value, str) and value in ISS_ROLES
