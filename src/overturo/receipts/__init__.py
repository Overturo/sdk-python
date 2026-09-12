"""client methods for the authority record endpoints.

The durable-record endpoints are plain bearer ApiToken calls — distinct
from both the DPoP authorize transport and the discovery-driven
oversight transport — so this subpackage takes explicit connection
params, the ``decisions`` module-function precedent.
"""

from .client import create_disclosure_receipt, retrieve_authorization_receipt

__all__ = [
    "create_disclosure_receipt",
    "retrieve_authorization_receipt",
]
