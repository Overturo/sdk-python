"""Relying-party SDK for the Overturo Authorize protocol (OAP v1.0).

Public surface of the OAP authorize SDK — the client class,
the DPoP key plumbing, the chronicle stream iterator, and the
receipt peeker. Cross-cutting types (OverturoDecision,
JwksKey, etc.) live in `overturo.models`; errors in
`overturo.errors`; verification in `overturo.verify`.
"""

from .adapter import OverturoDecisionAdapter
from .client import OverturoAuthorize
from .dpop import (
    DpopKeyPair,
    access_token_hash,
    jwk_thumbprint,
    sign_dpop_proof,
)
from .receipt import peek_receipt
from .record_stream import OverturoRecordStream

__all__ = [
    "OverturoAuthorize",
    "OverturoDecisionAdapter",
    "OverturoRecordStream",
    "DpopKeyPair",
    "access_token_hash",
    "jwk_thumbprint",
    "sign_dpop_proof",
    "peek_receipt",
]
