> **Release mirror.** This repository is a read-only snapshot of
> `overturo` 1.0.0, published from Overturo's main
> development repository. Issues and pull requests are welcome here; accepted
> changes are ported upstream and appear in the next release snapshot.
> Security reports: see [SECURITY.md](./SECURITY.md).

# overturo

Python SDK for [Overturo](https://overturo.com) — the trust conductor.

## Install

    pip install overturo

## Quickstart

    from overturo import OverturoAuthorize, OverturoOversight
    from overturo import decisions
    from overturo.errors import OapError, OapApprovalRequired, OverturoError

Subpackages:

- `overturo.authorize` — Relying-party SDK (OAP v1.0 authorize + verify)
- `overturo.oversight` — Issuer / attester SDK (Oversight Mode)
- `overturo.decisions` — Needs-approval URL minting + long-poll subscription
- `overturo.receipts` — Authority record client methods (durable Authorization Receipts + disclosure mint)

## Authority records

The durable **Authorization Receipt** is a different artifact from the short-lived runtime receipt `authorize()` returns — the runtime receipt's TTL bounds *honoring*, not evidence, while the durable record is the archival, offline-verifiable account of the authorization.

    from overturo import verify_record
    from overturo.receipts import retrieve_authorization_receipt, create_disclosure_receipt

    # The durable record (audit:verify scope). Flavors: canonical (default), signed, dpv.
    envelope = retrieve_authorization_receipt(
        base_url="https://overturo.us", api_token=token, record_id="acc_...", flavor="signed"
    )

    # Verify offline against the region's published keys (key_version -> base64 key,
    # e.g. reshaped from the region's key-discovery document).
    verified = verify_record(envelope, published_keys=published_keys)

    # Mint an operator-declared disclosure receipt (disclosures:write scope).
    minted = create_disclosure_receipt(
        base_url="https://overturo.us", api_token=token,
        flow_id="acc_...", agent_id="agt_...", disclosed_at="2026-08-06T10:00:00Z",
    )

Typed refusals raise `OverturoValidationError` carrying the machine code in `reason_code` (`unknown_flavor`, `not_signable`, `dpv_unavailable`; `agent_not_disclosed`, `invalid_disclosed_at`, `purposes_missing`). The 404 contract is parity-preserving: unknown, foreign, and non-authority ids are indistinguishable. An authorization-kind record is refused by the consent-receipts read with a typed hint — authority records are served only by these endpoints. Field semantics and verification: the Receipt Interop & Verification guide in the developer documentation.

## Contract and testing

This client is written against Overturo's published OpenAPI document, kept at
<https://github.com/overturo/openapi>. When the client and the API disagree, the
document is the authority; a change to it is a change to this client.

The test suite stubs recorded operations from the shared API response corpus
(<https://github.com/overturo/conformance>, `api_responses/`), vendored under
`tests/fixtures/api_responses`. Each recording was made against the real API and checked against
the published document before it was committed, so a passing suite means the
client parses what the API actually sends — not what a test author remembered.
Identifiers, timestamps and tokens in the recordings are placeholders
(`<PREFIX_ID:1>`, `2026-01-01T00:00:00Z`, `<TOKEN>`); the corpus README documents the
grammar.

Run the suite with `pytest`. When you add a test for a recorded operation, stub it
from the recording (`corpus_route(router, "Decisions_create", BASE)`) rather than writing the response by hand.

## License

Apache-2.0
