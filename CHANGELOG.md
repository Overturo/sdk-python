# CHANGELOG

## 1.0.1 (2026-09-12)

### Changed

- The README links the public documentation and the rendered API reference at overturo.com/developers; the vendored API response corpus is re-recorded against the published document, whose operations now list the SDKs that reach them (`x-overturo-sdks`).

## 1.0.0 (unreleased)

Initial release. Consolidates `overturo-authorize` v1.2.0 and
`overturo-oversight` v0.2.0 into a single package.

### Changed

- Source comments, tests, the example adapter and this changelog describe behaviour only; planning references were removed.
- The test suite is self-contained: the signed-record corpus and the discovery fixture are vendored under `tests/fixtures/` (the shared copies are read when the package sits next to them).

### Fixed — decision envelopes (found by the recorded API corpus)

- `DecisionToken.from_response` / `DecisionStatus.from_response` read the
  envelope the API actually sends: the token and the one-shot status arrive
  wrapped under `decision`, the validity bound is `deadline_at`, and a pending
  long-poll envelope carries no `session_token`. The previous parser raised
  `KeyError` on every real response.
- The test suite stubs recorded operations from the shared API response corpus
  (`tests/corpus.py`; vendored under `tests/fixtures/api_responses`); the discovery
  test reads a vendored copy of the shared discovery fixture when the shared corpus
  is not present.

### Added — pre-flight disclosure discovery

- **`overturo.decisions.discover(base_url, *, flow_id, publishable_key,
  locale=None)`** — fetch what a consent flow would ask a person (purposes,
  fields, steps, the action label, expiry, application branding) BEFORE any
  session exists, in public vocabulary and the requested locale. The publishable
  key is an embed-safe, per-application credential passed explicitly (this
  endpoint ignores any bearer token). Sync, standalone (takes `base_url`, not a
  client). An unknown / foreign / non-consent flow raises `OverturoApiError`
  (`http_status=404`). Returns the `FlowDisclosures` TypedDict.
- Cross-language parity is gated by the shared corpus at
  `lib/sdk/shared/conformance/discovery/flow_disclosures.json`.

### Added — authority records

- **`overturo.records`** — `verify_record` (durable signed-record
  verification: overturo-jcs-1 canonical bytes, a detached signature,
  published-key resolution by key_version, opt-in embedded-key mode),
  `verify_manifest_pin` / `manifest_content_hash` (the
  capability-manifest pin), and the `RecordInvalid` typed error.
  Cross-language parity is gated by the shared corpus at
  `lib/sdk/shared/conformance/signed_records/`.
- **`overturo.receipts`** — `retrieve_authorization_receipt` (the
  durable record, `audit:verify` scope; canonical/signed/dpv flavors)
  and `create_disclosure_receipt` (the operator-declared disclosure
  mint, `disclosures:write` scope). Typed refusals raise
  `OverturoValidationError` with the machine code in `reason_code`.

### Added — cross-border

- **`authorize(..., jurisdiction=...)`** — declare the action's target
  jurisdiction (an ISO country) so the platform can enforce a jurisdiction
  bound; mapped into the authorize context. A refusal arrives with
  `failed_bound == "jurisdiction_bounds"` (reason code
  `jurisdiction_not_permitted`), distinct from a transport-level refusal.
- **Cross-border credential verification** in `verify` — resolve a presented
  credential against its issuer's own published key (shares the
  `@overturo/verify` resolution; see that SDK's notes).

### Replaces

- `overturo-authorize` v1.2.0 → `overturo.authorize`
- `overturo-oversight` v0.2.0 → `overturo.oversight`

### Added

- `overturo.models` — single home for cross-cutting dataclasses (the earlier
  vendored `_shared.py` is gone).
- `overturo.errors.OverturoError` is now the unified root for both the
  protocol (`OapError`) and transport (`OverturoApiError`, etc.) families.
- `overturo.decisions` promoted from `overturo_oversight.decisions` to
  a top-level subpackage.
- `@experimental` decorator marks pre-1.0 oversight surfaces
  (`heartbeat`, `iss_role`, `sequence`).
