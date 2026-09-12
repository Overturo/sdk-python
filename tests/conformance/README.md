# Oversight SDK conformance harness (Python)

This release ships the **scaffolding**; a later release
ships the cross-SDK contract definitions this harness exercises.

## Running locally

```bash
# 1. Boot an Overturo server on http://localhost:5000
bin/dev

# 2. Seed the scenario engine
bin/scenario seed personas/oversight_conformance

# 3. From the SDK package root (lib/sdk/overturo-oversight-py):
pip install -e ".[test]"

OVERTURO_BASE_URL=http://localhost:5000 \
  OVERTURO_ATTESTER_TOKEN="$(bin/scenario read-attester-token personas/oversight_conformance)" \
  OVERTURO_TOUCHPOINT_ID="$(bin/scenario read-touchpoint-id personas/oversight_conformance)" \
  pytest tests/conformance/ --junitxml=junit.xml
```

## What's here (Phase A scaffolding)

- `conftest.py` — environment-var fixture + offline-skip helper
- `test_scaffolding.py` — sanity check that SDK + verify imports work

## What a later release will add

- Concrete `test_*.py` files covering each conformance contract
- Shared assertion library aligned with the TypeScript harness

The directory layout is locked NOW so the contract suite ships against a stable surface.
