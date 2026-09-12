"""pre-flight disclosure discovery (``decisions.discover``) tests.

Decodes the shared conformance fixture
(lib/sdk/shared/conformance/discovery/flow_disclosures.json) — the same corpus
the server + the other three clients hold — so a decoder that drifts from the
wire shape is a red suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from overturo import FlowDisclosures, decisions
from overturo.errors import OverturoApiError, OverturoValidationError

BASE = "https://overturo.test"
FLOW_ID = "flw_test_discovery"
PK = "pk_test_x"

SHARED_FIXTURE = (
    Path(__file__).parents[3] / "shared" / "conformance" / "discovery" / "flow_disclosures.json"
)
# The shared fixture when this package sits next to it; the vendored copy otherwise.
FIXTURE_PATH = (
    SHARED_FIXTURE
    if SHARED_FIXTURE.exists()
    else Path(__file__).parents[1] / "fixtures" / "discovery" / "flow_disclosures.json"
)
FIXTURE = json.loads(FIXTURE_PATH.read_text())
DISCLOSURES_URL = f"{BASE}/api/v1/decisions/flows/{FLOW_ID}/disclosures"


def test_flow_disclosures_typeddict_is_exported() -> None:
    # The passthrough JSON dict is typed as FlowDisclosures; assert the export
    # wiring (models -> decisions -> package root) resolves.
    assert FlowDisclosures is not None


@respx.mock
def test_discover_decodes_the_shared_fixture() -> None:
    respx.get(url__startswith=DISCLOSURES_URL).respond(200, json=FIXTURE)

    result = decisions.discover(BASE, flow_id=FLOW_ID, publishable_key=PK)

    assert result["schema"] == "overturo-disclosure/1"
    assert result["flow"]["kind"] == "consent"
    assert result["application"]["primary_color"] == "#0B5FFF"
    assert result["expiry"]["consent_duration_days"] == 365
    assert result["locale"]["fallback"] == "en"
    purpose = next(p for p in result["purposes"] if p["name"] == "care_reminders")
    assert purpose["mechanism"] == "opt_out"
    assert purpose["legal_basis"] == "consent"
    assert isinstance(purpose["data_labels"], list)
    assert "principal" in [f["completed_by"] for f in result["fields"]]
    assert result["outcomes"] == ["granted", "denied"]


@respx.mock
def test_discover_sends_publishable_key_and_locale_query() -> None:
    route = respx.get(url__startswith=DISCLOSURES_URL).respond(200, json=FIXTURE)

    decisions.discover(BASE, flow_id=FLOW_ID, publishable_key=PK, locale="de")

    request = route.calls.last.request
    assert request.headers["X-Publishable-Key"] == PK
    assert request.url.params["locale"] == "de"


@respx.mock
def test_discover_maps_uniform_404_to_overturo_api_error() -> None:
    respx.get(url__startswith=DISCLOSURES_URL).respond(
        404, json={"error": {"code": "flow_not_found", "message": "Flow not found"}}
    )

    with pytest.raises(OverturoApiError) as exc_info:
        decisions.discover(BASE, flow_id=FLOW_ID, publishable_key=PK)

    assert exc_info.value.http_status == 404


@respx.mock
def test_discover_validates_inputs_before_any_network_call() -> None:
    route = respx.get(url__startswith=DISCLOSURES_URL).respond(200, json=FIXTURE)

    with pytest.raises(OverturoValidationError):
        decisions.discover(BASE, flow_id="", publishable_key=PK)
    with pytest.raises(OverturoValidationError):
        decisions.discover(BASE, flow_id=FLOW_ID, publishable_key="")

    assert route.called is False


@respx.mock
def test_discover_omits_the_locale_query_when_not_given() -> None:
    route = respx.get(url__startswith=DISCLOSURES_URL).respond(200, json=FIXTURE)

    decisions.discover(BASE, flow_id=FLOW_ID, publishable_key=PK)

    assert "locale" not in route.calls.last.request.url.params


@respx.mock
def test_discover_raises_typed_error_on_envelope_less_200() -> None:
    respx.get(url__startswith=DISCLOSURES_URL).respond(200, json={"unexpected": True})

    with pytest.raises(OverturoApiError):
        decisions.discover(BASE, flow_id=FLOW_ID, publishable_key=PK)
