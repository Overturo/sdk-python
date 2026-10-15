"""consent records client: the Record API, the import and the status read
against the recorded corpus (sync + async), and the typed refusals."""

from __future__ import annotations

import json

import pytest
import respx

from overturo import consent_records
from overturo.errors import OverturoValidationError
from tests.corpus import corpus_body, corpus_exchange, corpus_route

BASE = "https://overturo.example"
AUTH = {"base_url": BASE, "api_token": "tok"}


@respx.mock
def test_create_sends_the_accepted_body_and_reads_the_record() -> None:
    recorded = corpus_exchange("ConsentRecords_create")
    route = corpus_route(respx, "ConsentRecords_create", BASE)

    record = consent_records.create_record(**AUTH, **recorded["request"]["body"])

    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer tok"
    assert json.loads(request.content) == recorded["request"]["body"]
    assert record["consent_record"]["status"] == "fulfilled"
    assert record["consent_record"]["channel"] == "controller_attested"
    assert {p["key"] for p in record["consent_record"]["purposes"]} >= {"marketing"}


@respx.mock
def test_retrieve_reads_the_record() -> None:
    corpus_route(respx, "ConsentRecords_show", BASE)
    body = corpus_body("ConsentRecords_show")
    record = consent_records.retrieve_record(**AUTH, record_id=body["consent_record"]["id"])
    assert record["consent_record"]["id"] == body["consent_record"]["id"]


@respx.mock
def test_commit_capture_commits_the_snippets_token() -> None:
    recorded = corpus_exchange("Decisions_authorize")
    route = corpus_route(respx, "Decisions_authorize", BASE)

    decision = consent_records.commit_capture(
        **AUTH, token="tok_capture", subject=recorded["request"]["body"]["subject"]
    )

    request = route.calls.last.request
    assert request.url.path.endswith("/authorize")
    assert json.loads(request.content) == recorded["request"]["body"]
    assert decision["decision"]["status"] == "fulfilled"
    assert decision["decision"]["channel"] == "form_capture"


def test_commit_capture_refuses_a_blank_token() -> None:
    with pytest.raises(OverturoValidationError):
        consent_records.commit_capture(**AUTH, token="")


@respx.mock
def test_import_and_import_status() -> None:
    recorded = corpus_exchange("ConsentRecords_imports")
    corpus_route(respx, "ConsentRecords_imports", BASE)
    result = consent_records.import_records(**AUTH, **recorded["request"]["body"])
    assert result["import"]["dry_run"] is True
    assert result["import"]["row_count"] == 1

    corpus_route(respx, "ConsentRecords_import", BASE)
    body = corpus_body("ConsentRecords_import")
    status = consent_records.retrieve_import(**AUTH, import_id=body["import"]["id"])
    assert status["import"]["id"] == body["import"]["id"]


@respx.mock
def test_status_by_subject_reference() -> None:
    route = corpus_route(respx, "Applications_ConsentStatuses_lookup", BASE)
    body = corpus_body("Applications_ConsentStatuses_lookup")
    result = consent_records.status(
        **AUTH, application_id=body["application_id"], email="contract-status@example.com"
    )
    assert "subject%5Bemail%5D=contract-status" in str(route.calls.last.request.url)
    assert result["application_id"] == body["application_id"]
    assert isinstance(result["purposes"], list)


def test_refusals_before_the_network() -> None:
    with pytest.raises(OverturoValidationError):
        consent_records.create_record(
            **AUTH, flow_id="", subject={"email": "a@b"}, decisions={"m": {"decision": "granted"}}
        )
    with pytest.raises(OverturoValidationError):
        consent_records.create_record(
            **AUTH, flow_id="flw", subject={}, decisions={"m": {"decision": "granted"}}
        )
    with pytest.raises(OverturoValidationError):
        consent_records.import_records(**AUTH, flow_id="flw", records=[])
    with pytest.raises(OverturoValidationError):
        consent_records.status(**AUTH, application_id="app")


@respx.mock
@pytest.mark.asyncio
async def test_async_twins() -> None:
    recorded = corpus_exchange("ConsentRecords_create")
    corpus_route(respx, "ConsentRecords_create", BASE)
    record = await consent_records.create_record_async(**AUTH, **recorded["request"]["body"])
    assert record["consent_record"]["status"] == "fulfilled"
