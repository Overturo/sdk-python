"""meetings client: the six organisation-side operations against the recorded
corpus (sync + async), the 204 cancel, and the typed refusals."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from overturo import meetings
from overturo.errors import OverturoApiError, OverturoUnauthorized, OverturoValidationError
from tests.corpus import corpus_body, corpus_exchange, corpus_route

BASE = "https://overturo.example"
APP = "app_abc"
MEETING = "vnsess_1"
AUTH = {"base_url": BASE, "api_token": "tok", "application_id": APP}


@respx.mock
def test_create_sends_the_accepted_body_and_reads_the_window() -> None:
    recorded = corpus_exchange("Applications_MeetingConsents_create")
    route = corpus_route(respx, "Applications_MeetingConsents_create", BASE)

    envelope = meetings.create_meeting(**AUTH, **recorded["request"]["body"])

    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer tok"
    assert json.loads(request.content) == recorded["request"]["body"]
    assert envelope["meeting_consent"]["platform"] == "zoom"
    assert envelope["meeting_consent"]["participants"] == {
        "total": 0,
        "decided": 0,
        "undecided": 0,
        "consented": 0,
    }
    assert isinstance(envelope["meeting_consent"]["ends_at"], str)


@respx.mock
def test_list_passes_the_page_size_and_reads_the_counts() -> None:
    route = corpus_route(respx, "Applications_MeetingConsents_index", BASE)

    listing = meetings.list_meetings(**AUTH, per_page=10)

    assert "per_page=10" in str(route.calls.last.request.url)
    body = corpus_body("Applications_MeetingConsents_index")
    assert len(listing["meeting_consents"]) == len(body["meeting_consents"])
    assert listing["meeting_consents"][0]["participants"]["decided"] == 2


@respx.mock
def test_retrieve_and_update_hit_the_member_path() -> None:
    corpus_route(respx, "Applications_MeetingConsents_show", BASE)
    corpus_route(respx, "Applications_MeetingConsents_update", BASE)

    shown = meetings.retrieve_meeting(**AUTH, meeting_id=MEETING)
    updated = meetings.update_meeting(**AUTH, meeting_id=MEETING, title="Corpus Review (moved)")

    assert shown["meeting_consent"]["status"] == "checked_in"
    expected = corpus_body("Applications_MeetingConsents_update")["meeting_consent"]["name"]
    assert updated["meeting_consent"]["name"] == expected


@respx.mock
def test_participants_carry_a_decision_per_purpose() -> None:
    corpus_route(respx, "Applications_MeetingConsents_participants", BASE)

    listing = meetings.list_participants(**AUTH, meeting_id=MEETING)

    consented = next(p for p in listing["participants"] if p["status"] == "consented")
    assert consented["decisions"]["meeting_recording"] == "granted"
    assert consented["decisions"]["ai_transcription"] == "declined"
    assert "declined" in {p["status"] for p in listing["participants"]}


@respx.mock
def test_cancel_accepts_the_204() -> None:
    route = corpus_route(respx, "Applications_MeetingConsents_destroy", BASE)

    assert meetings.cancel_meeting(**AUTH, meeting_id=MEETING) is None
    assert route.calls.last.request.method == "DELETE"


@respx.mock
async def test_async_twins_share_the_wire() -> None:
    corpus_route(respx, "Applications_MeetingConsents_show", BASE)
    corpus_route(respx, "Applications_MeetingConsents_destroy", BASE)

    shown = await meetings.retrieve_meeting_async(**AUTH, meeting_id=MEETING)
    assert shown["meeting_consent"]["status"] == "checked_in"
    assert await meetings.cancel_meeting_async(**AUTH, meeting_id=MEETING) is None


@respx.mock
def test_closed_meeting_is_a_typed_refusal_with_the_code() -> None:
    respx.patch(f"{BASE}/api/v1/applications/{APP}/meeting_consents/{MEETING}").mock(
        return_value=httpx.Response(
            409, json={"error": "This meeting has ended or was cancelled", "code": "meeting_closed"}
        )
    )

    with pytest.raises(OverturoValidationError) as info:
        meetings.update_meeting(**AUTH, meeting_id=MEETING, title="x")
    assert info.value.reason_code == "meeting_closed"


@respx.mock
def test_401_and_404_map_to_typed_errors() -> None:
    respx.get(f"{BASE}/api/v1/applications/{APP}/meeting_consents/{MEETING}").mock(
        return_value=httpx.Response(401, json={"error": "Invalid API key"})
    )
    with pytest.raises(OverturoUnauthorized):
        meetings.retrieve_meeting(**AUTH, meeting_id=MEETING)

    respx.get(f"{BASE}/api/v1/applications/{APP}/meeting_consents/missing").mock(
        return_value=httpx.Response(404, json={"error": "Meeting consent not found"})
    )
    with pytest.raises(OverturoApiError) as info:
        meetings.retrieve_meeting(**AUTH, meeting_id="missing")
    assert info.value.http_status == 404


def test_validation_before_the_network() -> None:
    with pytest.raises(OverturoValidationError):
        meetings.retrieve_meeting(
            base_url=BASE, api_token="tok", application_id="", meeting_id=MEETING
        )
    with pytest.raises(OverturoValidationError):
        meetings.update_meeting(**AUTH, meeting_id=MEETING, bogus="x")
