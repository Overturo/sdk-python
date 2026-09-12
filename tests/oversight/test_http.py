"""HttpClient unit coverage."""

import httpx
import pytest
import respx

from overturo._http import HttpClient
from overturo._logger import Logger
from overturo.errors import (
    OverturoRateLimited,
    OverturoServerError,
    OverturoUnauthorized,
    OverturoValidationError,
)
from overturo.oversight.token import TokenManager

URL = "https://overturo.test/api/v1/oap/attestations"


@pytest.fixture
def silent_logger():
    return Logger("silent")


@pytest.fixture
async def http_factory(silent_logger):
    clients: list[HttpClient] = []

    def _make(*, tokens: TokenManager, max_retries: int = 3) -> HttpClient:
        c = HttpClient(tokens, silent_logger, max_retries=max_retries, timeout_seconds=5.0)
        clients.append(c)
        return c

    yield _make
    for c in clients:
        await c.close()


@pytest.mark.asyncio
@respx.mock
async def test_post_json_happy_path(http_factory):
    respx.post(URL).respond(201, json={"ok": True})
    http = http_factory(tokens=TokenManager("tat_dev_initial"))
    result = await http.post_json(URL, {"x": 1})
    assert result == {"ok": True}


@pytest.mark.asyncio
@respx.mock
async def test_authorization_header_uses_current_token(http_factory):
    route = respx.post(URL).respond(201, json={"ok": True})
    http = http_factory(tokens=TokenManager("tat_dev_initial"))
    await http.post_json(URL, {})
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer tat_dev_initial"


@pytest.mark.asyncio
@respx.mock
async def test_401_maps_to_unauthorized_when_no_rotation(http_factory, monkeypatch):
    monkeypatch.delenv("OVERTURO_ATTESTER_TOKEN", raising=False)
    respx.post(URL).respond(
        401,
        json={"error": {"reason_code": "trusted_attester_unauthenticated", "message": "bad token"}},
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=0)
    with pytest.raises(OverturoUnauthorized):
        await http.post_json(URL, {})


@pytest.mark.asyncio
@respx.mock
async def test_422_maps_to_validation_error(http_factory):
    respx.post(URL).respond(
        422, json={"error": {"reason_code": "validation_failed", "message": "bad scope"}}
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"))
    with pytest.raises(OverturoValidationError):
        await http.post_json(URL, {})


@pytest.mark.asyncio
@respx.mock
async def test_500_maps_to_server_error_after_retries_exhausted(http_factory):
    respx.post(URL).respond(500, json={"error": {"reason_code": "internal_error"}})
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=0)
    with pytest.raises(OverturoServerError):
        await http.post_json(URL, {})


@pytest.mark.asyncio
@respx.mock
async def test_429_retries_then_succeeds(http_factory):
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(
                429, headers={"retry-after": "0"}, json={"error": {"reason_code": "rate_limited"}}
            ),
            httpx.Response(201, json={"ok": True}),
        ]
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=2)
    result = await http.post_json(URL, {})
    assert result == {"ok": True}
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_429_raises_rate_limited_after_max_retries(http_factory):
    respx.post(URL).respond(
        429,
        headers={"retry-after": "0"},
        json={"error": {"reason_code": "rate_limited", "detail": {"retry_after_seconds": 5}}},
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=1)
    with pytest.raises(OverturoRateLimited):
        await http.post_json(URL, {})


@pytest.mark.asyncio
@respx.mock
async def test_5xx_retries_then_succeeds(http_factory):
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(503, json={"error": {"reason_code": "internal_error"}}),
            httpx.Response(201, json={"ok": True}),
        ]
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=2)
    result = await http.post_json(URL, {})
    assert result == {"ok": True}
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_401_triggers_token_rotation_retry(http_factory, monkeypatch):
    monkeypatch.setenv("OVERTURO_ATTESTER_TOKEN", "tat_dev_rotated")
    route = respx.post(URL).mock(
        side_effect=[
            httpx.Response(
                401,
                json={"error": {"reason_code": "trusted_attester_unauthenticated"}},
            ),
            httpx.Response(201, json={"ok": True}),
        ]
    )
    http = http_factory(tokens=TokenManager("tat_dev_initial"), max_retries=0)
    result = await http.post_json(URL, {})
    assert result == {"ok": True}
    assert route.call_count == 2
    # Second call used the rotated token
    second_request = route.calls[1].request
    assert second_request.headers["Authorization"] == "Bearer tat_dev_rotated"
