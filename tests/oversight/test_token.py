"""TokenManager unit coverage."""

import pytest

from overturo.oversight.token import TokenManager


def test_current_returns_initial_token():
    t = TokenManager("tat_dev_initial")
    assert t.current() == "tat_dev_initial"


@pytest.mark.asyncio
async def test_refresh_returns_true_when_env_var_changed(monkeypatch):
    monkeypatch.delenv("OVERTURO_ATTESTER_TOKEN", raising=False)
    t = TokenManager("tat_dev_initial")
    monkeypatch.setenv("OVERTURO_ATTESTER_TOKEN", "tat_dev_rotated")

    assert await t.refresh() is True
    assert t.current() == "tat_dev_rotated"


@pytest.mark.asyncio
async def test_refresh_returns_false_when_env_var_matches(monkeypatch):
    t = TokenManager("tat_dev_same")
    monkeypatch.setenv("OVERTURO_ATTESTER_TOKEN", "tat_dev_same")

    assert await t.refresh() is False
    assert t.current() == "tat_dev_same"


@pytest.mark.asyncio
async def test_refresh_returns_false_when_no_env_and_no_provider(monkeypatch):
    monkeypatch.delenv("OVERTURO_ATTESTER_TOKEN", raising=False)
    t = TokenManager("tat_dev_initial")
    assert await t.refresh() is False
    assert t.current() == "tat_dev_initial"


@pytest.mark.asyncio
async def test_prefers_token_provider_over_env(monkeypatch):
    monkeypatch.setenv("OVERTURO_ATTESTER_TOKEN", "tat_dev_env")
    t = TokenManager("tat_dev_initial", token_provider=lambda: "tat_dev_provider")

    assert await t.refresh() is True
    assert t.current() == "tat_dev_provider"


@pytest.mark.asyncio
async def test_token_provider_may_be_async():
    async def provider() -> str:
        return "tat_dev_async"

    t = TokenManager("tat_dev_initial", token_provider=provider)
    await t.refresh()
    assert t.current() == "tat_dev_async"
