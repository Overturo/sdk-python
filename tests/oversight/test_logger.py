"""Logger + token redaction coverage."""

import logging

import pytest

from overturo._logger import Logger, _redact


def test_log_levels_silent(caplog):
    caplog.set_level(logging.DEBUG, logger="overturo")
    log = Logger("silent")
    log.warn("hidden")
    log.info("hidden")
    assert caplog.records == []


def test_log_levels_warn(caplog):
    caplog.set_level(logging.DEBUG, logger="overturo")
    log = Logger("warn")
    log.warn("visible")
    log.info("hidden")
    assert any("visible" in r.message for r in caplog.records)
    assert not any("hidden" in r.message for r in caplog.records)


def test_log_levels_info(caplog):
    caplog.set_level(logging.DEBUG, logger="overturo")
    log = Logger("info")
    log.warn("visible_warn")
    log.info("visible_info")
    log.debug("hidden")
    visible = " ".join(r.message for r in caplog.records)
    assert "visible_warn" in visible
    assert "visible_info" in visible
    assert "hidden" not in visible


def test_rejects_unknown_log_level():
    with pytest.raises(ValueError, match="unknown log level"):
        Logger("noisy")  # type: ignore[arg-type]


# ── token redaction ────────────────────────────────────────────────


def test_redacts_bearer_token_in_message(caplog):
    caplog.set_level(logging.DEBUG, logger="overturo")
    log = Logger("warn")
    log.warn("about to send with tat_dev_secret123abc DONE")
    combined = " ".join(r.message for r in caplog.records)
    assert "tat_dev_secret123abc" not in combined
    assert "tat_<redacted>" in combined


def test_redact_function_handles_none():
    assert _redact(None) == ""


def test_redact_function_handles_multiple_tokens():
    s = "tat_us_AAAA and tat_eu_BBBB"
    out = _redact(s)
    assert "tat_us_AAAA" not in out
    assert "tat_eu_BBBB" not in out
    assert out.count("tat_<redacted>") == 2


def test_redacts_urlsafe_base64_tokens_with_hyphen_and_underscore():
    """B2 regression — `SecureRandom.urlsafe_base64` emits `-` and `_`
    in the high-entropy suffix. The OLD `[A-Za-z0-9]+` regex truncated
    real tokens at the first `_`/`-`, leaking the suffix into logs."""
    s = "dispatching with token tat_us_LX3c5_Fik5jV-OQbCxYnXBe9_pT0aM-9k DONE"
    out = _redact(s)
    assert "LX3c5" not in out
    assert "Fik5jV" not in out
    assert "pT0aM" not in out
    assert "tat_<redacted>" in out
