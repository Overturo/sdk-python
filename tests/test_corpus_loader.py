"""The corpus loader resolves the vendored copy alone and widens placeholders."""

from __future__ import annotations

import re

from tests.corpus import VENDORED, corpus_body, corpus_dir, corpus_url_regex


def test_loads_a_recording_from_the_vendored_copy(monkeypatch) -> None:
    monkeypatch.setenv("OVERTURO_API_CORPUS_DIR", str(VENDORED))
    assert corpus_dir() == VENDORED
    assert corpus_body("Vouches_show")["vouch"]["id"] == "<PREFIX_ID:1>"


def test_url_regex_widens_placeholders_and_leaves_the_query_free() -> None:
    pattern = re.compile(corpus_url_regex("https://overturo.example", "Vouches_show"))
    assert pattern.match("https://overturo.example/api/v1/vouches/vch_dev_abc123")
    assert pattern.match("https://overturo.example/api/v1/vouches/vch_dev_abc123?expand=1")
    assert not pattern.match("https://overturo.example/api/v1/vouches/a/b")
