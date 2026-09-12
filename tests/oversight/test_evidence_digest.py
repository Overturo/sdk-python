"""evidence_digest unit coverage."""

import re

from overturo import evidence_digest

HEX_64 = re.compile(r"^[a-f0-9]{64}$")


def test_returns_64_hex_chars_matching_ov1_validator():
    digest = evidence_digest({"a": 1}, {"b": 2})
    assert HEX_64.match(digest)


def test_stable_across_key_order():
    a = evidence_digest({"a": 1, "b": 2}, {"x": 10})
    b = evidence_digest({"b": 2, "a": 1}, {"x": 10})
    assert a == b


def test_differs_when_input_differs():
    assert evidence_digest({"a": 1}, {"x": 10}) != evidence_digest({"a": 2}, {"x": 10})


def test_differs_when_output_differs_and_separator_prevents_swap_collision():
    # `{"a":1}|{"b":2}` ≠ `{"b":2}|{"a":1}` — the `|` separator
    # prevents accidental collisions from input/output ordering swaps.
    assert evidence_digest({"a": 1}, {"b": 2}) != evidence_digest({"b": 2}, {"a": 1})


def test_handles_nested_objects_and_arrays():
    digest = evidence_digest(
        {"nested": {"x": [1, 2, 3]}},
        {"result": {"ok": True}},
    )
    assert HEX_64.match(digest)
