"""canonicalize unit coverage."""

import pytest

from overturo.canonicalize import canonicalize


def test_sorts_object_keys_lexicographically():
    assert canonicalize({"b": 1, "a": 2, "c": 3}) == '{"a":2,"b":1,"c":3}'


def test_preserves_array_order():
    assert canonicalize([3, 1, 2]) == "[3,1,2]"


def test_string_escapes_double_quote():
    assert canonicalize('a"b') == '"a\\"b"'


def test_rejects_non_finite_numbers():
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize(float("nan"))
    with pytest.raises(ValueError, match="non-finite"):
        canonicalize(float("inf"))


def test_null_and_booleans():
    assert canonicalize(None) == "null"
    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"


def test_nested_objects_and_arrays():
    out = canonicalize({"nested": {"x": [1, 2, 3]}, "result": {"ok": True}})
    # keys sorted: nested before result
    assert out == '{"nested":{"x":[1,2,3]},"result":{"ok":true}}'


def test_rejects_non_string_dict_keys():
    with pytest.raises(TypeError, match="keys must be strings"):
        canonicalize({1: "a"})


def test_unicode_strings_passthrough():
    assert canonicalize("café") == '"café"'
