"""Endpoint manifest self-test.

`endpoints.json` at the package root declares every endpoint this client calls.
This test derives the set of endpoint paths from the package SOURCE (string
literals and f-strings mentioning /api/v1 or /.well-known, docstrings excluded)
and asserts it equals the manifest after path-parameter normalization. Discovered
endpoints (resolved from openid-configuration at runtime) are declared with a
`discovered` marker and are exempt from the source check.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "overturo"
MANIFEST = json.loads((ROOT / "endpoints.json").read_text())
PATH_RE = re.compile(r"(/api/v1/[^\s\"'`]*|/\.well-known/[^\s\"'`]*)")


def normalize(path: str) -> str:
    path = re.sub(r"\{[^}]*\}", "{}", path)
    path = re.sub(r":[a-z_]+", "{}", path)
    return path.rstrip("/").rstrip(".,")


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            value = body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                ids.add(id(value))
    return ids


SOURCE_TEXT: list[str] = []


def composed_from(declared: str, base: str) -> bool:
    """A declared path composed from a found base counts as built only when every
    literal segment after the base ("/cancel", "/wait") appears in the source."""
    if not declared.startswith(base + "/"):
        return False
    rest = [seg for seg in declared[len(base) :].split("/") if seg and seg != "{}"]
    text = "".join(SOURCE_TEXT)
    return all(f"/{seg}" in text for seg in rest)


def source_paths() -> set[str]:
    found: set[str] = set()
    for file in SRC.rglob("*.py"):
        tree = ast.parse(file.read_text())
        docstrings = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = "".join(
                    v.value if isinstance(v, ast.Constant) else "{}" for v in node.values
                )
            else:
                continue
            SOURCE_TEXT.append(text + "\n")
            for match in PATH_RE.finditer(text):
                found.add(normalize(match.group(1)))
    return found


def test_manifest_matches_source():
    declared = {normalize(e["path"]) for e in MANIFEST["endpoints"] if not e.get("discovered")}
    found = source_paths()
    # A path may be COMPOSED at runtime from a base literal (e.g. "/api/v1/decisions" + "/{token}"):
    # it counts as present when a found literal is a proper prefix of it.
    unsupported = {
        p for p in declared if p not in found and not any(composed_from(p, f) for f in found)
    }
    assert unsupported == set(), (
        f"declared in endpoints.json but absent from source: {sorted(unsupported)}"
    )
    # A found literal may be a composition BASE of a declared path ("/api/v1/decisions").
    undeclared = {
        f for f in found if f not in declared and not any(d.startswith(f + "/") for d in declared)
    }
    assert undeclared == set(), (
        f"built in source but not declared in endpoints.json: {sorted(undeclared)}"
    )


def test_manifest_shape():
    for entry in MANIFEST["endpoints"]:
        assert entry["method"] in {"GET", "POST", "PATCH", "PUT", "DELETE"}
        assert entry["path"].startswith("/"), entry
