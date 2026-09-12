"""
Conformance harness fixtures.

A later release will extend this with shared scenario-engine
fixtures; for now it just exposes a typed `env` fixture + offline
skip helper.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import pytest


@dataclass
class ConformanceEnv:
    base_url: str
    token: str
    touchpoint_id: str


@pytest.fixture
def env() -> ConformanceEnv:
    base_url = os.environ.get("OVERTURO_BASE_URL")
    token = os.environ.get("OVERTURO_ATTESTER_TOKEN")
    touchpoint_id = os.environ.get("OVERTURO_TOUCHPOINT_ID")
    if not (base_url and token and touchpoint_id):
        pytest.skip(
            "conformance harness requires OVERTURO_BASE_URL + "
            "OVERTURO_ATTESTER_TOKEN + OVERTURO_TOUCHPOINT_ID env vars; "
            "see README.md"
        )
    return ConformanceEnv(base_url=base_url, token=token, touchpoint_id=touchpoint_id)


def is_offline() -> bool:
    return os.environ.get("OVERTURO_BASE_URL") is None
