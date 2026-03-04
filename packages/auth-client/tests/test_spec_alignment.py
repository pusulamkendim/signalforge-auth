"""Validates that UserInfo fields stay in sync with UserResponse in the OpenAPI spec.

This test acts as a drift detector: if either side changes without updating the other,
the test fails immediately, catching contract breaks before they hit production.
"""
import json
from pathlib import Path

import pytest

from auth_client.models import UserInfo

SPEC_PATH = Path(__file__).parents[3] / "packages" / "auth-service" / "openapi.json"


@pytest.fixture
def me_schema() -> dict:
    spec = json.loads(SPEC_PATH.read_text())
    return spec["components"]["schemas"]["UserResponse"]


def test_required_fields_match_spec(me_schema: dict) -> None:
    spec_required = set(me_schema.get("required", []))
    model_required = set(UserInfo.model_json_schema().get("required", []))
    assert spec_required == model_required, (
        f"Required fields diverged — spec: {spec_required}, model: {model_required}"
    )


def test_property_names_match_spec(me_schema: dict) -> None:
    spec_props = set(me_schema["properties"].keys())
    model_props = set(UserInfo.model_json_schema()["properties"].keys())
    assert spec_props == model_props, (
        f"Properties diverged — spec: {spec_props}, model: {model_props}"
    )
