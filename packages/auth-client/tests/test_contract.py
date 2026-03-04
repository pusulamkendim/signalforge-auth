from __future__ import annotations

# Contract tests — verify that UserInfo.model_validate() accepts the exact
# wire format emitted by auth-service GET /api/v1/auth/me without error.
# No HTTP calls, no DB. These act as shape guards: if auth-service changes
# its response schema without updating auth-client's UserInfo model, these
# tests will catch it immediately.

from uuid import UUID

import pytest
from pydantic import ValidationError

from auth_client.models import UserInfo
from helpers import me_payload


# ---------------------------------------------------------------------------
# X01 — /me fields parse correctly
# ---------------------------------------------------------------------------

def test_me_response_fields_parse_into_user_info():  # X01
    data = me_payload()["data"]
    user = UserInfo.model_validate(data)
    assert user.email == "test@example.com"
    assert user.role == "user"
    assert user.plan == "free"
    assert user.permissions == []


# ---------------------------------------------------------------------------
# X02 — envelope unwrap pattern
# ---------------------------------------------------------------------------

def test_me_envelope_shape_matches_client_expectations():  # X02
    """auth-client does: resp.json().get('data', {}) then model_validate."""
    envelope = me_payload(permissions=["analysis:create"])
    inner = envelope.get("data", {})
    user = UserInfo.model_validate(inner)
    assert user.permissions == ["analysis:create"]


# ---------------------------------------------------------------------------
# X03 — permissions is list[str]
# ---------------------------------------------------------------------------

def test_permissions_field_is_list_of_strings():  # X03
    data = me_payload(permissions=["analysis:create", "read"])["data"]
    user = UserInfo.model_validate(data)
    assert isinstance(user.permissions, list)
    assert all(isinstance(p, str) for p in user.permissions)
    assert len(user.permissions) == 2


# ---------------------------------------------------------------------------
# X04 — canonical field name is 'plan', NOT 'plan_type'
# ---------------------------------------------------------------------------

def test_plan_field_name_is_plan_not_plan_type():  # X04
    """Passing plan_type without plan must raise ValidationError."""
    bad_payload = {
        "id": "00000000-0000-0000-0000-000000000001",
        "email": "test@example.com",
        "role": "user",
        "plan_type": "pro",   # wrong field name
        "permissions": [],
    }
    with pytest.raises(ValidationError):
        UserInfo.model_validate(bad_payload)


# ---------------------------------------------------------------------------
# X05 — id accepts UUID string
# ---------------------------------------------------------------------------

def test_id_field_accepts_uuid_string():  # X05
    """auth-service emits str(user.id); UserInfo must parse it back to UUID."""
    data = me_payload(id="123e4567-e89b-12d3-a456-426614174000")["data"]
    user = UserInfo.model_validate(data)
    assert isinstance(user.id, UUID)
    assert str(user.id) == "123e4567-e89b-12d3-a456-426614174000"


# ---------------------------------------------------------------------------
# X06 — missing 'data' key in envelope is handled safely
# ---------------------------------------------------------------------------

def test_envelope_unwrap_handles_missing_data_key():  # X06
    """resp.json().get('data', {}) returns {} when 'data' is absent.
    model_validate on empty dict must raise ValidationError (not KeyError/crash)."""
    envelope_without_data = {"success": True}
    inner = envelope_without_data.get("data", {})
    assert inner == {}
    with pytest.raises(ValidationError):
        UserInfo.model_validate(inner)
