from __future__ import annotations

import pytest
import httpx
import respx
from pydantic import ValidationError

from auth_client.client import AuthClient
from auth_client.models import AuthServiceError, UserInfo
from helpers import me_payload


# ---------------------------------------------------------------------------
# AuthClient.verify_token
# ---------------------------------------------------------------------------


async def test_verify_token_valid_returns_user_info():  # C01
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json=me_payload())
        )
        user = await client.verify_token("valid.jwt.token")
    assert isinstance(user, UserInfo)


async def test_verify_token_sets_email_field():  # C02
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json=me_payload(email="alice@example.com"))
        )
        user = await client.verify_token("tok")
    assert user is not None
    assert user.email == "alice@example.com"


async def test_verify_token_sets_permissions():  # C03
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(
                200, json=me_payload(permissions=["analysis:create", "read"])
            )
        )
        user = await client.verify_token("tok")
    assert user is not None
    assert user.permissions == ["analysis:create", "read"]


async def test_verify_token_401_returns_none():  # C04
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(401)
        )
        user = await client.verify_token("expired.token")
    assert user is None


async def test_verify_token_500_raises_auth_service_error():  # C05
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        with pytest.raises(AuthServiceError) as exc_info:
            await client.verify_token("tok")
    assert exc_info.value.status_code == 500


async def test_verify_token_network_error_raises_auth_service_error():  # C06
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        with pytest.raises(AuthServiceError) as exc_info:
            await client.verify_token("tok")
    assert exc_info.value.status_code == 0


async def test_verify_token_sends_bearer_header():  # C07
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        route = respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json=me_payload())
        )
        await client.verify_token("my-secret-token")
    assert route.called
    sent_headers = route.calls[0].request.headers
    assert sent_headers["authorization"] == "Bearer my-secret-token"


async def test_verify_token_calls_correct_url():  # C08
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        route = respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json=me_payload())
        )
        await client.verify_token("tok")
    assert str(route.calls[0].request.url) == "http://auth.test/api/v1/auth/me"


async def test_verify_token_admin_role_parsed():  # C09
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json=me_payload(role="admin"))
        )
        user = await client.verify_token("tok")
    assert user is not None
    assert user.role == "admin"


async def test_verify_token_envelope_missing_data_key():  # C10
    """Response without 'data' key → model_validate on empty dict → ValidationError."""
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        with pytest.raises(ValidationError):
            await client.verify_token("tok")


# ---------------------------------------------------------------------------
# AuthClient.get_user_permissions
# ---------------------------------------------------------------------------


async def test_get_user_permissions_returns_list():  # C11
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(
                200, json=me_payload(permissions=["analysis:create", "read"])
            )
        )
        perms = await client.get_user_permissions("tok")
    assert perms == ["analysis:create", "read"]


async def test_get_user_permissions_empty_when_token_invalid():  # C12
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(401)
        )
        perms = await client.get_user_permissions("invalid")
    assert perms == []


async def test_get_user_permissions_propagates_service_error():  # C13
    client = AuthClient(base_url="http://auth.test")
    with respx.mock:
        respx.get("http://auth.test/api/v1/auth/me").mock(
            return_value=httpx.Response(503, text="Service Unavailable")
        )
        with pytest.raises(AuthServiceError):
            await client.get_user_permissions("tok")


# ---------------------------------------------------------------------------
# UserInfo model (pure unit — no HTTP)
# ---------------------------------------------------------------------------


def test_user_info_is_admin_true_for_admin_role():  # C14
    user = UserInfo(
        id="00000000-0000-0000-0000-000000000001",
        email="a@b.com",
        role="admin",
        is_verified=False,
        plan="free",
        permissions=[],
    )
    assert user.is_admin is True


def test_user_info_is_admin_false_for_user_role():  # C15
    user = UserInfo(
        id="00000000-0000-0000-0000-000000000001",
        email="a@b.com",
        role="user",
        is_verified=False,
        plan="free",
        permissions=[],
    )
    assert user.is_admin is False


def test_has_permission_true_for_matching():  # C16
    user = UserInfo(
        id="00000000-0000-0000-0000-000000000001",
        email="a@b.com",
        role="user",
        is_verified=False,
        plan="free",
        permissions=["analysis:create"],
    )
    assert user.has_permission("analysis:create") is True


def test_has_permission_false_for_missing():  # C17
    user = UserInfo(
        id="00000000-0000-0000-0000-000000000001",
        email="a@b.com",
        role="user",
        is_verified=False,
        plan="free",
        permissions=["analysis:create"],
    )
    assert user.has_permission("admin:delete") is False


def test_has_permission_admin_bypasses_check():  # C18
    admin = UserInfo(
        id="00000000-0000-0000-0000-000000000001",
        email="a@b.com",
        role="admin",
        is_verified=False,
        plan="free",
        permissions=[],
    )
    assert admin.has_permission("any:permission") is True


def test_auth_service_error_stores_status_code():  # C19
    err = AuthServiceError(503, "unavailable")
    assert err.status_code == 503
    assert err.message == "unavailable"
