from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt

from auth_client.client import AuthClient
from auth_client.local_verifier import LocalTokenVerifier
from auth_client.middleware import get_current_user_from_service, require_permission_from_service
from auth_client.models import AuthServiceError, UserInfo
from helpers import make_user_info


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET = "test-secret-key"
_ALGO = "HS256"


def make_jwt(
    secret: str = _SECRET,
    algo: str = _ALGO,
    exp_delta_seconds: int = 3600,
    extra: dict | None = None,
) -> str:
    payload = {
        "sub": "user-1",
        "exp": datetime.now(timezone.utc) + timedelta(seconds=exp_delta_seconds),
        **(extra or {}),
    }
    return jose_jwt.encode(payload, secret, algorithm=algo)


def make_protected_app(auth_client: AuthClient) -> FastAPI:
    app = FastAPI()

    @app.get("/protected")
    async def protected(user: UserInfo = Depends(get_current_user_from_service(auth_client))):
        return {"email": user.email, "role": user.role, "plan": user.plan}

    @app.get("/needs-permission")
    async def needs_permission(
        user: UserInfo = Depends(
            require_permission_from_service("analysis:create", auth_client)
        )
    ):
        return {"email": user.email}

    return app


# ---------------------------------------------------------------------------
# get_current_user_from_service
# ---------------------------------------------------------------------------


async def test_valid_token_returns_user(mock_auth_client: MagicMock):  # M01
    mock_auth_client.verify_token.return_value = make_user_info()
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/protected", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "test@example.com"


async def test_invalid_token_returns_401(mock_auth_client: MagicMock):  # M02
    mock_auth_client.verify_token.return_value = None
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/protected", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401


async def test_service_error_returns_503(mock_auth_client: MagicMock):  # M03
    mock_auth_client.verify_token.side_effect = AuthServiceError(500, "internal error")
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/protected", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 503
    assert "unavailable" in resp.json()["detail"].lower()


async def test_missing_bearer_token_returns_401(mock_auth_client: MagicMock):  # M04
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/protected")
    assert resp.status_code == 401


async def test_user_object_injected_correctly(mock_auth_client: MagicMock):  # M05
    user = make_user_info(email="alice@example.com", role="admin", plan="pro")
    mock_auth_client.verify_token.return_value = user
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/protected", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == "admin"
    assert body["plan"] == "pro"


# ---------------------------------------------------------------------------
# require_permission_from_service
# ---------------------------------------------------------------------------


async def test_user_with_permission_allowed(mock_auth_client: MagicMock):  # M06
    mock_auth_client.verify_token.return_value = make_user_info(
        permissions=["analysis:create"]
    )
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/needs-permission", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200


async def test_user_without_permission_returns_403(mock_auth_client: MagicMock):  # M07
    mock_auth_client.verify_token.return_value = make_user_info(permissions=[])
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/needs-permission", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 403
    assert "Insufficient permission" in resp.json()["detail"]


async def test_admin_bypasses_permission_check(mock_auth_client: MagicMock):  # M08
    mock_auth_client.verify_token.return_value = make_user_info(
        role="admin", permissions=[]
    )
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/needs-permission", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 200


async def test_service_error_from_inner_dep_returns_503(mock_auth_client: MagicMock):  # M09
    mock_auth_client.verify_token.side_effect = AuthServiceError(500, "internal")
    app = make_protected_app(mock_auth_client)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/needs-permission", headers={"Authorization": "Bearer tok"})
    assert resp.status_code == 503


# ---------------------------------------------------------------------------
# LocalTokenVerifier
# ---------------------------------------------------------------------------


def test_valid_jwt_returns_payload():  # L01
    verifier = LocalTokenVerifier(_SECRET)
    token = make_jwt()
    result = verifier.verify_token(token)
    assert result is not None
    assert result["sub"] == "user-1"


def test_expired_token_returns_none():  # L02
    verifier = LocalTokenVerifier(_SECRET)
    token = make_jwt(exp_delta_seconds=-60)
    assert verifier.verify_token(token) is None


def test_wrong_algorithm_returns_none():  # L03
    """Token encoded with RS256 cannot be verified by an HS256 verifier."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    payload = {
        "sub": "user-1",
        "exp": datetime.now(timezone.utc) + timedelta(seconds=3600),
    }
    rs256_token = jose_jwt.encode(payload, private_key, algorithm="RS256")
    verifier = LocalTokenVerifier(_SECRET, algorithm="HS256")
    assert verifier.verify_token(rs256_token) is None


def test_wrong_secret_returns_none():  # L04
    token = make_jwt(secret="secret-A")
    verifier = LocalTokenVerifier("secret-B")
    assert verifier.verify_token(token) is None


def test_malformed_token_returns_none():  # L05
    verifier = LocalTokenVerifier(_SECRET)
    assert verifier.verify_token("not.a.jwt") is None


def test_missing_sub_claim_still_returns_payload():  # L06
    """LocalTokenVerifier does not enforce 'sub'; returns payload regardless."""
    payload = {"exp": datetime.now(timezone.utc) + timedelta(seconds=3600), "custom": "value"}
    token = jose_jwt.encode(payload, _SECRET, algorithm=_ALGO)
    verifier = LocalTokenVerifier(_SECRET)
    result = verifier.verify_token(token)
    assert result is not None
    assert result["custom"] == "value"
    assert "sub" not in result
