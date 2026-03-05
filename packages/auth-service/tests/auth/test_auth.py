from __future__ import annotations

# Auth endpoint tests.
# T32: happy path | T33: token theft | T34: token_version | T35: error scenarios
#
# All /api/v1/auth/* responses are wrapped by AuthEnvelopeMiddleware:
#   success → {"success": true,  "data": {...},          "meta": {...}}
#   error   → {"success": false, "error": {"code":..., "message":..., "details":...}, "meta": {...}}
#
# Conventions used below:
#   resp.json()["data"]              — unwrap successful payload
#   resp.json()["error"]["message"]  — read error detail
#   status code assertions are unchanged

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from httpx import AsyncClient
from jose import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthIdentity, RefreshToken, Session, Subscription, User
from app.core.config import get_auth_settings
from app.core.security import decode_access_token, generate_refresh_token, hash_password, hash_token


# ===========================================================================
# T32 — Happy path
# ===========================================================================


async def test_register_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert resp.status_code == 201, f"expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]

    # Register now returns { ok: true } — no tokens issued until email is verified
    assert data == {"ok": True}, f"expected {{ok: true}}, got {data!r}"

    # DB — user row
    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    assert user is not None, "User row should exist in DB"
    assert user.is_verified is False, "New user should not be verified yet"

    # DB — email identity
    identity = await db_session.scalar(
        select(AuthIdentity).where(
            AuthIdentity.user_id == user.id,
            AuthIdentity.provider == "email",
        )
    )
    assert identity is not None, "email AuthIdentity should exist in DB"

    # DB — free subscription
    sub = await db_session.scalar(
        select(Subscription).where(Subscription.user_id == user.id)
    )
    assert sub is not None, "Subscription should exist in DB"
    assert sub.plan_type == "free", f"expected plan_type='free', got {sub.plan_type!r}"


async def test_login_success(
    verified_user: dict[str, Any], client: AsyncClient
) -> None:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]
    assert data["tokens"]["access_token"], "access_token must not be empty"
    assert data["tokens"]["refresh_token"], "refresh_token must not be empty"


async def test_refresh_success(
    verified_user: dict[str, Any],
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    refresh_token = verified_user["tokens"]["refresh_token"]

    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]
    assert data["access_token"], "new access_token must not be empty"
    assert data["refresh_token"], "new refresh_token must not be empty"
    assert data["refresh_token"] != refresh_token, "refresh_token should be rotated"

    # Old token must be revoked in DB
    old_record = await db_session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(refresh_token)
        )
    )
    assert old_record is not None, "old RefreshToken record should still exist"
    assert old_record.is_revoked is True, "old refresh_token should be revoked"


async def test_logout_success(
    verified_user: dict[str, Any],
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    access_token = verified_user["tokens"]["access_token"]

    resp = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 204, f"expected 204, got {resp.status_code}"

    # Session must be deleted from DB
    payload = decode_access_token(access_token)
    session_id = UUID(payload["sid"])
    session = await db_session.scalar(select(Session).where(Session.id == session_id))
    assert session is None, "Session should be deleted after logout"

    # Refresh token family must be revoked
    refresh_token = verified_user["tokens"]["refresh_token"]
    record = await db_session.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_token(refresh_token))
    )
    assert record is not None, "RefreshToken record should still exist after logout"
    assert record.is_revoked is True, "refresh_token should be revoked after logout"


async def test_full_flow(client: AsyncClient, db_session: AsyncSession) -> None:
    """Register → Verify email → Login → Refresh → Logout — all in sequence."""
    from app.auth.models import AuthToken
    from app.auth.verification_service import VerificationService

    # 1. Register
    reg = await client.post(
        "/api/v1/auth/register",
        json={"email": "flow@example.com", "password": "password123"},
    )
    assert reg.status_code == 201, f"Register failed: {reg.text}"
    assert reg.json()["data"] == {"ok": True}

    # 2. Verify email (bypass email delivery — call service directly)
    user = await db_session.scalar(select(User).where(User.email == "flow@example.com"))
    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "email_verification", "127.0.0.1", "test-ua")
    verify = await client.post("/api/v1/auth/verify-email", json={"token": plain_token})
    assert verify.status_code == 200, f"Verify failed: {verify.text}"

    # 3. Login
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "flow@example.com", "password": "password123"},
    )
    assert login.status_code == 200, f"Login failed: {login.text}"
    refresh_token = login.json()["data"]["tokens"]["refresh_token"]

    # 3. Refresh
    refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh.status_code == 200, f"Refresh failed: {refresh.text}"
    new_refresh = refresh.json()["data"]["refresh_token"]
    assert new_refresh != refresh_token, "token should be rotated on refresh"

    # 4. Logout — use the access token from the refresh response
    new_access_token = refresh.json()["data"]["access_token"]
    logout = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert logout.status_code == 204, f"Logout failed: {logout.text}"


async def test_logout_expired_token(
    verified_user: dict[str, Any],
    client: AsyncClient,
) -> None:
    """An expired access token must be rejected with 401."""
    settings = get_auth_settings()
    payload = decode_access_token(verified_user["tokens"]["access_token"])
    expired_payload = {
        **payload,
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    expired_token = jwt.encode(expired_payload, settings.secret_key, algorithm="HS256")

    resp = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401, f"expected 401 for expired token, got {resp.status_code}"


async def test_logout_invalid_token(client: AsyncClient) -> None:
    """A token with a bad signature must be rejected with 401."""
    resp = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )
    assert resp.status_code == 401, f"expected 401 for invalid token, got {resp.status_code}"


async def test_logout_idempotent(
    verified_user: dict[str, Any],
    client: AsyncClient,
) -> None:
    """Calling logout twice with the same token must return 204 both times."""
    access_token = verified_user["tokens"]["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    resp1 = await client.post("/api/v1/auth/logout", headers=headers)
    assert resp1.status_code == 204, f"first logout: expected 204, got {resp1.status_code}"

    resp2 = await client.post("/api/v1/auth/logout", headers=headers)
    assert resp2.status_code == 204, f"second logout: expected 204, got {resp2.status_code}"


# ===========================================================================
# T33 — Token theft detection
# ===========================================================================


async def test_refresh_token_reuse_detection(
    verified_user: dict[str, Any],
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Reusing a consumed token must revoke the entire rotation family."""
    refresh_token_1 = verified_user["tokens"]["refresh_token"]

    # First use: token_1 → token_2 (token_1 is now consumed / is_revoked=True)
    resp1 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1},
    )
    assert resp1.status_code == 200
    refresh_token_2 = resp1.json()["data"]["refresh_token"]

    # Second use of token_1 → theft detected; entire family should be revoked
    resp2 = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1},
    )
    assert resp2.status_code == 401, (
        f"expected 401 on token reuse, got {resp2.status_code}"
    )

    # token_2 must also be revoked (family-level invalidation)
    record_2 = await db_session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(refresh_token_2)
        )
    )
    assert record_2 is not None, "token_2 record should still exist in DB"
    assert record_2.is_revoked is True, (
        "refresh_token_2 should be revoked as part of family revocation"
    )


async def test_revoked_token_rejected(
    verified_user: dict[str, Any],
    client: AsyncClient,
) -> None:
    """A token that was revoked via logout must be rejected on /refresh."""
    access_token = verified_user["tokens"]["access_token"]
    refresh_token = verified_user["tokens"]["refresh_token"]

    # Logout revokes the refresh token family
    await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    # Attempt to refresh with the now-revoked token
    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert resp.status_code == 401, (
        f"expected 401 for revoked token, got {resp.status_code}"
    )


# ===========================================================================
# T34 — token_version invalidation
# ===========================================================================


async def test_token_version_invalidation(
    verified_user: dict[str, Any],
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A JWT issued before a token_version bump must be rejected."""
    access_token = verified_user["tokens"]["access_token"]
    email = verified_user["user"]["email"]

    # Simulate logout-all / password change by incrementing token_version
    await db_session.execute(
        update(User).where(User.email == email).values(token_version=999)
    )
    await db_session.commit()

    # Old token should now be rejected
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 401, f"expected 401, got {resp.status_code}"
    assert resp.json()["error"]["message"] == "SESSION_EXPIRED", (
        f"expected message='SESSION_EXPIRED', got {resp.json()['error']['message']!r}"
    )


# ===========================================================================
# T35 — Permission and error scenarios
# ===========================================================================


async def test_register_duplicate_email(client: AsyncClient) -> None:
    body = {"email": "dup@example.com", "password": "password123"}

    resp1 = await client.post("/api/v1/auth/register", json=body)
    assert resp1.status_code == 201

    resp2 = await client.post("/api/v1/auth/register", json=body)
    assert resp2.status_code == 409, (
        f"expected 409 on duplicate email, got {resp2.status_code}"
    )
    assert resp2.json()["error"]["message"] == "EMAIL_EXISTS"


async def test_login_wrong_password(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # Create a verified user directly in DB (register alone leaves user unverified)
    user = User(
        email="wrongpass@example.com",
        password_hash=hash_password("password123"),
        is_active=True,
        is_verified=True,
        token_version=0,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(AuthIdentity(user_id=user.id, provider="email", provider_id="wrongpass@example.com"))
    db_session.add(Subscription(user_id=user.id, plan_type="free", status="active"))
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "wrongpass@example.com", "password": "WRONG_PASSWORD"},
    )
    assert resp.status_code == 401, (
        f"expected 401 on wrong password, got {resp.status_code}"
    )


async def test_login_nonexistent_email(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "password123"},
    )
    # Must return 401, NOT 409 — same error as wrong password (user enumeration protection)
    assert resp.status_code == 401, (
        f"expected 401 for non-existent email, got {resp.status_code}"
    )
    assert resp.status_code != 409, "must NOT return 409 — would reveal whether email exists"


async def test_require_role_forbidden(
    verified_user: dict[str, Any],
    client: AsyncClient,
) -> None:
    """A regular user must receive 403 when accessing an admin-only endpoint."""
    access_token = verified_user["tokens"]["access_token"]

    resp = await client.get(
        "/api/v1/auth/admin-only",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403, (
        f"expected 403 for non-admin user, got {resp.status_code}"
    )


async def test_invalid_access_token(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )
    assert resp.status_code == 401, (
        f"expected 401 for invalid token, got {resp.status_code}"
    )


async def test_expired_refresh_token(
    verified_user: dict[str, Any],
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A RefreshToken whose expires_at is in the past must be rejected."""
    email = verified_user["user"]["email"]
    user = await db_session.scalar(select(User).where(User.email == email))
    assert user is not None

    # Insert an already-expired token directly into DB
    plain_token, token_hash = generate_refresh_token()
    db_session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family_id=uuid4(),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": plain_token},
    )
    assert resp.status_code == 401, (
        f"expected 401 for expired token, got {resp.status_code}"
    )
    assert resp.json()["error"]["message"] == "TOKEN_EXPIRED", (
        f"expected message='TOKEN_EXPIRED', got {resp.json()['error']['message']!r}"
    )


# ===========================================================================
# A06 — Dynamic permission system
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper: create an admin user directly in the DB and return an access token.
# We bypass the register endpoint because it always creates role="user".
# ---------------------------------------------------------------------------


async def _create_admin_token(
    client: AsyncClient,
    db_session: AsyncSession,
    email: str = "admin@example.com",
    password: str = "adminpass123",
) -> str:
    admin = User(
        email=email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
        is_verified=True,
        token_version=0,
    )
    db_session.add(admin)
    await db_session.flush()

    db_session.add(
        AuthIdentity(
            user_id=admin.id,
            provider="email",
            provider_id=email,
        )
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    return resp.json()["data"]["tokens"]["access_token"]


async def test_define_permission_as_admin(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Admin can register a new permission name."""
    admin_token = await _create_admin_token(client, db_session)

    resp = await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "transcript:create", "description": "Create transcripts"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, f"expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]
    assert data["name"] == "transcript:create"
    assert data["description"] == "Create transcripts"


async def test_define_permission_duplicate(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Defining the same permission twice returns 409."""
    admin_token = await _create_admin_token(client, db_session)
    headers = {"Authorization": f"Bearer {admin_token}"}

    body = {"name": "transcript:read"}
    resp1 = await client.post("/api/v1/auth/permissions/define", json=body, headers=headers)
    assert resp1.status_code == 201

    resp2 = await client.post("/api/v1/auth/permissions/define", json=body, headers=headers)
    assert resp2.status_code == 409, (
        f"expected 409 on duplicate permission, got {resp2.status_code}"
    )


async def test_map_permission_to_plan(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Admin can attach a defined permission to a subscription plan."""
    admin_token = await _create_admin_token(client, db_session)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # First define the permission
    await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "transcript:create"},
        headers=headers,
    )

    resp = await client.post(
        "/api/v1/auth/plans/map",
        json={"plan_type": "free", "permission_name": "transcript:create"},
        headers=headers,
    )
    assert resp.status_code == 201, f"expected 201, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]
    assert data["plan_type"] == "free"


async def test_require_permission_with_mapping(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A free user can access an endpoint when the required permission is mapped to free."""
    admin_token = await _create_admin_token(client, db_session)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Define "analysis:create" and map it to the free plan
    await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "analysis:create"},
        headers=admin_headers,
    )
    await client.post(
        "/api/v1/auth/plans/map",
        json={"plan_type": "free", "permission_name": "analysis:create"},
        headers=admin_headers,
    )

    # Create a verified free user directly in DB and log in
    free_user = User(
        email="freeuser@example.com",
        password_hash=hash_password("password123"),
        is_active=True,
        is_verified=True,
        token_version=0,
    )
    db_session.add(free_user)
    await db_session.flush()
    db_session.add(AuthIdentity(user_id=free_user.id, provider="email", provider_id="freeuser@example.com"))
    db_session.add(Subscription(user_id=free_user.id, plan_type="free", status="active"))
    await db_session.commit()
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "freeuser@example.com", "password": "password123"},
    )
    user_token = login_resp.json()["data"]["tokens"]["access_token"]

    resp = await client.get(
        "/api/v1/auth/test-permission",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200, (
        f"expected 200 when permission is mapped to plan, got {resp.status_code}: {resp.text}"
    )
    assert resp.json()["data"] == {"ok": True}


async def test_require_permission_forbidden(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """A free user is denied when the required permission is not mapped to their plan."""
    admin_token = await _create_admin_token(client, db_session)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Define "analysis:export" but do NOT map it to free
    await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "analysis:export"},
        headers=admin_headers,
    )
    # "analysis:create" (what /test-permission checks) is also NOT mapped

    # Create a verified free user directly in DB and log in
    free_user2 = User(
        email="freeuser2@example.com",
        password_hash=hash_password("password123"),
        is_active=True,
        is_verified=True,
        token_version=0,
    )
    db_session.add(free_user2)
    await db_session.flush()
    db_session.add(AuthIdentity(user_id=free_user2.id, provider="email", provider_id="freeuser2@example.com"))
    db_session.add(Subscription(user_id=free_user2.id, plan_type="free", status="active"))
    await db_session.commit()
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "freeuser2@example.com", "password": "password123"},
    )
    user_token = login_resp.json()["data"]["tokens"]["access_token"]

    resp = await client.get(
        "/api/v1/auth/test-permission",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 403, (
        f"expected 403 when permission is not mapped to plan, got {resp.status_code}"
    )


async def test_list_permissions(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Admin can list all registered permissions."""
    admin_token = await _create_admin_token(client, db_session)
    headers = {"Authorization": f"Bearer {admin_token}"}

    await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "analysis:create"},
        headers=headers,
    )
    await client.post(
        "/api/v1/auth/permissions/define",
        json={"name": "analysis:export"},
        headers=headers,
    )

    resp = await client.get("/api/v1/auth/permissions", headers=headers)
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()["data"]
    assert len(data) == 2, f"expected 2 permissions, got {len(data)}"
    names = {p["name"] for p in data}
    assert names == {"analysis:create", "analysis:export"}
