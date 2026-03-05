from __future__ import annotations

# Verification & password-reset endpoint tests (T40–T51).
#
# Token plain values are never stored in the DB (only SHA-256 hashes), so tests
# call VerificationService.create_token() directly to obtain the plain token,
# then pass it to the endpoint under test.

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthIdentity, AuthToken, EmailLog, Session, Subscription, User
from app.auth.verification_service import VerificationService
from app.core.security import decode_access_token, hash_password, hash_token, verify_password


# ===========================================================================
# T40 — Register creates a verification token
# ===========================================================================


async def test_register_creates_verification_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Register → { ok: true }; DB must have an email_verification token."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "new@example.com", "password": "password123"},
    )
    assert resp.status_code == 201
    assert resp.json()["data"] == {"ok": True}

    user = await db_session.scalar(select(User).where(User.email == "new@example.com"))
    assert user is not None
    assert user.is_verified is False, "New user should not be verified yet"

    token_rec = await db_session.scalar(
        select(AuthToken).where(
            AuthToken.user_id == user.id,
            AuthToken.token_type == "email_verification",
        )
    )
    assert token_rec is not None, "auth_tokens must have an email_verification record"
    assert token_rec.used_at is None, "Token must not be consumed yet"
    assert token_rec.expires_at > datetime.now(timezone.utc), "Token must not be expired"

    log = await db_session.scalar(
        select(EmailLog).where(
            EmailLog.user_id == user.id,
            EmailLog.email_type == "verification",
        )
    )
    assert log is not None, "EmailLog record must exist for verification email"


# ===========================================================================
# T41 — Successful email verification
# ===========================================================================


async def test_verify_email_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Valid token → is_verified=True; all email_verification tokens deleted."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "verify@example.com", "password": "password123"},
    )
    user = await db_session.scalar(select(User).where(User.email == "verify@example.com"))

    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "email_verification", "127.0.0.1", "test-ua")

    resp = await client.post("/api/v1/auth/verify-email", json={"token": plain_token})
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}

    await db_session.refresh(user)
    assert user.is_verified is True

    remaining = await db_session.scalar(
        select(AuthToken).where(
            AuthToken.user_id == user.id,
            AuthToken.token_type == "email_verification",
        )
    )
    assert remaining is None, "All email_verification tokens should be deleted after use"


# ===========================================================================
# T42 — Verification token replay rejected
# ===========================================================================


async def test_verify_email_replay_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Using the same token a second time must return 401 (token was deleted)."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "replay@example.com", "password": "password123"},
    )
    user = await db_session.scalar(select(User).where(User.email == "replay@example.com"))
    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "email_verification", "127.0.0.1", "ua")

    resp1 = await client.post("/api/v1/auth/verify-email", json={"token": plain_token})
    assert resp1.status_code == 200

    resp2 = await client.post("/api/v1/auth/verify-email", json={"token": plain_token})
    assert resp2.status_code == 401, f"Replay must be rejected: {resp2.status_code}"


# ===========================================================================
# T43 — Expired verification token rejected
# ===========================================================================


async def test_verify_email_expired_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Expired token → 401; is_verified stays False."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "expired@example.com", "password": "password123"},
    )
    user = await db_session.scalar(select(User).where(User.email == "expired@example.com"))

    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "email_verification", "127.0.0.1", "ua")

    # Backdate the specific token we just created (look up by hash to avoid ambiguity)
    token_rec = await db_session.scalar(
        select(AuthToken).where(AuthToken.token_hash == hash_token(plain_token))
    )
    token_rec.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await db_session.commit()

    resp = await client.post("/api/v1/auth/verify-email", json={"token": plain_token})
    assert resp.status_code == 401, "Expired token must be rejected"

    await db_session.refresh(user)
    assert user.is_verified is False, "is_verified must not change on expired token"


# ===========================================================================
# T44 — resend-verification enumeration protection
# ===========================================================================


async def test_resend_verification_nonexistent_email(client: AsyncClient) -> None:
    """Unknown email → still { ok: true } (enumeration protection)."""
    resp = await client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "nobody@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}


async def test_resend_verification_already_verified(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Already-verified user → still { ok: true }, no new token created."""
    user = User(
        email="done@example.com",
        password_hash=hash_password("pw123"),
        is_verified=True,
        is_active=True,
        token_version=0,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(AuthIdentity(user_id=user.id, provider="email", provider_id="done@example.com"))
    db_session.add(Subscription(user_id=user.id, plan_type="free", status="active"))
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "done@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}

    token_count = await db_session.scalar(
        select(AuthToken).where(AuthToken.user_id == user.id)
    )
    assert token_count is None, "No token should be created for already-verified user"


async def test_resend_verification_creates_new_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Resend deletes the old token and creates a new one."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "resend@example.com", "password": "password123"},
    )
    user = await db_session.scalar(select(User).where(User.email == "resend@example.com"))

    first_token = await db_session.scalar(
        select(AuthToken).where(AuthToken.user_id == user.id)
    )
    first_id = first_token.id

    resp = await client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "resend@example.com"},
    )
    assert resp.status_code == 200

    # Fetch all remaining tokens for this user (should be exactly one, and a different one)
    all_tokens = (await db_session.scalars(
        select(AuthToken).where(AuthToken.user_id == user.id)
        .execution_options(populate_existing=True)
    )).all()
    assert len(all_tokens) == 1, f"Expected 1 token after resend, got {len(all_tokens)}"
    assert all_tokens[0].id != first_id, "A fresh token must be created on resend"


# ===========================================================================
# T45 — Password reset token created
# ===========================================================================


async def test_request_password_reset_creates_token(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """Valid email → password_reset token created + email logged."""
    resp = await client.post(
        "/api/v1/auth/request-password-reset",
        json={"email": "test@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}

    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    token_rec = await db_session.scalar(
        select(AuthToken).where(
            AuthToken.user_id == user.id,
            AuthToken.token_type == "password_reset",
        )
    )
    assert token_rec is not None, "password_reset token must be created"
    assert token_rec.used_at is None
    assert token_rec.expires_at > datetime.now(timezone.utc)

    log = await db_session.scalar(
        select(EmailLog).where(
            EmailLog.user_id == user.id,
            EmailLog.email_type == "password_reset",
        )
    )
    assert log is not None, "EmailLog must record the password_reset email"


# ===========================================================================
# T46 — Successful password reset
# ===========================================================================


async def test_reset_password_success(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """Valid token → password changed, token marked used."""
    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    old_hash = user.password_hash

    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "password_reset", "127.0.0.1", "ua")

    resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "NewSecurePass99"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}

    await db_session.refresh(user)
    assert user.password_hash != old_hash, "Password hash must change"
    assert verify_password("NewSecurePass99", user.password_hash), "New password must verify"

    token_rec = await db_session.scalar(
        select(AuthToken).where(
            AuthToken.user_id == user.id,
            AuthToken.token_type == "password_reset",
        )
    )
    assert token_rec is None, "Token must be deleted after successful reset"


# ===========================================================================
# T47 — Reset token replay rejected
# ===========================================================================


async def test_reset_password_replay_rejected(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """Using the same reset token twice → 401 on second attempt."""
    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "password_reset", "127.0.0.1", "ua")

    resp1 = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "FirstReset123"},
    )
    assert resp1.status_code == 200

    resp2 = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "SecondReset456"},
    )
    assert resp2.status_code == 401, f"Replay must be rejected: {resp2.status_code}"


# ===========================================================================
# T48 — Expired reset token rejected
# ===========================================================================


async def test_reset_password_expired_token(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """Expired reset token → 401; password unchanged."""
    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    old_hash = user.password_hash

    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "password_reset", "127.0.0.1", "ua")

    token_rec = await db_session.scalar(
        select(AuthToken).where(AuthToken.token_hash == hash_token(plain_token))
    )
    token_rec.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "ShouldNotWork1"},
    )
    assert resp.status_code == 401, "Expired reset token must be rejected"

    await db_session.refresh(user)
    assert user.password_hash == old_hash, "Password must not change on expired token"


# ===========================================================================
# T49 — Password reset revokes all sessions
# ===========================================================================


async def test_reset_password_revokes_sessions(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """After reset: existing session deleted; old JWT rejected; token_version bumped."""
    access_token = verified_user["tokens"]["access_token"]
    payload = decode_access_token(access_token)
    session_id = UUID(payload["sid"])
    old_token_version = payload["token_version"]

    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "password_reset", "127.0.0.1", "ua")

    resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "ResetAndRevoke99"},
    )
    assert resp.status_code == 200

    # Session must be deleted
    session = await db_session.scalar(select(Session).where(Session.id == session_id))
    assert session is None, "Session must be deleted after password reset"

    # token_version must increase
    await db_session.refresh(user)
    assert user.token_version > old_token_version, "token_version must be incremented"

    # Old access token must be rejected
    me_resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 401, "Old JWT must be invalid after password reset"


# ===========================================================================
# T50 — request-password-reset enumeration protection
# ===========================================================================


async def test_request_password_reset_nonexistent_email(client: AsyncClient) -> None:
    """Unknown email → { ok: true } (enumeration protection)."""
    resp = await client.post(
        "/api/v1/auth/request-password-reset",
        json={"email": "ghost@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"] == {"ok": True}


async def test_request_password_reset_response_identical_for_valid_invalid(
    client: AsyncClient, verified_user: dict[str, Any]
) -> None:
    """Response is identical for known and unknown emails."""
    valid_resp = await client.post(
        "/api/v1/auth/request-password-reset",
        json={"email": "test@example.com"},
    )
    invalid_resp = await client.post(
        "/api/v1/auth/request-password-reset",
        json={"email": "doesnotexist@example.com"},
    )
    assert valid_resp.status_code == invalid_resp.status_code == 200
    assert valid_resp.json()["data"] == invalid_resp.json()["data"] == {"ok": True}


# ===========================================================================
# T51 — Login with new password after reset
# ===========================================================================


async def test_login_with_new_password_after_reset(
    client: AsyncClient, db_session: AsyncSession, verified_user: dict[str, Any]
) -> None:
    """After reset: old password rejected; new password accepted."""
    user = await db_session.scalar(select(User).where(User.email == "test@example.com"))
    svc = VerificationService(db_session)
    plain_token = await svc.create_token(user, "password_reset", "127.0.0.1", "ua")

    await client.post(
        "/api/v1/auth/reset-password",
        json={"token": plain_token, "new_password": "BrandNew789"},
    )

    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert old_login.status_code == 401, "Old password must be rejected after reset"

    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "BrandNew789"},
    )
    assert new_login.status_code == 200, f"New password login failed: {new_login.text}"
    assert new_login.json()["data"]["tokens"]["access_token"], "access_token must be present"


# ===========================================================================
# Bonus — Unverified user cannot login
# ===========================================================================


async def test_login_blocked_for_unverified_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A user who has not verified their email gets EMAIL_NOT_VERIFIED on login."""
    await client.post(
        "/api/v1/auth/register",
        json={"email": "unverified@example.com", "password": "password123"},
    )

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "unverified@example.com", "password": "password123"},
    )
    assert resp.status_code == 401
    assert "EMAIL_NOT_VERIFIED" in resp.json()["error"]["message"] or \
           resp.json()["error"]["code"] == "EMAIL_NOT_VERIFIED", \
           f"Expected EMAIL_NOT_VERIFIED error, got: {resp.json()['error']}"
