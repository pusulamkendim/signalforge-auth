from __future__ import annotations

# VerificationService — manages one-time tokens for email verification and
# password reset. All tokens are stored as SHA-256 hashes; the plain value is
# returned to the caller (router) who hands it to EmailService for sending.

import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthToken, Session, User
from app.core.config import get_auth_settings
from app.core.security import hash_password, hash_token


class VerificationService:
    """Token lifecycle for email verification and password reset."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_token(
        self,
        user: User,
        token_type: str,
        ip: str,
        user_agent: str,
    ) -> str:
        """Create a one-time token, persist its hash, and return the plain value.

        Args:
            token_type: ``"email_verification"`` or ``"password_reset"``
            ip / user_agent: request metadata stored for audit purposes

        Returns:
            URL-safe plain token (32 bytes → 43 characters).
        """
        settings = get_auth_settings()
        plain = secrets.token_urlsafe(32)
        token_hash = hash_token(plain)

        if token_type == "email_verification":
            expire_hours = settings.email_verification_token_expire_hours
        else:
            expire_hours = settings.password_reset_token_expire_hours

        expires_at = datetime.now(timezone.utc) + timedelta(hours=expire_hours)

        record = AuthToken(
            user_id=user.id,
            token_hash=token_hash,
            token_type=token_type,
            expires_at=expires_at,
            ip_address=ip or None,
            user_agent=user_agent or None,
        )
        self.db.add(record)
        await self.db.commit()
        return plain

    async def verify_email(self, plain_token: str) -> User:
        """Consume an email-verification token and mark the user as verified.

        On success, ALL email_verification tokens for the user are deleted so
        that old links become immediately invalid.

        Raises:
            401 — token not found, already used, or expired.
        """
        token_hash = hash_token(plain_token)
        record = await self._lookup(token_hash, "email_verification")

        user = await self.db.scalar(select(User).where(User.id == record.user_id))
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "INVALID_TOKEN")

        user.is_verified = True

        # Delete all email_verification tokens for this user (invalidates old links)
        await self.db.execute(
            delete(AuthToken).where(
                AuthToken.user_id == user.id,
                AuthToken.token_type == "email_verification",
            )
        )

        await self.db.commit()
        return user

    async def resend_verification(
        self, email: str, ip: str, user_agent: str
    ) -> tuple[User, str] | None:
        """Re-issue a verification token, replacing any existing ones.

        Always returns without raising even if the email is unknown or the user
        is already verified (enumeration protection). Returns (user, plain_token)
        so the router can send the email, or None to signal a no-op.
        """
        user = await self.db.scalar(select(User).where(User.email == email))
        if not user or user.is_verified:
            return None

        # Invalidate existing tokens before issuing a new one
        await self.db.execute(
            delete(AuthToken).where(
                AuthToken.user_id == user.id,
                AuthToken.token_type == "email_verification",
            )
        )
        await self.db.commit()

        plain = await self.create_token(user, "email_verification", ip, user_agent)
        return user, plain

    async def request_password_reset(
        self, email: str, ip: str, user_agent: str
    ) -> tuple[User, str] | None:
        """Issue a password-reset token, replacing any existing ones.

        Returns (user, plain_token) or None (enumeration protection — the
        router always responds with { ok: true }).
        """
        user = await self.db.scalar(select(User).where(User.email == email))
        if not user:
            return None

        # Invalidate previous reset tokens
        await self.db.execute(
            delete(AuthToken).where(
                AuthToken.user_id == user.id,
                AuthToken.token_type == "password_reset",
            )
        )
        await self.db.commit()

        plain = await self.create_token(user, "password_reset", ip, user_agent)
        return user, plain

    async def reset_password(self, plain_token: str, new_password: str) -> None:
        """Consume a password-reset token, update the password, and revoke all sessions.

        After a successful reset:
        - ``user.password_hash`` is updated with Argon2id
        - ``auth_token.used_at`` is set (marks token consumed)
        - All ``sessions`` rows for the user are deleted
        - ``user.token_version`` is incremented (invalidates all outstanding JWTs)

        Raises:
            401 — token not found, already used, or expired.
        """
        token_hash = hash_token(plain_token)
        record = await self._lookup(token_hash, "password_reset")

        user = await self.db.scalar(select(User).where(User.id == record.user_id))
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "INVALID_TOKEN")

        user.password_hash = hash_password(new_password)
        user.token_version += 1

        record.used_at = datetime.now(timezone.utc)

        # Revoke all active sessions (forces re-login everywhere)
        await self.db.execute(
            delete(Session).where(Session.user_id == user.id)
        )

        await self.db.commit()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _lookup(self, token_hash: str, token_type: str) -> AuthToken:
        """Fetch and validate an AuthToken record.

        Raises 401 on any failure (not found / wrong type / expired / used).
        """
        record = await self.db.scalar(
            select(AuthToken).where(
                AuthToken.token_hash == token_hash,
                AuthToken.token_type == token_type,
            )
        )
        if not record:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "INVALID_TOKEN")

        if record.used_at is not None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "INVALID_TOKEN")

        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "TOKEN_EXPIRED")

        return record
