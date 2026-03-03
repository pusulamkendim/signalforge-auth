from __future__ import annotations

# AuthService — all authentication business logic lives here.
# The router layer is intentionally thin: it only handles HTTP concerns
# (request parsing, response building) and delegates everything else to this class.

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthIdentity, RefreshToken, Session, Subscription, User
from app.auth.schemas import LoginRequest, RegisterRequest
from app.core.config import get_auth_settings
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)

# Single constant keeps all "wrong credentials" paths indistinguishable,
# preventing user-enumeration via differing error messages.
_INVALID_CREDENTIALS = "Invalid credentials"


class AuthService:
    """Business logic for user registration, login, token rotation, and logout."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def register(self, request: RegisterRequest) -> User:
        """Create a new email/password account.

        Creates User + AuthIdentity + free Subscription in a single transaction.
        Raises 409 if the email is already taken.
        """
        # 1. Email uniqueness check
        existing = await self.db.scalar(
            select(User).where(User.email == request.email)
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        # 2. Create user record
        user = User(
            email=request.email,
            password_hash=hash_password(request.password),
        )
        self.db.add(user)
        await self.db.flush()  # populate user.id without committing

        # 3. Email / password identity
        self.db.add(
            AuthIdentity(
                user_id=user.id,
                provider="email",
                provider_id=request.email,
            )
        )

        # 4. Free subscription
        self.db.add(
            Subscription(
                user_id=user.id,
                plan_type="free",
                status="active",
            )
        )

        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def login(
        self, request: LoginRequest, ip: str, user_agent: str
    ) -> tuple[User, str, str]:
        """Authenticate with email/password and open a new session.

        Returns:
            (user, access_token, plain_refresh_token)

        All failure paths return the same 401 detail string to prevent
        user-enumeration attacks.
        """
        # 1. Look up user
        user = await self.db.scalar(
            select(User).where(User.email == request.email)
        )
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

        # 2. Account status
        if not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

        # 3. Email identity must exist (guards against OAuth-only accounts)
        identity = await self.db.scalar(
            select(AuthIdentity).where(
                AuthIdentity.user_id == user.id,
                AuthIdentity.provider == "email",
            )
        )
        if not identity:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

        # 4. Password check — pass "" for OAuth users (no password hash) so that
        #    verify_password catches InvalidHashError and returns False cleanly.
        if not verify_password(request.password, user.password_hash or ""):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, _INVALID_CREDENTIALS)

        # 5-9. Issue tokens and persist the session
        access_token, plain_token = await self.create_session(user, ip, user_agent)
        return user, access_token, plain_token

    async def refresh_token(self, plain_token: str) -> tuple[str, str]:
        """Rotate a refresh token using the family-based reuse-detection strategy.

        Detects theft: if a token that was already used (or revoked) is presented,
        the entire rotation family is revoked immediately.

        Returns:
            (new_access_token, new_plain_refresh_token)
        """
        token_hash = hash_token(plain_token)
        now = datetime.now(timezone.utc)

        # 1. Lookup
        record = await self.db.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        if not record:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

        # 2. Expiry check — make tzinfo explicit for asyncpg datetime objects
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")

        # 3. Revoked token presented → theft; invalidate entire family
        if record.is_revoked:
            await self._revoke_family(record.family_id)
            await self.db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token reuse detected")

        # 4. Already-used token presented → replay attack; same response
        if record.used_at is not None:
            await self._revoke_family(record.family_id)
            await self.db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token reuse detected")

        # 5. Mark current token as consumed
        record.is_revoked = True
        record.used_at = now

        # 6. Issue next token in the same rotation chain
        new_plain, new_hash = generate_refresh_token()
        settings = get_auth_settings()
        new_record = RefreshToken(
            user_id=record.user_id,
            token_hash=new_hash,
            family_id=record.family_id,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
        self.db.add(new_record)
        await self.db.flush()  # populate new_record.id for the session FK update

        # 6b. Keep the session linked to the latest refresh token in the chain
        session = await self.db.scalar(
            select(Session).where(Session.refresh_token_id == record.id)
        )
        if session:
            session.refresh_token_id = new_record.id

        # 7. Re-fetch user to get current token_version / role
        user = await self.db.scalar(
            select(User).where(User.id == record.user_id)
        )
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

        subscription = await self._get_user_subscription(record.user_id)
        plan_type = subscription.plan_type if subscription else "free"

        # 8. New access token with session claim
        new_access_token = create_access_token(
            {
                "sub": str(user.id),
                "role": user.role,
                "plan": plan_type,
                "permissions": [],
                "token_version": user.token_version,
                "sid": str(session.id) if session else "",
            }
        )

        await self.db.commit()
        return new_access_token, new_plain

    async def logout(self, session_id: UUID) -> None:
        """Close the session and revoke its refresh-token rotation family.

        Idempotent — silently succeeds if the session is not found.
        """
        session = await self.db.scalar(
            select(Session).where(Session.id == session_id)
        )
        if not session:
            return

        # Revoke the entire token family linked to this session
        if session.refresh_token_id:
            refresh_record = await self.db.scalar(
                select(RefreshToken).where(RefreshToken.id == session.refresh_token_id)
            )
            if refresh_record:
                await self._revoke_family(refresh_record.family_id)

        await self.db.delete(session)
        await self.db.commit()

    async def create_session(
        self, user: User, ip: str, user_agent: str
    ) -> tuple[str, str]:
        """Issue a new access + refresh token pair and persist the session.

        Commits the transaction before returning.

        Returns:
            (access_token, plain_refresh_token)
        """
        subscription = await self._get_user_subscription(user.id)
        plan_type = subscription.plan_type if subscription else "free"

        plain_token, token_hash = generate_refresh_token()
        settings = get_auth_settings()

        refresh_record = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            family_id=uuid4(),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.refresh_token_expire_days),
        )
        self.db.add(refresh_record)
        await self.db.flush()  # populate refresh_record.id for the FK below

        session = Session(
            user_id=user.id,
            refresh_token_id=refresh_record.id,
            ip_address=ip,
            user_agent=user_agent,
        )
        self.db.add(session)
        await self.db.flush()  # populate session.id for the sid claim

        access_token = create_access_token(
            {
                "sub": str(user.id),
                "role": user.role,
                "plan": plan_type,
                "permissions": [],
                "token_version": user.token_version,
                "sid": str(session.id),
            }
        )

        await self.db.commit()
        return access_token, plain_token

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _get_user_subscription(self, user_id: UUID) -> Subscription | None:
        return await self.db.scalar(
            select(Subscription).where(Subscription.user_id == user_id)
        )

    async def _revoke_family(self, family_id: UUID) -> None:
        """Mark every active token in *family_id* as revoked.

        Does NOT commit — caller decides when to commit.
        """
        result = await self.db.scalars(
            select(RefreshToken).where(
                RefreshToken.family_id == family_id,
                RefreshToken.is_revoked.is_(False),
            )
        )
        for token in result.all():
            token.is_revoked = True
