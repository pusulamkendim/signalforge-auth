from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthIdentity, Subscription, User
from app.auth.oauth.providers.base import OAuthUserInfo


class OAuthService:
    """Handles OAuth account linking and user creation."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def find_or_create_user(
        self, info: OAuthUserInfo
    ) -> tuple[User, bool]:
        """Resolve or create a user for the given OAuth profile.

        Account linking logic:
        1. AuthIdentity(provider, provider_id) exists → return existing user
        2. User with same email exists:
           a. Provider email not verified (GitHub) → reject (OAUTH_EMAIL_NOT_VERIFIED)
           b. User.is_verified = False → reject (ACCOUNT_NOT_VERIFIED)
           c. Otherwise → link new AuthIdentity to existing user
        3. No user → create User + AuthIdentity + Subscription
           Race condition: unique constraint on users.email + retry on IntegrityError

        Returns:
            (user, is_new_user)
        """
        # Path 1: existing identity
        identity = await self.db.scalar(
            select(AuthIdentity).where(
                AuthIdentity.provider == info.provider,
                AuthIdentity.provider_id == info.provider_id,
            )
        )
        if identity:
            user = await self.db.scalar(
                select(User).where(User.id == identity.user_id)
            )
            if user:
                # Update metadata on each login
                identity.metadata_ = info.raw
                await self.db.commit()
                return user, False

        # Path 2: email match
        existing_user = await self.db.scalar(
            select(User).where(User.email == info.email)
        )
        if existing_user:
            # Provider email must be verified to auto-link
            if not info.email_verified:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "OAUTH_EMAIL_NOT_VERIFIED",
                )
            # Existing user must be verified
            if not existing_user.is_verified:
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    "ACCOUNT_NOT_VERIFIED",
                )
            # Link new identity
            self.db.add(AuthIdentity(
                user_id=existing_user.id,
                provider=info.provider,
                provider_id=info.provider_id,
                metadata_=info.raw,
            ))
            await self.db.commit()
            return existing_user, False

        # Path 3: new user
        return await self._create_oauth_user(info)

    async def _create_oauth_user(
        self, info: OAuthUserInfo
    ) -> tuple[User, bool]:
        """Create a new User + AuthIdentity + Subscription.

        On unique constraint violation (race condition), fall back to linking
        the identity to the existing user.
        """
        user = User(
            email=info.email,
            password_hash=None,
            is_verified=True,  # OAuth provider verified the email
        )
        self.db.add(user)
        try:
            await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            # Another request created the user concurrently — link instead
            existing = await self.db.scalar(
                select(User).where(User.email == info.email)
            )
            if not existing:
                raise  # unexpected
            self.db.add(AuthIdentity(
                user_id=existing.id,
                provider=info.provider,
                provider_id=info.provider_id,
                metadata_=info.raw,
            ))
            await self.db.commit()
            return existing, False

        # Identity
        self.db.add(AuthIdentity(
            user_id=user.id,
            provider=info.provider,
            provider_id=info.provider_id,
            metadata_=info.raw,
        ))

        # Free subscription
        self.db.add(Subscription(
            user_id=user.id,
            plan_type="free",
            status="active",
        ))

        await self.db.commit()
        await self.db.refresh(user)
        return user, True
