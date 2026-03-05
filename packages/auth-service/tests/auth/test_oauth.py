"""OAuth integration tests.

Tests cover:
- Provider registry
- OAuthStateManager (state/PKCE, exchange code, replay attacks)
- OAuthService (account linking, race conditions)
- Router endpoints (authorize, callback, exchange)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import AuthIdentity, Subscription, User
from app.auth.oauth.providers.base import OAuthUserInfo
from app.auth.oauth.providers.registry import get_provider, list_providers
from app.auth.oauth.service import OAuthService
from app.auth.oauth.state import OAuthStateManager
from app.core.config import get_auth_settings
from app.core.security import hash_password
from app.main import app


# ---------------------------------------------------------------------------
# Redis fixture — OAuth tests need Redis for state management
# ---------------------------------------------------------------------------

@pytest.fixture
async def redis_client():
    """Provide a real Redis connection (test DB 1) and wire it into app.state."""
    settings = get_auth_settings()
    r = aioredis.from_url(settings.redis_url, decode_responses=True)
    await r.ping()
    # Wire into app so that endpoints can access it via request.app.state.redis
    app.state.redis = r
    yield r
    await r.flushdb()
    await r.aclose()


@pytest.fixture
def state_mgr(redis_client) -> OAuthStateManager:
    return OAuthStateManager(redis_client)


# ---------------------------------------------------------------------------
# Provider registry tests
# ---------------------------------------------------------------------------


class TestProviderRegistry:
    def test_get_google_provider(self):
        p = get_provider("google")
        assert p.name == "google"

    def test_get_github_provider(self):
        p = get_provider("github")
        assert p.name == "github"

    def test_unknown_provider_raises(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            get_provider("unknown")
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "OAUTH_PROVIDER_NOT_SUPPORTED"

    def test_list_providers(self):
        providers = list_providers()
        assert "google" in providers
        assert "github" in providers


# ---------------------------------------------------------------------------
# State manager tests
# ---------------------------------------------------------------------------


class TestStateManager:
    async def test_create_and_validate_state(self, state_mgr: OAuthStateManager):
        state, code_verifier, code_challenge = await state_mgr.create_state(
            "http://localhost:3000"
        )
        assert len(state) >= 32
        assert len(code_verifier) >= 32
        assert len(code_challenge) > 0

        cv, redirect_uri = await state_mgr.validate_state(state)
        assert cv == code_verifier
        assert redirect_uri == "http://localhost:3000"

    async def test_state_replay_attack(self, state_mgr: OAuthStateManager):
        """Same state token used twice → OAUTH_STATE_INVALID on second call."""
        state, _, _ = await state_mgr.create_state("http://localhost:3000")

        # First use succeeds
        await state_mgr.validate_state(state)

        # Second use fails (GETDEL already consumed the key)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await state_mgr.validate_state(state)
        assert exc_info.value.detail == "OAUTH_STATE_INVALID"

    async def test_invalid_state_rejected(self, state_mgr: OAuthStateManager):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await state_mgr.validate_state("nonexistent-state-token")
        assert exc_info.value.detail == "OAUTH_STATE_INVALID"

    async def test_exchange_code_round_trip(self, state_mgr: OAuthStateManager):
        data = {"user_id": "abc", "access_token": "at", "refresh_token": "rt", "expires_in": 900}
        code = await state_mgr.create_exchange_code(data)
        assert len(code) >= 32

        result = await state_mgr.validate_exchange_code(code)
        assert result == data

    async def test_exchange_code_replay(self, state_mgr: OAuthStateManager):
        """Same exchange code used twice → OAUTH_EXCHANGE_CODE_INVALID."""
        data = {"user_id": "abc"}
        code = await state_mgr.create_exchange_code(data)

        await state_mgr.validate_exchange_code(code)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await state_mgr.validate_exchange_code(code)
        assert exc_info.value.detail == "OAUTH_EXCHANGE_CODE_INVALID"

    async def test_invalid_exchange_code_rejected(self, state_mgr: OAuthStateManager):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await state_mgr.validate_exchange_code("nonexistent-code-12345678901234567890")
        assert exc_info.value.detail == "OAUTH_EXCHANGE_CODE_INVALID"

    async def test_pkce_s256_challenge(self, state_mgr: OAuthStateManager):
        """Verify S256 code_challenge follows RFC 7636."""
        import hashlib
        from base64 import urlsafe_b64encode

        state, code_verifier, code_challenge = await state_mgr.create_state(
            "http://localhost:3000"
        )
        expected = urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert code_challenge == expected


# ---------------------------------------------------------------------------
# OAuthService — account linking tests
# ---------------------------------------------------------------------------


class TestOAuthService:
    def _make_info(
        self,
        provider: str = "google",
        provider_id: str = "123",
        email: str = "oauth@example.com",
        email_verified: bool = True,
    ) -> OAuthUserInfo:
        return OAuthUserInfo(
            provider=provider,
            provider_id=provider_id,
            email=email,
            email_verified=email_verified,
            raw={"id": provider_id},
        )

    async def test_new_user_created(self, db_session: AsyncSession):
        """OAuth login for new email → creates User + AuthIdentity + Subscription."""
        svc = OAuthService(db_session)
        info = self._make_info(email="new@example.com")

        user, is_new = await svc.find_or_create_user(info)

        assert is_new is True
        assert user.email == "new@example.com"
        assert user.is_verified is True
        assert user.password_hash is None

        # Verify identity was created
        identity = await db_session.scalar(
            select(AuthIdentity).where(
                AuthIdentity.user_id == user.id,
                AuthIdentity.provider == "google",
            )
        )
        assert identity is not None
        assert identity.provider_id == "123"

        # Verify subscription was created
        sub = await db_session.scalar(
            select(Subscription).where(Subscription.user_id == user.id)
        )
        assert sub is not None
        assert sub.plan_type == "free"

    async def test_existing_identity_returns_user(self, db_session: AsyncSession):
        """Same provider+provider_id → returns existing user, no duplicate."""
        svc = OAuthService(db_session)
        info = self._make_info(email="repeat@example.com", provider_id="456")

        user1, is_new1 = await svc.find_or_create_user(info)
        assert is_new1 is True

        user2, is_new2 = await svc.find_or_create_user(info)
        assert is_new2 is False
        assert user2.id == user1.id

    async def test_link_to_verified_email_user(self, db_session: AsyncSession):
        """OAuth email matches verified email-registered user → link identity."""
        # Create existing verified user with email identity
        user = User(
            email="existing@example.com",
            password_hash=hash_password("pass123"),
            is_verified=True,
        )
        db_session.add(user)
        await db_session.flush()
        db_session.add(AuthIdentity(
            user_id=user.id, provider="email", provider_id="existing@example.com"
        ))
        db_session.add(Subscription(user_id=user.id, plan_type="free", status="active"))
        await db_session.commit()

        # OAuth login with same email
        svc = OAuthService(db_session)
        info = self._make_info(email="existing@example.com", provider_id="789")

        linked_user, is_new = await svc.find_or_create_user(info)
        assert is_new is False
        assert linked_user.id == user.id

        # Verify both identities exist
        identities = (await db_session.scalars(
            select(AuthIdentity).where(AuthIdentity.user_id == user.id)
        )).all()
        providers = {i.provider for i in identities}
        assert providers == {"email", "google"}

    async def test_unverified_email_user_rejected(self, db_session: AsyncSession):
        """OAuth email matches UNVERIFIED user → ACCOUNT_NOT_VERIFIED."""
        user = User(
            email="unverified@example.com",
            password_hash=hash_password("pass123"),
            is_verified=False,
        )
        db_session.add(user)
        await db_session.commit()

        svc = OAuthService(db_session)
        info = self._make_info(email="unverified@example.com")

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await svc.find_or_create_user(info)
        assert exc_info.value.detail == "ACCOUNT_NOT_VERIFIED"

    async def test_github_unverified_email_rejected(self, db_session: AsyncSession):
        """GitHub email_verified=False + existing user → OAUTH_EMAIL_NOT_VERIFIED."""
        user = User(
            email="github@example.com",
            password_hash=hash_password("pass123"),
            is_verified=True,
        )
        db_session.add(user)
        await db_session.commit()

        svc = OAuthService(db_session)
        info = self._make_info(
            provider="github",
            email="github@example.com",
            email_verified=False,
        )

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await svc.find_or_create_user(info)
        assert exc_info.value.detail == "OAUTH_EMAIL_NOT_VERIFIED"


# ---------------------------------------------------------------------------
# Router integration tests
# ---------------------------------------------------------------------------


def _mock_google_provider():
    """Return a mock GoogleProvider that returns a canned OAuthUserInfo."""
    provider = MagicMock()
    provider.name = "google"
    provider.get_authorization_url.return_value = "https://accounts.google.com/o/oauth2/v2/auth?mocked=true"
    provider.exchange_code = AsyncMock(return_value={"access_token": "mock-at"})
    provider.get_user_info = AsyncMock(return_value=OAuthUserInfo(
        provider="google",
        provider_id="goog-999",
        email="oauthuser@example.com",
        name="OAuth User",
        avatar_url=None,
        email_verified=True,
        raw={"id": "goog-999"},
    ))
    return provider


class TestOAuthRouter:
    async def test_authorize_redirects_to_provider(
        self, client: AsyncClient, redis_client
    ):
        """GET /oauth/google/authorize → 302 to Google."""
        resp = await client.get(
            "/api/v1/auth/oauth/google/authorize",
            params={"redirect_uri": "http://localhost:3000"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "accounts.google.com" in location
        assert "state=" in location

    async def test_authorize_unknown_provider(
        self, client: AsyncClient, redis_client
    ):
        """GET /oauth/unknown/authorize → 400 OAUTH_PROVIDER_NOT_SUPPORTED."""
        resp = await client.get(
            "/api/v1/auth/oauth/unknown/authorize",
            params={"redirect_uri": "http://localhost:3000"},
        )
        assert resp.status_code == 400

    async def test_authorize_disallowed_redirect_uri(
        self, client: AsyncClient, redis_client
    ):
        """GET /oauth/google/authorize with bad redirect_uri → 400."""
        resp = await client.get(
            "/api/v1/auth/oauth/google/authorize",
            params={"redirect_uri": "https://evil.com"},
        )
        assert resp.status_code == 400

    async def test_callback_full_flow(
        self, client: AsyncClient, db_session: AsyncSession, redis_client
    ):
        """Full callback flow: state → exchange → AuthResponse."""
        state_mgr = OAuthStateManager(redis_client)
        state, code_verifier, code_challenge = await state_mgr.create_state(
            "http://localhost:3000"
        )

        mock_provider = _mock_google_provider()

        with patch(
            "app.auth.oauth.router.get_provider", return_value=mock_provider
        ):
            resp = await client.get(
                "/api/v1/auth/oauth/google/callback",
                params={"code": "auth-code-123", "state": state},
                follow_redirects=False,
            )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("http://localhost:3000?code=")

        # Extract exchange code from redirect
        exchange_code = location.split("code=")[1]

        # Exchange code for tokens
        exchange_resp = await client.post(
            "/api/v1/auth/oauth/exchange",
            json={"code": exchange_code},
        )
        assert exchange_resp.status_code == 200
        data = exchange_resp.json()["data"]
        assert "user" in data
        assert "tokens" in data
        assert data["user"]["email"] == "oauthuser@example.com"
        assert data["user"]["is_verified"] is True

    async def test_callback_state_replay_attack(
        self, client: AsyncClient, redis_client
    ):
        """Callback with same state twice → second call fails."""
        state_mgr = OAuthStateManager(redis_client)
        state, _, _ = await state_mgr.create_state("http://localhost:3000")

        mock_provider = _mock_google_provider()

        with patch(
            "app.auth.oauth.router.get_provider", return_value=mock_provider
        ):
            # First call succeeds
            resp1 = await client.get(
                "/api/v1/auth/oauth/google/callback",
                params={"code": "auth-code-123", "state": state},
                follow_redirects=False,
            )
            assert resp1.status_code == 302

            # Second call with same state → OAUTH_STATE_INVALID
            resp2 = await client.get(
                "/api/v1/auth/oauth/google/callback",
                params={"code": "auth-code-456", "state": state},
            )
            assert resp2.status_code == 400

    async def test_callback_invalid_state(
        self, client: AsyncClient, redis_client
    ):
        """Callback with invalid state → 400."""
        resp = await client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "auth-code", "state": "invalid-state-token"},
        )
        assert resp.status_code == 400

    async def test_exchange_replay_attack(
        self, client: AsyncClient, db_session: AsyncSession, redis_client
    ):
        """Same exchange code used twice → OAUTH_EXCHANGE_CODE_INVALID."""
        state_mgr = OAuthStateManager(redis_client)
        state, _, _ = await state_mgr.create_state("http://localhost:3000")

        mock_provider = _mock_google_provider()

        with patch(
            "app.auth.oauth.router.get_provider", return_value=mock_provider
        ):
            resp = await client.get(
                "/api/v1/auth/oauth/google/callback",
                params={"code": "auth-code", "state": state},
                follow_redirects=False,
            )

        exchange_code = resp.headers["location"].split("code=")[1]

        # First exchange succeeds
        resp1 = await client.post(
            "/api/v1/auth/oauth/exchange",
            json={"code": exchange_code},
        )
        assert resp1.status_code == 200

        # Second exchange fails
        resp2 = await client.post(
            "/api/v1/auth/oauth/exchange",
            json={"code": exchange_code},
        )
        assert resp2.status_code == 400

    async def test_exchange_short_code_rejected(
        self, client: AsyncClient, redis_client
    ):
        """Exchange with code < 32 chars → 400 validation error."""
        resp = await client.post(
            "/api/v1/auth/oauth/exchange",
            json={"code": "short"},
        )
        assert resp.status_code == 400
