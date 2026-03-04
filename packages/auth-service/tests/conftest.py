from __future__ import annotations

# Test fixtures for the auth module.
#
# Event-loop strategy: asyncio_default_fixture_loop_scope=function (pytest.ini)
# Each async fixture and test runs in its own function-scoped event loop.
# A fresh AsyncEngine is created per test so its connection pool is always
# bound to the correct loop — eliminating "Future attached to different loop".

from collections.abc import AsyncGenerator
from typing import Any

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

# --- Clear settings cache BEFORE importing app modules so pytest-env's
#     .env.test values are used instead of the real .env values. ----------
from app.core.config import get_auth_settings

get_auth_settings.cache_clear()

# --- App imports (must come AFTER cache_clear) ----------------------------
import app.auth.models  # noqa: F401  — registers ORM classes with Base.metadata
from app.core.base_model import Base
from app.core.database import get_db
from app.main import app

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TEST_DB_NAME = "signalforge_auth_test"
_TEST_DB_URL = f"postgresql+asyncpg://postgres:postgres@localhost:5433/{_TEST_DB_NAME}"
_ADMIN_DB_URL = "postgresql://postgres:postgres@localhost:5433/postgres"

# Truncation order respects FK dependencies (most-dependent first).
_TRUNCATE = (
    "sessions, refresh_tokens, auth_tokens, "
    "usage_logs, usage_limits, permissions, audit_logs, email_logs, "
    "plan_permission_mappings, permission_definitions, "
    "subscriptions, auth_identities, anonymous_sessions, users, stripe_event_logs"
)


# ---------------------------------------------------------------------------
# Session-scoped: disable rate limiting for all tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_rate_limits() -> None:
    """Disable slowapi rate limits for all tests (all share 127.0.0.1)."""
    from app.core.limiter import limiter
    original = limiter.enabled
    limiter.enabled = False
    yield
    limiter.enabled = original


# ---------------------------------------------------------------------------
# Function-scoped: fresh engine + clean DB session per test
# ---------------------------------------------------------------------------


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession backed by a fresh engine for every test.

    Steps per test:
    1. Ensure signalforge_auth_test DB exists (fast no-op after first run).
    2. Create a new AsyncEngine bound to the current event loop.
    3. Run create_all (idempotent — skips existing tables).
    4. Open a session and truncate all tables so each test starts clean.
    5. Yield the session.
    6. Close the session and dispose the engine (releases all connections).
    """
    # 1. Ensure the test database exists
    admin_conn = await asyncpg.connect(_ADMIN_DB_URL)
    try:
        exists = await admin_conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", _TEST_DB_NAME
        )
        if not exists:
            await admin_conn.execute(f"CREATE DATABASE {_TEST_DB_NAME}")
    finally:
        await admin_conn.close()

    # 2. Fresh engine — pool is bound to this test's event loop
    engine: AsyncEngine = create_async_engine(_TEST_DB_URL, echo=False, pool_pre_ping=True)

    try:
        # 3. Create tables (idempotent)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # 4. Open session, wipe data, yield
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        async with factory() as session:
            await session.execute(
                text(f"TRUNCATE TABLE {_TRUNCATE} RESTART IDENTITY CASCADE")
            )
            await session.commit()
            yield session

    finally:
        # 5. Release all pooled connections
        await engine.dispose()


# ---------------------------------------------------------------------------
# Function-scoped: HTTP client with test DB wired in
# ---------------------------------------------------------------------------


@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx AsyncClient whose get_db dependency returns db_session.

    All requests made through this client hit the test database and share
    the same session object, making DB assertions straightforward.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Function-scoped: pre-verified user (bypasses email flow)
# ---------------------------------------------------------------------------

# Import models here to avoid circular imports at module level
from app.auth.models import AuthIdentity, Subscription, User
from app.core.security import hash_password


@pytest.fixture
async def verified_user(client: AsyncClient, db_session: AsyncSession) -> dict[str, Any]:
    """Insert a verified user directly into the DB, log them in, and return AuthResponse.

    Register endpoint now returns { ok: true } (no tokens), so this fixture
    bypasses the email-verification flow by creating the user in the DB directly
    with ``is_verified=True``. All tests that just need an authenticated user
    should use this fixture instead of calling /register.
    """
    user = User(
        email="test@example.com",
        password_hash=hash_password("password123"),
        is_active=True,
        is_verified=True,
        token_version=0,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(
        AuthIdentity(
            user_id=user.id,
            provider="email",
            provider_id="test@example.com",
        )
    )
    db_session.add(
        Subscription(user_id=user.id, plan_type="free", status="active")
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "password123"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["data"]
