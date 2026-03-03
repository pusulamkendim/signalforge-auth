from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_auth_settings

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
# Created once at import time; module-level singleton.
_settings = get_auth_settings()

engine = create_async_engine(
    _settings.database_url,
    echo=_settings.environment == "development",
    pool_pre_ping=True,   # recycle stale connections automatically
    pool_size=10,
    max_overflow=20,
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,   # prevent lazy-load errors after commit
    autoflush=False,
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Open a fresh AsyncSession per request and close it afterwards.

    Usage::

        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
