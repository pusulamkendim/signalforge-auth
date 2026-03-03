from __future__ import annotations

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis

from app.core.config import get_auth_settings


async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    """Open a Redis connection per request and close it afterwards.

    The connection URL is sourced from AuthSettings (REDIS_URL env var).

    Usage::

        @router.get("/example")
        async def example(redis: aioredis.Redis = Depends(get_redis)):
            value = await redis.get("some-key")
    """
    settings = get_auth_settings()
    client: aioredis.Redis = aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
    )
    try:
        yield client
    finally:
        await client.aclose()
