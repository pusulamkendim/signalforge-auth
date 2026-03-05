from __future__ import annotations

import hashlib
import json
import secrets
from base64 import urlsafe_b64encode

from fastapi import HTTPException, status
from redis.asyncio import Redis

# Redis key prefixes
_STATE_PREFIX = "oauth:state:"
_EXCHANGE_PREFIX = "oauth:exchange:"

# TTLs
_STATE_TTL = 600       # 10 minutes
_EXCHANGE_TTL = 90     # 90 seconds


class OAuthStateManager:
    """Manages OAuth state tokens and one-time exchange codes via Redis."""

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    # ------------------------------------------------------------------
    # State + PKCE
    # ------------------------------------------------------------------

    async def create_state(
        self, redirect_uri: str
    ) -> tuple[str, str, str]:
        """Generate state, code_verifier, and code_challenge.

        Stores state → {code_verifier, redirect_uri} in Redis with TTL.

        Returns:
            (state, code_verifier, code_challenge)
        """
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = self._s256_challenge(code_verifier)

        value = json.dumps({
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        })
        await self.redis.set(f"{_STATE_PREFIX}{state}", value, ex=_STATE_TTL)
        return state, code_verifier, code_challenge

    async def validate_state(self, state: str) -> tuple[str, str]:
        """Consume a state token (single-use via GETDEL).

        Returns:
            (code_verifier, redirect_uri)

        Raises:
            400 OAUTH_STATE_INVALID if not found or already consumed.
        """
        raw = await self.redis.getdel(f"{_STATE_PREFIX}{state}")
        if raw is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "OAUTH_STATE_INVALID"
            )
        data = json.loads(raw)
        return data["code_verifier"], data["redirect_uri"]

    # ------------------------------------------------------------------
    # One-time exchange code
    # ------------------------------------------------------------------

    async def create_exchange_code(self, session_data: dict) -> str:
        """Generate a one-time exchange code backed by Redis.

        Args:
            session_data: dict with user_id, access_token, refresh_token, expires_in

        Returns:
            URL-safe exchange code (>= 32 bytes).
        """
        code = secrets.token_urlsafe(32)
        value = json.dumps(session_data)
        await self.redis.set(
            f"{_EXCHANGE_PREFIX}{code}", value, ex=_EXCHANGE_TTL
        )
        return code

    async def validate_exchange_code(self, code: str) -> dict:
        """Consume an exchange code (single-use via GETDEL).

        Returns:
            The session_data dict.

        Raises:
            400 OAUTH_EXCHANGE_CODE_INVALID if not found or already consumed.
        """
        raw = await self.redis.getdel(f"{_EXCHANGE_PREFIX}{code}")
        if raw is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "OAUTH_EXCHANGE_CODE_INVALID"
            )
        return json.loads(raw)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _s256_challenge(verifier: str) -> str:
        """Compute S256 code_challenge from a code_verifier (RFC 7636)."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
