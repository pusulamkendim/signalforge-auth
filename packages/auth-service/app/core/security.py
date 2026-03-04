from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import HTTPException, status
from jose import JWTError, jwt

from app.core.config import get_auth_settings

# ---------------------------------------------------------------------------
# Argon2id hasher — module-level singleton (avoids repeated instantiation).
# Parameters follow OWASP Password Storage Cheat Sheet recommendations.
# ---------------------------------------------------------------------------
_ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

_ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    """Return an Argon2id hash of *plain*."""
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*, False on any mismatch or error.

    Catches both VerifyMismatchError (wrong password) and InvalidHashError
    (e.g. empty string passed for OAuth-only users who have no password hash).
    """
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_access_token(data: dict) -> str:
    """Encode *data* as a signed HS256 JWT access token.

    Standard claims added automatically:
      - jti : unique token ID (future blocklist support)
      - iat : issued-at timestamp
      - exp : expiry = now + ACCESS_TOKEN_EXPIRE_MINUTES
    """
    settings = get_auth_settings()
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and verify a JWT access token.

    Raises HTTPException 401 on any validation failure (expired, bad signature,
    malformed, etc.).
    """
    settings = get_auth_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UNAUTHORIZED",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Refresh-token helpers
# ---------------------------------------------------------------------------


def generate_refresh_token() -> tuple[str, str]:
    """Generate a cryptographically secure refresh-token pair.

    Returns:
        (plain_token, token_hash) — only the hash is persisted in the database.
    """
    plain_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    return plain_token, token_hash


def hash_token(plain: str) -> str:
    """Return the SHA-256 hex digest of *plain*.

    Used to derive the lookup key for stored token records without persisting
    the raw token value.
    """
    return hashlib.sha256(plain.encode()).hexdigest()
