from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Auth-module settings.

    Intentionally separate from app/config/settings.py (Settings / get_settings)
    to avoid any naming conflicts.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",          # silently ignore unrelated .env keys
        case_sensitive=False,
    )

    # -- Database -------------------------------------------------------------
    # Expects postgresql+asyncpg://; plain postgresql:// is auto-converted by
    # the field validator below.
    database_url: str = "postgresql+asyncpg://user:password@localhost:5432/dbname"

    # -- Redis ----------------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # -- JWT ------------------------------------------------------------------
    secret_key: str = "change-me"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # -- Verification tokens --------------------------------------------------
    email_verification_token_expire_hours: int = 24
    password_reset_token_expire_hours: int = 1

    # -- Email (Resend) -------------------------------------------------------
    resend_api_key: str = ""
    email_from: str = "noreply@example.com"
    frontend_url: str = "http://localhost:3000"

    # -- Rate limiting --------------------------------------------------------
    rate_limit_login: str = "10/minute"
    rate_limit_resend_verification: str = "3/hour"
    rate_limit_password_reset: str = "3/hour"

    # -- General --------------------------------------------------------------
    environment: str = "development"

    # -- Validators -----------------------------------------------------------
    @field_validator("database_url", mode="before")
    @classmethod
    def ensure_asyncpg_driver(cls, v: str) -> str:
        """Rewrite postgresql:// or postgres:// to postgresql+asyncpg://."""
        if isinstance(v, str) and (
            v.startswith("postgresql://") or v.startswith("postgres://")
        ):
            return v.replace("://", "+asyncpg://", 1)
        return v


@lru_cache
def get_auth_settings() -> AuthSettings:
    """Return a cached AuthSettings singleton.

    To reset the cache in tests::

        get_auth_settings.cache_clear()
    """
    return AuthSettings()
