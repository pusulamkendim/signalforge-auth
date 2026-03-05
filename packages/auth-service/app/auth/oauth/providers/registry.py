from __future__ import annotations

from fastapi import HTTPException, status

from app.auth.oauth.providers.base import OAuthProvider
from app.auth.oauth.providers.github import GitHubProvider
from app.auth.oauth.providers.google import GoogleProvider

_PROVIDERS: dict[str, type[OAuthProvider]] = {
    "google": GoogleProvider,
    "github": GitHubProvider,
}


def get_provider(name: str) -> OAuthProvider:
    """Return a provider instance by name.

    Raises 400 OAUTH_PROVIDER_NOT_SUPPORTED for unknown names.
    """
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "OAUTH_PROVIDER_NOT_SUPPORTED"
        )
    return cls()


def list_providers() -> list[str]:
    """Return the names of all registered providers."""
    return list(_PROVIDERS.keys())
