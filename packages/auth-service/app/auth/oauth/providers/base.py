from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class OAuthUserInfo:
    """Normalized user profile returned by any OAuth provider."""

    provider: str          # "google" | "github"
    provider_id: str       # unique ID from the provider
    email: str
    name: str | None = None
    avatar_url: str | None = None
    email_verified: bool = False
    raw: dict = field(default_factory=dict)


class OAuthProvider(ABC):
    """Abstract base for OAuth 2.0 providers."""

    name: str

    @abstractmethod
    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str,
    ) -> str:
        """Return the provider's authorization URL for the user to visit."""

    @abstractmethod
    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict:
        """Exchange an authorization code for an access token dict."""

    @abstractmethod
    async def get_user_info(self, token: dict) -> OAuthUserInfo:
        """Fetch the user's profile from the provider using the access token."""
