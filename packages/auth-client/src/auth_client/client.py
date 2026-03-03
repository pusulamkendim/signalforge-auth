from __future__ import annotations

import os
from typing import Optional

import httpx

from auth_client.models import AuthServiceError, UserInfo


class AuthClient:
    """HTTP client for the SignalForge Auth Service.

    Usage::

        client = AuthClient(base_url="http://localhost:8001")
        user = await client.verify_token(token)
        if user:
            print(user.email, user.permissions)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("AUTH_SERVICE_URL", "http://localhost:8001")
        ).rstrip("/")
        self._timeout = timeout

    async def verify_token(self, token: str) -> Optional[UserInfo]:
        """Verify a Bearer token by calling GET /api/v1/auth/me.

        Returns:
            UserInfo if the token is valid, None if invalid/expired (401).

        Raises:
            AuthServiceError: for unexpected failures (5xx, network errors).
        """
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            try:
                resp = await http.get(
                    f"{self.base_url}/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.RequestError as exc:
                raise AuthServiceError(0, f"Network error: {exc}") from exc

        if resp.status_code == 401:
            return None
        if not resp.is_success:
            raise AuthServiceError(resp.status_code, resp.text)

        # Auth responses are wrapped in envelope: {"success": true, "data": {...}}
        data = resp.json().get("data", {})
        return UserInfo.model_validate(data)

    async def get_user_permissions(self, token: str) -> list[str]:
        """Return the permission list for the token owner.

        Returns an empty list when the token is invalid.
        """
        user = await self.verify_token(token)
        return user.permissions if user else []
