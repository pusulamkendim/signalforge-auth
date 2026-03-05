from __future__ import annotations

from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from app.auth.oauth.providers.base import OAuthProvider, OAuthUserInfo
from app.core.config import get_auth_settings

_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_TOKEN_URL = "https://github.com/login/oauth/access_token"
_USER_URL = "https://api.github.com/user"
_EMAILS_URL = "https://api.github.com/user/emails"
_SCOPES = "read:user user:email"


class GitHubProvider(OAuthProvider):
    name = "github"

    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str,
    ) -> str:
        settings = get_auth_settings()
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect_uri,
            "scope": _SCOPES,
            "state": state,
            # GitHub does not support PKCE — state provides CSRF protection
        }
        return f"{_AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict:
        settings = get_auth_settings()
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                _TOKEN_URL,
                data={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
        if resp.status_code != 200:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "OAUTH_CODE_EXCHANGE_FAILED"
            )
        data = resp.json()
        if "error" in data:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "OAUTH_CODE_EXCHANGE_FAILED"
            )
        return data

    async def get_user_info(self, token: dict) -> OAuthUserInfo:
        access_token = token.get("access_token", "")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            # Fetch profile
            user_resp = await client.get(_USER_URL, headers=headers)
            if user_resp.status_code != 200:
                raise HTTPException(
                    status.HTTP_502_BAD_GATEWAY, "OAUTH_PROFILE_FETCH_FAILED"
                )
            user_data = user_resp.json()

            # Fetch emails (profile email may be private)
            emails_resp = await client.get(_EMAILS_URL, headers=headers)
            if emails_resp.status_code != 200:
                raise HTTPException(
                    status.HTTP_502_BAD_GATEWAY, "OAUTH_PROFILE_FETCH_FAILED"
                )
            emails_data = emails_resp.json()

        # Find primary verified email
        primary_email = None
        email_verified = False
        for entry in emails_data:
            if entry.get("primary"):
                primary_email = entry.get("email")
                email_verified = entry.get("verified", False)
                break

        # Fallback to profile email
        if not primary_email:
            primary_email = user_data.get("email")

        if not primary_email:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "OAUTH_EMAIL_NOT_PROVIDED"
            )

        return OAuthUserInfo(
            provider="github",
            provider_id=str(user_data["id"]),
            email=primary_email,
            name=user_data.get("name"),
            avatar_url=user_data.get("avatar_url"),
            email_verified=email_verified,
            raw=user_data,
        )
