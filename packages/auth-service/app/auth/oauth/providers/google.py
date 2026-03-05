from __future__ import annotations

from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from app.auth.oauth.providers.base import OAuthProvider, OAuthUserInfo
from app.core.config import get_auth_settings

_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
_SCOPES = "openid email profile"


class GoogleProvider(OAuthProvider):
    name = "google"

    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str,
    ) -> str:
        settings = get_auth_settings()
        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": _SCOPES,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "select_account",
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
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code_verifier": code_verifier,
                },
            )
        if resp.status_code != 200:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "OAUTH_CODE_EXCHANGE_FAILED"
            )
        return resp.json()

    async def get_user_info(self, token: dict) -> OAuthUserInfo:
        access_token = token.get("access_token", "")
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                _USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if resp.status_code != 200:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY, "OAUTH_PROFILE_FETCH_FAILED"
            )
        data = resp.json()
        email = data.get("email")
        if not email:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "OAUTH_EMAIL_NOT_PROVIDED"
            )
        return OAuthUserInfo(
            provider="google",
            provider_id=str(data["id"]),
            email=email,
            name=data.get("name"),
            avatar_url=data.get("picture"),
            email_verified=data.get("verified_email", False),
            raw=data,
        )
