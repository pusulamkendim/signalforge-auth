from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import Subscription
from app.auth.oauth.providers.registry import get_provider
from app.auth.oauth.schemas import OAuthExchangeRequest
from app.auth.oauth.service import OAuthService
from app.auth.oauth.state import OAuthStateManager
from app.auth.permission_service import PermissionService
from app.auth.schemas import AuthResponse, TokenResponse, UserResponse
from app.auth.service import AuthService
from app.core.config import get_auth_settings
from app.core.database import get_db
from app.core.limiter import limiter

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_state_manager(request: Request) -> OAuthStateManager:
    return OAuthStateManager(request.app.state.redis)


def _validate_redirect_uri(redirect_uri: str) -> None:
    """Ensure redirect_uri is in the allowlist."""
    settings = get_auth_settings()
    allowed = [
        u.strip()
        for u in settings.oauth_redirect_uri_allowlist.split(",")
        if u.strip()
    ]
    if redirect_uri not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "OAUTH_REDIRECT_URI_NOT_ALLOWED"
        )


def _build_callback_uri(request: Request, provider: str) -> str:
    """Build the OAuth callback URI for the given provider."""
    return str(request.url_for("oauth_callback", provider=provider))


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/{provider}/authorize")
@limiter.limit("20/minute")
async def oauth_authorize(
    provider: str,
    redirect_uri: str,
    request: Request,
    state_mgr: OAuthStateManager = Depends(_get_state_manager),
):
    """Initiate OAuth flow: generate state, redirect to provider."""
    _validate_redirect_uri(redirect_uri)
    oauth_provider = get_provider(provider)

    callback_uri = _build_callback_uri(request, provider)
    state, _code_verifier, code_challenge = await state_mgr.create_state(
        redirect_uri
    )

    authorization_url = oauth_provider.get_authorization_url(
        state=state,
        code_challenge=code_challenge,
        redirect_uri=callback_uri,
    )
    return RedirectResponse(url=authorization_url, status_code=302)


@router.get("/{provider}/callback", name="oauth_callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: AsyncSession = Depends(get_db),
    state_mgr: OAuthStateManager = Depends(_get_state_manager),
):
    """Handle OAuth provider callback: validate, exchange, create session."""
    # Provider error (user denied, etc.)
    if error:
        # We don't know redirect_uri without state, redirect to default
        settings = get_auth_settings()
        fallback = settings.oauth_redirect_uri_allowlist.split(",")[0].strip()
        return RedirectResponse(
            url=f"{fallback}?error=OAUTH_PROVIDER_ERROR",
            status_code=302,
        )

    if not code or not state:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "OAUTH_STATE_INVALID"
        )

    # Validate state (GETDEL — single use, replay protection)
    code_verifier, redirect_uri = await state_mgr.validate_state(state)

    # Exchange code for tokens
    oauth_provider = get_provider(provider)
    callback_uri = _build_callback_uri(request, provider)
    token_data = await oauth_provider.exchange_code(
        code=code,
        code_verifier=code_verifier,
        redirect_uri=callback_uri,
    )

    # Fetch user profile
    user_info = await oauth_provider.get_user_info(token_data)

    # Find or create user (account linking)
    oauth_svc = OAuthService(db)
    try:
        user, _is_new = await oauth_svc.find_or_create_user(user_info)
    except HTTPException as exc:
        return RedirectResponse(
            url=f"{redirect_uri}?error={exc.detail}",
            status_code=302,
        )

    # Create session (reuse AuthService.create_session)
    auth_svc = AuthService(db)
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")
    access_token, refresh_token = await auth_svc.create_session(user, ip, ua)

    # Build exchange code with session data
    settings = get_auth_settings()
    session_data = {
        "user_id": str(user.id),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": settings.access_token_expire_minutes * 60,
    }
    exchange_code = await state_mgr.create_exchange_code(session_data)

    # Redirect to frontend with exchange code
    return RedirectResponse(
        url=f"{redirect_uri}?code={exchange_code}",
        status_code=302,
    )


@router.post("/exchange", response_model=AuthResponse)
@limiter.limit("10/minute")
async def oauth_exchange(
    body: OAuthExchangeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    state_mgr: OAuthStateManager = Depends(_get_state_manager),
):
    """Exchange a one-time code for tokens (final step of OAuth flow)."""
    from uuid import UUID
    from app.auth.models import User

    session_data = await state_mgr.validate_exchange_code(body.code)
    user_id = UUID(session_data["user_id"])

    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "UNAUTHORIZED")

    subscription = await db.scalar(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    plan_type = subscription.plan_type if subscription else "free"

    perm_svc = PermissionService(db)
    permissions = await perm_svc.get_user_permissions(user_id, plan_type)

    return AuthResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            role=user.role,
            is_verified=user.is_verified,
            plan=plan_type,
            permissions=permissions,
        ),
        tokens=TokenResponse(
            access_token=session_data["access_token"],
            refresh_token=session_data["refresh_token"],
            expires_in=session_data["expires_in"],
        ),
    )
