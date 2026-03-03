from __future__ import annotations

# Auth router — public auth endpoints + admin permission management.
# This layer only handles HTTP concerns; all business logic lives in service classes.

from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status as http_status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, oauth2_scheme, require_permission, require_role
from app.auth.models import Subscription, User
from app.auth.permission_service import PermissionService
from app.auth.schemas import (
    AuthResponse,
    DefinePermissionRequest,
    LoginRequest,
    MapPermissionRequest,
    PermissionDefinitionResponse,
    PlanPermissionMappingResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.auth.service import AuthService
from app.core.config import get_auth_settings
from app.core.security import decode_access_token
from app.core.database import get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _token_response(access_token: str, refresh_token: str) -> TokenResponse:
    """Build a TokenResponse with the correct expires_in value."""
    settings = get_auth_settings()
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


def _user_response(user: User, plan_type: str) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        is_verified=user.is_verified,
        plan_type=plan_type,
    )


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


@router.post("/register", response_model=AuthResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Create a new account and return an authenticated session.

    Raises 409 if the email address is already registered.
    """
    service = AuthService(db)
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    user = await service.register(body)
    access_token, plain_token = await service.create_session(user, ip, ua)

    subscription = await service._get_user_subscription(user.id)
    plan_type = subscription.plan_type if subscription else "free"

    return AuthResponse(
        user=_user_response(user, plan_type),
        tokens=_token_response(access_token, plain_token),
    )


@router.post("/login", response_model=AuthResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Authenticate with email/password and return a session.

    Returns 401 for any authentication failure. The detail string is intentionally
    generic to prevent user-enumeration.
    """
    service = AuthService(db)
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    user, access_token, plain_token = await service.login(body, ip, ua)

    subscription = await service._get_user_subscription(user.id)
    plan_type = subscription.plan_type if subscription else "free"

    return AuthResponse(
        user=_user_response(user, plan_type),
        tokens=_token_response(access_token, plain_token),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Rotate a refresh token and issue a new token pair.

    Returns 401 if the token is invalid, expired, or has already been used
    (reuse detection). On reuse detection the entire rotation family is revoked.
    """
    service = AuthService(db)
    new_access, new_refresh = await service.refresh_token(body.refresh_token)
    return _token_response(new_access, new_refresh)


@router.post("/logout", status_code=204)
async def logout(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Revoke the session identified by the Bearer access token.

    Returns 204 regardless of whether the session was already gone (idempotent).
    Returns 401 for expired or invalid tokens.
    """
    payload = decode_access_token(token)  # raises 401 on expired / bad signature
    try:
        session_id = UUID(payload.get("sid", ""))
    except (ValueError, AttributeError):
        return Response(status_code=http_status.HTTP_204_NO_CONTENT)

    service = AuthService(db)
    await service.logout(session_id)
    return Response(status_code=http_status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# User profile
# ---------------------------------------------------------------------------


@router.get("/me")
async def get_me(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return the authenticated user's profile including resolved permissions."""
    subscription = await db.scalar(
        select(Subscription).where(Subscription.user_id == user.id)
    )
    plan_type = subscription.plan_type if subscription else "free"

    svc = PermissionService(db)
    permissions = await svc.get_user_permissions(user.id, plan_type)

    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "plan": plan_type,
        "permissions": permissions,
    }


# ---------------------------------------------------------------------------
# Permission management — admin only
# ---------------------------------------------------------------------------


@router.post(
    "/permissions/define",
    response_model=PermissionDefinitionResponse,
    status_code=201,
)
async def define_permission(
    body: DefinePermissionRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> PermissionDefinitionResponse:
    """Register a new permission name. Admin only."""
    svc = PermissionService(db)
    return await svc.define_permission(body.name, body.description)


@router.post(
    "/plans/map",
    response_model=PlanPermissionMappingResponse,
    status_code=201,
)
async def map_permission_to_plan(
    body: MapPermissionRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> PlanPermissionMappingResponse:
    """Attach a permission to a subscription plan. Admin only."""
    svc = PermissionService(db)
    return await svc.map_to_plan(body.plan_type, body.permission_name)


@router.get("/permissions", response_model=list[PermissionDefinitionResponse])
async def list_permissions(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[PermissionDefinitionResponse]:
    """List all registered permissions. Admin only."""
    svc = PermissionService(db)
    return await svc.list_permissions()


@router.get(
    "/plans/{plan_type}/permissions",
    response_model=list[PermissionDefinitionResponse],
)
async def list_plan_permissions(
    plan_type: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
) -> list[PermissionDefinitionResponse]:
    """List permissions assigned to a specific plan. Admin only."""
    svc = PermissionService(db)
    return await svc.list_plan_permissions(plan_type)


# ---------------------------------------------------------------------------
# Test-support / utility endpoints
# ---------------------------------------------------------------------------


@router.get("/admin-only")
async def admin_only(user: User = Depends(require_role("admin"))) -> dict[str, bool]:
    """Admin-only sentinel endpoint used in role-enforcement tests."""
    return {"ok": True}


# Test-support endpoint — permission enforcement tests
@router.get("/test-permission")
async def test_permission_endpoint(
    user: User = Depends(require_permission("analysis:create")),
) -> dict[str, bool]:
    """Requires the 'analysis:create' permission. Used by permission enforcement tests."""
    return {"ok": True}
