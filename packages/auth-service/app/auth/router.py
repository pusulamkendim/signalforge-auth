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
    OkResponse,
    PermissionDefinitionResponse,
    PlanPermissionMappingResponse,
    RefreshRequest,
    RegisterRequest,
    RequestPasswordResetRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailRequest,
)
from app.auth.service import AuthService
from app.auth.verification_service import VerificationService
from app.core.config import get_auth_settings
from app.core.database import get_db
from app.core.email_service import EmailService
from app.core.limiter import limiter
from app.core.security import decode_access_token

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


async def _user_response(
    user: User,
    plan_type: str,
    db: AsyncSession,
) -> UserResponse:
    """Build the canonical UserResponse for a given user and plan."""
    svc = PermissionService(db)
    permissions = await svc.get_user_permissions(user.id, plan_type)
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        is_verified=user.is_verified,
        plan=plan_type,
        permissions=permissions,
    )


async def _plan_type(user_id: UUID, db: AsyncSession) -> str:
    """Resolve plan_type from the subscriptions table, defaulting to 'free'."""
    subscription = await db.scalar(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    return subscription.plan_type if subscription else "free"


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


@router.post("/register", response_model=OkResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Create a new account, send a verification email, and return { ok: true }.

    The user cannot log in until they click the verification link.
    Raises 409 if the email address is already registered.
    """
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    service = AuthService(db)
    user = await service.register(body)

    v_service = VerificationService(db)
    plain_token = await v_service.create_token(user, "email_verification", ip, ua)

    email_svc = EmailService(db)
    await email_svc.send_verification_email(user, plain_token)

    return OkResponse()


@router.post("/login", response_model=AuthResponse)
@limiter.limit(lambda: get_auth_settings().rate_limit_login)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AuthResponse:
    """Authenticate with email/password and return a session.

    Returns 401 for any authentication failure. The detail string is intentionally
    generic to prevent user-enumeration, except for EMAIL_NOT_VERIFIED which
    signals that the account exists but has not been confirmed yet.
    """
    service = AuthService(db)
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    user, access_token, plain_token = await service.login(body, ip, ua)
    plan = await _plan_type(user.id, db)

    return AuthResponse(
        user=await _user_response(user, plan, db),
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
# Email verification
# ---------------------------------------------------------------------------


@router.post("/verify-email", response_model=OkResponse)
async def verify_email(
    body: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Consume a verification token and mark the user's email as verified.

    Returns 401 for invalid, expired, or already-used tokens.
    After success all remaining email_verification tokens for the user are deleted.
    """
    v_service = VerificationService(db)
    await v_service.verify_email(body.token)
    return OkResponse()


@router.post("/resend-verification", response_model=OkResponse)
@limiter.limit(lambda: get_auth_settings().rate_limit_resend_verification)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Re-send the verification email.

    Always returns { ok: true } regardless of whether the email exists or the
    user is already verified (prevents user enumeration).
    """
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    v_service = VerificationService(db)
    result = await v_service.resend_verification(body.email, ip, ua)

    if result is not None:
        user, plain_token = result
        email_svc = EmailService(db)
        await email_svc.send_verification_email(user, plain_token)

    return OkResponse()


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


@router.post("/request-password-reset", response_model=OkResponse)
@limiter.limit(lambda: get_auth_settings().rate_limit_password_reset)
async def request_password_reset(
    body: RequestPasswordResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Initiate a password reset flow.

    Always returns { ok: true } regardless of whether the email exists
    (prevents user enumeration).
    """
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")

    v_service = VerificationService(db)
    result = await v_service.request_password_reset(body.email, ip, ua)

    if result is not None:
        user, plain_token = result
        email_svc = EmailService(db)
        await email_svc.send_password_reset_email(user, plain_token)

    return OkResponse()


@router.post("/reset-password", response_model=OkResponse)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> OkResponse:
    """Consume a password-reset token and update the user's password.

    On success:
    - password hash is updated with Argon2id
    - all active sessions are revoked
    - token_version is incremented (invalidates all outstanding JWTs)

    Returns 401 for invalid, expired, or already-used tokens.
    """
    v_service = VerificationService(db)
    await v_service.reset_password(body.token, body.new_password)
    return OkResponse()


# ---------------------------------------------------------------------------
# User profile
# ---------------------------------------------------------------------------


@router.get("/me", response_model=UserResponse)
async def get_me(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Return the authenticated user's profile including resolved permissions."""
    plan = await _plan_type(user.id, db)
    return await _user_response(user, plan, db)


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


@router.get("/admin-only", response_model=OkResponse)
async def admin_only(user: User = Depends(require_role("admin"))) -> OkResponse:
    """Admin-only sentinel endpoint used in role-enforcement tests."""
    return OkResponse()


@router.get("/test-permission", response_model=OkResponse)
async def test_permission_endpoint(
    user: User = Depends(require_permission("analysis:create")),
) -> OkResponse:
    """Requires the 'analysis:create' permission. Used by permission enforcement tests."""
    return OkResponse()
