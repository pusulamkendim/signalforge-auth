from __future__ import annotations

# FastAPI dependency callables for auth.
# Import and use these with Depends() in any router that requires authentication.

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import Subscription, User
from app.core.database import get_db
from app.core.security import decode_access_token

# Tells FastAPI where to send users to obtain a token (used in OpenAPI docs).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate a Bearer JWT and return the authenticated User.

    Raises HTTP 401 when:
      - Token is missing, expired, or has an invalid signature.
      - The user referenced by ``sub`` does not exist.
      - The account is disabled (``is_active=False``).
      - ``token_version`` in the JWT does not match the stored value
        (happens after a logout-all / password-change cycle).
    """
    payload = decode_access_token(token)

    raw_id: str | None = payload.get("sub")
    if not raw_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    # Validate that the claim is a well-formed UUID before hitting the DB.
    try:
        user_id = UUID(raw_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    # Guard against stale JWTs issued before a logout-all or token invalidation.
    if payload.get("token_version") != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalidated",
        )

    return user


def require_role(role: str):
    """Return a dependency that enforces *role* membership.

    Admins (``role == "admin"``) bypass all role checks.

    Usage::

        @router.get("/admin-only")
        async def admin_route(user: User = Depends(require_role("admin"))):
            ...
    """

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role != role and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return dependency


def require_permission(permission: str):
    """Return a dependency that enforces a named permission.

    Resolution order:
      1. Admins always pass.
      2. Look up the user's plan via the Subscription table.
      3. Query PermissionService for plan-level + per-user overrides.
      4. Raise HTTP 403 if *permission* is not in the resolved set.

    Usage::

        @router.post("/analyses")
        async def create_analysis(user = Depends(require_permission("analysis:create"))):
            ...
    """

    async def dependency(
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if user.role == "admin":
            return user

        subscription = await db.scalar(
            select(Subscription).where(Subscription.user_id == user.id)
        )
        plan_type = subscription.plan_type if subscription else "free"

        from app.auth.permission_service import PermissionService

        svc = PermissionService(db)
        user_permissions = await svc.get_user_permissions(user.id, plan_type)

        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permission",
            )
        return user

    return dependency
