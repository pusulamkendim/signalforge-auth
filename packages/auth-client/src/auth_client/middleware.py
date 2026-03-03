from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from auth_client.client import AuthClient
from auth_client.models import AuthServiceError, UserInfo

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=True)


def get_current_user_from_service(auth_client: AuthClient):
    """FastAPI dependency factory that validates the Bearer token via the auth service.

    Usage::

        _auth = AuthClient()

        @router.get("/protected")
        async def protected(user: UserInfo = Depends(get_current_user_from_service(_auth))):
            return {"hello": user.email}
    """

    async def _dependency(token: str = Depends(_oauth2_scheme)) -> UserInfo:
        try:
            user = await auth_client.verify_token(token)
        except AuthServiceError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Auth service unavailable: {exc.message}",
            )
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

    return _dependency


def require_permission_from_service(permission: str, auth_client: AuthClient):
    """FastAPI dependency factory that checks a specific permission via the auth service.

    Usage::

        _auth = AuthClient()

        @router.post("/analyses")
        async def create(user: UserInfo = Depends(require_permission_from_service("analysis:create", _auth))):
            ...
    """

    async def _dependency(
        user: UserInfo = Depends(get_current_user_from_service(auth_client)),
    ) -> UserInfo:
        if not user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permission",
            )
        return user

    return _dependency
