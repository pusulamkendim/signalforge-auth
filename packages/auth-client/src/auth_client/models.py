from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class UserInfo(BaseModel):
    """Authenticated user profile returned by the auth service.

    Field names mirror the GET /api/v1/auth/me response exactly.
    Note: the plan field is named ``plan`` (not ``plan_type``) in the response.
    """

    id: UUID
    email: str
    role: str
    is_verified: bool
    plan: str = "free"
    permissions: list[str] = []

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def has_permission(self, permission: str) -> bool:
        """Return True if the user has the given permission or is an admin."""
        return self.is_admin or permission in self.permissions


class AuthServiceError(Exception):
    """Raised when the auth service returns an unexpected error."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"Auth service error {status_code}: {message}")
