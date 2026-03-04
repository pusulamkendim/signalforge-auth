from __future__ import annotations

# Pydantic v2 request / response schemas for the auth module.
# EmailStr requires the `email-validator` package to be installed.

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class RequestPasswordResetRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until the access token expires


class UserResponse(BaseModel):
    """Canonical user representation returned by /register, /login, and /me.

    Single source of truth — schema changes here propagate to all three
    endpoints and, via openapi.json, to generated TypeScript types.
    """

    id: UUID
    email: str
    role: str
    is_verified: bool
    plan: str = "free"  # populated from the subscriptions table
    permissions: list[str] = []  # resolved from plan + explicit grants

    model_config = ConfigDict(from_attributes=True)


class AuthResponse(BaseModel):
    user: UserResponse
    tokens: TokenResponse


class OkResponse(BaseModel):
    """Sentinel response for boolean-outcome endpoints."""

    ok: bool = True


# ---------------------------------------------------------------------------
# Permission management schemas
# ---------------------------------------------------------------------------


class DefinePermissionRequest(BaseModel):
    name: str
    description: str | None = None


class MapPermissionRequest(BaseModel):
    plan_type: str
    permission_name: str


class PermissionDefinitionResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlanPermissionMappingResponse(BaseModel):
    id: UUID
    plan_type: str
    permission_definition_id: UUID
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
