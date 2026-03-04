from __future__ import annotations

from uuid import UUID

from auth_client.models import UserInfo


def me_payload(
    id: str = "00000000-0000-0000-0000-000000000001",
    email: str = "test@example.com",
    role: str = "user",
    is_verified: bool = False,
    plan: str = "free",
    permissions: list[str] | None = None,
) -> dict:
    """Build the envelope-wrapped response shape emitted by GET /api/v1/auth/me."""
    return {
        "success": True,
        "data": {
            "id": id,
            "email": email,
            "role": role,
            "is_verified": is_verified,
            "plan": plan,
            "permissions": permissions if permissions is not None else [],
        },
    }


def make_user_info(**overrides) -> UserInfo:
    defaults = dict(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        email="test@example.com",
        role="user",
        is_verified=False,
        plan="free",
        permissions=["analysis:create"],
    )
    return UserInfo(**{**defaults, **overrides})
