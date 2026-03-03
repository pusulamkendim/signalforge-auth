from __future__ import annotations

# Service layer for dynamic permission management.
# Handles PermissionDefinition CRUD, plan→permission mappings,
# and resolving a user's effective permissions (plan-level + per-user overrides).

from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import Permission, PermissionDefinition, PlanPermissionMapping


class PermissionService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Definition management
    # ------------------------------------------------------------------

    async def define_permission(
        self, name: str, description: str | None = None
    ) -> PermissionDefinition:
        """Register a new permission name.

        Raises HTTP 409 if *name* already exists.
        """
        existing = await self.db.scalar(
            select(PermissionDefinition).where(PermissionDefinition.name == name)
        )
        if existing:
            raise HTTPException(409, f"Permission '{name}' already exists")

        definition = PermissionDefinition(name=name, description=description)
        self.db.add(definition)
        await self.db.commit()
        await self.db.refresh(definition)
        return definition

    async def list_permissions(self) -> list[PermissionDefinition]:
        """Return every registered PermissionDefinition."""
        result = await self.db.scalars(select(PermissionDefinition))
        return list(result.all())

    # ------------------------------------------------------------------
    # Plan mappings
    # ------------------------------------------------------------------

    async def map_to_plan(
        self, plan_type: str, permission_name: str
    ) -> PlanPermissionMapping:
        """Attach a permission to a subscription plan.

        Raises HTTP 404 if *permission_name* is not registered.
        Raises HTTP 409 if the mapping already exists.
        """
        definition = await self.db.scalar(
            select(PermissionDefinition).where(
                PermissionDefinition.name == permission_name
            )
        )
        if not definition:
            raise HTTPException(404, f"Permission '{permission_name}' not found")

        existing = await self.db.scalar(
            select(PlanPermissionMapping).where(
                PlanPermissionMapping.plan_type == plan_type,
                PlanPermissionMapping.permission_definition_id == definition.id,
            )
        )
        if existing:
            raise HTTPException(
                409,
                f"Permission '{permission_name}' already mapped to plan '{plan_type}'",
            )

        mapping = PlanPermissionMapping(
            plan_type=plan_type,
            permission_definition_id=definition.id,
        )
        self.db.add(mapping)
        await self.db.commit()
        await self.db.refresh(mapping)
        return mapping

    async def get_plan_permissions(self, plan_type: str) -> list[str]:
        """Return all permission names mapped to *plan_type*."""
        rows = await self.db.execute(
            select(PermissionDefinition.name)
            .join(
                PlanPermissionMapping,
                PlanPermissionMapping.permission_definition_id == PermissionDefinition.id,
            )
            .where(PlanPermissionMapping.plan_type == plan_type)
        )
        return list(rows.scalars().all())

    async def list_plan_permissions(
        self, plan_type: str
    ) -> list[PermissionDefinition]:
        """Return PermissionDefinition objects for every permission on *plan_type*."""
        result = await self.db.execute(
            select(PermissionDefinition)
            .join(
                PlanPermissionMapping,
                PlanPermissionMapping.permission_definition_id == PermissionDefinition.id,
            )
            .where(PlanPermissionMapping.plan_type == plan_type)
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # User effective permissions
    # ------------------------------------------------------------------

    async def get_user_permissions(
        self, user_id: UUID, plan_type: str
    ) -> list[str]:
        """Return the merged set of permissions for a user.

        Sources (union, deduped):
          1. All permissions mapped to the user's *plan_type*.
          2. Per-user override rows in the Permission table that have not expired.
        """
        plan_permissions = await self.get_plan_permissions(plan_type)

        now = datetime.now(timezone.utc)
        rows = await self.db.scalars(
            select(Permission).where(
                Permission.user_id == user_id,
                or_(
                    Permission.expires_at.is_(None),
                    Permission.expires_at > now,
                ),
            )
        )
        extra = [p.permission for p in rows.all()]

        return list(set(plan_permissions) | set(extra))
