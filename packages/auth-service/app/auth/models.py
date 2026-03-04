from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base_model import Base


# ---------------------------------------------------------------------------
# User — core identity record; every authenticated principal has one row
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    # Nullable: OAuth-only users never set a password
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    # Incremented on logout-all; checked against the JWT claim to invalidate
    token_version: Mapped[int] = mapped_column(default=0, nullable=False)

    # Relationships
    identities: Mapped[list[AuthIdentity]] = relationship(
        "AuthIdentity", back_populates="user"
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        "RefreshToken", back_populates="user"
    )
    sessions: Mapped[list[Session]] = relationship(
        "Session", back_populates="user"
    )
    permissions: Mapped[list[Permission]] = relationship(
        "Permission",
        back_populates="user",
        foreign_keys="[Permission.user_id]",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id!r} email={self.email!r}>"


# ---------------------------------------------------------------------------
# AuthIdentity — maps a User to one external / email identity provider
# ---------------------------------------------------------------------------
class AuthIdentity(Base):
    __tablename__ = "auth_identities"

    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_id", name="uq_auth_identities_provider_pid"
        ),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    provider_id: Mapped[str] = mapped_column(String, nullable=False)
    # OAuth / provider-specific profile data (e.g. avatar URL, display name)
    metadata_: Mapped[dict | None] = mapped_column(JSONB, name="metadata", nullable=True)

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="identities")

    def __repr__(self) -> str:
        return f"<AuthIdentity id={self.id!r} provider={self.provider!r}>"


# ---------------------------------------------------------------------------
# RefreshToken — persisted refresh-token with family-based rotation support
# ---------------------------------------------------------------------------
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # SHA-256 hash of the raw token; the plain token is never persisted
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    # Groups all tokens in the same rotation chain for reuse detection
    family_id: Mapped[UUID] = mapped_column(nullable=False)
    is_revoked: Mapped[bool] = mapped_column(default=False, nullable=False)
    # Set when the token is first consumed; NULL means unused
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="refresh_tokens")

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id!r} is_revoked={self.is_revoked!r}>"


# ---------------------------------------------------------------------------
# Session — active browser / device session linked to a User
# ---------------------------------------------------------------------------
class Session(Base):
    __tablename__ = "sessions"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id"), nullable=True, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    last_active_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<Session id={self.id!r} user_id={self.user_id!r}>"


# ---------------------------------------------------------------------------
# AuthToken — one-time tokens for email verification and password reset.
# Extensible: token_type is a plain string (e.g. "email_verification",
# "password_reset") so SMS or other channel types can be added later.
# The plain token is NEVER stored — only the SHA-256 hex hash.
# ---------------------------------------------------------------------------
class AuthToken(Base):
    __tablename__ = "auth_tokens"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String, nullable=False)
    # DB column is "type"; attribute renamed to avoid collision with Python built-in
    token_type: Mapped[str] = mapped_column(String, name="type", nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)

    # Relationships
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return f"<AuthToken id={self.id!r} token_type={self.token_type!r}>"


# ---------------------------------------------------------------------------
# Subscription — Stripe-backed plan record attached to a User
# ---------------------------------------------------------------------------
class Subscription(Base):
    __tablename__ = "subscriptions"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stripe_subscription_id: Mapped[str | None] = mapped_column(
        String, unique=True, nullable=True
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    # 'free' | 'pro_monthly' | 'pro_yearly'
    plan_type: Mapped[str] = mapped_column(String, default="free", nullable=False)
    # 'active' | 'canceled' | 'past_due' | 'trialing'
    status: Mapped[str] = mapped_column(String, default="active", nullable=False)
    current_period_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    current_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_at_period_end: Mapped[bool] = mapped_column(default=False, nullable=False)
    trial_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return f"<Subscription id={self.id!r} plan_type={self.plan_type!r}>"


# ---------------------------------------------------------------------------
# UsageLimit — quota record for a user within a billing period
# ---------------------------------------------------------------------------
class UsageLimit(Base):
    __tablename__ = "usage_limits"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # 'weekly' | 'monthly' | 'yearly'
    period_type: Mapped[str] = mapped_column(String, default="monthly", nullable=False)
    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    analyses_used: Mapped[int] = mapped_column(default=0, nullable=False)
    # -1 means unlimited; free tier defaults to 3
    analyses_limit: Mapped[int] = mapped_column(default=3, nullable=False)
    tokens_used: Mapped[int] = mapped_column(default=0, nullable=False)
    tokens_limit: Mapped[int] = mapped_column(default=50000, nullable=False)
    max_video_minutes: Mapped[int] = mapped_column(default=60, nullable=False)

    # Relationships
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return f"<UsageLimit id={self.id!r} user_id={self.user_id!r}>"


# ---------------------------------------------------------------------------
# UsageLog — immutable event trail for each API / resource action
# ---------------------------------------------------------------------------
class UsageLog(Base):
    __tablename__ = "usage_logs"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # e.g. 'transcript:create', 'analysis:create'
    action_type: Mapped[str] = mapped_column(String, nullable=False)
    resource_id: Mapped[UUID | None] = mapped_column(nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String, nullable=True)
    tokens_used: Mapped[int | None] = mapped_column(nullable=True)
    metadata_: Mapped[dict | None] = mapped_column(JSONB, name="metadata", nullable=True)

    # Relationships
    user: Mapped[User] = relationship("User")

    def __repr__(self) -> str:
        return f"<UsageLog id={self.id!r} action_type={self.action_type!r}>"


# ---------------------------------------------------------------------------
# Permission — fine-grained capability grant for a User (per-user overrides)
# The valid permission names are no longer constrained by a DB CHECK; they are
# governed by the PermissionDefinition table to allow dynamic registration.
# ---------------------------------------------------------------------------
class Permission(Base):
    __tablename__ = "permissions"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission: Mapped[str] = mapped_column(String, nullable=False)
    # Self-referential; NULL means system-granted
    granted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships — two FKs to users.id require explicit foreign_keys
    user: Mapped[User] = relationship(
        "User",
        back_populates="permissions",
        foreign_keys="[Permission.user_id]",
    )
    granter: Mapped[User | None] = relationship(
        "User",
        foreign_keys="[Permission.granted_by]",
    )

    def __repr__(self) -> str:
        return f"<Permission id={self.id!r} permission={self.permission!r}>"


# ---------------------------------------------------------------------------
# PermissionDefinition — registry of valid permission names
# ---------------------------------------------------------------------------
class PermissionDefinition(Base):
    __tablename__ = "permission_definitions"

    name: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)

    # Relationships
    plan_mappings: Mapped[list[PlanPermissionMapping]] = relationship(
        "PlanPermissionMapping", back_populates="permission_definition"
    )

    def __repr__(self) -> str:
        return f"<PermissionDefinition id={self.id!r} name={self.name!r}>"


# ---------------------------------------------------------------------------
# PlanPermissionMapping — maps a PermissionDefinition to a subscription plan
# ---------------------------------------------------------------------------
class PlanPermissionMapping(Base):
    __tablename__ = "plan_permission_mappings"

    __table_args__ = (
        UniqueConstraint(
            "plan_type",
            "permission_definition_id",
            name="uq_plan_permission_mappings",
        ),
    )

    plan_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    permission_definition_id: Mapped[UUID] = mapped_column(
        ForeignKey("permission_definitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Relationships
    permission_definition: Mapped[PermissionDefinition] = relationship(
        "PermissionDefinition", back_populates="plan_mappings"
    )

    def __repr__(self) -> str:
        return f"<PlanPermissionMapping id={self.id!r} plan_type={self.plan_type!r}>"


# ---------------------------------------------------------------------------
# AuditLog — system-wide event log; actor may be NULL for automated actions
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_logs"

    # SET NULL keeps the record intact even if the user is later deleted
    actor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # e.g. 'user.created', 'plan.upgraded', 'password.changed'
    action: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_id: Mapped[UUID | None] = mapped_column(nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column(JSONB, name="metadata", nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id!r} action={self.action!r}>"


# ---------------------------------------------------------------------------
# EmailLog — delivery record for every outbound transactional email
# ---------------------------------------------------------------------------
class EmailLog(Base):
    __tablename__ = "email_logs"

    # SET NULL keeps delivery records even after user deletion
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    to_email: Mapped[str] = mapped_column(String, nullable=False)
    # DB column is "type"; attribute renamed to avoid collision with Python built-in
    email_type: Mapped[str] = mapped_column(String, name="type", nullable=False)
    # 'queued' | 'sent' | 'failed' | 'bounced'
    status: Mapped[str] = mapped_column(String, default="queued", nullable=False)
    provider_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<EmailLog id={self.id!r} email_type={self.email_type!r}>"


# ---------------------------------------------------------------------------
# StripeEventLog — idempotency record for every received Stripe webhook event
# ---------------------------------------------------------------------------
class StripeEventLog(Base):
    __tablename__ = "stripe_event_logs"

    # Stripe event ID (evt_xxx) — used for deduplication
    event_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    # e.g. 'checkout.session.completed', 'invoice.payment_failed'
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    payload_: Mapped[dict | None] = mapped_column(JSONB, name="payload", nullable=True)

    def __repr__(self) -> str:
        return f"<StripeEventLog id={self.id!r} event_type={self.event_type!r}>"


# ---------------------------------------------------------------------------
# AnonymousSession — temporary session for unauthenticated visitors
# ---------------------------------------------------------------------------
class AnonymousSession(Base):
    __tablename__ = "anonymous_sessions"

    session_token_hash: Mapped[str] = mapped_column(
        String, unique=True, nullable=False
    )
    # SET NULL when the anonymous session is later converted to a real account
    converted_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AnonymousSession id={self.id!r} expires_at={self.expires_at!r}>"
