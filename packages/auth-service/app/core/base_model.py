from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Shared base class for all auth ORM models.

    Uses SQLAlchemy 2.0 Mapped / mapped_column style exclusively
    (no legacy Column API).

    Common columns injected into every subclass:
      - id          : UUID primary key (auto-generated)
      - created_at  : record creation timestamp (DB server_default)
      - updated_at  : last-update timestamp (DB server_default + onupdate)
    """

    __abstract__ = True

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
