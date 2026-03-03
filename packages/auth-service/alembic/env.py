from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# ---------------------------------------------------------------------------
# Auth models must be imported so that Base.metadata is populated before
# Alembic inspects it.  Add new model imports here as auth tables are created.
# ---------------------------------------------------------------------------
from app.core.base_model import Base  # noqa: F401  — registers metadata
from app.core.config import get_auth_settings
import app.auth.models  # noqa: F401  — registers auth tables with Base.metadata

# ---------------------------------------------------------------------------
# Alembic Config object (gives access to values in alembic.ini)
# ---------------------------------------------------------------------------
config = context.config

# Set up Python logging from the [loggers] section in alembic.ini.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url with the value from AuthSettings so .env is the
# single source of truth — no duplication in alembic.ini.
_auth_settings = get_auth_settings()
config.set_main_option("sqlalchemy.url", _auth_settings.database_url)

target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Offline migrations (no live DB connection)
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to the database.

    Useful for generating migration scripts to review before applying.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (live async DB connection)
# ---------------------------------------------------------------------------
def do_run_migrations(connection) -> None:  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live database using an async engine."""
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),  # type: ignore[arg-type]
        echo=False,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
