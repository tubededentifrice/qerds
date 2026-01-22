"""Alembic migration environment configuration.

This module configures how Alembic runs migrations:
- Loads SQLAlchemy models for autogenerate support
- Configures database connection from environment
- Supports both online and offline migration modes
"""

import os
from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import create_engine, pool

# Import all models to register them with metadata
# This is required for autogenerate to detect changes
from qerds.db.models import Base

# Alembic Config object for access to .ini values
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate support
# All models inherit from Base, so Base.metadata has all tables
target_metadata = Base.metadata


def _include_object(
    _obj: Any,
    _name: str | None,
    _type: str,
    _reflected: bool,
    _compare_to: Any | None,
) -> bool:
    """Include all objects in autogenerate comparisons."""
    return True


def get_url() -> str:
    """Get database URL from environment or config.

    Priority:
    1. DATABASE_URL environment variable
    2. sqlalchemy.url from alembic.ini
    """
    return os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url", ""))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Generates SQL script without connecting to database.
    Useful for review or manual application.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include object name in autogenerate for better diffs
        include_object=_include_object,
        # Compare types to detect column type changes
        compare_type=True,
        # Compare server defaults
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates engine and runs migrations within a transaction.
    """
    # Override URL from environment if set
    url = get_url()

    # Create engine with connection pooling disabled for migrations
    # NullPool ensures connections are closed immediately after use
    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Include object name in autogenerate for better diffs
            include_object=_include_object,
            # Compare types to detect column type changes
            compare_type=True,
            # Compare server defaults
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# Run appropriate migration mode based on context
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
