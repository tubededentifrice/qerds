"""QERDS Database module.

Database models and migrations:
- SQLAlchemy 2.x ORM models
- Alembic migration configuration
- Connection pooling via psycopg
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

# Module-level session factory (initialized on first use)
_engine = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_database_url() -> str:
    """Get the database URL from settings.

    Returns:
        PostgreSQL connection URL for async driver.
    """
    from qerds.core.settings import get_settings

    settings = get_settings()
    # Convert PostgresDsn to string
    url = str(settings.database.url)
    # Ensure we're using the async driver
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    return url


def _init_engine() -> None:
    """Initialize the database engine and session factory."""
    global _engine, _async_session_factory

    if _engine is not None:
        return

    from qerds.core.settings import get_settings

    settings = get_settings()
    url = _get_database_url()

    _engine = create_async_engine(
        url,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_timeout=settings.database.pool_timeout,
        echo=settings.database.echo,
    )

    _async_session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


@asynccontextmanager
async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Get an async database session.

    This is a context manager that yields a session and handles
    cleanup (commit/rollback) automatically.

    Usage:
        async with get_async_session() as session:
            # Use session for database operations
            result = await session.execute(query)
            await session.commit()

    Yields:
        AsyncSession for database operations.
    """
    _init_engine()

    if _async_session_factory is None:
        msg = "Database session factory not initialized"
        raise RuntimeError(msg)

    session = _async_session_factory()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def close_engine() -> None:
    """Close the database engine.

    Call this during application shutdown to clean up connections.
    """
    global _engine, _async_session_factory

    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _async_session_factory = None
