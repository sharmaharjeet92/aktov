"""SQLAlchemy async engine and session setup."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from chainwatch_cloud.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=(settings.environment == "dev"),
    pool_pre_ping=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables. Intended for dev/test only — use Alembic in production."""
    from chainwatch_cloud.models.base import Base  # noqa: F811

    # Import all models so they register with Base.metadata
    import chainwatch_cloud.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    """Dispose of the connection pool."""
    await engine.dispose()
