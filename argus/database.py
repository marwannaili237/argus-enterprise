"""
Database connection and session management.

Provides async SQLAlchemy engine and session factory with
proper connection pooling, error handling, and lifecycle management.
"""
import logging
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncEngine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, QueuePool
from config import get_settings

logger = logging.getLogger("argus.database")
settings = get_settings()


def _get_engine_kwargs() -> dict:
    """Get engine configuration based on database URL."""
    kwargs = {
        "echo": False,
        "future": True,
    }
    
    # SQLite-specific configuration
    if "sqlite" in settings.argus_db_url:
        kwargs["connect_args"] = {
            "check_same_thread": False,
            "timeout": 30,  # 30 second timeout for locks
        }
        kwargs["poolclass"] = NullPool  # SQLite doesn't benefit from connection pooling
    else:
        # PostgreSQL and other databases: use connection pooling
        kwargs["pool_size"] = 20
        kwargs["max_overflow"] = 10
        kwargs["pool_pre_ping"] = True  # Test connections before using them
        kwargs["pool_recycle"] = 3600  # Recycle connections after 1 hour
        kwargs["poolclass"] = QueuePool
    
    return kwargs


engine: AsyncEngine = create_async_engine(
    settings.argus_db_url,
    **_get_engine_kwargs(),
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


async def init_db():
    """Initialize database schema by creating all tables."""
    try:
        from models import (
            User, Investigation, Evidence, Monitor, AuditLog, Webhook, InvestigationNote,
            Case, CaseInvestigation, CaseNote, Tag, TagAssociation,
            Watchlist, IOCEntry, ChainOfCustody, EnrichedEntity,
        )
        # Canonical layer (new — does not touch existing tables)
        from canonical.models import (
            CanonicalEntity, Identity, IdentityEntity, RawEvidence, Observation,
            EntityObservation, Relationship, RelationshipProvenance, EntityInvestigationLink,
            IdentityEvent, PluginHealthRecord, AdapterFixtureRecord,
            DecisionEvent, ReviewQueueItem, IdentityMergeRecord,
        )
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database schema initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database schema: {e}")
        raise


async def get_db():
    """
    Dependency injection function for FastAPI routes.
    Provides an async SQLAlchemy session.
    
    Usage:
        async def my_route(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            await session.close()


async def close_db():
    """Close database connections. Call on application shutdown."""
    await engine.dispose()
    logger.info("Database connections closed")
