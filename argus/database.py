from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.argus_db_url,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.argus_db_url else {},
)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
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


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session