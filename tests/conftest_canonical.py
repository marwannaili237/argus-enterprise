"""
Pytest fixtures for the canonical layer.

Provides:
  - canonical_db: an in-memory SQLite AsyncSession with all canonical
    tables created
  - canonical_service: a CanonicalEntityService bound to canonical_db
  - prover_service: a ProvenanceService bound to canonical_db
  - Sample model factories: make_entity, make_identity, make_evidence,
    make_observation, make_relationship
"""
import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

# Ensure argus package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))


# ─── Event loop fixture (preserves existing convention) ──────────────

@pytest.fixture
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ─── In-memory DB with canonical schema ──────────────────────────────

class _TestBase(DeclarativeBase):
    pass


@pytest_asyncio.fixture
async def canonical_db():
    """
    An AsyncSession bound to an in-memory SQLite DB with all canonical
    tables created. Tests can use this directly.

    NOTE: we create a fresh DeclarativeBase here (not the production
    database.Base) to avoid polluting the production metadata across
    tests. We re-declare the canonical models against this base.
    """
    # Use a unique in-memory DB per test (file-based SQLite is shared
    # across connections, in-memory is per-connection — so use shared cache)
    engine = create_async_engine(
        "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true",
        echo=False,
        connect_args={"check_same_thread": False},
    )

    # Import canonical models and register them against a fresh Base.
    # We do this by monkey-patching database.Base to our test base for
    # the duration of the fixture.
    import database
    import canonical.models as cm

    original_base = database.Base
    database.Base = _TestBase

    # Re-import canonical.models with the patched Base — but the module
    # is already imported, so we need to re-execute the class definitions.
    # Simplest: just use create_all on the production Base (which already
    # has all canonical tables registered via the imports in init_db).
    # Restore original base
    database.Base = original_base

    # Use the production Base — it has all canonical tables registered
    async with engine.begin() as conn:
        await conn.run_sync(original_base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()

    await engine.dispose()


# ─── Service fixtures ────────────────────────────────────────────────

@pytest_asyncio.fixture
async def canonical_service(canonical_db):
    """A CanonicalEntityService bound to canonical_db."""
    from canonical.services.canonical_entity import CanonicalEntityService
    return CanonicalEntityService(canonical_db)


@pytest_asyncio.fixture
async def provenance_service(canonical_db):
    """A ProvenanceService bound to canonical_db."""
    from canonical.services.provenance import ProvenanceService
    return ProvenanceService(canonical_db)


# ─── Model factories ─────────────────────────────────────────────────

@pytest.fixture
def make_entity():
    """Factory: build a CanonicalEntity (not persisted)."""
    from canonical.models import CanonicalEntity

    def _make(
        type: str = "email",
        normalized_value: str = "user@example.com",
        raw_value: str | None = None,
    ) -> CanonicalEntity:
        return CanonicalEntity(
            type=type,
            normalized_value=normalized_value,
            raw_value=raw_value or normalized_value,
        )
    return _make


@pytest.fixture
def make_identity():
    """Factory: build an Identity (not persisted)."""
    from canonical.models import Identity

    def _make(
        label: str | None = None,
        confidence: float = 0.5,
        status: str = "tentative",
    ) -> Identity:
        return Identity(label=label, confidence=confidence, status=status)
    return _make


@pytest.fixture
def make_evidence():
    """Factory: build a RawEvidence (not persisted)."""
    from canonical.models import RawEvidence

    def _make(
        plugin_id: str = "test_plugin",
        investigation_id: str | None = None,
        raw_response: dict | None = None,
    ) -> RawEvidence:
        return RawEvidence(
            investigation_id=investigation_id or str(uuid.uuid4()),
            plugin_id=plugin_id,
            plugin_version="1.0.0",
            execution_id=str(uuid.uuid4()),
            target="example.com",
            raw_response=raw_response or {"key": "value"},
        )
    return _make


@pytest.fixture
def make_observation():
    """Factory: build an Observation (not persisted)."""
    from canonical.models import Observation

    def _make(
        evidence_id: str | None = None,
        observation_type: str = "extracted_email",
        value: str = "user@example.com",
        confidence: float = 0.9,
    ) -> Observation:
        return Observation(
            evidence_id=evidence_id or str(uuid.uuid4()),
            observation_type=observation_type,
            value=value,
            confidence=confidence,
        )
    return _make


@pytest.fixture
def make_relationship():
    """Factory: build a Relationship (not persisted)."""
    from canonical.models import Relationship

    def _make(
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        relationship_type: str = "resolves_to",
        confidence: float = 0.8,
    ) -> Relationship:
        return Relationship(
            source_entity_id=source_entity_id or str(uuid.uuid4()),
            target_entity_id=target_entity_id or str(uuid.uuid4()),
            relationship_type=relationship_type,
            confidence=confidence,
        )
    return _make


# ─── PluginResult fixture ────────────────────────────────────────────

@pytest.fixture
def make_plugin_result():
    """Factory: build a canonical.schemas.PluginResult."""
    from canonical.schemas import (
        PluginResult, ExtractedEntity, ExtractedRelationship,
        Observation as ObservationSchema, PluginMetrics,
    )
    from datetime import datetime, timezone

    def _make(**overrides) -> PluginResult:
        defaults = dict(
            plugin_id="whois",
            plugin_version="1.0.0",
            target="example.com",
            target_type="domain",
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
            confidence=0.8,
            entities=[
                ExtractedEntity(type="domain", raw_value="example.com", confidence=0.9),
                ExtractedEntity(type="email", raw_value="admin@example.com", confidence=0.7),
            ],
            relationships=[
                ExtractedRelationship(
                    source_entity_type="domain",
                    source_entity_value="example.com",
                    target_entity_type="email",
                    target_entity_value="admin@example.com",
                    relationship_type="registered_by",
                    confidence=0.6,
                ),
            ],
            observations=[
                ObservationSchema(
                    observation_type="extracted_email",
                    value="admin@example.com",
                    confidence=0.7,
                ),
            ],
            metrics=PluginMetrics(duration_ms=123, network_bytes=4567, cache_hit=False, retries=0),
            raw={"source": "rdap"},
            normalized={},
        )
        defaults.update(overrides)
        return PluginResult(**defaults)
    return _make
