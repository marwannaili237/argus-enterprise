"""
Tests for IngestionService — the canonical ingestion pipeline.

Verifies:
  - Validation rejection
  - Idempotency (re-ingest same execution → no-op)
  - Caps enforcement
  - Entity upsert + investigation link
  - Observation persistence + entity link
  - Relationship upsert + provenance link
  - Single-transaction rollback on error
  - Integration with the full pipeline
"""
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.schemas import (
    PluginResult, ExtractedEntity, ExtractedRelationship,
    Observation as ObservationSchema, Evidence as EvidenceSchema, PluginMetrics,
)
from canonical.ingestion import IngestionService, IngestionError


@pytest_asyncio.fixture
async def ingestion_db():
    """In-memory DB with canonical schema."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    import database
    from canonical.models import (
        CanonicalEntity, Identity, IdentityEntity, RawEvidence, Observation,
        EntityObservation, Relationship, RelationshipProvenance, EntityInvestigationLink,
        IdentityEvent, PluginHealthRecord, AdapterFixtureRecord,
    )

    engine = create_async_engine(
        "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(database.Base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()
    await engine.dispose()


@pytest_asyncio.fixture
async def ingestion_service(ingestion_db):
    return IngestionService(ingestion_db)


def _make_plugin_result(**overrides) -> PluginResult:
    """Build a valid PluginResult for testing."""
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
        metrics=PluginMetrics(duration_ms=100),
        raw={"source": "rdap"},
    )
    defaults.update(overrides)
    return PluginResult(**defaults)


class TestIngestionValidation:
    @pytest.mark.asyncio
    async def test_rejects_invalid_result(self, ingestion_service):
        """A result with bad schema_version should be rejected."""
        pr = _make_plugin_result()
        pr.schema_version = 99  # Invalid
        with pytest.raises(IngestionError, match="Validation failed"):
            await ingestion_service.ingest(pr)

    @pytest.mark.asyncio
    async def test_rejects_empty_plugin_id(self, ingestion_service):
        # Pydantic rejects empty plugin_id at construction — use model_construct
        # to bypass and test the validator's handling.
        pr = PluginResult.model_construct(
            plugin_id="",
            target="example.com",
            target_type="domain",
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
        )
        with pytest.raises(IngestionError, match="Validation failed"):
            await ingestion_service.ingest(pr)

    @pytest.mark.asyncio
    async def test_rejects_future_timestamp(self, ingestion_service):
        from datetime import timedelta
        pr = _make_plugin_result(executed_at=datetime.now(timezone.utc) + timedelta(hours=1))
        with pytest.raises(IngestionError, match="Validation failed"):
            await ingestion_service.ingest(pr)


class TestIngestionIdempotency:
    @pytest.mark.asyncio
    async def test_reingest_same_execution_is_noop(self, ingestion_service):
        """Ingesting the same (execution_id, plugin_id) twice returns the same evidence."""
        pr = _make_plugin_result()
        ev1 = await ingestion_service.ingest(pr)
        ev2 = await ingestion_service.ingest(pr)
        assert ev1.id == ev2.id

    @pytest.mark.asyncio
    async def test_different_execution_creates_new_evidence(self, ingestion_service):
        pr1 = _make_plugin_result()
        ev1 = await ingestion_service.ingest(pr1)

        pr2 = _make_plugin_result(execution_id=str(uuid.uuid4()))
        ev2 = await ingestion_service.ingest(pr2)
        assert ev1.id != ev2.id


class TestIngestionCaps:
    @pytest.mark.asyncio
    async def test_rejects_too_many_entities(self, ingestion_service, monkeypatch):
        import canonical.confidence as conf
        monkeypatch.setattr(conf, "INGESTION_MAX_ENTITIES_PER_CALL", 2)
        pr = _make_plugin_result(entities=[
            ExtractedEntity(type="domain", raw_value=f"d{i}.com", confidence=0.5)
            for i in range(3)
        ])
        with pytest.raises(IngestionError, match="Too many entities"):
            await ingestion_service.ingest(pr)

    @pytest.mark.asyncio
    async def test_rejects_too_many_observations(self, ingestion_service, monkeypatch):
        import canonical.confidence as conf
        monkeypatch.setattr(conf, "INGESTION_MAX_OBSERVATIONS_PER_CALL", 2)
        pr = _make_plugin_result(observations=[
            ObservationSchema(observation_type="t", value=f"v{i}", confidence=0.5)
            for i in range(3)
        ])
        with pytest.raises(IngestionError, match="Too many observations"):
            await ingestion_service.ingest(pr)

    @pytest.mark.asyncio
    async def test_rejects_too_many_relationships(self, ingestion_service, monkeypatch):
        import canonical.confidence as conf
        monkeypatch.setattr(conf, "INGESTION_MAX_RELATIONSHIPS_PER_CALL", 2)
        pr = _make_plugin_result(relationships=[
            ExtractedRelationship(
                source_entity_type="domain", source_entity_value=f"a{i}.com",
                target_entity_type="ip", target_entity_value=f"1.2.3.{i}",
                relationship_type="resolves_to", confidence=0.5,
            )
            for i in range(3)
        ])
        with pytest.raises(IngestionError, match="Too many relationships"):
            await ingestion_service.ingest(pr)


class TestIngestionEntityUpsert:
    @pytest.mark.asyncio
    async def test_creates_canonical_entity(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result()
        await ingestion_service.ingest(pr)

        from canonical.models import CanonicalEntity
        from sqlalchemy import select
        result = await ingestion_db.execute(
            select(CanonicalEntity).where(CanonicalEntity.type == "domain")
        )
        ent = result.scalar_one_or_none()
        assert ent is not None
        assert ent.normalized_value == "example.com"
        assert ent.investigation_count == 1

    @pytest.mark.asyncio
    async def test_dedupes_canonical_entity_across_ingestions(self, ingestion_service, ingestion_db):
        """Same entity ingested twice (different investigations) → 1 entity, count=2."""
        pr1 = _make_plugin_result()
        await ingestion_service.ingest(pr1)

        pr2 = _make_plugin_result(
            investigation_id=str(uuid.uuid4()),
            execution_id=str(uuid.uuid4()),
        )
        await ingestion_service.ingest(pr2)

        from canonical.models import CanonicalEntity
        from sqlalchemy import select, func
        result = await ingestion_db.execute(
            select(func.count()).select_from(CanonicalEntity).where(
                CanonicalEntity.type == "domain",
                CanonicalEntity.normalized_value == "example.com",
            )
        )
        assert result.scalar() == 1

        # Investigation count should be 2
        ent_result = await ingestion_db.execute(
            select(CanonicalEntity).where(
                CanonicalEntity.type == "domain",
                CanonicalEntity.normalized_value == "example.com",
            )
        )
        ent = ent_result.scalar_one()
        assert ent.investigation_count == 2

    @pytest.mark.asyncio
    async def test_links_entity_to_investigation(self, ingestion_service, ingestion_db):
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(investigation_id=inv_id)
        await ingestion_service.ingest(pr)

        from canonical.models import EntityInvestigationLink
        from sqlalchemy import select, func
        result = await ingestion_db.execute(
            select(func.count()).select_from(EntityInvestigationLink).where(
                EntityInvestigationLink.investigation_id == inv_id
            )
        )
        # 2 entities in the result → 2 links
        assert result.scalar() == 2


class TestIngestionObservations:
    @pytest.mark.asyncio
    async def test_persists_observations(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result()
        ev = await ingestion_service.ingest(pr)

        from canonical.models import Observation
        from sqlalchemy import select, func
        result = await ingestion_db.execute(
            select(func.count()).select_from(Observation).where(
                Observation.evidence_id == ev.id
            )
        )
        assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_links_observation_to_entity(self, ingestion_service, ingestion_db):
        """The first observation should link to the first entity (by index)."""
        pr = _make_plugin_result()
        ev = await ingestion_service.ingest(pr)

        from canonical.models import EntityObservation, Observation, CanonicalEntity
        from sqlalchemy import select
        # Find the observation
        obs_result = await ingestion_db.execute(
            select(Observation).where(Observation.evidence_id == ev.id)
        )
        obs = obs_result.scalar_one()
        # Find the entity link
        link_result = await ingestion_db.execute(
            select(EntityObservation).where(EntityObservation.observation_id == obs.id)
        )
        link = link_result.scalar_one_or_none()
        assert link is not None
        # Verify the entity is the domain (index 0 in entities list)
        ent_result = await ingestion_db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == link.entity_id)
        )
        ent = ent_result.scalar_one()
        assert ent.type == "domain"
        assert ent.normalized_value == "example.com"


class TestIngestionRelationships:
    @pytest.mark.asyncio
    async def test_creates_relationship(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result()
        await ingestion_service.ingest(pr)

        from canonical.models import Relationship
        from sqlalchemy import select, func
        result = await ingestion_db.execute(
            select(func.count()).select_from(Relationship)
        )
        assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_relationship_has_provenance(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result()
        ev = await ingestion_service.ingest(pr)

        from canonical.models import Relationship, RelationshipProvenance
        from sqlalchemy import select
        rel_result = await ingestion_db.execute(select(Relationship))
        rel = rel_result.scalar_one()
        prov_result = await ingestion_db.execute(
            select(RelationshipProvenance).where(
                RelationshipProvenance.relationship_id == rel.id
            )
        )
        prov = prov_result.scalar_one_or_none()
        assert prov is not None
        assert prov.evidence_id == ev.id

    @pytest.mark.asyncio
    async def test_relationship_dedup_on_reingest(self, ingestion_service, ingestion_db):
        """Same relationship ingested twice (different evidence) → 1 relationship, 2 provenance links."""
        pr1 = _make_plugin_result()
        await ingestion_service.ingest(pr1)

        pr2 = _make_plugin_result(
            execution_id=str(uuid.uuid4()),
            investigation_id=str(uuid.uuid4()),
        )
        await ingestion_service.ingest(pr2)

        from canonical.models import Relationship, RelationshipProvenance
        from sqlalchemy import select, func
        rel_count = (await ingestion_db.execute(
            select(func.count()).select_from(Relationship)
        )).scalar()
        assert rel_count == 1  # Deduped

        prov_count = (await ingestion_db.execute(
            select(func.count()).select_from(RelationshipProvenance)
        )).scalar()
        assert prov_count == 2  # Two pieces of evidence supporting it


class TestIngestionTransactionBoundary:
    @pytest.mark.asyncio
    async def test_rollback_on_error(self, ingestion_service, ingestion_db):
        """If ingestion fails partway, no partial data is committed.

        We simulate this by making the result invalid (bad schema version)
        after a successful ingestion has already happened in the same session.
        The first ingestion's data should still be there (committed by the
        caller), but the second should not have partially written.
        """
        pr1 = _make_plugin_result()
        await ingestion_service.ingest(pr1)
        await ingestion_db.commit()  # Commit the first

        # Now try an invalid ingestion
        pr2 = _make_plugin_result(
            execution_id=str(uuid.uuid4()),
            investigation_id=str(uuid.uuid4()),
        )
        pr2.schema_version = 99  # Invalid
        with pytest.raises(IngestionError):
            await ingestion_service.ingest(pr2)
        await ingestion_db.rollback()

        # Only the first ingestion's evidence should exist
        from canonical.models import RawEvidence
        from sqlalchemy import select, func
        result = await ingestion_db.execute(
            select(func.count()).select_from(RawEvidence)
        )
        assert result.scalar() == 1


class TestIngestionSourceUrl:
    @pytest.mark.asyncio
    async def test_source_url_from_evidence_list(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result(
            evidence=[EvidenceSchema(source_url="https://rdap.org/example.com", source_reliability=0.9)],
        )
        ev = await ingestion_service.ingest(pr)
        assert ev.source_url == "https://rdap.org/example.com"
        assert ev.source_reliability == 0.9

    @pytest.mark.asyncio
    async def test_no_source_url_when_evidence_empty(self, ingestion_service, ingestion_db):
        pr = _make_plugin_result(evidence=[])
        ev = await ingestion_service.ingest(pr)
        assert ev.source_url is None
        assert ev.source_reliability is None
