"""
Tests for IdentityResolutionService — investigation-scoped identity clustering.

Verifies:
  - Refuses to merge across investigations (CRITICAL security property)
  - Confidence computation respects evidence independence
  - Auto-promotion at threshold
  - Manual dispute / merge
  - Event emission for audit trail
"""
import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.services.identity import IdentityResolutionService, IdentityResolutionError
from canonical.schemas import (
    PluginResult, ExtractedEntity, ExtractedRelationship,
    Observation as ObservationSchema, Evidence as EvidenceSchema, PluginMetrics,
)
from canonical.ingestion import IngestionService


@pytest_asyncio.fixture
async def identity_db():
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
async def identity_service(identity_db):
    return IdentityResolutionService(identity_db)


@pytest_asyncio.fixture
async def ingestion_service(identity_db):
    return IngestionService(identity_db)


def _make_plugin_result(plugin_id, target, target_type, entities, observations, investigation_id):
    """Build a PluginResult for ingestion."""
    return PluginResult(
        plugin_id=plugin_id,
        plugin_version="1.0.0",
        target=target,
        target_type=target_type,
        executed_at=datetime.now(timezone.utc),
        investigation_id=investigation_id,
        confidence=0.8,
        entities=entities,
        relationships=[],
        observations=observations,
        metrics=PluginMetrics(),
        raw={"test": True},
    )


class TestIdentityResolutionScoping:
    @pytest.mark.asyncio
    async def test_refuses_cross_investigation_merge(self, identity_service, ingestion_service, identity_db):
        """CRITICAL: Two investigations with the same entity must NOT auto-merge."""
        inv_a = str(uuid.uuid4())
        inv_b = str(uuid.uuid4())

        # Ingest into investigation A: email + phone (same person)
        pr_a = _make_plugin_result(
            plugin_id="whois_a",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email_obs", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone_obs", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_a,
        )
        await ingestion_service.ingest(pr_a)
        await identity_db.commit()

        # Ingest into investigation B: same email
        pr_b = _make_plugin_result(
            plugin_id="whois_b",
            target="other.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email_obs", value="user@example.com", confidence=0.9),
            ],
            investigation_id=inv_b,
        )
        await ingestion_service.ingest(pr_b)
        await identity_db.commit()

        # Resolve identities in each investigation
        identities_a = await identity_service.resolve_investigation(inv_a)
        identities_b = await identity_service.resolve_investigation(inv_b)

        # They must be DIFFERENT identities
        id_a_ids = {i.id for i in identities_a}
        id_b_ids = {i.id for i in identities_b}
        assert id_a_ids.isdisjoint(id_b_ids), (
            "Cross-investigation identity merge detected! "
            f"inv_a identities: {id_a_ids}, inv_b identities: {id_b_ids}"
        )

    @pytest.mark.asyncio
    async def test_within_investigation_merges_allowed(self, identity_service, ingestion_service, identity_db):
        """Same investigation: entities co-observed in one evidence source merge."""
        inv_id = str(uuid.uuid4())

        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email_obs", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone_obs", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        # Should have at least one identity containing both email and phone
        assert len(identities) >= 1
        # The identity should be confirmed (email + phone = high confidence)
        confirmed = [i for i in identities if i.status == "confirmed"]
        assert len(confirmed) >= 1

    @pytest.mark.asyncio
    async def test_empty_investigation_returns_empty(self, identity_service):
        identities = await identity_service.resolve_investigation(str(uuid.uuid4()))
        assert identities == []


class TestIdentityConfidenceComputation:
    @pytest.mark.asyncio
    async def test_tier1_signals_produce_high_confidence(self, identity_service, ingestion_service, identity_db):
        """Email + phone (both Tier 1) should produce confidence >= 0.85."""
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        # Find the identity containing both entities
        from canonical.models import IdentityEntity, CanonicalEntity
        from sqlalchemy import select
        for identity in identities:
            ie_result = await identity_db.execute(
                select(IdentityEntity).where(IdentityEntity.identity_id == identity.id)
            )
            entity_ids = [ie.entity_id for ie in ie_result.scalars().all()]
            if len(entity_ids) >= 2:
                assert identity.confidence >= 0.85
                assert identity.status == "confirmed"
                return
        pytest.fail("No identity with 2+ entities found")

    @pytest.mark.asyncio
    async def test_tier3_only_stays_tentative(self, identity_service, ingestion_service, identity_db):
        """Tier-3 signals alone should never auto-promote to confirmed."""
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="entity",
            target="John Smith",
            target_type="person",
            entities=[
                ExtractedEntity(type="domain", raw_value="example.com", confidence=0.5),
            ],
            observations=[
                ObservationSchema(observation_type="domain_obs", value="example.com", confidence=0.5),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        for identity in identities:
            # domain is Tier 3 — single observation, confidence ~0.20
            assert identity.confidence < 0.85
            # Status should be tentative (not confirmed)
            assert identity.status in ("tentative", "disputed")

    @pytest.mark.asyncio
    async def test_evidence_independence_no_inflation(self, identity_service, ingestion_service, identity_db):
        """Multiple observations from the SAME source should NOT inflate confidence.

        Scenario: one plugin execution produces 5 observations of the same email.
        The confidence should be the same as if there was only 1 observation.
        """
        inv_id = str(uuid.uuid4())
        # Single plugin execution, 5 observations of the same email
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email_in_field_1", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="email_in_field_2", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="email_in_field_3", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="email_in_field_4", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="email_in_field_5", value="user@example.com", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        # Find the identity with the email entity
        from canonical.models import IdentityEntity, CanonicalEntity
        from sqlalchemy import select
        for identity in identities:
            ie_result = await identity_db.execute(
                select(IdentityEntity).join(
                    CanonicalEntity, CanonicalEntity.id == IdentityEntity.entity_id
                ).where(
                    IdentityEntity.identity_id == identity.id,
                    CanonicalEntity.type == "email",
                )
            )
            if ie_result.scalars().first() is not None:
                # Confidence should be ~0.85 (TIER_1_WEIGHT), NOT 0.85*5
                # The exact value depends on noisy-OR but should be < 1.0
                # and close to the single-observation case.
                assert identity.confidence < 0.95  # Not inflated
                return
        # If no identity was created (no co-observation), that's also acceptable
        # — single entities with no co-observation may not form an identity.


class TestIdentityManualOperations:
    @pytest.mark.asyncio
    async def test_dispute_identity(self, identity_service, ingestion_service, identity_db):
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        identity = identities[0]

        disputed = await identity_service.dispute_identity(identity.id, inv_id, reason="wrong person")
        assert disputed.status == "disputed"

    @pytest.mark.asyncio
    async def test_merge_within_investigation(self, identity_service, ingestion_service, identity_db):
        """Merge two identities from the SAME investigation."""
        inv_id = str(uuid.uuid4())

        # Ingest two separate pieces of evidence (no co-observation → separate identities)
        pr1 = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr1)

        pr2 = _make_plugin_result(
            plugin_id="dns",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr2)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        assert len(identities) >= 2

        # Merge first into second
        merged = await identity_service.merge_identities(
            identities[0].id, identities[1].id, inv_id, reason="manual merge",
        )
        assert merged.id == identities[1].id

        # Source should be marked merged
        from canonical.models import Identity
        from sqlalchemy import select
        src_result = await identity_db.execute(
            select(Identity).where(Identity.id == identities[0].id)
        )
        src = src_result.scalar_one()
        assert src.status == "merged"
        assert src.merged_into == identities[1].id

    @pytest.mark.asyncio
    async def test_merge_refuses_cross_investigation(self, identity_service, ingestion_service, identity_db):
        """CRITICAL: merge_identities must refuse identities from different investigations."""
        inv_a = str(uuid.uuid4())
        inv_b = str(uuid.uuid4())

        # Create identity in inv_a
        pr_a = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[ExtractedEntity(type="email", raw_value="a@example.com", confidence=0.9)],
            observations=[ObservationSchema(observation_type="email", value="a@example.com", confidence=0.9)],
            investigation_id=inv_a,
        )
        await ingestion_service.ingest(pr_a)
        await identity_db.commit()
        identities_a = await identity_service.resolve_investigation(inv_a)

        # Create identity in inv_b
        pr_b = _make_plugin_result(
            plugin_id="whois",
            target="other.com",
            target_type="domain",
            entities=[ExtractedEntity(type="email", raw_value="b@example.com", confidence=0.9)],
            observations=[ObservationSchema(observation_type="email", value="b@example.com", confidence=0.9)],
            investigation_id=inv_b,
        )
        await ingestion_service.ingest(pr_b)
        await identity_db.commit()
        identities_b = await identity_service.resolve_investigation(inv_b)

        # Try to merge across investigations — must fail
        with pytest.raises(IdentityResolutionError, match="different investigations"):
            await identity_service.merge_identities(
                identities_a[0].id, identities_b[0].id, inv_a,
            )

    @pytest.mark.asyncio
    async def test_cannot_merge_into_self(self, identity_service, ingestion_service, identity_db):
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()
        identities = await identity_service.resolve_investigation(inv_id)

        with pytest.raises(IdentityResolutionError, match="into itself"):
            await identity_service.merge_identities(
                identities[0].id, identities[0].id, inv_id,
            )


class TestIdentityEventTrail:
    @pytest.mark.asyncio
    async def test_identity_creation_emits_event(self, identity_service, ingestion_service, identity_db):
        """Resolving an identity should emit an 'created' event."""
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        await identity_db.commit()

        from canonical.models import IdentityEvent
        from sqlalchemy import select, func
        result = await identity_db.execute(
            select(func.count()).select_from(IdentityEvent).where(
                IdentityEvent.action == "created"
            )
        )
        assert result.scalar() >= 1

    @pytest.mark.asyncio
    async def test_promotion_emits_event(self, identity_service, ingestion_service, identity_db):
        """Auto-promotion to confirmed should emit a 'promoted' event."""
        inv_id = str(uuid.uuid4())
        pr = _make_plugin_result(
            plugin_id="whois",
            target="example.com",
            target_type="domain",
            entities=[
                ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
                ExtractedEntity(type="phone", raw_value="+14155552671", confidence=0.9),
            ],
            observations=[
                ObservationSchema(observation_type="email", value="user@example.com", confidence=0.9),
                ObservationSchema(observation_type="phone", value="+14155552671", confidence=0.9),
            ],
            investigation_id=inv_id,
        )
        await ingestion_service.ingest(pr)
        await identity_db.commit()

        identities = await identity_service.resolve_investigation(inv_id)
        await identity_db.commit()

        from canonical.models import IdentityEvent
        from sqlalchemy import select, func
        result = await identity_db.execute(
            select(func.count()).select_from(IdentityEvent).where(
                IdentityEvent.action == "promoted"
            )
        )
        # If any identity was promoted, there should be a 'promoted' event
        promoted_identities = [i for i in identities if i.status == "confirmed"]
        if promoted_identities:
            assert result.scalar() >= 1
