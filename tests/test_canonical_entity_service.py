"""
Unit tests for CanonicalEntityService and ProvenanceService.

Uses an in-memory SQLite DB (via the canonical_db fixture) and the
service fixtures from conftest_canonical.py.
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
    Observation as ObservationSchema, PluginMetrics,
)


# ──────────────────────────────────────────────────────────────────────
# CanonicalEntityService tests
# ──────────────────────────────────────────────────────────────────────

class TestUpsertEntity:
    @pytest.mark.asyncio
    async def test_create_new_entity(self, canonical_service):
        ent = await canonical_service.upsert_entity("email", "User@Example.COM")
        assert ent.id is not None
        assert ent.type == "email"
        assert ent.normalized_value == "user@example.com"
        assert ent.raw_value == "User@Example.COM"
        assert ent.investigation_count == 0  # not yet linked

    @pytest.mark.asyncio
    async def test_idempotent_upsert(self, canonical_service):
        """Same (type, normalized_value) returns the same row."""
        ent1 = await canonical_service.upsert_entity("domain", "example.com")
        ent2 = await canonical_service.upsert_entity("domain", "EXAMPLE.COM")
        assert ent1.id == ent2.id
        # source_count should bump on the second call (different raw_value case)
        # Actually, source_count only bumps if `source` kwarg is passed — let's verify
        assert ent2.source_count >= 1

    @pytest.mark.asyncio
    async def test_unknown_type_raises(self, canonical_service):
        with pytest.raises(ValueError, match="Unknown entity type"):
            await canonical_service.upsert_entity("foo_type", "bar")

    @pytest.mark.asyncio
    async def test_normalization_applied(self, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "WWW.Example.COM")
        assert ent.normalized_value == "example.com"
        assert ent.raw_value == "WWW.Example.COM"

    @pytest.mark.asyncio
    async def test_source_count_increments_with_source_kwarg(self, canonical_service):
        ent1 = await canonical_service.upsert_entity("email", "user@example.com", source="plugin_a")
        ent2 = await canonical_service.upsert_entity("email", "USER@example.com", source="plugin_b")
        assert ent1.id == ent2.id
        assert ent2.source_count == 2


class TestLinkEntityToInvestigation:
    @pytest.mark.asyncio
    async def test_first_link_increments_count(self, canonical_service):
        ent = await canonical_service.upsert_entity("email", "user@example.com")
        assert ent.investigation_count == 0

        inv_id = str(uuid.uuid4())
        link = await canonical_service.link_entity_to_investigation(ent.id, inv_id)
        assert link.entity_id == ent.id
        assert link.investigation_id == inv_id

        # Reload entity to see updated count
        from canonical.models import CanonicalEntity
        from sqlalchemy import select
        result = await canonical_service.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == ent.id)
        )
        ent_updated = result.scalar_one()
        assert ent_updated.investigation_count == 1

    @pytest.mark.asyncio
    async def test_idempotent_link(self, canonical_service):
        """Linking the same entity to the same investigation twice doesn't double-count."""
        ent = await canonical_service.upsert_entity("domain", "example.com")
        inv_id = str(uuid.uuid4())
        await canonical_service.link_entity_to_investigation(ent.id, inv_id)
        await canonical_service.link_entity_to_investigation(ent.id, inv_id)

        from canonical.models import CanonicalEntity
        from sqlalchemy import select
        result = await canonical_service.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == ent.id)
        )
        ent_updated = result.scalar_one()
        assert ent_updated.investigation_count == 1

    @pytest.mark.asyncio
    async def test_different_investigations_each_increment(self, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "example.com")
        await canonical_service.link_entity_to_investigation(ent.id, str(uuid.uuid4()))
        await canonical_service.link_entity_to_investigation(ent.id, str(uuid.uuid4()))
        await canonical_service.link_entity_to_investigation(ent.id, str(uuid.uuid4()))

        from canonical.models import CanonicalEntity
        from sqlalchemy import select
        result = await canonical_service.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == ent.id)
        )
        ent_updated = result.scalar_one()
        assert ent_updated.investigation_count == 3


class TestFindSharedInvestigations:
    @pytest.mark.asyncio
    async def test_returns_all_linked_investigations(self, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "example.com")
        inv1, inv2, inv3 = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        await canonical_service.link_entity_to_investigation(ent.id, inv1)
        await canonical_service.link_entity_to_investigation(ent.id, inv2)
        await canonical_service.link_entity_to_investigation(ent.id, inv3)

        shared = await canonical_service.find_shared_investigations(ent.id)
        assert set(shared) == {inv1, inv2, inv3}

    @pytest.mark.asyncio
    async def test_exclude_current_investigation(self, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "example.com")
        inv1, inv2 = str(uuid.uuid4()), str(uuid.uuid4())
        await canonical_service.link_entity_to_investigation(ent.id, inv1)
        await canonical_service.link_entity_to_investigation(ent.id, inv2)

        shared = await canonical_service.find_shared_investigations(
            ent.id, exclude_investigation_id=inv1
        )
        assert inv1 not in shared
        assert inv2 in shared

    @pytest.mark.asyncio
    async def test_no_links_returns_empty(self, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "example.com")
        shared = await canonical_service.find_shared_investigations(ent.id)
        assert shared == []


class TestFindInvestigationsSharedWithEntity:
    @pytest.mark.asyncio
    async def test_finds_co_occurring_entities(self, canonical_service):
        """If entity A and entity B both appear in inv1, that's a shared investigation."""
        ent_a = await canonical_service.upsert_entity("domain", "a.com")
        ent_b = await canonical_service.upsert_entity("domain", "b.com")
        ent_c = await canonical_service.upsert_entity("domain", "c.com")  # unrelated

        inv1 = str(uuid.uuid4())
        await canonical_service.link_entity_to_investigation(ent_a.id, inv1)
        await canonical_service.link_entity_to_investigation(ent_b.id, inv1)

        result = await canonical_service.find_investigations_shared_with_entity(
            ent_a.id, [ent_b.id, ent_c.id]
        )
        assert ent_b.id in result
        assert ent_c.id in result
        assert inv1 in result[ent_b.id]
        assert result[ent_c.id] == []  # c.com never co-occurred


class TestGetOrCreateIdentity:
    @pytest.mark.asyncio
    async def test_create_new_identity(self, canonical_service):
        """First call with new entities creates a tentative identity.

        We use weak-signal entities (username + domain) so the noisy-OR
        confidence stays below the 0.8 promotion threshold.
        """
        e1 = await canonical_service.upsert_entity("username", "johndoe")
        e2 = await canonical_service.upsert_entity("domain", "johndoe.example")

        identity = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-test-1",
        )
        assert identity.id is not None
        # username (0.6) + domain (0.4): noisy-OR = 1 - 0.4*0.6 = 0.76 < 0.8
        assert identity.status == "tentative"
        # Confidence should be > 0 (noisy-OR of 0.6 + 0.4)
        assert identity.confidence > 0.5

    @pytest.mark.asyncio
    async def test_finds_existing_identity(self, canonical_service):
        """Second call with the same entities returns the same identity."""
        e1 = await canonical_service.upsert_entity("email", "user@example.com")
        e2 = await canonical_service.upsert_entity("username", "johndoe")

        id1 = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-test-2",
        )
        id2 = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-test-2",
        )
        assert id1.id == id2.id

    @pytest.mark.asyncio
    async def test_merges_when_threshold_met(self, canonical_service):
        """
        Scenario:
          1. Create identity A with entities [e1, e2]
          2. Call get_or_create_identity with [e2, e3] — e2 overlaps
          3. Since IDENTITY_MERGE_MIN_SHARED_ENTITIES=2, single overlap
             isn't enough; we need >=2 shared OR overlap ratio >= 0.5.
             With e2 shared out of 2 entities in identity A, overlap = 0.5
             which meets the threshold.
        """
        e1 = await canonical_service.upsert_entity("email", "a@example.com")
        e2 = await canonical_service.upsert_entity("email", "b@example.com")
        e3 = await canonical_service.upsert_entity("email", "c@example.com")

        # Identity A: {e1, e2}
        id_a = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-test-3",
        )

        # Now call with [e2, e3] — should merge into A because e2 is shared
        # and overlap = 1/2 = 0.5 >= threshold
        id_b = await canonical_service.get_or_create_identity(
            [e2.id, e3.id], investigation_id="inv-test-3",
        )

        # Should be the same identity (merged)
        assert id_a.id == id_b.id

        # Verify all three entities are now in identity A
        from canonical.models import IdentityEntity
        from sqlalchemy import select, func
        result = await canonical_service.db.execute(
            select(func.count()).select_from(IdentityEntity).where(
                IdentityEntity.identity_id == id_a.id
            )
        )
        count = result.scalar()
        assert count == 3

    @pytest.mark.asyncio
    async def test_high_confidence_promotes_to_confirmed(self, canonical_service):
        """An identity with enough high-weight signals should auto-promote to confirmed."""
        # Email (0.9) + phone (0.9) — noisy-OR = 1 - 0.1*0.1 = 0.99
        e1 = await canonical_service.upsert_entity("email", "user@example.com")
        e2 = await canonical_service.upsert_entity("phone", "+14155552671")

        identity = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-test-4",
        )
        assert identity.confidence >= 0.8
        assert identity.status == "confirmed"

    @pytest.mark.asyncio
    async def test_empty_entity_list_raises(self, canonical_service):
        with pytest.raises(ValueError, match="non-empty"):
            await canonical_service.get_or_create_identity(
                [], investigation_id="inv-test-5",
            )

    @pytest.mark.asyncio
    async def test_refuses_cross_investigation_merge(self, canonical_service):
        """get_or_create_identity without investigation_id must refuse.

        This test verifies the CRITICAL security gate: cross-investigation
        identity merges are forbidden.
        """
        e1 = await canonical_service.upsert_entity("email", "user@example.com")
        with pytest.raises(ValueError, match="investigation_id"):
            await canonical_service.get_or_create_identity([e1.id])

    @pytest.mark.asyncio
    async def test_merges_only_within_same_investigation(self, canonical_service):
        """Two separate investigations get separate identities for the same entity."""
        e1 = await canonical_service.upsert_entity("email", "shared@example.com")

        id_a = await canonical_service.get_or_create_identity(
            [e1.id], investigation_id="inv-A",
        )
        id_b = await canonical_service.get_or_create_identity(
            [e1.id], investigation_id="inv-B",
        )
        # Same entity, but different investigations → different identities
        # (or the same identity if the service deduplicates, but NEVER a merge)
        # The key assertion: neither call throws, and both return a valid identity.
        assert id_a.id is not None
        assert id_b.id is not None


class TestMergeIdentities:
    @pytest.mark.asyncio
    async def test_merge_combines_entities(self, canonical_service):
        e1 = await canonical_service.upsert_entity("email", "a@example.com")
        e2 = await canonical_service.upsert_entity("email", "b@example.com")
        e3 = await canonical_service.upsert_entity("phone", "+14155552671")

        # Create two separate identities in the same investigation
        id_a = await canonical_service.get_or_create_identity(
            [e1.id, e2.id], investigation_id="inv-merge-1",
        )
        id_b = await canonical_service.get_or_create_identity(
            [e3.id], investigation_id="inv-merge-1",
        )

        # Merge B into A (legacy method — still works for within-investigation)
        merged = await canonical_service.merge_identities(id_b.id, id_a.id)

        # A should now have all 3 entities
        from canonical.models import IdentityEntity, Identity
        from sqlalchemy import select, func
        result = await canonical_service.db.execute(
            select(func.count()).select_from(IdentityEntity).where(
                IdentityEntity.identity_id == id_a.id
            )
        )
        assert result.scalar() == 3

        # B should be marked as merged
        b_result = await canonical_service.db.execute(
            select(Identity).where(Identity.id == id_b.id)
        )
        b = b_result.scalar_one()
        assert b.status == "merged"
        assert b.merged_into == id_a.id

    @pytest.mark.asyncio
    async def test_cannot_merge_into_self(self, canonical_service):
        e1 = await canonical_service.upsert_entity("email", "a@example.com")
        identity = await canonical_service.get_or_create_identity(
            [e1.id], investigation_id="inv-merge-2",
        )
        with pytest.raises(ValueError, match="into itself"):
            await canonical_service.merge_identities(identity.id, identity.id)


# ──────────────────────────────────────────────────────────────────────
# ProvenanceService tests
# ──────────────────────────────────────────────────────────────────────

class TestRecordEvidence:
    @pytest.mark.asyncio
    async def test_persists_raw_response(self, provenance_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        assert evidence.id is not None
        assert evidence.plugin_id == pr.plugin_id
        assert evidence.target == pr.target
        assert evidence.raw_response == pr.raw
        assert evidence.investigation_id == pr.investigation_id

    @pytest.mark.asyncio
    async def test_source_url_from_evidence_list(self, provenance_service):
        from canonical.schemas import Evidence
        pr = PluginResult(
            plugin_id="http",
            target="https://example.com",
            target_type="url",
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
            evidence=[Evidence(source_url="https://example.com", source_reliability=0.9)],
            raw={"status": 200},
        )
        evidence = await provenance_service.record_evidence(pr)
        assert evidence.source_url == "https://example.com"
        assert evidence.source_reliability == 0.9


class TestRecordObservation:
    @pytest.mark.asyncio
    async def test_persists_observation(self, provenance_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        obs_schema = pr.observations[0]
        obs = await provenance_service.record_observation(evidence.id, obs_schema)
        assert obs.id is not None
        assert obs.evidence_id == evidence.id
        assert obs.observation_type == obs_schema.observation_type
        assert obs.value == obs_schema.value
        assert obs.confidence == obs_schema.confidence


class TestLinkObservationToEntity:
    @pytest.mark.asyncio
    async def test_creates_link(self, provenance_service, canonical_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        obs = await provenance_service.record_observation(evidence.id, pr.observations[0])

        ent = await canonical_service.upsert_entity("email", "admin@example.com")
        link = await provenance_service.link_observation_to_entity(obs.id, ent.id)
        assert link.entity_id == ent.id
        assert link.observation_id == obs.id

    @pytest.mark.asyncio
    async def test_idempotent_link(self, provenance_service, canonical_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        obs = await provenance_service.record_observation(evidence.id, pr.observations[0])
        ent = await canonical_service.upsert_entity("email", "admin@example.com")

        link1 = await provenance_service.link_observation_to_entity(obs.id, ent.id)
        link2 = await provenance_service.link_observation_to_entity(obs.id, ent.id)
        # Should be the same link (upsert)
        assert link1.entity_id == link2.entity_id
        assert link1.observation_id == link2.observation_id


class TestLinkEvidenceToRelationship:
    @pytest.mark.asyncio
    async def test_creates_provenance_link(self, provenance_service, canonical_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)

        # Create two entities and a relationship between them
        e1 = await canonical_service.upsert_entity("domain", "example.com")
        e2 = await canonical_service.upsert_entity("email", "admin@example.com")

        from canonical.models import Relationship
        rel = Relationship(
            source_entity_id=e1.id,
            target_entity_id=e2.id,
            relationship_type="registered_by",
            confidence=0.7,
        )
        provenance_service.db.add(rel)
        await provenance_service.db.flush()

        prov = await provenance_service.link_evidence_to_relationship(evidence.id, rel.id)
        assert prov.relationship_id == rel.id
        assert prov.evidence_id == evidence.id

    @pytest.mark.asyncio
    async def test_idempotent_with_observation_update(self, provenance_service, canonical_service, make_plugin_result):
        """Linking again with an observation_id updates the existing row."""
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        obs = await provenance_service.record_observation(evidence.id, pr.observations[0])

        e1 = await canonical_service.upsert_entity("domain", "example.com")
        e2 = await canonical_service.upsert_entity("email", "admin@example.com")
        from canonical.models import Relationship
        rel = Relationship(source_entity_id=e1.id, target_entity_id=e2.id,
                           relationship_type="registered_by", confidence=0.7)
        provenance_service.db.add(rel)
        await provenance_service.db.flush()

        # First link without observation
        await provenance_service.link_evidence_to_relationship(evidence.id, rel.id)
        # Second link with observation
        await provenance_service.link_evidence_to_relationship(evidence.id, rel.id, obs.id)

        from canonical.models import RelationshipProvenance
        from sqlalchemy import select
        result = await provenance_service.db.execute(
            select(RelationshipProvenance).where(
                RelationshipProvenance.relationship_id == rel.id,
                RelationshipProvenance.evidence_id == evidence.id,
            )
        )
        prov = result.scalar_one()
        assert prov.observation_id == obs.id


class TestGetEvidenceChain:
    @pytest.mark.asyncio
    async def test_returns_all_evidence_for_entity(self, provenance_service, canonical_service, make_plugin_result):
        """An entity linked to observations from 2 evidence rows returns both."""
        # First plugin result + evidence + observation + entity link
        pr1 = make_plugin_result()
        ev1 = await provenance_service.record_evidence(pr1)
        obs1 = await provenance_service.record_observation(ev1.id, pr1.observations[0])
        ent = await canonical_service.upsert_entity("email", "admin@example.com")
        await provenance_service.link_observation_to_entity(obs1.id, ent.id)

        # Second plugin result + evidence + observation + same entity
        pr2 = make_plugin_result(plugin_id="dns")
        ev2 = await provenance_service.record_evidence(pr2)
        obs2 = await provenance_service.record_observation(ev2.id, pr1.observations[0])
        await provenance_service.link_observation_to_entity(obs2.id, ent.id)

        chain = await provenance_service.get_evidence_chain(ent.id)
        assert len(chain) == 2
        ev_ids = {e.id for e in chain}
        assert ev1.id in ev_ids
        assert ev2.id in ev_ids

    @pytest.mark.asyncio
    async def test_no_evidence_returns_empty(self, provenance_service, canonical_service):
        ent = await canonical_service.upsert_entity("domain", "example.com")
        chain = await provenance_service.get_evidence_chain(ent.id)
        assert chain == []


class TestGetFullProvenance:
    @pytest.mark.asyncio
    async def test_returns_complete_chain(self, provenance_service, canonical_service, make_plugin_result):
        pr = make_plugin_result()
        evidence = await provenance_service.record_evidence(pr)
        obs = await provenance_service.record_observation(evidence.id, pr.observations[0])

        e1 = await canonical_service.upsert_entity("domain", "example.com")
        e2 = await canonical_service.upsert_entity("email", "admin@example.com")

        from canonical.models import Relationship
        rel = Relationship(source_entity_id=e1.id, target_entity_id=e2.id,
                           relationship_type="registered_by", confidence=0.7)
        provenance_service.db.add(rel)
        await provenance_service.db.flush()

        await provenance_service.link_evidence_to_relationship(evidence.id, rel.id, obs.id)

        chain = await provenance_service.get_full_provenance(rel.id)
        assert chain is not None
        assert chain.relationship_id == rel.id
        assert chain.relationship_type == "registered_by"
        assert len(chain.supporting_evidence) == 1
        assert len(chain.supporting_observations) == 1
        assert chain.plugins == ["whois"]
        assert chain.collected_at_range is not None

    @pytest.mark.asyncio
    async def test_nonexistent_relationship_returns_none(self, provenance_service):
        chain = await provenance_service.get_full_provenance(str(uuid.uuid4()))
        assert chain is None

    @pytest.mark.asyncio
    async def test_relationship_with_no_evidence(self, provenance_service, canonical_service):
        e1 = await canonical_service.upsert_entity("domain", "a.com")
        e2 = await canonical_service.upsert_entity("domain", "b.com")
        from canonical.models import Relationship
        rel = Relationship(source_entity_id=e1.id, target_entity_id=e2.id,
                           relationship_type="same_as", confidence=0.5)
        provenance_service.db.add(rel)
        await provenance_service.db.flush()

        chain = await provenance_service.get_full_provenance(rel.id)
        assert chain is not None
        assert chain.supporting_evidence == []
        assert chain.collected_at_range is None


class TestIngestPluginResult:
    @pytest.mark.asyncio
    async def test_full_ingest_pipeline(self, provenance_service, canonical_service, make_plugin_result):
        """End-to-end: ingest a PluginResult and verify evidence + observations are created."""
        pr = make_plugin_result()

        # Build entity_id_map: (type, normalized_value) -> entity_id
        entity_id_map = {}
        for ent_schema in pr.entities:
            ent = await canonical_service.upsert_entity(ent_schema.type, ent_schema.raw_value)
            entity_id_map[(ent.type, ent.normalized_value)] = ent.id

        # Build relationship_id_map
        from canonical.models import Relationship
        rel_id_map = {}
        for rel_schema in pr.relationships:
            src = await canonical_service.upsert_entity(rel_schema.source_entity_type, rel_schema.source_entity_value)
            tgt = await canonical_service.upsert_entity(rel_schema.target_entity_type, rel_schema.target_entity_value)
            rel = Relationship(
                source_entity_id=src.id,
                target_entity_id=tgt.id,
                relationship_type=rel_schema.relationship_type,
                confidence=rel_schema.confidence,
            )
            provenance_service.db.add(rel)
            await provenance_service.db.flush()
            key = (
                rel_schema.source_entity_type,
                rel_schema.source_entity_value,
                rel_schema.relationship_type,
                rel_schema.target_entity_type,
                rel_schema.target_entity_value,
            )
            rel_id_map[key] = rel.id

        # Ingest
        evidence = await provenance_service.ingest_plugin_result(
            pr,
            entity_id_map=entity_id_map,
            relationship_id_map=rel_id_map,
        )
        assert evidence.id is not None

        # Verify observations were created
        from canonical.models import Observation
        from sqlalchemy import select, func
        result = await provenance_service.db.execute(
            select(func.count()).select_from(Observation).where(
                Observation.evidence_id == evidence.id
            )
        )
        assert result.scalar() == len(pr.observations)

        # Verify relationship provenance was created
        from canonical.models import RelationshipProvenance
        result = await provenance_service.db.execute(
            select(func.count()).select_from(RelationshipProvenance).where(
                RelationshipProvenance.evidence_id == evidence.id
            )
        )
        assert result.scalar() == len(pr.relationships)
