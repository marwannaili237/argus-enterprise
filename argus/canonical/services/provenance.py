"""
ProvenanceService — records and queries the full evidence chain.

Every observation and every relationship in the canonical store must
trace back to a piece of raw evidence (and the plugin that produced it).
This service enforces that contract: it's the single entry point for
writing raw_evidence, observations, and relationship provenance rows.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import logging

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from canonical.models import (
    RawEvidence, Observation, EntityObservation,
    Relationship, RelationshipProvenance,
    CanonicalEntity,
)
from canonical.schemas import PluginResult, Observation as ObservationSchema, ProvenanceChain

logger = logging.getLogger("argus.canonical.provenance_service")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ProvenanceService:
    """
    Construct with an AsyncSession. Typical FastAPI usage:

        async def get_provenance_service(
            db: AsyncSession = Depends(get_db),
        ) -> ProvenanceService:
            return ProvenanceService(db)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Record raw evidence ─────────────────────────────────────────

    async def record_evidence(
        self,
        plugin_result: PluginResult,
        *,
        source_url: Optional[str] = None,
        source_reliability: Optional[float] = None,
    ) -> RawEvidence:
        """
        Persist a RawEvidence row from a PluginResult.

        The `raw_response` column is set to plugin_result.raw (the
        immutable original source response). This row is the anchor
        for all observations and relationship provenance that follow.
        """
        # Prefer the first entry in plugin_result.evidence if it has
        # source_url / source_reliability; fall back to the kwargs.
        ev_source_url = source_url
        ev_source_rel = source_reliability
        if plugin_result.evidence and not ev_source_url:
            first_ev = plugin_result.evidence[0]
            ev_source_url = first_ev.source_url
            ev_source_rel = first_ev.source_reliability

        evidence = RawEvidence(
            investigation_id=str(plugin_result.investigation_id),
            plugin_id=plugin_result.plugin_id,
            plugin_version=plugin_result.plugin_version,
            execution_id=plugin_result.execution_id,
            target=plugin_result.target,
            collected_at=_utcnow(),
            raw_response=plugin_result.raw or {},
            source_url=ev_source_url,
            source_reliability=ev_source_rel,
        )
        self.db.add(evidence)
        await self.db.flush()
        return evidence

    # ─── Record observation ──────────────────────────────────────────

    async def record_observation(
        self,
        evidence_id: str,
        obs: ObservationSchema,
    ) -> Observation:
        """
        Persist an Observation row linked to a RawEvidence row.
        Does NOT link the observation to a canonical entity — use
        link_observation_to_entity for that.
        """
        observation = Observation(
            evidence_id=evidence_id,
            observation_type=obs.observation_type,
            value=obs.value,
            context=obs.context,
            confidence=obs.confidence,
            extracted_at=_utcnow(),
        )
        self.db.add(observation)
        await self.db.flush()
        return observation

    # ─── Link observation ↔ entity ───────────────────────────────────

    async def link_observation_to_entity(
        self,
        observation_id: str,
        entity_id: str,
    ) -> EntityObservation:
        """Upsert an EntityObservation link."""
        # Check existing
        result = await self.db.execute(
            select(EntityObservation).where(
                EntityObservation.entity_id == entity_id,
                EntityObservation.observation_id == observation_id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return existing

        link = EntityObservation(
            entity_id=entity_id,
            observation_id=observation_id,
        )
        self.db.add(link)
        await self.db.flush()
        return link

    # ─── Link evidence → relationship ────────────────────────────────

    async def link_evidence_to_relationship(
        self,
        evidence_id: str,
        relationship_id: str,
        observation_id: Optional[str] = None,
    ) -> RelationshipProvenance:
        """
        Record that a piece of evidence (and optionally a specific
        observation within that evidence) supports a relationship.
        """
        # Check existing (relationship_id, evidence_id) is PK
        result = await self.db.execute(
            select(RelationshipProvenance).where(
                RelationshipProvenance.relationship_id == relationship_id,
                RelationshipProvenance.evidence_id == evidence_id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            # If observation_id is provided and existing has none, update it
            if observation_id and not existing.observation_id:
                existing.observation_id = observation_id
                await self.db.flush()
            return existing

        link = RelationshipProvenance(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            observation_id=observation_id,
        )
        self.db.add(link)
        await self.db.flush()
        return link

    # ─── Get evidence chain for an entity ────────────────────────────

    async def get_evidence_chain(self, entity_id: str) -> list[RawEvidence]:
        """
        Return all RawEvidence rows that produced observations linked
        to this entity, ordered by collected_at ascending.
        """
        # entity_observations -> observations -> raw_evidence
        result = await self.db.execute(
            select(RawEvidence)
            .join(Observation, Observation.evidence_id == RawEvidence.id)
            .join(EntityObservation, EntityObservation.observation_id == Observation.id)
            .where(EntityObservation.entity_id == entity_id)
            .order_by(RawEvidence.collected_at.asc())
            .distinct()
        )
        return list(result.scalars().all())

    # ─── Get full provenance for a relationship ──────────────────────

    async def get_full_provenance(self, relationship_id: str) -> Optional[ProvenanceChain]:
        """
        Build the full provenance chain for a relationship:
          - the relationship itself
          - all supporting RawEvidence (via RelationshipProvenance)
          - all supporting Observations (via RelationshipProvenance.observation_id)
          - the plugins that produced the evidence
          - the time range over which the evidence was collected
        """
        # Load the relationship
        rel_result = await self.db.execute(
            select(Relationship).where(Relationship.id == relationship_id)
        )
        rel = rel_result.scalar_one_or_none()
        if not rel:
            return None

        # Load provenance links
        prov_result = await self.db.execute(
            select(RelationshipProvenance).where(
                RelationshipProvenance.relationship_id == relationship_id
            )
        )
        prov_links = prov_result.scalars().all()

        if not prov_links:
            return ProvenanceChain(
                relationship_id=rel.id,
                relationship_type=rel.relationship_type,
                source_entity_id=rel.source_entity_id,
                target_entity_id=rel.target_entity_id,
                confidence=rel.confidence,
                supporting_evidence=[],
                supporting_observations=[],
                plugins=[],
                collected_at_range=None,
            )

        # Load evidence rows
        evidence_ids = {p.evidence_id for p in prov_links}
        ev_result = await self.db.execute(
            select(RawEvidence).where(RawEvidence.id.in_(evidence_ids))
        )
        evidence_rows = list(ev_result.scalars().all())
        evidence_by_id = {e.id: e for e in evidence_rows}

        # Load observation rows (those explicitly linked via provenance)
        obs_ids = {p.observation_id for p in prov_links if p.observation_id}
        observation_rows: list[Observation] = []
        if obs_ids:
            obs_result = await self.db.execute(
                select(Observation).where(Observation.id.in_(obs_ids))
            )
            observation_rows = list(obs_result.scalars().all())

        # Build the response dicts (lightweight serialization)
        supporting_evidence = [
            {
                "id": e.id,
                "plugin_id": e.plugin_id,
                "plugin_version": e.plugin_version,
                "execution_id": e.execution_id,
                "investigation_id": e.investigation_id,
                "target": e.target,
                "collected_at": e.collected_at.isoformat() if e.collected_at else None,
                "source_url": e.source_url,
                "source_reliability": e.source_reliability,
            }
            for e in evidence_rows
        ]

        supporting_observations = [
            {
                "id": o.id,
                "evidence_id": o.evidence_id,
                "observation_type": o.observation_type,
                "value": o.value,
                "context": o.context,
                "confidence": o.confidence,
                "extracted_at": o.extracted_at.isoformat() if o.extracted_at else None,
            }
            for o in observation_rows
        ]

        plugins = sorted({e.plugin_id for e in evidence_rows})

        # Time range
        timestamps = [e.collected_at for e in evidence_rows if e.collected_at]
        if timestamps:
            collected_at_range = (min(timestamps), max(timestamps))
        else:
            collected_at_range = None

        return ProvenanceChain(
            relationship_id=rel.id,
            relationship_type=rel.relationship_type,
            source_entity_id=rel.source_entity_id,
            target_entity_id=rel.target_entity_id,
            confidence=rel.confidence,
            supporting_evidence=supporting_evidence,
            supporting_observations=supporting_observations,
            plugins=plugins,
            collected_at_range=collected_at_range,
        )

    # ─── Convenience: ingest a full PluginResult ─────────────────────

    async def ingest_plugin_result(
        self,
        plugin_result: PluginResult,
        *,
        entity_id_map: Optional[dict[tuple[str, str], str]] = None,
        relationship_id_map: Optional[dict[tuple[str, str, str, str, str], str]] = None,
    ) -> RawEvidence:
        """
        Convenience method: record evidence + all observations in one go.

        Args:
            plugin_result: the validated PluginResult
            entity_id_map: optional mapping from (type, normalized_value)
                -> canonical entity_id, used to link observations to
                entities. If absent, observations are recorded without
                entity links.
            relationship_id_map: optional mapping from
                (src_type, src_value, rel_type, tgt_type, tgt_value) ->
                relationship_id, used to link evidence to relationships.

        Returns the created RawEvidence row.
        """
        evidence = await self.record_evidence(plugin_result)

        # Record all observations
        for obs_schema in plugin_result.observations:
            obs = await self.record_observation(evidence.id, obs_schema)
            # Link to entity if map provided and the observation declares a linked entity
            if entity_id_map and obs_schema.linked_entity_type and obs_schema.linked_entity_value:
                key = (obs_schema.linked_entity_type, obs_schema.linked_entity_value.strip().lower())
                ent_id = entity_id_map.get(key)
                if ent_id:
                    await self.link_observation_to_entity(obs.id, ent_id)

        # Link evidence to relationships if map provided
        if relationship_id_map:
            for rel_schema in plugin_result.relationships:
                key = (
                    rel_schema.source_entity_type,
                    rel_schema.source_entity_value,
                    rel_schema.relationship_type,
                    rel_schema.target_entity_type,
                    rel_schema.target_entity_value,
                )
                rel_id = relationship_id_map.get(key)
                if rel_id:
                    await self.link_evidence_to_relationship(evidence.id, rel_id)

        return evidence


__all__ = ["ProvenanceService"]
