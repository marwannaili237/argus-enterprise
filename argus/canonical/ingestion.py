"""
IngestionService — the single entry point for canonical ingestion.

Pipeline (all in one DB transaction):
  1. Validate the canonical PluginResult (PluginResultValidator)
  2. Reject if validation fails (structural failure)
  3. Record RawEvidence (immutable)
  4. For each Observation: persist + link to entity
  5. For each ExtractedEntity: upsert canonical entity + link to investigation + link to observation
  6. For each ExtractedRelationship: upsert relationship + link provenance to evidence
  7. Commit (or rollback on any error)

Rules:
  - Single transaction boundary. Either everything commits or nothing does.
  - Idempotent: re-ingesting the same (execution_id, plugin_id) is a no-op
    (returns the existing RawEvidence).
  - Caps entities/observations/relationships per call to prevent runaway.
  - Does NOT perform identity resolution (that's IdentityResolutionService).
  - Does NOT perform cross-investigation correlation (that's a separate engine).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from canonical.schemas import PluginResult, ExtractedEntity, ExtractedRelationship, Observation as ObservationSchema
from canonical.models import (
    RawEvidence, Observation, EntityObservation,
    CanonicalEntity, Relationship, RelationshipProvenance,
    EntityInvestigationLink, IdentityEntity, Identity,
    ALLOWED_ENTITY_TYPES,
)
from canonical.normalizer import Normalizer
from canonical.validator import PluginResultValidator, ValidationResult
from canonical import confidence as conf

logger = logging.getLogger("argus.canonical.ingestion")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class IngestionError(Exception):
    """Raised when ingestion fails structurally (validation, caps, etc.)."""

    def __init__(self, message: str, *, code: str = "ingestion_error"):
        self.code = code
        super().__init__(message)


class IngestionService:
    """
    Orchestration service. Construct with an AsyncSession.

    Typical usage:
        svc = IngestionService(db)
        evidence = await svc.ingest(plugin_result)
        # evidence is committed; canonical entities + observations persisted
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Public API ──────────────────────────────────────────────────

    async def ingest(self, result: PluginResult) -> RawEvidence:
        """
        Ingest a canonical PluginResult.

        Returns the persisted RawEvidence row.

        Raises IngestionError if:
          - validation fails
          - caps are exceeded
          - idempotency check finds an existing evidence for this execution

        All DB writes happen in the caller's transaction. If an exception
        is raised, the caller should rollback.
        """
        # ─── Step 1: Validate ────────────────────────────────────────
        vr = PluginResultValidator.validate_structure(result)
        if not vr.is_valid:
            err_msgs = "; ".join(f"{e.path}: {e.message}" for e in vr.errors[:5])
            raise IngestionError(
                f"Validation failed: {err_msgs}",
                code="validation_failed",
            )
        # Use the sanitized result from here on
        sanitized = vr.sanitized_result or result

        # ─── Step 2: Enforce caps ────────────────────────────────────
        self._enforce_caps(sanitized)

        # ─── Step 3: Idempotency check ───────────────────────────────
        existing = await self._find_existing_evidence(sanitized.execution_id, sanitized.plugin_id)
        if existing:
            logger.debug(
                "Skipping ingestion — evidence already exists for execution_id=%s plugin_id=%s",
                sanitized.execution_id, sanitized.plugin_id,
            )
            return existing

        # ─── Step 4: Record raw evidence ─────────────────────────────
        evidence = await self._record_evidence(sanitized)

        # ─── Step 5: Process observations ────────────────────────────
        observation_id_map = await self._process_observations(evidence.id, sanitized.observations)

        # ─── Step 6: Process entities ────────────────────────────────
        entity_id_map = await self._process_entities(
            evidence.id, sanitized.entities, sanitized.investigation_id, observation_id_map, sanitized,
        )

        # ─── Step 7: Process relationships ───────────────────────────
        await self._process_relationships(evidence.id, sanitized.relationships, entity_id_map)

        # ─── Step 8: Flush (caller commits) ──────────────────────────
        await self.db.flush()
        return evidence

    # ─── Internal: caps ──────────────────────────────────────────────

    def _enforce_caps(self, result: PluginResult) -> None:
        if len(result.entities) > conf.INGESTION_MAX_ENTITIES_PER_CALL:
            raise IngestionError(
                f"Too many entities: {len(result.entities)} > {conf.INGESTION_MAX_ENTITIES_PER_CALL}",
                code="entities_cap_exceeded",
            )
        if len(result.observations) > conf.INGESTION_MAX_OBSERVATIONS_PER_CALL:
            raise IngestionError(
                f"Too many observations: {len(result.observations)} > {conf.INGESTION_MAX_OBSERVATIONS_PER_CALL}",
                code="observations_cap_exceeded",
            )
        if len(result.relationships) > conf.INGESTION_MAX_RELATIONSHIPS_PER_CALL:
            raise IngestionError(
                f"Too many relationships: {len(result.relationships)} > {conf.INGESTION_MAX_RELATIONSHIPS_PER_CALL}",
                code="relationships_cap_exceeded",
            )

    # ─── Internal: idempotency ───────────────────────────────────────

    async def _find_existing_evidence(self, execution_id: str, plugin_id: str) -> Optional[RawEvidence]:
        result = await self.db.execute(
            select(RawEvidence).where(
                RawEvidence.execution_id == execution_id,
                RawEvidence.plugin_id == plugin_id,
            ).limit(1)
        )
        return result.scalar_one_or_none()

    # ─── Internal: record evidence ───────────────────────────────────

    async def _record_evidence(self, result: PluginResult) -> RawEvidence:
        # Pull source_url + reliability from the first Evidence entry if present
        source_url: Optional[str] = None
        source_reliability: Optional[float] = None
        if result.evidence:
            ev0 = result.evidence[0]
            source_url = ev0.source_url
            source_reliability = ev0.source_reliability

        evidence = RawEvidence(
            investigation_id=str(result.investigation_id),
            plugin_id=result.plugin_id,
            plugin_version=result.plugin_version,
            execution_id=result.execution_id,
            target=result.target,
            collected_at=_utcnow(),
            raw_response=result.raw or {},
            source_url=source_url,
            source_reliability=source_reliability,
        )
        self.db.add(evidence)
        await self.db.flush()
        return evidence

    # ─── Internal: observations ──────────────────────────────────────

    async def _process_observations(
        self,
        evidence_id: str,
        observations: list[ObservationSchema],
    ) -> dict[int, str]:
        """
        Persist all observations. Returns a map from observation index
        (in the input list) to observation_id.
        """
        id_map: dict[int, str] = {}
        for idx, obs_schema in enumerate(observations):
            obs = Observation(
                evidence_id=evidence_id,
                observation_type=obs_schema.observation_type,
                value=obs_schema.value,
                context=obs_schema.context,
                confidence=obs_schema.confidence,
                extracted_at=_utcnow(),
            )
            self.db.add(obs)
            await self.db.flush()
            id_map[idx] = obs.id
        return id_map

    # ─── Internal: entities ──────────────────────────────────────────

    async def _process_entities(
        self,
        evidence_id: str,
        entities: list[ExtractedEntity],
        investigation_id: str,
        observation_id_map: dict[int, str],
        result: PluginResult,
    ) -> dict[tuple[str, str], str]:
        """
        Upsert canonical entities, link to investigation, link to observations.

        Returns a map from (entity_type, normalized_value) → canonical_entity_id.
        This map is used by _process_relationships to resolve references.
        """
        entity_id_map: dict[tuple[str, str], str] = {}

        for idx, ent_schema in enumerate(entities):
            # Normalize the value (sanitizer should have done this, but be defensive)
            normalized = ent_schema.normalized_value or Normalizer.normalize(ent_schema.type, ent_schema.raw_value)
            if not normalized:
                logger.debug("Skipping entity with empty normalized value: %s/%s", ent_schema.type, ent_schema.raw_value)
                continue

            # Upsert canonical entity
            canonical = await self._upsert_canonical_entity(
                type=ent_schema.type,
                raw_value=ent_schema.raw_value,
                normalized_value=normalized,
            )

            # Link entity to investigation
            await self._link_entity_to_investigation(canonical.id, investigation_id)

            # Link entity to the corresponding observation (if the observation
            # declared a linked entity, we already have it; otherwise, link to
            # the observation at the same index if it exists)
            obs_id = observation_id_map.get(idx)
            if obs_id:
                await self._link_observation_to_entity(obs_id, canonical.id)

            entity_id_map[(ent_schema.type, normalized)] = canonical.id

        return entity_id_map

    async def _upsert_canonical_entity(
        self,
        type: str,
        raw_value: str,
        normalized_value: str,
    ) -> CanonicalEntity:
        """Insert or update a canonical entity."""
        result = await self.db.execute(
            select(CanonicalEntity).where(
                CanonicalEntity.type == type,
                CanonicalEntity.normalized_value == normalized_value,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.last_seen = _utcnow()
            existing.source_count = (existing.source_count or 1) + 1
            return existing

        ent = CanonicalEntity(
            type=type,
            normalized_value=normalized_value,
            raw_value=raw_value,
            first_seen=_utcnow(),
            last_seen=_utcnow(),
            investigation_count=0,
            source_count=1,
        )
        self.db.add(ent)
        await self.db.flush()
        return ent

    async def _link_entity_to_investigation(
        self,
        entity_id: str,
        investigation_id: str,
    ) -> None:
        """Upsert entity_investigation_links + bump investigation_count on first link."""
        result = await self.db.execute(
            select(EntityInvestigationLink).where(
                EntityInvestigationLink.entity_id == entity_id,
                EntityInvestigationLink.investigation_id == investigation_id,
            )
        )
        if result.scalar_one_or_none():
            return  # Already linked

        self.db.add(EntityInvestigationLink(
            entity_id=entity_id,
            investigation_id=str(investigation_id),
        ))

        # Bump investigation_count
        ent_result = await self.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == entity_id)
        )
        ent = ent_result.scalar_one_or_none()
        if ent:
            ent.investigation_count = (ent.investigation_count or 0) + 1
            ent.last_seen = _utcnow()

    async def _link_observation_to_entity(
        self,
        observation_id: str,
        entity_id: str,
    ) -> None:
        """Upsert entity_observations link."""
        result = await self.db.execute(
            select(EntityObservation).where(
                EntityObservation.entity_id == entity_id,
                EntityObservation.observation_id == observation_id,
            )
        )
        if result.scalar_one_or_none():
            return
        self.db.add(EntityObservation(
            entity_id=entity_id,
            observation_id=observation_id,
        ))

    # ─── Internal: relationships ─────────────────────────────────────

    async def _process_relationships(
        self,
        evidence_id: str,
        relationships: list[ExtractedRelationship],
        entity_id_map: dict[tuple[str, str], str],
    ) -> None:
        """Upsert relationships + link provenance to evidence."""
        for rel_schema in relationships:
            # Resolve source and target entity IDs via the map
            src_norm = Normalizer.normalize(rel_schema.source_entity_type, rel_schema.source_entity_value)
            tgt_norm = Normalizer.normalize(rel_schema.target_entity_type, rel_schema.target_entity_value)

            src_id = entity_id_map.get((rel_schema.source_entity_type, src_norm))
            tgt_id = entity_id_map.get((rel_schema.target_entity_type, tgt_norm))

            # If the entities weren't in the input list, upsert them on the fly
            # (relationships may reference entities that the plugin didn't
            # explicitly extract but that we can infer from the relationship itself)
            if not src_id:
                src_ent = await self._upsert_canonical_entity(
                    rel_schema.source_entity_type, rel_schema.source_entity_value, src_norm,
                )
                src_id = src_ent.id
            if not tgt_id:
                tgt_ent = await self._upsert_canonical_entity(
                    rel_schema.target_entity_type, rel_schema.target_entity_value, tgt_norm,
                )
                tgt_id = tgt_ent.id

            # Upsert relationship
            rel = await self._upsert_relationship(src_id, tgt_id, rel_schema.relationship_type, rel_schema.confidence)

            # Link provenance
            await self._link_provenance(rel.id, evidence_id)

    async def _upsert_relationship(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        confidence: float,
    ) -> Relationship:
        """Find existing relationship or create new one."""
        result = await self.db.execute(
            select(Relationship).where(
                Relationship.source_entity_id == source_entity_id,
                Relationship.target_entity_id == target_entity_id,
                Relationship.relationship_type == relationship_type,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.last_seen = _utcnow()
            # Keep the higher confidence
            if confidence > existing.confidence:
                existing.confidence = confidence
            return existing

        rel = Relationship(
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            relationship_type=relationship_type,
            confidence=confidence,
            first_seen=_utcnow(),
            last_seen=_utcnow(),
        )
        self.db.add(rel)
        await self.db.flush()
        return rel

    async def _link_provenance(
        self,
        relationship_id: str,
        evidence_id: str,
        observation_id: Optional[str] = None,
    ) -> None:
        """Upsert relationship_provenance."""
        result = await self.db.execute(
            select(RelationshipProvenance).where(
                RelationshipProvenance.relationship_id == relationship_id,
                RelationshipProvenance.evidence_id == evidence_id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            if observation_id and not existing.observation_id:
                existing.observation_id = observation_id
            return
        self.db.add(RelationshipProvenance(
            relationship_id=relationship_id,
            evidence_id=evidence_id,
            observation_id=observation_id,
        ))


__all__ = ["IngestionService", "IngestionError"]
