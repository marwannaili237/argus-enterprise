"""
IdentityResolutionService — investigation-scoped identity clustering.

CRITICAL RULE: This service NEVER performs cross-investigation merges.
Identity resolution happens WITHIN one investigation only. Cross-
investigation correlation is a separate concern (Correlation Engine,
not yet implemented) that PROPOSES matches — it does not execute them.

Confidence computation:
  - Uses noisy-OR over INDEPENDENT evidence sources only.
  - Two observations are independent iff they come from different
    (plugin_id, source_url) pairs (see canonical.confidence.EvidenceSource).
  - Observations from the same plugin execution on the same source
    count as ONE signal, not N signals.

Lifecycle:
  - New identity → status="tentative"
  - Confidence >= IDENTITY_PROMOTION_THRESHOLD → status="confirmed" (auto)
  - Manual dispute → status="disputed"
  - Manual merge → one identity becomes "merged" with merged_into pointer

All identity operations emit events to identity_events (see migration 0002)
for audit/replay.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from canonical.models import (
    CanonicalEntity, Identity, IdentityEntity,
    EntityInvestigationLink, RawEvidence, Observation, EntityObservation,
    ALLOWED_ENTITY_TYPES,
)
from canonical.confidence import (
    signal_weight_for_type, tier_for_type,
    IDENTITY_PROMOTION_THRESHOLD, IDENTITY_DISPUTE_THRESHOLD,
    EvidenceSource,
)

logger = logging.getLogger("argus.canonical.identity_resolution")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class IdentityResolutionError(Exception):
    """Raised on invalid identity operations."""


class IdentityResolutionService:
    """
    Investigation-scoped identity resolution.

    Construct with an AsyncSession. The investigation_id is passed to
    each method — this service is stateless across investigations.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Resolve identities for an investigation ─────────────────────

    async def resolve_investigation(
        self,
        investigation_id: str,
        *,
        entity_ids: Optional[list[str]] = None,
    ) -> list[Identity]:
        """
        Run identity resolution WITHIN one investigation.

        1. If entity_ids is None, load all canonical entities linked to this investigation.
        2. Group entities into identity candidates using deterministic rules.
        3. For each candidate, compute confidence using noisy-OR over independent evidence.
        4. Find or create Identity rows; link entities via IdentityEntity.
        5. Auto-promote identities that cross the promotion threshold.

        Returns the list of resolved Identity rows.

        This method NEVER touches identities from other investigations.
        """
        # 1. Load entities for this investigation
        if entity_ids is None:
            entity_ids = await self._load_investigation_entities(investigation_id)

        if not entity_ids:
            return []

        # 2. Group entities into identity candidates.
        # A candidate is a set of entities that should plausibly be the same actor.
        # Heuristic: entities of different types that share at least one investigation
        # AND are observed together in the same evidence source.
        candidates = await self._build_identity_candidates(entity_ids, investigation_id)

        # 3. For each candidate, find-or-create an identity + compute confidence
        identities: list[Identity] = []
        for candidate_entity_ids in candidates:
            identity = await self._find_or_create_identity_for_entities(
                candidate_entity_ids, investigation_id,
            )
            identities.append(identity)

        return identities

    # ─── Internal: load entities for an investigation ────────────────

    async def _load_investigation_entities(self, investigation_id: str) -> list[str]:
        """Return canonical_entity_ids linked to this investigation."""
        result = await self.db.execute(
            select(EntityInvestigationLink.entity_id).where(
                EntityInvestigationLink.investigation_id == str(investigation_id)
            )
        )
        return [row[0] for row in result.all()]

    # ─── Internal: build identity candidates ─────────────────────────

    async def _build_identity_candidates(
        self,
        entity_ids: list[str],
        investigation_id: str,
    ) -> list[set[str]]:
        """
        Group entities into identity candidates.

        Deterministic algorithm:
          1. Start with each entity as its own candidate.
          2. For every pair of entities, check if they were observed
             together in the same RawEvidence within THIS investigation.
          3. If yes, and the pair includes a strong signal (Tier 1),
             merge the candidates.

        This is O(N^2) in entities but N is small per investigation
        (typically <100).
        """
        # Initialize: each entity is its own candidate
        # Use union-find for efficient merging
        parent: dict[str, str] = {eid: eid for eid in entity_ids}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]  # path compression
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Load all entities with their types
        ent_result = await self.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id.in_(entity_ids))
        )
        entities_by_id = {e.id: e for e in ent_result.scalars().all()}

        # For each pair, check co-observation within this investigation
        # Optimized: load all (entity_id, evidence_id) pairs for these entities
        # filtered to this investigation's evidence
        co_obs = await self._load_co_observations(entity_ids, investigation_id)

        # co_obs: dict[evidence_id, set[entity_id]]
        for ev_id, ent_set in co_obs.items():
            # Only merge if the evidence contains at least one Tier-1 entity
            has_tier1 = any(
                tier_for_type(entities_by_id[eid].type) == 1
                for eid in ent_set if eid in entities_by_id
            )
            if not has_tier1:
                continue
            # Merge all entities in this co-observation
            ent_list = list(ent_set)
            for i in range(1, len(ent_list)):
                union(ent_list[0], ent_list[i])

        # Group by root
        candidates: dict[str, set[str]] = {}
        for eid in entity_ids:
            root = find(eid)
            candidates.setdefault(root, set()).add(eid)

        return list(candidates.values())

    async def _load_co_observations(
        self,
        entity_ids: list[str],
        investigation_id: str,
    ) -> dict[str, set[str]]:
        """
        For each evidence_id in this investigation, return the set of
        entities (from entity_ids) that were observed in that evidence.
        """
        # Join: evidence (filtered by investigation_id) → observations → entity_observations
        result = await self.db.execute(
            select(
                RawEvidence.id.label("evidence_id"),
                EntityObservation.entity_id,
            )
            .select_from(RawEvidence)
            .join(Observation, Observation.evidence_id == RawEvidence.id)
            .join(EntityObservation, EntityObservation.observation_id == Observation.id)
            .where(
                RawEvidence.investigation_id == str(investigation_id),
                EntityObservation.entity_id.in_(entity_ids),
            )
            .distinct()
        )
        co_obs: dict[str, set[str]] = {}
        for row in result.all():
            ev_id = row.evidence_id
            ent_id = row.entity_id
            co_obs.setdefault(ev_id, set()).add(ent_id)
        return co_obs

    # ─── Internal: find or create identity ───────────────────────────

    async def _find_or_create_identity_for_entities(
        self,
        entity_ids: set[str],
        investigation_id: str,
    ) -> Identity:
        """
        Find an existing identity that contains ALL of these entities
        (within this investigation), or create a new one.

        CRITICAL: only considers identities whose entities are linked to
        THIS investigation. Never touches cross-investigation identities.
        """
        # Load entities to get their types for confidence computation
        ent_result = await self.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id.in_(list(entity_ids)))
        )
        entities = list(ent_result.scalars().all())
        if not entities:
            raise IdentityResolutionError("No entities found for identity candidate")

        # Check if any identity already contains all these entities
        existing_identity = await self._find_identity_containing_all(entity_ids, investigation_id)
        if existing_identity:
            # Update confidence (in case new observations were added)
            return await self._recompute_confidence(existing_identity, investigation_id)

        # Create new tentative identity
        identity = Identity(
            label=None,
            confidence=0.0,
            status="tentative",
        )
        self.db.add(identity)
        await self.db.flush()  # populate identity.id

        # Link entities
        for ent in entities:
            self.db.add(IdentityEntity(
                identity_id=identity.id,
                entity_id=ent.id,
                signal_weight=signal_weight_for_type(ent.type),
            ))

        # Compute confidence
        identity = await self._recompute_confidence(identity, investigation_id)

        # Emit event
        await self._emit_event(
            identity_id=identity.id,
            action="created",
            investigation_id=investigation_id,
            details={"entity_count": len(entities), "confidence": identity.confidence},
        )

        return identity

    async def _find_identity_containing_all(
        self,
        entity_ids: set[str],
        investigation_id: str,
    ) -> Optional[Identity]:
        """
        Find an identity whose IdentityEntity set is a subset of entity_ids
        AND whose entities are all linked to this investigation.
        """
        # Find identities linked to ANY of these entities
        result = await self.db.execute(
            select(IdentityEntity.identity_id).where(
                IdentityEntity.entity_id.in_(list(entity_ids))
            ).distinct()
        )
        candidate_identity_ids = [row[0] for row in result.all()]

        for identity_id in candidate_identity_ids:
            # Get all entities in this identity
            ent_result = await self.db.execute(
                select(IdentityEntity.entity_id).where(
                    IdentityEntity.identity_id == identity_id
                )
            )
            identity_entity_ids = {row[0] for row in ent_result.all()}

            # Check if all identity entities are in our candidate set
            if identity_entity_ids.issubset(entity_ids):
                # Verify all are linked to this investigation
                inv_result = await self.db.execute(
                    select(EntityInvestigationLink.entity_id).where(
                        EntityInvestigationLink.investigation_id == str(investigation_id),
                        EntityInvestigationLink.entity_id.in_(list(identity_entity_ids)),
                    )
                )
                linked = {row[0] for row in inv_result.all()}
                if linked == identity_entity_ids:
                    # Load and return the identity
                    id_result = await self.db.execute(
                        select(Identity).where(Identity.id == identity_id)
                    )
                    return id_result.scalar_one_or_none()

        return None

    # ─── Internal: confidence computation ────────────────────────────

    async def _recompute_confidence(
        self,
        identity: Identity,
        investigation_id: str,
    ) -> Identity:
        """
        Recompute identity confidence using noisy-OR over INDEPENDENT
        evidence sources.

        Independence rule: observations from the same (plugin_id, source_url)
        pair are DEPENDENT — they count as one signal.

        Algorithm:
          1. Load all IdentityEntity rows for this identity.
          2. For each entity, load all observations (within this investigation)
             and group them by EvidenceSource (plugin_id, source_url).
          3. For each entity, the per-entity contribution is the MAX
             signal_weight across its independent evidence sources
             (not the sum — dependent observations don't add).
          4. Combine across entities using noisy-OR:
             confidence = 1 - product(1 - w_i) for each entity i
        """
        # Load identity entities
        ie_result = await self.db.execute(
            select(IdentityEntity).where(IdentityEntity.identity_id == identity.id)
        )
        identity_entities = ie_result.scalars().all()

        if not identity_entities:
            identity.confidence = 0.0
            return identity

        # For each entity, compute the per-entity weight (max across independent sources)
        per_entity_weights: list[float] = []
        for ie in identity_entities:
            weight = await self._compute_entity_weight(
                ie.entity_id, ie.signal_weight, investigation_id,
            )
            per_entity_weights.append(weight)

        # Noisy-OR
        prob_none = 1.0
        for w in per_entity_weights:
            prob_none *= (1.0 - max(0.0, min(1.0, w)))
        identity.confidence = max(0.0, min(1.0, 1.0 - prob_none))
        identity.updated_at = _utcnow()

        # Auto-promote
        if identity.status == "tentative" and identity.confidence >= IDENTITY_PROMOTION_THRESHOLD:
            identity.status = "confirmed"
            await self._emit_event(
                identity_id=identity.id,
                action="promoted",
                investigation_id=investigation_id,
                details={"confidence": identity.confidence, "threshold": IDENTITY_PROMOTION_THRESHOLD},
            )

        return identity

    async def _compute_entity_weight(
        self,
        entity_id: str,
        base_weight: float,
        investigation_id: str,
    ) -> float:
        """
        Compute the effective weight for one entity within one investigation.

        For Tier-1 entities (email, phone, wallet, PGP), the base weight
        is the contribution — independent observations don't inflate it
        because a single Tier-1 match is already strong.

        For Tier-2 and Tier-3 entities, multiple INDEPENDENT observations
        (different sources) DO increase the weight — but with diminishing
        returns (logarithmic, not linear).
        """
        # Count independent evidence sources for this entity in this investigation
        source_count = await self._count_independent_sources(entity_id, investigation_id)

        tier = tier_for_type(
            # Look up the entity type
            (await self._get_entity_type(entity_id)) or ""
        )

        if tier == 1:
            # Tier-1: single match is enough. Don't inflate.
            return base_weight

        # Tier 2/3: multiple independent sources increase confidence
        # but with diminishing returns: w_effective = base * (1 + log(source_count))
        import math
        if source_count <= 1:
            return base_weight
        multiplier = 1.0 + math.log(source_count)
        return min(1.0, base_weight * multiplier)

    async def _count_independent_sources(
        self,
        entity_id: str,
        investigation_id: str,
    ) -> int:
        """Count distinct (plugin_id, source_url) pairs that observed this entity in this investigation."""
        result = await self.db.execute(
            select(
                RawEvidence.plugin_id,
                RawEvidence.source_url,
            )
            .select_from(RawEvidence)
            .join(Observation, Observation.evidence_id == RawEvidence.id)
            .join(EntityObservation, EntityObservation.observation_id == Observation.id)
            .where(
                EntityObservation.entity_id == entity_id,
                RawEvidence.investigation_id == str(investigation_id),
            )
            .distinct()
        )
        sources = {
            EvidenceSource(plugin_id=row.plugin_id, source_url=row.source_url)
            for row in result.all()
        }
        return len(sources)

    async def _get_entity_type(self, entity_id: str) -> Optional[str]:
        result = await self.db.execute(
            select(CanonicalEntity.type).where(CanonicalEntity.id == entity_id)
        )
        row = result.first()
        return row[0] if row else None

    # ─── Manual operations ───────────────────────────────────────────

    async def dispute_identity(
        self,
        identity_id: str,
        investigation_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Identity:
        """Mark an identity as disputed. Requires investigation scope for audit."""
        result = await self.db.execute(select(Identity).where(Identity.id == identity_id))
        identity = result.scalar_one_or_none()
        if not identity:
            raise IdentityResolutionError(f"Identity {identity_id} not found")

        identity.status = "disputed"
        identity.updated_at = _utcnow()
        await self._emit_event(
            identity_id=identity_id,
            action="disputed",
            investigation_id=investigation_id,
            details={"reason": reason or "manual dispute"},
        )
        return identity

    async def merge_identities(
        self,
        source_identity_id: str,
        target_identity_id: str,
        investigation_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Identity:
        """
        Merge source into target. Both must be in the same investigation.
        Source is marked 'merged' with merged_into=target.
        """
        if source_identity_id == target_identity_id:
            raise IdentityResolutionError("Cannot merge identity into itself")

        # Load both
        src_result = await self.db.execute(select(Identity).where(Identity.id == source_identity_id))
        source = src_result.scalar_one_or_none()
        if not source:
            raise IdentityResolutionError(f"Source identity {source_identity_id} not found")

        tgt_result = await self.db.execute(select(Identity).where(Identity.id == target_identity_id))
        target = tgt_result.scalar_one_or_none()
        if not target:
            raise IdentityResolutionError(f"Target identity {target_identity_id} not found")

        # Verify both are scoped to this investigation (defensive — should always be true)
        # by checking that their entities are linked to this investigation
        src_in_inv = await self._identity_in_investigation(source_identity_id, investigation_id)
        tgt_in_inv = await self._identity_in_investigation(target_identity_id, investigation_id)
        if not src_in_inv or not tgt_in_inv:
            raise IdentityResolutionError(
                "Cannot merge identities from different investigations (cross-investigation merge forbidden)"
            )

        # Reparent IdentityEntity rows from source to target (dedup, keep max weight)
        src_links_result = await self.db.execute(
            select(IdentityEntity).where(IdentityEntity.identity_id == source_identity_id)
        )
        src_links = src_links_result.scalars().all()

        for link in src_links:
            existing_result = await self.db.execute(
                select(IdentityEntity).where(
                    IdentityEntity.identity_id == target_identity_id,
                    IdentityEntity.entity_id == link.entity_id,
                )
            )
            existing = existing_result.scalar_one_or_none()
            if existing:
                if link.signal_weight > existing.signal_weight:
                    existing.signal_weight = link.signal_weight
                await self.db.delete(link)
            else:
                link.identity_id = target_identity_id

        source.status = "merged"
        source.merged_into = target_identity_id
        source.updated_at = _utcnow()

        target = await self._recompute_confidence(target, investigation_id)

        await self._emit_event(
            identity_id=target_identity_id,
            action="merged",
            investigation_id=investigation_id,
            details={"source_identity": source_identity_id, "reason": reason or "manual merge"},
        )
        return target

    async def _identity_in_investigation(self, identity_id: str, investigation_id: str) -> bool:
        """Check if any of the identity's entities is linked to this investigation."""
        result = await self.db.execute(
            select(func.count()).select_from(IdentityEntity)
            .join(EntityInvestigationLink,
                  EntityInvestigationLink.entity_id == IdentityEntity.entity_id)
            .where(
                IdentityEntity.identity_id == identity_id,
                EntityInvestigationLink.investigation_id == str(investigation_id),
            )
        )
        return (result.scalar() or 0) > 0

    # ─── Event emission (audit trail) ────────────────────────────────

    async def _emit_event(
        self,
        identity_id: str,
        action: str,
        investigation_id: str,
        details: dict,
    ) -> None:
        """
        Emit an identity event for audit/replay.

        Stored in identity_events table (added in migration 0002).
        If the table doesn't exist yet (pre-migration), this is a no-op
        so the service remains usable in test environments.
        """
        try:
            # Import here to avoid circular dep
            from canonical.models import IdentityEvent
            event = IdentityEvent(
                identity_id=identity_id,
                action=action,
                investigation_id=str(investigation_id),
                details=details,
            )
            self.db.add(event)
            await self.db.flush()
        except Exception as e:
            # Don't fail the identity operation if event logging fails
            logger.warning("Failed to emit identity event: %s", e)


__all__ = ["IdentityResolutionService", "IdentityResolutionError"]
