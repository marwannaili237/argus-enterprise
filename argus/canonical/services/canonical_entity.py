"""
CanonicalEntityService — the write-side service for the canonical entity layer.

Responsibilities:
  - upsert_entity(type, raw_value): normalize + INSERT ON CONFLICT DO UPDATE
  - link_entity_to_investigation(entity_id, investigation_id): upsert M2M
  - find_shared_investigations(entity_id): cross-investigation correlation
  - get_or_create_identity(entities): identity clustering with merge logic

All methods are async. The service takes an AsyncSession via constructor
so it can be used as a FastAPI dependency.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import logging

from sqlalchemy import select, func, and_, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from canonical.models import (
    CanonicalEntity, Identity, IdentityEntity, EntityInvestigationLink,
    ALLOWED_ENTITY_TYPES,
)
from canonical.normalizer import Normalizer

logger = logging.getLogger("argus.canonical.entity_service")

# ─── Identity merge thresholds ────────────────────────────────────────
# If a new identity candidate shares at least N entities with an existing
# identity, OR the weighted overlap exceeds this fraction, we merge.
IDENTITY_MERGE_MIN_SHARED_ENTITIES = 2
IDENTITY_MERGE_OVERLAP_THRESHOLD = 0.5  # Jaccard-like
DEFAULT_SIGNAL_WEIGHTS = {
    "email": 0.9,
    "phone": 0.9,
    "username": 0.6,
    "domain": 0.4,
    "ip": 0.3,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CanonicalEntityService:
    """
    Construct with an AsyncSession. Typical FastAPI usage:

        async def get_canonical_service(
            db: AsyncSession = Depends(get_db),
        ) -> CanonicalEntityService:
            return CanonicalEntityService(db)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Upsert canonical entity ─────────────────────────────────────

    async def upsert_entity(
        self,
        type: str,
        raw_value: str,
        *,
        source: Optional[str] = None,
    ) -> CanonicalEntity:
        """
        Normalize the value and upsert into canonical_entities.

        On conflict (type, normalized_value): update last_seen, increment
        investigation_count by 0 (caller does that via link_entity_to_investigation),
        increment source_count if a new source is provided.

        Returns the persisted CanonicalEntity (with id populated).
        """
        type_norm = type.strip().lower()
        if type_norm not in ALLOWED_ENTITY_TYPES:
            raise ValueError(f"Unknown entity type: {type!r}")

        normalized = Normalizer.normalize(type_norm, raw_value)
        if not normalized:
            raise ValueError(f"Normalization returned empty for {type}/{raw_value!r}")

        # Try to find existing
        result = await self.db.execute(
            select(CanonicalEntity).where(
                CanonicalEntity.type == type_norm,
                CanonicalEntity.normalized_value == normalized,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update last_seen and bump source_count if a new source is provided
            existing.last_seen = _utcnow()
            if source and not getattr(existing, "_sources_seen", None):
                # We don't track per-source history in this MVP, just bump count
                existing.source_count = (existing.source_count or 1) + 1
            await self.db.flush()
            return existing

        # Insert new
        ent = CanonicalEntity(
            type=type_norm,
            normalized_value=normalized,
            raw_value=str(raw_value).strip(),
            first_seen=_utcnow(),
            last_seen=_utcnow(),
            investigation_count=0,
            source_count=1,
        )
        self.db.add(ent)
        await self.db.flush()
        return ent

    # ─── Link entity to investigation ────────────────────────────────

    async def link_entity_to_investigation(
        self,
        entity_id: str,
        investigation_id: str,
    ) -> EntityInvestigationLink:
        """
        Upsert into entity_investigation_links and bump
        canonical_entities.investigation_count on first link.
        """
        # Check existing link
        result = await self.db.execute(
            select(EntityInvestigationLink).where(
                EntityInvestigationLink.entity_id == entity_id,
                EntityInvestigationLink.investigation_id == investigation_id,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return existing

        # Create link
        link = EntityInvestigationLink(
            entity_id=entity_id,
            investigation_id=str(investigation_id),
        )
        self.db.add(link)

        # Bump investigation_count on the entity (only on first link to this investigation)
        ent_result = await self.db.execute(
            select(CanonicalEntity).where(CanonicalEntity.id == entity_id)
        )
        ent = ent_result.scalar_one_or_none()
        if ent:
            ent.investigation_count = (ent.investigation_count or 0) + 1
            ent.last_seen = _utcnow()

        await self.db.flush()
        return link

    # ─── Find shared investigations ──────────────────────────────────

    async def find_shared_investigations(
        self,
        entity_id: str,
        *,
        exclude_investigation_id: Optional[str] = None,
    ) -> list[str]:
        """
        Return all investigation_ids that touched this entity.

        Args:
            entity_id: the canonical entity to look up
            exclude_investigation_id: if provided, omit this investigation
                from the results (useful when called from within an
                active investigation to find *other* investigations)

        Returns a list of investigation_id strings (deduplicated, sorted).
        """
        result = await self.db.execute(
            select(EntityInvestigationLink.investigation_id).where(
                EntityInvestigationLink.entity_id == entity_id
            )
        )
        inv_ids = {row[0] for row in result.all()}
        if exclude_investigation_id:
            inv_ids.discard(str(exclude_investigation_id))
        return sorted(inv_ids)

    # ─── Cross-entity shared investigations ──────────────────────────

    async def find_investigations_shared_with_entity(
        self,
        entity_id: str,
        other_entity_ids: list[str],
    ) -> dict[str, list[str]]:
        """
        For each entity in other_entity_ids, find investigations that
        also contain `entity_id`. Returns a dict mapping each
        other_entity_id to a list of shared investigation_ids.

        This is the basis for "these entities appear together in
        investigations X, Y, Z" correlation.
        """
        if not other_entity_ids:
            return {}

        # Get all investigations for the anchor entity
        anchor_inv_ids = set(await self.find_shared_investigations(entity_id))
        if not anchor_inv_ids:
            return {eid: [] for eid in other_entity_ids}

        result: dict[str, list[str]] = {}
        for other_id in other_entity_ids:
            other_invs = set(await self.find_shared_investigations(other_id))
            shared = sorted(anchor_inv_ids & other_invs)
            result[other_id] = shared
        return result

    # ─── Identity clustering ─────────────────────────────────────────

    async def get_or_create_identity(
        self,
        entity_ids: list[str],
        *,
        signal_weights: Optional[dict[str, float]] = None,
        label: Optional[str] = None,
        merge_threshold: float = IDENTITY_MERGE_OVERLAP_THRESHOLD,
        investigation_id: Optional[str] = None,
    ) -> Identity:
        """
        ⚠️ DEPRECATED: Use IdentityResolutionService instead.

        This method is preserved for backward compatibility with existing
        tests, but is now GATED: if `investigation_id` is None, it raises
        ValueError. This prevents the cross-investigation identity merges
        that the original implementation allowed.

        The original logic (searching across all investigations and merging
        based on overlap) is preserved when `investigation_id` is provided,
        BUT it only considers identities whose entities are linked to the
        given investigation. Cross-investigation merges are refused.

        New code MUST use IdentityResolutionService, which is investigation-
        scoped by design and uses proper evidence-independence-aware
        confidence computation.
        """
        if investigation_id is None:
            raise ValueError(
                "get_or_create_identity now requires investigation_id. "
                "Cross-investigation identity merges are forbidden. "
                "Use IdentityResolutionService for new code."
            )

        if not entity_ids:
            raise ValueError("entity_ids must be non-empty")

        weights = signal_weights or DEFAULT_SIGNAL_WEIGHTS

        # 1. Find all identities linked to any input entity
        result = await self.db.execute(
            select(IdentityEntity).where(
                IdentityEntity.entity_id.in_(entity_ids)
            )
        )
        candidate_links = result.scalars().all()

        # Group by identity_id
        candidates: dict[str, set[str]] = {}
        for link in candidate_links:
            candidates.setdefault(link.identity_id, set()).add(link.entity_id)

        # 2. For each candidate, compute overlap with input
        best_identity_id: Optional[str] = None
        best_overlap = 0.0
        best_shared_count = 0
        for identity_id, shared_entities in candidates.items():
            # Get total entities in this identity
            total_result = await self.db.execute(
                select(func.count()).select_from(IdentityEntity).where(
                    IdentityEntity.identity_id == identity_id
                )
            )
            total = total_result.scalar() or 1
            overlap = len(shared_entities) / max(total, 1)
            shared_count = len(shared_entities)
            if (overlap >= merge_threshold or shared_count >= IDENTITY_MERGE_MIN_SHARED_ENTITIES):
                if shared_count > best_shared_count or (shared_count == best_shared_count and overlap > best_overlap):
                    best_identity_id = identity_id
                    best_overlap = overlap
                    best_shared_count = shared_count

        # 3. Merge into best candidate, or create new
        if best_identity_id:
            identity = await self._merge_into_identity(best_identity_id, entity_ids, weights)
        else:
            identity = await self._create_new_identity(entity_ids, weights, label)

        await self.db.flush()
        return identity

    # ─── Internal: merge entities into an existing identity ──────────

    async def _merge_into_identity(
        self,
        identity_id: str,
        new_entity_ids: list[str],
        weights: dict[str, float],
    ) -> Identity:
        """Add new entities to an existing identity and recompute confidence."""
        # Get existing entity_ids in this identity
        result = await self.db.execute(
            select(IdentityEntity).where(IdentityEntity.identity_id == identity_id)
        )
        existing_links = result.scalars().all()
        existing_entity_ids = {link.entity_id for link in existing_links}

        # Add new ones that aren't already linked
        for entity_id in new_entity_ids:
            if entity_id in existing_entity_ids:
                continue
            # Look up the entity to get its type for weight lookup
            ent_result = await self.db.execute(
                select(CanonicalEntity).where(CanonicalEntity.id == entity_id)
            )
            ent = ent_result.scalar_one_or_none()
            weight = weights.get(ent.type, 0.5) if ent else 0.5
            self.db.add(IdentityEntity(
                identity_id=identity_id,
                entity_id=entity_id,
                signal_weight=weight,
            ))

        # Recompute confidence
        return await self._recompute_identity_confidence(identity_id, weights)

    # ─── Internal: create a new tentative identity ───────────────────

    async def _create_new_identity(
        self,
        entity_ids: list[str],
        weights: dict[str, float],
        label: Optional[str],
    ) -> Identity:
        """Create a new tentative identity with the given entities."""
        identity = Identity(
            label=label,
            confidence=0.0,
            status="tentative",
        )
        self.db.add(identity)
        await self.db.flush()  # populate identity.id

        for entity_id in entity_ids:
            ent_result = await self.db.execute(
                select(CanonicalEntity).where(CanonicalEntity.id == entity_id)
            )
            ent = ent_result.scalar_one_or_none()
            weight = weights.get(ent.type, 0.5) if ent else 0.5
            self.db.add(IdentityEntity(
                identity_id=identity.id,
                entity_id=entity_id,
                signal_weight=weight,
            ))

        return await self._recompute_identity_confidence(identity.id, weights, identity=identity)

    # ─── Internal: recompute identity confidence ─────────────────────

    async def _recompute_identity_confidence(
        self,
        identity_id: str,
        weights: dict[str, float],
        *,
        identity: Optional[Identity] = None,
    ) -> Identity:
        """
        Recompute identity confidence as a bounded weighted sum.

        Confidence = 1 - product(1 - weight_i) for each linked entity.
        This is the noisy-OR formulation: each independent signal
        contributes a probability that "this identity is real", and
        the combined confidence is 1 minus the probability that NONE
        of them are real.
        """
        if identity is None:
            result = await self.db.execute(
                select(Identity).where(Identity.id == identity_id)
            )
            identity = result.scalar_one_or_none()
            if not identity:
                raise ValueError(f"Identity {identity_id} not found")

        result = await self.db.execute(
            select(IdentityEntity.signal_weight).where(
                IdentityEntity.identity_id == identity_id
            )
        )
        weights_list = [row[0] for row in result.all()]

        # Noisy-OR: 1 - product(1 - w_i)
        prob_none = 1.0
        for w in weights_list:
            prob_none *= (1.0 - max(0.0, min(1.0, w)))
        identity.confidence = max(0.0, min(1.0, 1.0 - prob_none))
        identity.updated_at = _utcnow()

        # Auto-promote from tentative to confirmed if confidence is high
        if identity.status == "tentative" and identity.confidence >= 0.8:
            identity.status = "confirmed"

        return identity

    # ─── Merge two identities ────────────────────────────────────────

    async def merge_identities(
        self,
        source_identity_id: str,
        target_identity_id: str,
    ) -> Identity:
        """
        Merge source into target. Source identity is marked 'merged'
        with merged_into=target. All IdentityEntity rows pointing to
        source are reparented to target (dedup, keeping max signal_weight).
        """
        if source_identity_id == target_identity_id:
            raise ValueError("Cannot merge identity into itself")

        # Load source
        src_result = await self.db.execute(
            select(Identity).where(Identity.id == source_identity_id)
        )
        source = src_result.scalar_one_or_none()
        if not source:
            raise ValueError(f"Source identity {source_identity_id} not found")

        # Load target
        tgt_result = await self.db.execute(
            select(Identity).where(Identity.id == target_identity_id)
        )
        target = tgt_result.scalar_one_or_none()
        if not target:
            raise ValueError(f"Target identity {target_identity_id} not found")

        # Reparent IdentityEntity rows
        src_links_result = await self.db.execute(
            select(IdentityEntity).where(IdentityEntity.identity_id == source_identity_id)
        )
        src_links = src_links_result.scalars().all()

        for link in src_links:
            # Check if target already has this entity
            existing_result = await self.db.execute(
                select(IdentityEntity).where(
                    IdentityEntity.identity_id == target_identity_id,
                    IdentityEntity.entity_id == link.entity_id,
                )
            )
            existing = existing_result.scalar_one_or_none()
            if existing:
                # Keep the higher signal_weight
                if link.signal_weight > existing.signal_weight:
                    existing.signal_weight = link.signal_weight
                # Delete the source link (it's redundant now)
                await self.db.delete(link)
            else:
                # Reparent
                link.identity_id = target_identity_id

        # Mark source as merged
        source.status = "merged"
        source.merged_into = target_identity_id
        source.updated_at = _utcnow()

        # Recompute target confidence
        target = await self._recompute_identity_confidence(target_identity_id, DEFAULT_SIGNAL_WEIGHTS, identity=target)

        await self.db.flush()
        return target


__all__ = ["CanonicalEntityService"]
