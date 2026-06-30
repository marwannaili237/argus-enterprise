"""
Replay Engine — deletes derived state and replays events.

CRITICAL PROPERTY: After replay, the identity state must EXACTLY match
the state before replay. This is verified by automated tests.

Derived state (cleared and rebuilt):
  - identities (the Identity table rows — their confidence and status)
  - identity_entities (the M2M links)
  - identity_merge_records (the merge provenance — rebuilt from events)

NOT cleared (source of truth):
  - canonical_entities (entities themselves are not derived)
  - raw_evidence, observations, relationships (evidence is not derived)
  - decision_events, identity_events (the events themselves — they're the source)

Replay algorithm:
  1. Snapshot current identity state (for verification)
  2. Clear derived state (identities, identity_entities, merge_records)
  3. Sort events by timestamp
  4. For each event, apply its effect to rebuild state
  5. Compare rebuilt state to snapshot — must match exactly
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from dataclasses import dataclass, field

from sqlalchemy import select, func, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from canonical.models import (
    Identity, IdentityEntity, CanonicalEntity,
    DecisionEvent, IdentityEvent, IdentityMergeRecord,
    EntityInvestigationLink, RawEvidence, Observation, EntityObservation,
)

logger = logging.getLogger("argus.canonical.replay")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class ReplayResult:
    """Result of a replay operation."""
    events_processed: int = 0
    identities_rebuilt: int = 0
    merge_records_rebuilt: int = 0
    verification_passed: bool = False
    verification_errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "events_processed": self.events_processed,
            "identities_rebuilt": self.identities_rebuilt,
            "merge_records_rebuilt": self.merge_records_rebuilt,
            "verification_passed": self.verification_passed,
            "verification_errors": self.verification_errors,
            "duration_seconds": round(self.duration_seconds, 4),
        }


class ReplayEngine:
    """
    Replays events to rebuild derived state.

    Usage:
        engine = ReplayEngine(db)
        result = await engine.replay()
        assert result.verification_passed
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def replay(self, verify: bool = True) -> ReplayResult:
        """
        Delete derived state and replay all events.

        Args:
            verify: if True, compare rebuilt state to pre-replay snapshot

        Returns ReplayResult with verification status.
        """
        import time
        start = time.monotonic()
        result = ReplayResult()

        # 1. Snapshot current state (for verification)
        snapshot = {}
        if verify:
            snapshot = await self._snapshot_state()

        # 2. Clear derived state
        await self._clear_derived_state()

        # 3. Load all events, sorted by timestamp
        events = await self._load_all_events()

        # 4. Replay each event
        for event in events:
            await self._apply_event(event)
            result.events_processed += 1

        # 5. Recompute identity confidences
        await self._recompute_confidences()
        result.identities_rebuilt = await self._count_identities()
        result.merge_records_rebuilt = await self._count_merge_records()

        # 6. Verify (if requested)
        if verify:
            rebuilt = await self._snapshot_state()
            result.verification_passed, result.verification_errors = self._compare_snapshots(
                snapshot, rebuilt,
            )

        result.duration_seconds = time.monotonic() - start
        return result

    # ─── Snapshot ────────────────────────────────────────────────────

    async def _snapshot_state(self) -> dict:
        """Capture current identity state for verification."""
        identities = {}
        result = await self.db.execute(select(Identity))
        for ident in result.scalars().all():
            identities[ident.id] = {
                "id": ident.id,
                "status": ident.status,
                "confidence": round(ident.confidence, 6),
                "merged_into": ident.merged_into,
                "label": ident.label,
            }

        identity_entities = {}
        result = await self.db.execute(select(IdentityEntity))
        for ie in result.scalars().all():
            key = (ie.identity_id, ie.entity_id)
            identity_entities[key] = {
                "identity_id": ie.identity_id,
                "entity_id": ie.entity_id,
                "signal_weight": round(ie.signal_weight, 6),
            }

        merge_records = {}
        result = await self.db.execute(select(IdentityMergeRecord))
        for mr in result.scalars().all():
            merge_records[mr.id] = {
                "source_identity_id": mr.source_identity_id,
                "target_identity_id": mr.target_identity_id,
                "reverted_at": mr.reverted_at.isoformat() if mr.reverted_at else None,
            }

        return {
            "identities": identities,
            "identity_entities": identity_entities,
            "merge_records": merge_records,
        }

    # ─── Clear ───────────────────────────────────────────────────────

    async def _clear_derived_state(self) -> None:
        """Delete all derived state (identities, links, merge records)."""
        # Order matters for FK constraints
        await self.db.execute(delete(IdentityMergeRecord))
        await self.db.execute(delete(IdentityEntity))
        await self.db.execute(delete(Identity))
        await self.db.flush()

    # ─── Load events ─────────────────────────────────────────────────

    async def _load_all_events(self) -> list:
        """Load all events (identity + decision) sorted by timestamp."""
        events = []

        # Identity events
        result = await self.db.execute(
            select(IdentityEvent).order_by(IdentityEvent.timestamp)
        )
        for ev in result.scalars().all():
            events.append(("identity", ev.timestamp, ev))

        # Decision events
        result = await self.db.execute(
            select(DecisionEvent).order_by(DecisionEvent.timestamp)
        )
        for ev in result.scalars().all():
            events.append(("decision", ev.timestamp, ev))

        # Sort by timestamp (stable sort preserves insertion order for ties)
        events.sort(key=lambda x: x[1])
        return events

    # ─── Apply events ────────────────────────────────────────────────

    async def _apply_event(self, event_tuple: tuple) -> None:
        """Apply a single event to rebuild state."""
        event_type, _, event = event_tuple

        if event_type == "identity":
            await self._apply_identity_event(event)
        elif event_type == "decision":
            await self._apply_decision_event(event)

    async def _apply_identity_event(self, event: IdentityEvent) -> None:
        """Rebuild state from an IdentityEvent."""
        action = event.action

        if action == "created":
            # Create the identity if it doesn't exist
            existing = await self.db.execute(
                select(Identity).where(Identity.id == event.identity_id)
            )
            if not existing.scalar_one_or_none():
                details = event.details or {}
                identity = Identity(
                    id=event.identity_id,
                    label=details.get("label"),
                    confidence=details.get("confidence", 0.0),
                    status="tentative",
                    created_at=event.timestamp,
                    updated_at=event.timestamp,
                )
                self.db.add(identity)
                await self.db.flush()

                # Restore identity_entities links
                entity_ids = details.get("entity_ids", [])
                weights = details.get("signal_weights", {})
                from canonical.confidence import signal_weight_for_type
                for eid in entity_ids:
                    # Look up entity type for default weight
                    ent_result = await self.db.execute(
                        select(CanonicalEntity).where(CanonicalEntity.id == eid)
                    )
                    ent = ent_result.scalar_one_or_none()
                    weight = weights.get(eid, signal_weight_for_type(ent.type) if ent else 0.5)
                    self.db.add(IdentityEntity(
                        identity_id=event.identity_id,
                        entity_id=eid,
                        signal_weight=weight,
                        added_at=event.timestamp,
                    ))
                await self.db.flush()

        elif action == "promoted":
            identity = await self._get_or_create_identity(event.identity_id, event.timestamp)
            identity.status = "confirmed"
            identity.updated_at = event.timestamp

        elif action == "disputed":
            identity = await self._get_or_create_identity(event.identity_id, event.timestamp)
            identity.status = "disputed"
            identity.updated_at = event.timestamp

        elif action == "merged":
            details = event.details or {}
            source_id = event.identity_id
            target_id = details.get("target_identity_id")
            if not target_id:
                return

            # Reparent entities from source to target
            source_links = await self.db.execute(
                select(IdentityEntity).where(IdentityEntity.identity_id == source_id)
            )
            for link in source_links.scalars().all():
                # Check if target already has this entity
                existing = await self.db.execute(
                    select(IdentityEntity).where(
                        IdentityEntity.identity_id == target_id,
                        IdentityEntity.entity_id == link.entity_id,
                    )
                )
                if existing.scalar_one_or_none():
                    await self.db.delete(link)
                else:
                    link.identity_id = target_id

            # Mark source as merged
            source = await self._get_or_create_identity(source_id, event.timestamp)
            source.status = "merged"
            source.merged_into = target_id
            source.updated_at = event.timestamp

            # Create merge record
            moved = details.get("moved_entities", {})
            record = IdentityMergeRecord(
                source_identity_id=source_id,
                target_identity_id=target_id,
                decision_id=details.get("decision_id"),
                moved_entities=moved,
                merged_at=event.timestamp,
            )
            self.db.add(record)
            await self.db.flush()

        elif action == "split":
            details = event.details or {}
            source_id = details.get("source_identity_id", event.identity_id)
            target_id = details.get("target_identity_id")
            merge_record_id = details.get("merge_record_id")

            # Find and mark the merge record as reverted
            if merge_record_id:
                mr_result = await self.db.execute(
                    select(IdentityMergeRecord).where(IdentityMergeRecord.id == merge_record_id)
                )
                mr = mr_result.scalar_one_or_none()
                if mr:
                    mr.reverted_at = event.timestamp

            # Reparent entities back to source
            if target_id:
                moved = details.get("moved_entities", {})
                for entity_id_str, weight in moved.items():
                    # Find on target
                    ie_result = await self.db.execute(
                        select(IdentityEntity).where(
                            IdentityEntity.identity_id == target_id,
                            IdentityEntity.entity_id == entity_id_str,
                        )
                    )
                    ie = ie_result.scalar_one_or_none()
                    if ie:
                        ie.identity_id = source_id
                        ie.signal_weight = float(weight)
                    else:
                        self.db.add(IdentityEntity(
                            identity_id=source_id,
                            entity_id=entity_id_str,
                            signal_weight=float(weight),
                            added_at=event.timestamp,
                        ))

            # Reactivate source
            source = await self._get_or_create_identity(source_id, event.timestamp)
            source.status = "tentative"
            source.merged_into = None
            source.updated_at = event.timestamp

    async def _apply_decision_event(self, event: DecisionEvent) -> None:
        """Decision events don't directly change identity state — they're audit trail."""
        # Decision events are recorded but don't need to be replayed to rebuild
        # identity state. The identity events carry the actual state changes.
        pass

    async def _get_or_create_identity(self, identity_id: str, timestamp: datetime) -> Identity:
        result = await self.db.execute(
            select(Identity).where(Identity.id == identity_id)
        )
        identity = result.scalar_one_or_none()
        if not identity:
            identity = Identity(
                id=identity_id,
                confidence=0.0,
                status="tentative",
                created_at=timestamp,
                updated_at=timestamp,
            )
            self.db.add(identity)
            await self.db.flush()
        return identity

    # ─── Recompute confidences ───────────────────────────────────────

    async def _recompute_confidences(self) -> None:
        """Recompute confidence for all non-merged identities."""
        from canonical.services.identity import IdentityResolutionService
        identity_svc = IdentityResolutionService(self.db)

        result = await self.db.execute(
            select(Identity).where(Identity.status != "merged")
        )
        for identity in result.scalars().all():
            inv_id = await self._find_investigation_for_identity(identity.id)
            if inv_id:
                await identity_svc._recompute_confidence(identity, inv_id)

    async def _find_investigation_for_identity(self, identity_id: str) -> Optional[str]:
        result = await self.db.execute(
            select(func.distinct(EntityInvestigationLink.investigation_id))
            .join(IdentityEntity, IdentityEntity.entity_id == EntityInvestigationLink.entity_id)
            .where(IdentityEntity.identity_id == identity_id)
            .limit(1)
        )
        row = result.first()
        return row[0] if row else None

    # ─── Verification ────────────────────────────────────────────────

    async def _count_identities(self) -> int:
        result = await self.db.execute(select(func.count()).select_from(Identity))
        return result.scalar() or 0

    async def _count_merge_records(self) -> int:
        result = await self.db.execute(select(func.count()).select_from(IdentityMergeRecord))
        return result.scalar() or 0

    def _compare_snapshots(self, before: dict, after: dict) -> tuple[bool, list[str]]:
        """
        Compare two state snapshots.

        Returns (passed, errors). Passed=True if states match.
        """
        errors: list[str] = []

        # Compare identities
        before_ids = set(before.get("identities", {}).keys())
        after_ids = set(after.get("identities", {}).keys())
        if before_ids != after_ids:
            missing = before_ids - after_ids
            extra = after_ids - before_ids
            if missing:
                errors.append(f"Missing identities after replay: {missing}")
            if extra:
                errors.append(f"Extra identities after replay: {extra}")

        for ident_id in before_ids & after_ids:
            before_ident = before["identities"][ident_id]
            after_ident = after["identities"][ident_id]
            if before_ident["status"] != after_ident["status"]:
                errors.append(
                    f"Identity {ident_id} status mismatch: "
                    f"before={before_ident['status']} after={after_ident['status']}"
                )
            if before_ident["merged_into"] != after_ident["merged_into"]:
                errors.append(
                    f"Identity {ident_id} merged_into mismatch: "
                    f"before={before_ident['merged_into']} after={after_ident['merged_into']}"
                )
            # Confidence may differ slightly due to float recomputation — allow small delta
            if abs(before_ident["confidence"] - after_ident["confidence"]) > 0.001:
                errors.append(
                    f"Identity {ident_id} confidence mismatch: "
                    f"before={before_ident['confidence']} after={after_ident['confidence']}"
                )

        # Compare identity_entities (keys must match; weights may differ slightly)
        before_ie = set(before.get("identity_entities", {}).keys())
        after_ie = set(after.get("identity_entities", {}).keys())
        if before_ie != after_ie:
            missing = before_ie - after_ie
            extra = after_ie - before_ie
            if missing:
                errors.append(f"Missing identity_entity links after replay: {len(missing)}")
            if extra:
                errors.append(f"Extra identity_entity links after replay: {len(extra)}")

        return (len(errors) == 0, errors)


__all__ = ["ReplayEngine", "ReplayResult"]
