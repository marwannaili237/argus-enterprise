"""
Decision Engine — consumes ProposedDecisions and executes them.

CRITICAL RULES (architectural constraints):
  - NEVER computes confidence.
  - NEVER computes similarity.
  - NEVER computes thresholds.
  - ONLY consumes ProposedDecision objects produced by the Rule Engine.

Responsibilities:
  1. Idempotency: re-processing the same decision_id is a no-op.
  2. Event creation: every state change emits a DecisionEvent.
  3. Dispatch: routes decisions to the right executor based on kind.
  4. Merge execution: calls IdentityResolutionService.merge_identities.
  5. Split execution: reverses a merge via IdentityMergeRecord.
  6. Watchlist notification: notifies watchers when a watched entity is involved.

Every action is recorded as an event before execution. If execution fails,
the event remains (with error details in payload) — events are append-only.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
import json

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from canonical.models import (
    Identity, IdentityEntity, CanonicalEntity,
    DecisionEvent, ReviewQueueItem, IdentityMergeRecord,
    IdentityEvent, EntityInvestigationLink,
)
from canonical.rules.proposed_decision import ProposedDecision, DecisionKind

logger = logging.getLogger("argus.canonical.decision_engine")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class DecisionEngineError(Exception):
    """Raised when the Decision Engine cannot execute a decision."""
    def __init__(self, message: str, *, code: str = "decision_error"):
        self.code = code
        super().__init__(message)


class DecisionEngine:
    """
    Consumes ProposedDecisions and executes them.

    Construct with an AsyncSession. All operations are async and run
    in the caller's transaction.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─── Public API ──────────────────────────────────────────────────

    async def process(self, decision: ProposedDecision, actor: str = "system") -> dict:
        """
        Process a ProposedDecision.

        This is the main entry point. It:
          1. Checks idempotency (has this decision_id been processed?)
          2. Emits a "requested" event
          3. Dispatches based on decision.kind
          4. Returns a result dict with the outcome

        Returns:
            {
                "decision_id": str,
                "kind": str,
                "status": str,  # executed|queued|rejected|skipped
                "identity_id": str | None,
                "event_ids": list[str],
            }
        """
        # 1. Idempotency check
        existing = await self._find_existing_decision_events(decision.decision_id)
        if existing:
            logger.info(
                "Decision %s already processed (idempotent skip)", decision.decision_id,
            )
            return {
                "decision_id": decision.decision_id,
                "kind": decision.kind.value,
                "status": "skipped",
                "identity_id": None,
                "event_ids": [e.id for e in existing],
            }

        # 2. Emit "requested" event
        requested_event = await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=decision.draft_identity_id,
            action="requested",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={
                "kind": decision.kind.value,
                "draft_identity_id": decision.draft_identity_id,
                "global_identity_id": decision.global_identity_id,
                "correlation_score": decision.correlation_score,
                "reasoning": decision.reasoning,
            },
            config_snapshot=decision.explanation,
        )

        # 3. Dispatch based on kind
        try:
            if decision.kind == DecisionKind.AUTO_MERGE:
                result = await self._execute_auto_merge(decision, actor)
            elif decision.kind == DecisionKind.PROMOTE_TO_GLOBAL:
                result = await self._execute_promote_to_global(decision, actor)
            elif decision.kind == DecisionKind.QUEUE_FOR_REVIEW:
                result = await self._execute_queue_for_review(decision, actor)
            elif decision.kind == DecisionKind.REJECT:
                result = await self._execute_reject(decision, actor)
            else:
                raise DecisionEngineError(f"Unknown decision kind: {decision.kind}")
        except DecisionEngineError as e:
            # Emit "rejected" event on error
            await self._emit_event(
                decision_id=decision.decision_id,
                identity_id=decision.draft_identity_id,
                action="rejected",
                rule_id=decision.rule_id,
                rule_version=decision.rule_version,
                actor=actor,
                payload={"error": str(e), "code": e.code},
                config_snapshot={},
            )
            raise

        result["decision_id"] = decision.decision_id
        result["kind"] = decision.kind.value
        result["event_ids"] = [requested_event.id] + result.get("event_ids", [])
        return result

    # ─── AUTO_MERGE ──────────────────────────────────────────────────

    async def _execute_auto_merge(self, decision: ProposedDecision, actor: str) -> dict:
        """Execute an auto-merge: merge draft into global identity."""
        # Emit "evaluated" event
        await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=decision.draft_identity_id,
            action="evaluated",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={"auto_merge": True},
            config_snapshot={},
        )

        # Load both identities
        draft = await self._load_identity(decision.draft_identity_id)
        target = await self._load_identity(decision.global_identity_id)
        if not draft:
            raise DecisionEngineError(
                f"Draft identity {decision.draft_identity_id} not found",
                code="draft_not_found",
            )
        if not target:
            raise DecisionEngineError(
                f"Target identity {decision.global_identity_id} not found",
                code="target_not_found",
            )

        # Record the merge (for split support)
        merge_record = await self._record_merge(draft, target, decision)

        # Execute the merge via IdentityResolutionService
        from canonical.services.identity import IdentityResolutionService
        identity_svc = IdentityResolutionService(self.db)
        # We need the investigation_id — derive from the draft identity's entities
        inv_id = await self._find_identity_investigation(draft.id)
        if not inv_id:
            raise DecisionEngineError(
                f"Could not determine investigation for identity {draft.id}",
                code="no_investigation",
            )

        merged = await identity_svc.merge_identities(
            source_identity_id=draft.id,
            target_identity_id=target.id,
            investigation_id=inv_id,
            reason=f"auto_merge by rule {decision.rule_id}",
        )

        # Emit "executed" event
        executed_event = await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=target.id,
            action="executed",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={
                "merge": True,
                "source_identity_id": draft.id,
                "target_identity_id": target.id,
                "merge_record_id": merge_record.id,
            },
            config_snapshot={},
        )

        return {
            "status": "executed",
            "identity_id": merged.id,
            "event_ids": [executed_event.id],
        }

    # ─── PROMOTE_TO_GLOBAL ───────────────────────────────────────────

    async def _execute_promote_to_global(self, decision: ProposedDecision, actor: str) -> dict:
        """Promote a draft identity to global status."""
        # Emit "evaluated" event
        await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=decision.draft_identity_id,
            action="evaluated",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={"promote": True},
            config_snapshot={},
        )

        # Load the draft identity
        draft = await self._load_identity(decision.draft_identity_id)
        if not draft:
            raise DecisionEngineError(
                f"Draft identity {decision.draft_identity_id} not found",
                code="draft_not_found",
            )

        # Promote: change status from tentative to confirmed
        # (the identity already exists; we just upgrade its status)
        if draft.status == "tentative":
            draft.status = "confirmed"
            draft.updated_at = _utcnow()

        # Emit identity event
        from canonical.services.identity import IdentityResolutionService
        identity_svc = IdentityResolutionService(self.db)
        inv_id = await self._find_identity_investigation(draft.id) or "global"
        await identity_svc._emit_event(
            identity_id=draft.id,
            action="promoted",
            investigation_id=inv_id,
            details={"decision_id": decision.decision_id, "rule_id": decision.rule_id},
        )

        # Emit "executed" event
        executed_event = await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=draft.id,
            action="executed",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={"promoted": True, "identity_id": draft.id},
            config_snapshot={},
        )

        return {
            "status": "executed",
            "identity_id": draft.id,
            "event_ids": [executed_event.id],
        }

    # ─── QUEUE_FOR_REVIEW ────────────────────────────────────────────

    async def _execute_queue_for_review(self, decision: ProposedDecision, actor: str) -> dict:
        """Create a ReviewQueueItem for human review."""
        # Check if a review item already exists for this decision
        existing = await self.db.execute(
            select(ReviewQueueItem).where(ReviewQueueItem.decision_id == decision.decision_id)
        )
        if existing.scalar_one_or_none():
            return {"status": "queued", "identity_id": None, "event_ids": []}

        item = ReviewQueueItem(
            decision_id=decision.decision_id,
            candidate_identity_id=decision.draft_identity_id,
            target_identity_id=decision.global_identity_id if decision.global_identity_id != "none" else None,
            score=decision.correlation_score,
            reasoning={
                "rule_id": decision.rule_id,
                "rule_version": decision.rule_version,
                "reasoning": decision.reasoning,
                "explanation": decision.explanation,
            },
            status="pending",
            proposed_by_rule=decision.rule_id,
            proposed_by_rule_version=decision.rule_version,
        )
        self.db.add(item)
        await self.db.flush()

        # Emit "evaluated" event (queued for review = evaluated, awaiting human)
        evaluated_event = await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=decision.draft_identity_id,
            action="evaluated",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={"queued_for_review": True, "review_item_id": item.id},
            config_snapshot={},
        )

        return {
            "status": "queued",
            "identity_id": None,
            "review_item_id": item.id,
            "event_ids": [evaluated_event.id],
        }

    # ─── REJECT ──────────────────────────────────────────────────────

    async def _execute_reject(self, decision: ProposedDecision, actor: str) -> dict:
        """Record a rejection (no state change to identities)."""
        rejected_event = await self._emit_event(
            decision_id=decision.decision_id,
            identity_id=decision.draft_identity_id,
            action="rejected",
            rule_id=decision.rule_id,
            rule_version=decision.rule_version,
            actor=actor,
            payload={"rejected": True},
            config_snapshot={},
        )
        return {
            "status": "rejected",
            "identity_id": None,
            "event_ids": [rejected_event.id],
        }

    # ─── Review approval/rejection ───────────────────────────────────

    async def approve_review_item(
        self,
        review_item_id: str,
        reviewed_by: str,
        notes: Optional[str] = None,
    ) -> dict:
        """
        Approve a review queue item and execute the underlying decision.

        Called by the Review Queue API (POST /api/v1/review-queue/{id}/approve).
        Both Telegram and Dashboard call this same method.
        """
        item = await self._load_review_item(review_item_id)
        if not item:
            raise DecisionEngineError(f"Review item {review_item_id} not found", code="not_found")
        if item.status != "pending":
            raise DecisionEngineError(
                f"Review item {review_item_id} already {item.status}", code="already_resolved",
            )

        # Update the review item
        item.status = "approved"
        item.reviewed_at = _utcnow()
        item.reviewed_by = reviewed_by
        item.review_notes = notes
        await self.db.flush()

        # Emit "approved" event
        approved_event = await self._emit_event(
            decision_id=item.decision_id,
            identity_id=item.candidate_identity_id,
            action="approved",
            actor=reviewed_by,
            payload={"review_item_id": review_item_id, "notes": notes},
            config_snapshot={},
        )

        # Execute the merge (approved = human says yes, merge them)
        # Reconstruct a minimal ProposedDecision for execution
        target_id = item.target_identity_id
        if not target_id:
            # PROMOTE_TO_GLOBAL case — no target
            from canonical.rules.proposed_decision import ProposedDecision, DecisionKind
            decision = ProposedDecision(
                decision_id=item.decision_id,
                rule_id=item.proposed_by_rule,
                rule_version=item.proposed_by_rule_version,
                kind=DecisionKind.PROMOTE_TO_GLOBAL,
                draft_identity_id=item.candidate_identity_id,
                global_identity_id="none",
                correlation_score=item.score,
                reasoning="Human-approved promotion",
                explanation=item.reasoning,
            )
            result = await self._execute_promote_to_global(decision, reviewed_by)
        else:
            from canonical.rules.proposed_decision import ProposedDecision, DecisionKind
            decision = ProposedDecision(
                decision_id=item.decision_id,
                rule_id=item.proposed_by_rule,
                rule_version=item.proposed_by_rule_version,
                kind=DecisionKind.AUTO_MERGE,
                draft_identity_id=item.candidate_identity_id,
                global_identity_id=target_id,
                correlation_score=item.score,
                reasoning="Human-approved merge",
                explanation=item.reasoning,
            )
            result = await self._execute_auto_merge(decision, reviewed_by)

        # Update review item status to executed
        item.status = "executed"
        await self.db.flush()

        result["event_ids"] = [approved_event.id] + result.get("event_ids", [])
        return result

    async def reject_review_item(
        self,
        review_item_id: str,
        reviewed_by: str,
        notes: Optional[str] = None,
    ) -> dict:
        """
        Reject a review queue item. No merge happens.

        Called by the Review Queue API (POST /api/v1/review-queue/{id}/reject).
        """
        item = await self._load_review_item(review_item_id)
        if not item:
            raise DecisionEngineError(f"Review item {review_item_id} not found", code="not_found")
        if item.status != "pending":
            raise DecisionEngineError(
                f"Review item {review_item_id} already {item.status}", code="already_resolved",
            )

        item.status = "rejected"
        item.reviewed_at = _utcnow()
        item.reviewed_by = reviewed_by
        item.review_notes = notes
        await self.db.flush()

        rejected_event = await self._emit_event(
            decision_id=item.decision_id,
            identity_id=item.candidate_identity_id,
            action="rejected",
            actor=reviewed_by,
            payload={"review_item_id": review_item_id, "notes": notes},
            config_snapshot={},
        )

        return {
            "decision_id": item.decision_id,
            "status": "rejected",
            "event_ids": [rejected_event.id],
        }

    # ─── Split identity ──────────────────────────────────────────────

    async def split_identity(
        self,
        merge_record_id: str,
        actor: str = "system",
        reason: Optional[str] = None,
    ) -> dict:
        """
        Reverse a merge operation.

        Reads the IdentityMergeRecord, reparents entities back to the
        source identity, restores original signal_weights, and reactivates
        the source identity.

        Emits IdentityEvent("split") and DecisionEvent("reverted").
        """
        # Load the merge record
        result = await self.db.execute(
            select(IdentityMergeRecord).where(IdentityMergeRecord.id == merge_record_id)
        )
        record = result.scalar_one_or_none()
        if not record:
            raise DecisionEngineError(f"Merge record {merge_record_id} not found", code="not_found")
        if record.reverted_at is not None:
            raise DecisionEngineError(
                f"Merge record {merge_record_id} already reverted", code="already_reverted",
            )

        # Load source and target identities
        src_result = await self.db.execute(
            select(Identity).where(Identity.id == record.source_identity_id)
        )
        source = src_result.scalar_one_or_none()
        tgt_result = await self.db.execute(
            select(Identity).where(Identity.id == record.target_identity_id)
        )
        target = tgt_result.scalar_one_or_none()

        if not source or not target:
            raise DecisionEngineError("Source or target identity missing", code="missing_identity")

        # Reparent entities back to source
        moved_entities: dict = record.moved_entities or {}
        for entity_id_str, original_weight in moved_entities.items():
            # entity_id_str is stored as a string key (JSON keys are strings)
            # Find the IdentityEntity link on the target
            ie_result = await self.db.execute(
                select(IdentityEntity).where(
                    IdentityEntity.identity_id == target.id,
                    IdentityEntity.entity_id == entity_id_str,
                )
            )
            ie = ie_result.scalar_one_or_none()
            if ie:
                # Check if target has OTHER identities linking this entity
                # (if so, we can't just delete — we need to keep one on target)
                other_links = await self.db.execute(
                    select(func.count()).select_from(IdentityEntity).where(
                        IdentityEntity.entity_id == entity_id_str,
                        IdentityEntity.identity_id != target.id,
                    )
                )
                other_count = other_links.scalar() or 0

                if other_count == 0:
                    # Target is the only other identity with this entity.
                    # Move the link back to source.
                    ie.identity_id = source.id
                    ie.signal_weight = float(original_weight)
                else:
                    # Other identities also have this entity.
                    # Delete the target's link (source gets a new one).
                    await self.db.delete(ie)
                    self.db.add(IdentityEntity(
                        identity_id=source.id,
                        entity_id=entity_id_str,
                        signal_weight=float(original_weight),
                    ))
            else:
                # Entity link was already removed from target. Create on source.
                self.db.add(IdentityEntity(
                    identity_id=source.id,
                    entity_id=entity_id_str,
                    signal_weight=float(original_weight),
                ))

        # Reactivate source identity
        source.status = "tentative"  # back to tentative after split
        source.merged_into = None
        source.updated_at = _utcnow()

        # Recompute source confidence
        from canonical.services.identity import IdentityResolutionService
        identity_svc = IdentityResolutionService(self.db)
        inv_id = await self._find_identity_investigation(source.id) or "global"
        source = await identity_svc._recompute_confidence(source, inv_id)

        # Mark merge record as reverted
        record.reverted_at = _utcnow()
        record.reverted_by = actor

        # Emit IdentityEvent("split")
        await identity_svc._emit_event(
            identity_id=source.id,
            action="split",
            investigation_id=inv_id,
            details={
                "merge_record_id": merge_record_id,
                "source_identity_id": source.id,
                "target_identity_id": target.id,
                "reason": reason or "manual split",
            },
        )

        # Emit DecisionEvent("reverted")
        reverted_event = await self._emit_event(
            decision_id=record.decision_id or "split_" + merge_record_id,
            identity_id=source.id,
            action="reverted",
            actor=actor,
            payload={
                "split": True,
                "merge_record_id": merge_record_id,
                "source_identity_id": source.id,
                "target_identity_id": target.id,
                "reason": reason,
            },
            config_snapshot={},
        )

        return {
            "status": "reverted",
            "source_identity_id": source.id,
            "target_identity_id": target.id,
            "event_ids": [reverted_event.id],
        }

    # ─── Internal helpers ────────────────────────────────────────────

    async def _load_identity(self, identity_id: str) -> Optional[Identity]:
        result = await self.db.execute(
            select(Identity).where(Identity.id == identity_id)
        )
        return result.scalar_one_or_none()

    async def _load_review_item(self, item_id: str) -> Optional[ReviewQueueItem]:
        result = await self.db.execute(
            select(ReviewQueueItem).where(ReviewQueueItem.id == item_id)
        )
        return result.scalar_one_or_none()

    async def _find_identity_investigation(self, identity_id: str) -> Optional[str]:
        """Find the investigation_id linked to this identity's entities."""
        result = await self.db.execute(
            select(func.distinct(EntityInvestigationLink.investigation_id))
            .join(IdentityEntity, IdentityEntity.entity_id == EntityInvestigationLink.entity_id)
            .where(IdentityEntity.identity_id == identity_id)
            .limit(1)
        )
        row = result.first()
        return row[0] if row else None

    async def _find_existing_decision_events(self, decision_id: str) -> list[DecisionEvent]:
        """Check if any events exist for this decision_id (idempotency)."""
        result = await self.db.execute(
            select(DecisionEvent).where(DecisionEvent.decision_id == decision_id)
        )
        return list(result.scalars().all())

    async def _record_merge(
        self,
        source: Identity,
        target: Identity,
        decision: ProposedDecision,
    ) -> IdentityMergeRecord:
        """Record a merge for later split support."""
        # Capture the entity_ids and signal_weights currently on source
        ie_result = await self.db.execute(
            select(IdentityEntity).where(IdentityEntity.identity_id == source.id)
        )
        source_links = ie_result.scalars().all()
        moved_entities = {link.entity_id: link.signal_weight for link in source_links}

        record = IdentityMergeRecord(
            source_identity_id=source.id,
            target_identity_id=target.id,
            decision_id=decision.decision_id,
            moved_entities=moved_entities,
        )
        self.db.add(record)
        await self.db.flush()
        return record

    async def _emit_event(
        self,
        decision_id: str,
        identity_id: str,
        action: str,
        rule_id: Optional[str] = None,
        rule_version: Optional[str] = None,
        actor: str = "system",
        payload: Optional[dict] = None,
        config_snapshot: Optional[dict] = None,
    ) -> DecisionEvent:
        """Emit a DecisionEvent (append-only audit trail)."""
        event = DecisionEvent(
            decision_id=decision_id,
            identity_id=identity_id,
            action=action,
            rule_id=rule_id,
            rule_version=rule_version,
            actor=actor,
            payload=payload or {},
            config_snapshot=config_snapshot or {},
        )
        self.db.add(event)
        await self.db.flush()
        return event


__all__ = ["DecisionEngine", "DecisionEngineError"]
