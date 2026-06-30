"""
Review Queue API — endpoints for listing, approving, and rejecting
pending identity decisions.

CRITICAL: Both Telegram bot and Dashboard MUST call these same endpoints.
No Telegram-specific logic exists. Business logic lives only in the
Decision Engine.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel, Field
from typing import Optional
import json

from database import get_db
from models import User
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends
from canonical.models import ReviewQueueItem, DecisionEvent
from canonical.decision_engine import DecisionEngine, DecisionEngineError

router = APIRouter(prefix="/review-queue", tags=["review-queue"])


class ReviewActionRequest(BaseModel):
    """Request body for approve/reject endpoints."""
    notes: Optional[str] = Field(None, max_length=2000)


class ReviewQueueItemResponse(BaseModel):
    """Response model for a review queue item."""
    id: str
    decision_id: str
    candidate_identity_id: str
    target_identity_id: Optional[str]
    score: float
    reasoning: dict
    status: str
    proposed_by_rule: str
    proposed_by_rule_version: str
    created_at: str
    reviewed_at: Optional[str]
    reviewed_by: Optional[str]
    review_notes: Optional[str]


@router.get("")
async def list_review_queue(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None, pattern=r"^(pending|approved|rejected|executed)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    List review queue items, optionally filtered by status.

    Returns paginated results with total count.
    """
    stmt = select(ReviewQueueItem)
    if status:
        stmt = stmt.where(ReviewQueueItem.status == status)

    # Total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginated results
    stmt = stmt.order_by(desc(ReviewQueueItem.created_at)).limit(limit).offset(offset)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return {
        "items": [
            {
                "id": item.id,
                "decision_id": item.decision_id,
                "candidate_identity_id": item.candidate_identity_id,
                "target_identity_id": item.target_identity_id,
                "score": item.score,
                "reasoning": item.reasoning,
                "status": item.status,
                "proposed_by_rule": item.proposed_by_rule,
                "proposed_by_rule_version": item.proposed_by_rule_version,
                "created_at": item.created_at.isoformat(),
                "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
                "reviewed_by": item.reviewed_by,
                "review_notes": item.review_notes,
            }
            for item in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{item_id}")
async def get_review_item(
    item_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single review queue item by ID."""
    result = await db.execute(
        select(ReviewQueueItem).where(ReviewQueueItem.id == item_id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(404, "Review item not found")

    return {
        "id": item.id,
        "decision_id": item.decision_id,
        "candidate_identity_id": item.candidate_identity_id,
        "target_identity_id": item.target_identity_id,
        "score": item.score,
        "reasoning": item.reasoning,
        "status": item.status,
        "proposed_by_rule": item.proposed_by_rule,
        "proposed_by_rule_version": item.proposed_by_rule_version,
        "created_at": item.created_at.isoformat(),
        "reviewed_at": item.reviewed_at.isoformat() if item.reviewed_at else None,
        "reviewed_by": item.reviewed_by,
        "review_notes": item.review_notes,
    }


@router.post("/{item_id}/approve", dependencies=[_Depends(rate_limit(limit=20, window=60))])
async def approve_review_item(
    item_id: str,
    req: ReviewActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a review queue item.

    This executes the underlying decision (merge or promote).
    Both Telegram and Dashboard call this same endpoint.
    """
    engine = DecisionEngine(db)
    try:
        result = await engine.approve_review_item(
            review_item_id=item_id,
            reviewed_by=f"user:{current_user.id}",
            notes=req.notes,
        )
        await db.commit()
        return result
    except DecisionEngineError as e:
        await db.rollback()
        raise HTTPException(400, str(e))
    except Exception as e:
        await db.rollback()
        raise HTTPException(500, f"Failed to approve: {e}")


@router.post("/{item_id}/reject", dependencies=[_Depends(rate_limit(limit=20, window=60))])
async def reject_review_item(
    item_id: str,
    req: ReviewActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Reject a review queue item.

    No merge happens. The decision is recorded as rejected.
    Both Telegram and Dashboard call this same endpoint.
    """
    engine = DecisionEngine(db)
    try:
        result = await engine.reject_review_item(
            review_item_id=item_id,
            reviewed_by=f"user:{current_user.id}",
            notes=req.notes,
        )
        await db.commit()
        return result
    except DecisionEngineError as e:
        await db.rollback()
        raise HTTPException(400, str(e))
    except Exception as e:
        await db.rollback()
        raise HTTPException(500, f"Failed to reject: {e}")


@router.get("/{item_id}/events")
async def get_decision_events(
    item_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all decision events for a review item (full audit trail)."""
    # Load the review item to get the decision_id
    result = await db.execute(
        select(ReviewQueueItem).where(ReviewQueueItem.id == item_id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(404, "Review item not found")

    # Load all events for this decision
    events_result = await db.execute(
        select(DecisionEvent)
        .where(DecisionEvent.decision_id == item.decision_id)
        .order_by(DecisionEvent.timestamp)
    )
    events = events_result.scalars().all()

    return {
        "decision_id": item.decision_id,
        "events": [
            {
                "id": e.id,
                "action": e.action,
                "rule_id": e.rule_id,
                "rule_version": e.rule_version,
                "actor": e.actor,
                "timestamp": e.timestamp.isoformat(),
                "payload": e.payload,
            }
            for e in events
        ],
    }
