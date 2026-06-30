"""Webhook management routes."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from database import get_db
from models import User, Webhook
from api.deps import get_current_user

logger = logging.getLogger("argus.webhooks")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

VALID_EVENTS = {"investigation_complete", "monitor_alert"}


class CreateWebhookRequest(BaseModel):
    url: str
    events: list[str]


@router.post("")
async def create_webhook(
    req: CreateWebhookRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    for ev in req.events:
        if ev not in VALID_EVENTS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event '{ev}'. Allowed: {', '.join(sorted(VALID_EVENTS))}",
            )

    wh = Webhook(
        user_id=current_user.id,
        url=req.url.strip(),
        events=req.events,
        active=True,
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)
    return {
        "id": wh.id,
        "url": wh.url,
        "events": wh.events,
        "active": wh.active,
        "created_at": wh.created_at.isoformat(),
    }


@router.get("")
async def list_webhooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Webhook)
        .where(Webhook.user_id == current_user.id)
        .order_by(desc(Webhook.created_at))
    )
    webhooks = result.scalars().all()
    return [
        {
            "id": wh.id,
            "url": wh.url,
            "events": wh.events,
            "active": wh.active,
            "created_at": wh.created_at.isoformat(),
        }
        for wh in webhooks
    ]


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.user_id == current_user.id,
        )
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(wh)
    await db.commit()
    return {"deleted": True}
