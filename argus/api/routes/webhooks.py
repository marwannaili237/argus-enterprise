"""Webhook management routes with SSRF protection."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, field_validator
from database import get_db
from models import User, Webhook
from api.deps import get_current_user
from intel.ssrf import is_safe_url

logger = logging.getLogger("argus.webhooks")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

VALID_EVENTS = {"investigation_complete", "monitor_alert"}


class CreateWebhookRequest(BaseModel):
    url: str
    events: list[str]
    
    @field_validator("url", mode="after")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate webhook URL for SSRF and other security issues."""
        if not v:
            raise ValueError("Webhook URL cannot be empty")
        
        v = v.strip()
        
        # Check URL safety (prevents SSRF attacks)
        safe, reason = is_safe_url(v)
        if not safe:
            raise ValueError(f"Webhook URL is not allowed: {reason}")
        
        # Ensure HTTPS in production (allow HTTP for localhost only)
        if not v.startswith("https://"):
            if not v.startswith("http://localhost"):
                raise ValueError("Webhook URL must use HTTPS (HTTP is only allowed for localhost)")
        
        return v


@router.post("")
async def create_webhook(
    req: CreateWebhookRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new webhook for investigation and monitor events."""
    # Validate events
    for ev in req.events:
        if ev not in VALID_EVENTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event '{ev}'. Allowed: {', '.join(sorted(VALID_EVENTS))}",
            )
    
    if not req.events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one event must be specified",
        )

    wh = Webhook(
        user_id=current_user.id,
        url=req.url,
        events=req.events,
        active=True,
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)
    
    logger.info(f"Webhook created for user {current_user.id}: {wh.id}")
    
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
    """List all webhooks for the current user."""
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


@router.patch("/{webhook_id}")
async def update_webhook(
    webhook_id: int,
    req: CreateWebhookRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a webhook's URL and events."""
    # Validate events
    for ev in req.events:
        if ev not in VALID_EVENTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event '{ev}'. Allowed: {', '.join(sorted(VALID_EVENTS))}",
            )
    
    result = await db.execute(
        select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.user_id == current_user.id,
        )
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    wh.url = req.url
    wh.events = req.events
    await db.commit()
    
    logger.info(f"Webhook updated for user {current_user.id}: {wh.id}")
    
    return {
        "id": wh.id,
        "url": wh.url,
        "events": wh.events,
        "active": wh.active,
        "created_at": wh.created_at.isoformat(),
    }


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook."""
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
    
    logger.info(f"Webhook deleted for user {current_user.id}: {webhook_id}")
    
    return {"deleted": True}
