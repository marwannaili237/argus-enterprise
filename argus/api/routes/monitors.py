from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from database import get_db
from models import User, Monitor
from api.deps import get_current_user
from datetime import datetime, timezone, timedelta

router = APIRouter(prefix="/monitors", tags=["monitors"])

SCHEDULES = {
    "hourly":  1,
    "daily":   24,
    "weekly":  168,
}


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CreateMonitorRequest(BaseModel):
    target: str
    schedule: str = "daily"    # hourly | daily | weekly
    telegram_chat_id: int
    webhook_url: str | None = None


class UpdateMonitorRequest(BaseModel):
    active: bool | None = None
    schedule: str | None = None
    webhook_url: str | None = None


@router.post("")
async def create_monitor(
    req: CreateMonitorRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if req.schedule not in SCHEDULES:
        raise HTTPException(status_code=400, detail=f"Invalid schedule. Use: {', '.join(SCHEDULES)}")

    from plugins.runner import classify_target
    target_type = classify_target(req.target.strip())

    # Check for duplicate
    existing = await db.execute(
        select(Monitor).where(
            Monitor.user_id == current_user.id,
            Monitor.target == req.target.strip(),
            Monitor.active == True,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Already monitoring this target")

    interval = SCHEDULES[req.schedule]
    monitor = Monitor(
        user_id=current_user.id,
        target=req.target.strip(),
        target_type=target_type,
        telegram_chat_id=req.telegram_chat_id,
        schedule=req.schedule,
        interval_hours=interval,
        next_check=_utcnow() + timedelta(hours=interval),
        active=True,
        webhook_url=req.webhook_url,
    )
    db.add(monitor)
    await db.commit()
    await db.refresh(monitor)

    return {
        "id": monitor.id,
        "target": monitor.target,
        "target_type": monitor.target_type,
        "schedule": monitor.schedule,
        "interval_hours": monitor.interval_hours,
        "next_check": monitor.next_check.isoformat() if monitor.next_check else None,
        "active": monitor.active,
        "created_at": monitor.created_at.isoformat(),
    }


@router.get("")
async def list_monitors(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Monitor)
        .where(Monitor.user_id == current_user.id)
        .order_by(desc(Monitor.created_at))
        .limit(20)
    )
    monitors = result.scalars().all()
    return [
        {
            "id": m.id,
            "target": m.target,
            "target_type": m.target_type,
            "schedule": m.schedule,
            "active": m.active,
            "last_checked": m.last_checked.isoformat() if m.last_checked else None,
            "next_check": m.next_check.isoformat() if m.next_check else None,
            "change_count": m.change_count,
            "last_investigation_id": m.last_investigation_id,
            "created_at": m.created_at.isoformat(),
        }
        for m in monitors
    ]


@router.patch("/{monitor_id}")
async def update_monitor(
    monitor_id: int,
    req: UpdateMonitorRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.user_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    if req.active is not None:
        monitor.active = req.active
    if req.schedule and req.schedule in SCHEDULES:
        monitor.schedule = req.schedule
        monitor.interval_hours = SCHEDULES[req.schedule]
        monitor.next_check = _utcnow() + timedelta(hours=monitor.interval_hours)
    if req.webhook_url is not None:
        monitor.webhook_url = req.webhook_url

    await db.commit()
    return {"id": monitor.id, "active": monitor.active, "schedule": monitor.schedule, "webhook_url": monitor.webhook_url}


@router.delete("/{monitor_id}")
async def delete_monitor(
    monitor_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.user_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    await db.delete(monitor)
    await db.commit()
    return {"deleted": True}


@router.post("/{monitor_id}/check-now")
async def trigger_check(
    monitor_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Force an immediate check for a specific monitor."""
    from datetime import datetime, timezone
    result = await db.execute(
        select(Monitor).where(Monitor.id == monitor_id, Monitor.user_id == current_user.id)
    )
    monitor = result.scalar_one_or_none()
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    monitor.next_check = _utcnow()  # trigger on next scheduler tick
    await db.commit()
    return {"triggered": True, "monitor_id": monitor_id}
