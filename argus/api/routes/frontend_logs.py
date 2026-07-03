from fastapi import APIRouter, Body, Request
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import FrontendLog
from sqlalchemy import insert
from typing import Any

router = APIRouter(prefix="/frontend-logs", tags=["frontend-logs"])

@router.post("")
async def post_log(
    request: Request,
    payload: dict = Body(...),
    db: AsyncSession = Depends(get_db)
):
    level = payload.get("level", "info")
    message = payload.get("message", "")
    context = payload.get("context", {})
    
    # Optional: try to get user from token if present
    user_id = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        # This is a simplified way to get user_id without full auth middleware
        # In production, use proper dependency
        pass

    log = FrontendLog(
        level=level,
        message=message,
        context=context,
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()
    return {"status": "ok"}

# Import Depends here to avoid circular imports if necessary
from fastapi import Depends

@router.get("/view", response_model=None)
async def view_logs(
    current_user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, le=1000),
):
    """View recent frontend logs (admin only)."""
    from sqlalchemy import desc
    result = await db.execute(
        select(FrontendLog).order_by(desc(FrontendLog.created_at)).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "level": log.level,
            "message": log.message,
            "context": log.context,
            "ip": log.ip_address,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
