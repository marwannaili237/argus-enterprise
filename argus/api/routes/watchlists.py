from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, delete
from pydantic import BaseModel
from database import get_db
from models import Watchlist, IOCEntry, Investigation, User
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends

router = APIRouter(prefix="/watchlists", tags=["watchlists"])


class WatchlistCreate(BaseModel):
    name: str
    description: str | None = None
    ioc_type: str = "any"  # ip|domain|url|email|hash|any


class IOCEntryCreate(BaseModel):
    value: str
    ioc_type: str
    notes: str | None = None
    tlp: str = "AMBER"
    confidence: int = 50


@router.post("", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def create_watchlist(req: WatchlistCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    wl = Watchlist(user_id=user.id, name=req.name, description=req.description, ioc_type=req.ioc_type)
    db.add(wl)
    await db.commit()
    await db.refresh(wl)
    return {"id": wl.id, "name": wl.name, "ioc_type": wl.ioc_type}


@router.get("")
async def list_watchlists(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Watchlist).where(Watchlist.user_id == user.id).order_by(desc(Watchlist.updated_at)))
    out = []
    for wl in result.scalars().all():
        cnt_result = await db.execute(select(IOCEntry).where(IOCEntry.watchlist_id == wl.id))
        out.append({
            "id": wl.id, "name": wl.name, "description": wl.description,
            "ioc_type": wl.ioc_type, "entry_count": len(cnt_result.scalars().all()),
            "created_at": wl.created_at.isoformat(),
        })
    return out


@router.get("/{wl_id}")
async def get_watchlist(wl_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Watchlist).where(Watchlist.id == wl_id, Watchlist.user_id == user.id))
    wl = result.scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "Watchlist not found")
    entries_result = await db.execute(select(IOCEntry).where(IOCEntry.watchlist_id == wl_id).order_by(desc(IOCEntry.last_seen)))
    entries = [
        {
            "id": e.id, "value": e.value, "ioc_type": e.ioc_type,
            "source": e.source, "notes": e.notes, "tlp": e.tlp, "confidence": e.confidence,
            "first_seen": e.first_seen.isoformat(), "last_seen": e.last_seen.isoformat(),
        }
        for e in entries_result.scalars().all()
    ]
    return {
        "id": wl.id, "name": wl.name, "description": wl.description,
        "ioc_type": wl.ioc_type, "entries": entries,
    }


@router.delete("/{wl_id}")
async def delete_watchlist(wl_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Watchlist).where(Watchlist.id == wl_id, Watchlist.user_id == user.id))
    wl = result.scalar_one_or_none()
    if not wl:
        raise HTTPException(404, "Watchlist not found")
    await db.delete(wl)
    await db.commit()
    return {"ok": True}


@router.post("/{wl_id}/entries", dependencies=[_Depends(rate_limit(limit=60, window=60))])
async def add_ioc(wl_id: int, req: IOCEntryCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    entry = IOCEntry(watchlist_id=wl_id, value=req.value, ioc_type=req.ioc_type,
                     source="manual", notes=req.notes, tlp=req.tlp, confidence=req.confidence)
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return {"id": entry.id, "value": entry.value, "ioc_type": entry.ioc_type}


@router.delete("/entries/{entry_id}")
async def delete_ioc(entry_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOCEntry).where(IOCEntry.id == entry_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(404, "Entry not found")
    await db.delete(entry)
    await db.commit()
    return {"ok": True}


# ─── IOC search across all investigations ────────────────────────────────


@router.get("/ioc/search")
async def search_ioc(q: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Search IOC entries across all investigations and watchlists."""
    result = await db.execute(
        select(IOCEntry).where(IOCEntry.value.ilike(f"%{q}%")).limit(50)
    )
    return [
        {
            "id": e.id, "value": e.value, "ioc_type": e.ioc_type,
            "source": e.source, "investigation_id": e.investigation_id,
            "watchlist_id": e.watchlist_id, "tlp": e.tlp, "confidence": e.confidence,
            "last_seen": e.last_seen.isoformat(),
        }
        for e in result.scalars().all()
    ]
