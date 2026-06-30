"""
Global search endpoint — full-text search across investigations, evidence,
cases, watchlists, and IOCs.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func, text, String
from pydantic import BaseModel, Field
from database import get_db
from models import (
    Investigation, Evidence, Case, CaseNote, Watchlist, IOCEntry,
    EnrichedEntity, User, InvestigationNote,
)
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends

router = APIRouter(prefix="/search", tags=["search"])


class SearchResponse(BaseModel):
    query: str
    total: int
    results: list[dict]


@router.get("", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def global_search(
    q: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
):
    """
    Full-text search across all user-owned entities:
    - Investigations (by target)
    - Evidence (by JSON-stringified data)
    - Cases (by name, description)
    - Case notes (by content)
    - Watchlists (by name, description)
    - IOC entries (by value, notes)
    - Enriched entities (by value, context)
    - Investigation notes (by content)

    Returns aggregated, deduplicated-by-(type,id) results.
    """
    if not q or len(q) < 2:
        raise HTTPException(400, "Query must be at least 2 characters")

    pattern = f"%{q}%"
    results: list[dict] = []

    # 1. Investigations by target
    r = await db.execute(
        select(Investigation).where(
            Investigation.user_id == current_user.id,
            Investigation.target.ilike(pattern),
        ).limit(limit)
    )
    for inv in r.scalars().all():
        results.append({
            "type": "investigation",
            "id": inv.id,
            "title": inv.target,
            "subtitle": f"{inv.target_type} · {inv.status}",
            "url": f"/#investigation/{inv.id}",
            "created_at": inv.created_at.isoformat(),
        })

    # 2. Evidence (search JSON data as text — SQLite-specific)
    # Use CAST to text for cross-DB compatibility
    r = await db.execute(
        select(Evidence)
        .join(Investigation, Investigation.id == Evidence.investigation_id)
        .where(
            Investigation.user_id == current_user.id,
            func.cast(Evidence.data, String).ilike(pattern),
        ).limit(limit)
    )
    for ev in r.scalars().all():
        results.append({
            "type": "evidence",
            "id": ev.id,
            "title": f"Evidence: {ev.plugin_name}",
            "subtitle": f"Investigation #{ev.investigation_id}",
            "url": f"/#investigation/{ev.investigation_id}",
            "plugin": ev.plugin_name,
            "collected_at": ev.collected_at.isoformat(),
        })

    # 3. Cases by name/description
    r = await db.execute(
        select(Case).where(
            Case.user_id == current_user.id,
            or_(Case.name.ilike(pattern), Case.description.ilike(pattern)),
        ).limit(limit)
    )
    for c in r.scalars().all():
        results.append({
            "type": "case",
            "id": c.id,
            "title": c.name,
            "subtitle": c.description[:100] if c.description else "",
            "url": f"/#case/{c.id}",
            "tlp": c.tlp,
            "status": c.status,
        })

    # 4. Case notes
    r = await db.execute(
        select(CaseNote)
        .join(Case, Case.id == CaseNote.case_id)
        .where(
            Case.user_id == current_user.id,
            CaseNote.content.ilike(pattern),
        ).limit(limit)
    )
    for n in r.scalars().all():
        results.append({
            "type": "case_note",
            "id": n.id,
            "title": f"Case note #{n.id}",
            "subtitle": n.content[:100],
            "url": f"/#case/{n.case_id}",
            "created_at": n.created_at.isoformat(),
        })

    # 5. Watchlists by name/description
    r = await db.execute(
        select(Watchlist).where(
            Watchlist.user_id == current_user.id,
            or_(Watchlist.name.ilike(pattern), Watchlist.description.ilike(pattern)),
        ).limit(limit)
    )
    for w in r.scalars().all():
        results.append({
            "type": "watchlist",
            "id": w.id,
            "title": w.name,
            "subtitle": w.description[:100] if w.description else "",
            "url": f"/#watchlist/{w.id}",
        })

    # 6. IOC entries by value/notes
    r = await db.execute(
        select(IOCEntry)
        .join(Watchlist, Watchlist.id == IOCEntry.watchlist_id, isouter=True)
        .where(
            or_(Watchlist.user_id == current_user.id, IOCEntry.watchlist_id.is_(None)),
            or_(IOCEntry.value.ilike(pattern), IOCEntry.notes.ilike(pattern)),
        ).limit(limit)
    )
    for ioc in r.scalars().all():
        results.append({
            "type": "ioc",
            "id": ioc.id,
            "title": ioc.value,
            "subtitle": f"{ioc.ioc_type} · TLP:{ioc.tlp} · {ioc.notes[:60] if ioc.notes else ''}",
            "url": f"/#watchlist/{ioc.watchlist_id}" if ioc.watchlist_id else None,
        })

    # 7. Enriched entities by value/context
    r = await db.execute(
        select(EnrichedEntity)
        .join(Investigation, Investigation.id == EnrichedEntity.investigation_id)
        .where(
            Investigation.user_id == current_user.id,
            or_(EnrichedEntity.value.ilike(pattern), EnrichedEntity.context.ilike(pattern)),
        ).limit(limit)
    )
    for ent in r.scalars().all():
        results.append({
            "type": "entity",
            "id": ent.id,
            "title": ent.value,
            "subtitle": f"{ent.entity_type} · from {ent.source_plugin or 'regex'}",
            "url": f"/#investigation/{ent.investigation_id}",
            "investigation_id": ent.investigation_id,
        })

    # 8. Investigation notes
    r = await db.execute(
        select(InvestigationNote)
        .join(Investigation, Investigation.id == InvestigationNote.investigation_id)
        .where(
            Investigation.user_id == current_user.id,
            InvestigationNote.content.ilike(pattern),
        ).limit(limit)
    )
    for n in r.scalars().all():
        results.append({
            "type": "investigation_note",
            "id": n.id,
            "title": f"Note on Investigation #{n.investigation_id}",
            "subtitle": n.content[:100],
            "url": f"/#investigation/{n.investigation_id}",
            "created_at": n.created_at.isoformat(),
        })

    return {
        "query": q,
        "total": len(results),
        "results": results[:limit],
    }
