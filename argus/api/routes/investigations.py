from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, asc, func, or_
from pydantic import BaseModel, Field
from database import get_db
from models import User, Investigation, Evidence
from api.deps import get_current_user
from api.rate_limit import rate_limit
from plugins.runner import run_investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])


class StartInvestigationRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    telegram_chat_id: int | None = None
    telegram_message_id: int | None = None
    template: str | None = Field(None, pattern=r"^(full|quick|email_intel|brand|person|brand_protection|darkweb|pep_sanctions|due_diligence|c2_hunt)$")


@router.post("", dependencies=[Depends(rate_limit(limit=30, window=60))])
async def start_investigation(
    req: StartInvestigationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from plugins.runner import classify_target
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "Target cannot be empty")
    target_type = classify_target(target)
    if target_type == "unknown":
        raise HTTPException(400, f"Could not classify target: {target}")

    inv = Investigation(
        user_id=current_user.id,
        target=target,
        target_type=target_type,
        status="running",
        telegram_chat_id=req.telegram_chat_id,
        telegram_message_id=req.telegram_message_id,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)

    background_tasks.add_task(run_investigation, inv.id, req.template)
    return {"id": inv.id, "target": inv.target, "target_type": target_type, "status": "running", "template": req.template}


@router.get("")
async def list_investigations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: str | None = None,
    target_type: str | None = None,
    q: str | None = None,  # full-text search on target
    sort_by: str = Query("created_at", pattern=r"^(created_at|completed_at|target|status)$"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    """List investigations with pagination, filtering, sorting, and search."""
    stmt = select(Investigation).where(Investigation.user_id == current_user.id)

    if status:
        stmt = stmt.where(Investigation.status == status)
    if target_type:
        stmt = stmt.where(Investigation.target_type == target_type)
    if q:
        stmt = stmt.where(Investigation.target.ilike(f"%{q}%"))

    # Sorting
    col = getattr(Investigation, sort_by)
    stmt = stmt.order_by(desc(col) if sort_order == "desc" else asc(col))

    # Total count (before pagination)
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Pagination
    stmt = stmt.limit(limit).offset(offset)
    result = await db.execute(stmt)
    investigations = result.scalars().all()

    return {
        "items": [
            {
                "id": inv.id,
                "target": inv.target,
                "target_type": inv.target_type,
                "status": inv.status,
                "created_at": inv.created_at.isoformat(),
                "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
            }
            for inv in investigations
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{inv_id}")
async def get_investigation(
    inv_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    evidence_result = await db.execute(
        select(Evidence).where(Evidence.investigation_id == inv_id)
    )
    evidence = evidence_result.scalars().all()

    return {
        "id": inv.id,
        "target": inv.target,
        "target_type": inv.target_type,
        "status": inv.status,
        "summary": inv.summary,
        "created_at": inv.created_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        "evidence": [
            {"plugin": e.plugin_name, "data": e.data, "collected_at": e.collected_at.isoformat()}
            for e in evidence
        ],
    }


class AnalyzeRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    evidence: dict


@router.post("/{inv_id}/analyze", dependencies=[Depends(rate_limit(limit=10, window=60))])
async def analyze_investigation(
    inv_id: int,
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    from plugins.ai_analysis import AiAnalysisPlugin
    plugin = AiAnalysisPlugin()
    if not plugin._configured:
        raise HTTPException(status_code=503, detail="AI analysis not configured — set GEMINI_API_KEY")

    ai_result = await plugin.run(req.target, evidence_data=req.evidence)
    if not ai_result.success:
        raise HTTPException(status_code=500, detail=ai_result.error)

    # Store as evidence
    from sqlalchemy import delete
    await db.execute(
        delete(Evidence).where(
            Evidence.investigation_id == inv_id,
            Evidence.plugin_name == "ai_analysis"
        )
    )
    ai_evidence = Evidence(
        investigation_id=inv_id,
        plugin_name="ai_analysis",
        data=ai_result.data,
    )
    db.add(ai_evidence)
    await db.commit()

    return {"report": ai_result.data.get("report"), "model": ai_result.data.get("model")}


class BulkInvestigateRequest(BaseModel):
    """Bulk investigation request — up to 50 targets at once."""
    targets: list[str] = Field(..., min_length=1, max_length=50)
    template: str | None = Field(None, pattern=r"^(full|quick|email_intel|brand|person|brand_protection|darkweb|pep_sanctions|due_diligence|c2_hunt)$")


@router.post("/bulk", dependencies=[Depends(rate_limit(limit=5, window=60))])
async def bulk_investigate(
    req: BulkInvestigateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit up to 50 targets for investigation in a single request.
    Each target runs as an independent background task.
    Returns the list of created investigation IDs.
    """
    from plugins.runner import classify_target
    created = []
    skipped = []
    for raw in req.targets:
        t = raw.strip()
        if not t:
            continue
        target_type = classify_target(t)
        if target_type == "unknown":
            skipped.append({"target": t, "reason": "unclassified"})
            continue
        inv = Investigation(
            user_id=current_user.id,
            target=t,
            target_type=target_type,
            status="running",
        )
        db.add(inv)
        await db.flush()
        background_tasks.add_task(run_investigation, inv.id, req.template)
        created.append({"id": inv.id, "target": t, "target_type": target_type})
    await db.commit()
    return {"created": created, "skipped": skipped, "total_created": len(created)}


class CompareResponse(BaseModel):
    """Compare two investigations on the same target."""
    investigation_1: dict
    investigation_2: dict
    diff: dict


@router.get("/{inv_id1}/compare/{inv_id2}")
async def compare_investigations(
    inv_id1: int,
    inv_id2: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Compare two investigations on the same target."""
    results = []
    for inv_id in (inv_id1, inv_id2):
        r = await db.execute(
            select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
        )
        inv = r.scalar_one_or_none()
        if not inv:
            raise HTTPException(404, f"Investigation {inv_id} not found")
        ev_r = await db.execute(select(Evidence).where(Evidence.investigation_id == inv_id))
        evidence = ev_r.scalars().all()
        results.append({
            "id": inv.id,
            "target": inv.target,
            "target_type": inv.target_type,
            "created_at": inv.created_at.isoformat(),
            "evidence_by_plugin": {e.plugin_name: e.data for e in evidence},
        })

    # Compute diff: plugins only in inv1, only in inv2, in both with different data
    plugins_1 = set(results[0]["evidence_by_plugin"].keys())
    plugins_2 = set(results[1]["evidence_by_plugin"].keys())
    only_in_1 = sorted(plugins_1 - plugins_2)
    only_in_2 = sorted(plugins_2 - plugins_1)
    common = plugins_1 & plugins_2
    changed = []
    for p in sorted(common):
        if results[0]["evidence_by_plugin"][p] != results[1]["evidence_by_plugin"][p]:
            changed.append(p)

    return {
        "investigation_1": results[0],
        "investigation_2": results[1],
        "diff": {
            "only_in_1": only_in_1,
            "only_in_2": only_in_2,
            "changed_in_both": changed,
        },
    }
