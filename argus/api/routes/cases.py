from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from database import get_db
from models import Case, CaseInvestigation, CaseNote, Investigation, User
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    name: str
    description: str | None = None
    tlp: str = "AMBER"
    priority: str = "medium"


class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    tlp: str | None = None
    priority: str | None = None


class AddInvestigation(BaseModel):
    investigation_id: int


class CaseNoteCreate(BaseModel):
    content: str


@router.post("", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def create_case(req: CaseCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    case = Case(user_id=user.id, name=req.name, description=req.description, tlp=req.tlp, priority=req.priority)
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return {"id": case.id, "name": case.name, "status": case.status, "tlp": case.tlp, "priority": case.priority}


@router.get("")
async def list_cases(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.user_id == user.id).order_by(desc(Case.updated_at)))
    cases = result.scalars().all()
    out = []
    for c in cases:
        # Count investigations
        cnt_result = await db.execute(
            select(CaseInvestigation).where(CaseInvestigation.case_id == c.id)
        )
        inv_count = len(cnt_result.scalars().all())
        out.append({
            "id": c.id, "name": c.name, "description": c.description,
            "status": c.status, "tlp": c.tlp, "priority": c.priority,
            "investigation_count": inv_count,
            "created_at": c.created_at.isoformat(), "updated_at": c.updated_at.isoformat(),
        })
    return out


@router.get("/{case_id}")
async def get_case(case_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user.id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    # Get investigations
    inv_result = await db.execute(
        select(CaseInvestigation).where(CaseInvestigation.case_id == case_id)
    )
    cis = inv_result.scalars().all()
    investigations = []
    for ci in cis:
        inv = (await db.execute(select(Investigation).where(Investigation.id == ci.investigation_id))).scalar_one_or_none()
        if inv:
            investigations.append({
                "id": inv.id, "target": inv.target, "target_type": inv.target_type,
                "status": inv.status, "added_at": ci.added_at.isoformat(),
            })
    # Get notes
    notes_result = await db.execute(select(CaseNote).where(CaseNote.case_id == case_id).order_by(desc(CaseNote.created_at)))
    notes = [{"id": n.id, "content": n.content, "created_at": n.created_at.isoformat()} for n in notes_result.scalars().all()]
    return {
        "id": case.id, "name": case.name, "description": case.description,
        "status": case.status, "tlp": case.tlp, "priority": case.priority,
        "created_at": case.created_at.isoformat(), "updated_at": case.updated_at.isoformat(),
        "investigations": investigations, "notes": notes,
    }


@router.patch("/{case_id}")
async def update_case(case_id: int, req: CaseUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user.id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    for k, v in req.dict(exclude_unset=True).items():
        setattr(case, k, v)
    await db.commit()
    return {"ok": True}


@router.delete("/{case_id}")
async def delete_case(case_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user.id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    await db.delete(case)
    await db.commit()
    return {"ok": True}


@router.post("/{case_id}/investigations", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def add_investigation_to_case(case_id: int, req: AddInvestigation,
                                    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user.id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Case not found")
    inv_result = await db.execute(select(Investigation).where(Investigation.id == req.investigation_id))
    if not inv_result.scalar_one_or_none():
        raise HTTPException(404, "Investigation not found")
    ci = CaseInvestigation(case_id=case_id, investigation_id=req.investigation_id, added_by=user.id)
    db.add(ci)
    await db.commit()
    return {"ok": True}


@router.delete("/{case_id}/investigations/{inv_id}")
async def remove_investigation_from_case(case_id: int, inv_id: int,
                                         user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CaseInvestigation).where(CaseInvestigation.case_id == case_id, CaseInvestigation.investigation_id == inv_id)
    )
    ci = result.scalar_one_or_none()
    if not ci:
        raise HTTPException(404, "Not in case")
    await db.delete(ci)
    await db.commit()
    return {"ok": True}


@router.post("/{case_id}/notes", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def add_case_note(case_id: int, req: CaseNoteCreate,
                        user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    note = CaseNote(case_id=case_id, user_id=user.id, content=req.content)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return {"id": note.id, "content": note.content, "created_at": note.created_at.isoformat()}
