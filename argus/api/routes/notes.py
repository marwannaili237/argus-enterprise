from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from database import get_db
from models import User, Investigation, InvestigationNote
from api.deps import get_current_user

router = APIRouter(tags=["notes"])


class CreateNoteRequest(BaseModel):
    content: str


@router.post("/investigations/{inv_id}/notes")
async def add_note(
    inv_id: int,
    req: CreateNoteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a note to an investigation."""
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="Note content is empty")

    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    note = InvestigationNote(
        investigation_id=inv_id,
        user_id=current_user.id,
        content=req.content.strip(),
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    return {
        "id": note.id,
        "investigation_id": note.investigation_id,
        "content": note.content,
        "created_at": note.created_at.isoformat(),
    }


@router.get("/investigations/{inv_id}/notes")
async def list_notes(
    inv_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List notes for an investigation."""
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    notes_result = await db.execute(
        select(InvestigationNote)
        .where(InvestigationNote.investigation_id == inv_id)
        .order_by(desc(InvestigationNote.created_at))
    )
    notes = notes_result.scalars().all()

    return [
        {
            "id": n.id,
            "investigation_id": n.investigation_id,
            "content": n.content,
            "created_at": n.created_at.isoformat(),
        }
        for n in notes
    ]