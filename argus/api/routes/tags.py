from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel
from database import get_db
from models import Tag, TagAssociation, User
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends

router = APIRouter(prefix="/tags", tags=["tags"])


class TagCreate(BaseModel):
    name: str
    color: str = "#e94560"


class TagApply(BaseModel):
    entity_type: str  # investigation|case|ioc|evidence
    entity_id: int


@router.post("", dependencies=[_Depends(rate_limit(limit=30, window=60))])
async def create_tag(req: TagCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    tag = Tag(user_id=user.id, name=req.name, color=req.color)
    db.add(tag)
    await db.commit()
    await db.refresh(tag)
    return {"id": tag.id, "name": tag.name, "color": tag.color}


@router.get("")
async def list_tags(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tag).where((Tag.user_id == user.id) | (Tag.user_id.is_(None))))
    return [{"id": t.id, "name": t.name, "color": t.color} for t in result.scalars().all()]


@router.delete("/{tag_id}")
async def delete_tag(tag_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tag).where(Tag.id == tag_id, Tag.user_id == user.id))
    tag = result.scalar_one_or_none()
    if not tag:
        raise HTTPException(404, "Tag not found")
    await db.execute(delete(TagAssociation).where(TagAssociation.tag_id == tag_id))
    await db.delete(tag)
    await db.commit()
    return {"ok": True}


@router.post("/{tag_id}/apply", dependencies=[_Depends(rate_limit(limit=60, window=60))])
async def apply_tag(tag_id: int, req: TagApply, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    assoc = TagAssociation(tag_id=tag_id, entity_type=req.entity_type, entity_id=req.entity_id)
    db.add(assoc)
    await db.commit()
    return {"ok": True}


@router.delete("/{tag_id}/apply/{entity_type}/{entity_id}")
async def remove_tag(tag_id: int, entity_type: str, entity_id: int,
                     user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(
        delete(TagAssociation).where(
            TagAssociation.tag_id == tag_id,
            TagAssociation.entity_type == entity_type,
            TagAssociation.entity_id == entity_id,
        )
    )
    await db.commit()
    return {"ok": True}


@router.get("/for/{entity_type}/{entity_id}")
async def get_tags_for_entity(entity_type: str, entity_id: int,
                              user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Tag).join(TagAssociation, TagAssociation.tag_id == Tag.id)
        .where(TagAssociation.entity_type == entity_type, TagAssociation.entity_id == entity_id)
    )
    return [{"id": t.id, "name": t.name, "color": t.color} for t in result.scalars().all()]
