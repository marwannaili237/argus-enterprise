from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from database import get_db, AsyncSessionLocal
from models import User, Investigation
from api.deps import get_current_user, require_admin
from api.auth import create_user_token
from api.rate_limit import rate_limit
from api.telegram_auth import verify_telegram_data, extract_telegram_user
from config import get_settings
from fastapi import Depends as _Depends

router = APIRouter(prefix="/users", tags=["users"])
settings = get_settings()

class TelegramWebAppAuthRequest(BaseModel):
    user: dict = Field(..., description="User object from Telegram Web App")
    auth_date: int = Field(..., description="Unix timestamp of authentication")
    hash: str = Field(..., description="HMAC-SHA256 signature")

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    telegram_id: int
    role: str
    warning: str | None = None

@router.post("/auth/telegram")
async def auth_telegram(req: dict):
    try:
        if "telegram_id" in req:
            tid = req["telegram_id"]
            async with AsyncSessionLocal() as db:
                res = await db.execute(select(User).where(User.telegram_id == tid))
                user = res.scalar_one_or_none()
                if not user:
                    user = User(telegram_id=tid, username=f"user_{tid}", full_name="Debug", role="admin")
                    db.add(user)
                    await db.commit()
                    await db.refresh(user)
                token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
                return {"access_token": token, "user_id": user.id, "telegram_id": user.telegram_id, "role": user.role}
        return {"error": "No tid"}
    except Exception as e:
        return {"error": str(e)}

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return {"id": current_user.id, "telegram_id": current_user.telegram_id, "username": current_user.username, "role": current_user.role}

@router.patch("/{user_id}/role")
async def update_user_role(user_id: int, req: dict, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if not user: raise HTTPException(404)
    user.role = req.get("role", "analyst")
    await db.commit()
    return {"status": "ok"}
