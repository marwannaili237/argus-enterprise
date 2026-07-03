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
        print("Auth telegram called with req:", req)
        if "telegram_id" in req:
            return {"access_token": "test_token", "user_id": 1, "telegram_id": req["telegram_id"], "role": "admin"}
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
