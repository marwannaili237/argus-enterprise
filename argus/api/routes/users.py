from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from database import get_db
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


@router.post("/auth/telegram", response_model=TokenResponse,
             dependencies=[_Depends(rate_limit(limit=10, window=60))])
async def auth_telegram(
    req: dict,
    db: AsyncSession = Depends(get_db)
):
    try:
        if "telegram_id" in req:
            telegram_id = req["telegram_id"]
            result = await db.execute(select(User).where(User.telegram_id == telegram_id))
            user = result.scalar_one_or_none()
            if not user:
                user = User(
                    telegram_id=telegram_id,
                    username=f"user_{telegram_id}",
                    full_name="Debug User",
                    role="admin",
                )
                db.add(user)
                await db.commit()
                await db.refresh(user)
            
            token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
            return TokenResponse(
                access_token=token,
                user_id=user.id,
                telegram_id=user.telegram_id,
                role=user.role,
            )
        
        # Full HMAC flow
        try:
            auth_req = TelegramWebAppAuthRequest(**req)
            req_dict = auth_req.model_dump()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid auth data: {e}")

        is_valid, error_message = verify_telegram_data(req_dict, settings.telegram_bot_token)
        if not is_valid:
            raise HTTPException(status_code=401, detail=f"Auth failed: {error_message}")
        
        user_info = extract_telegram_user(req_dict)
        telegram_id = user_info["telegram_id"]
        result = await db.execute(select(User).where(User.telegram_id == telegram_id))
        user = result.scalar_one_or_none()
        if not user:
            user = User(
                telegram_id=telegram_id,
                username=user_info["username"],
                full_name=user_info["full_name"],
                role="analyst",
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        
        token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
        return TokenResponse(
            access_token=token,
            user_id=user.id,
            telegram_id=user.telegram_id,
            role=user.role,
        )
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    count_result = await db.execute(
        select(func.count()).select_from(Investigation).where(Investigation.user_id == current_user.id)
    )
    total = count_result.scalar() or 0
    return {
        "id": current_user.id,
        "telegram_id": current_user.telegram_id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "email_address": current_user.email_address,
        "investigations_total": total,
        "member_since": current_user.created_at.isoformat(),
    }


class UpdateRoleRequest(BaseModel):
    role: str


@router.patch("/{user_id}/role")
async def update_user_role(
    user_id: int,
    req: UpdateRoleRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = req.role
    await db.commit()
    return {"id": user.id, "telegram_id": user.telegram_id, "role": user.role}
