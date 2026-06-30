from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, Field
from database import get_db
from models import User, Investigation
from api.deps import get_current_user, require_admin
from api.auth import create_user_token
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends

router = APIRouter(prefix="/users", tags=["users"])


class TelegramAuthRequest(BaseModel):
    telegram_id: int = Field(..., gt=0, lt=10_000_000_000)  # Telegram IDs are positive < 10B
    username: str | None = Field(None, max_length=64)
    full_name: str | None = Field(None, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    telegram_id: int
    role: str
    warning: str | None = None


@router.post("/auth/telegram", response_model=TokenResponse,
             dependencies=[_Depends(rate_limit(limit=10, window=60))])
async def auth_telegram(req: TelegramAuthRequest, db: AsyncSession = Depends(get_db)):
    """
    Exchange a Telegram ID for a JWT.

    ⚠️ SECURITY NOTE: This endpoint does NOT verify the caller actually owns
    the Telegram ID. In production you MUST either:
      (a) Use Telegram's `data-send` Web App flow with HMAC verification, or
      (b) Have the bot issue the JWT directly (bot/handlers/start.py) and
          deliver it to the user via a deep-link.
    For local/dev use, the first registered user becomes admin automatically.

    See SECURITY.md for the recommended hardening path.
    """
    result = await db.execute(select(User).where(User.telegram_id == req.telegram_id))
    user = result.scalar_one_or_none()

    # Determine if this is the first user (becomes admin)
    user_count_result = await db.execute(select(func.count()).select_from(User))
    user_count = user_count_result.scalar() or 0
    is_first_user = user_count == 0

    warning = (
        "Dev-mode auth: any Telegram ID is accepted. Use the Telegram bot "
        "(/start) for secure authentication in production."
    )

    if not user:
        user = User(
            telegram_id=req.telegram_id,
            username=req.username,
            full_name=req.full_name,
            role="admin" if is_first_user else "analyst",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    else:
        user.username = req.username or user.username
        user.full_name = req.full_name or user.full_name
        await db.commit()

    token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        telegram_id=user.telegram_id,
        role=user.role,
        warning=warning,
    )


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    count_result = await db.execute(
        select(func.count()).where(Investigation.user_id == current_user.id)
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
    """Change a user's role. Admin only."""
    valid_roles = {"admin", "analyst", "viewer"}
    if req.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = req.role
    await db.commit()

    return {"id": user.id, "telegram_id": user.telegram_id, "role": user.role}