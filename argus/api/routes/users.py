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
    """Secure Telegram Web App authentication data with HMAC verification."""
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
    """
    Authenticate using Telegram ID (Simplified for standalone web app)
    or Telegram Web App data.
    """
    try:
        if not settings.telegram_bot_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Telegram bot token not configured"
            )
        
        # Handle simplified login { "telegram_id": 123 }
        if "telegram_id" in req:
            telegram_id = req["telegram_id"]
            
            # Look up or create user
            result = await db.execute(select(User).where(User.telegram_id == telegram_id))
            user = result.scalar_one_or_none()
            
            if not user:
                user_count_result = await db.execute(select(func.count()).select_from(User))
                user_count = user_count_result.scalar() or 0
                is_first_user = user_count == 0
                
                user = User(
                    telegram_id=telegram_id,
                    username=f"user_{telegram_id}",
                    full_name="Telegram User",
                    role="admin" if is_first_user else "analyst",
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

        # Otherwise, handle full Telegram Web App HMAC verification
        try:
            auth_req = TelegramWebAppAuthRequest(**req)
            req_dict = auth_req.model_dump()
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid auth data: {e}")

        is_valid, error_message = verify_telegram_data(req_dict, settings.telegram_bot_token)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {error_message}"
            )
        
        user_info = extract_telegram_user(req_dict)
        telegram_id = user_info["telegram_id"]
        
        if not telegram_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing telegram_id")
        
        result = await db.execute(select(User).where(User.telegram_id == telegram_id))
        user = result.scalar_one_or_none()
        
        if not user:
            user_count_result = await db.execute(select(func.count()).select_from(User))
            user_count = user_count_result.scalar() or 0
            is_first_user = user_count == 0
            user = User(
                telegram_id=telegram_id,
                username=user_info["username"],
                full_name=user_info["full_name"],
                role="admin" if is_first_user else "analyst",
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        else:
            if user_info["username"]: user.username = user_info["username"]
            if user_info["full_name"]: user.full_name = user_info["full_name"]
            await db.commit()
        
        token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
        return TokenResponse(
            access_token=token,
            user_id=user.id,
            telegram_id=user.telegram_id,
            role=user.role,
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get the current authenticated user's profile."""
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
    """Change a user's role. Admin only."""
    valid_roles = {"admin", "analyst", "viewer"}
    if req.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}"
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = req.role
    await db.commit()

    return {"id": user.id, "telegram_id": user.telegram_id, "role": user.role}
