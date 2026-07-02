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
    req: TelegramWebAppAuthRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate using Telegram Web App data with HMAC-SHA256 verification.
    
    This endpoint implements the secure Telegram Web App authentication flow:
    1. Receives user data, auth_date, and HMAC signature from Telegram Web App
    2. Verifies the HMAC signature using the bot token
    3. Checks that auth_date is recent (prevents replay attacks)
    4. Creates or updates the user in the database
    5. Issues a JWT token
    
    Security: This endpoint prevents spoofing by verifying the HMAC signature
    and checking the freshness of the auth_date timestamp.
    
    Reference: https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
    """
    if not settings.telegram_bot_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telegram bot token not configured"
        )
    
    # Verify the Telegram data using HMAC
    req_dict = req.model_dump()
    is_valid, error_message = verify_telegram_data(req_dict, settings.telegram_bot_token)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {error_message}"
        )
    
    # Extract user information from verified data
    user_info = extract_telegram_user(req_dict)
    telegram_id = user_info["telegram_id"]
    
    if not telegram_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing telegram_id in user data"
        )
    
    # Look up or create user
    result = await db.execute(select(User).where(User.telegram_id == telegram_id))
    user = result.scalar_one_or_none()
    
    if not user:
        # Determine if this is the first user (becomes admin)
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
        # Update user information if provided
        if user_info["username"]:
            user.username = user_info["username"]
        if user_info["full_name"]:
            user.full_name = user_info["full_name"]
        await db.commit()
    
    # Create JWT token
    token = create_user_token(telegram_id=user.telegram_id, user_id=user.id)
    
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        telegram_id=user.telegram_id,
        role=user.role,
    )


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
