from fastapi import APIRouter
router = APIRouter(prefix="/debug", tags=["debug"])
@router.get("/ping")
async def ping():
    return {"message": "pong"}
