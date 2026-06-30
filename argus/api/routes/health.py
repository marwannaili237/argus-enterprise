from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "service": "argus-api", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/ready")
async def ready():
    return {"status": "ready"}
