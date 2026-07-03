from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter()


@router.get("/health")
async def health():
    return {"status": "ok", "service": "argus-api", "timestamp": datetime.now(timezone.utc).isoformat()}

@router.post("/test-auth")
async def test_auth(req: dict):
    return {"status": "ok", "message": "Health router works", "received": req}


@router.get("/ready")
async def ready():
    return {"status": "ready"}
