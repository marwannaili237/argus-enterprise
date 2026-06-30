"""
Argus OSINT — In-memory sliding window rate limiter.

Usage as a FastAPI dependency:
    @router.post("/something", dependencies=[Depends(rate_limit(limit=10, window=60))])
"""
import time
import asyncio
from fastapi import Request, HTTPException, status
from fastapi import Depends


# {key: [timestamp, timestamp, ...]}
_requests: dict[str, list[float]] = {}


def _cleanup(key: str, window: float):
    """Remove timestamps older than the sliding window."""
    now = time.monotonic()
    cutoff = now - window
    if key in _requests:
        _requests[key] = [t for t in _requests[key] if t > cutoff]
        if not _requests[key]:
            del _requests[key]


def _check_limit(key: str, limit: int, window: float) -> bool:
    """
    Returns True if the request is allowed, False if rate limited.
    """
    _cleanup(key, window)
    now = time.monotonic()
    timestamps = _requests.setdefault(key, [])
    if len(timestamps) >= limit:
        return False
    timestamps.append(now)
    return True


def rate_limit(limit: int = 30, window: int = 60):
    """
    FastAPI dependency that enforces a sliding window rate limit.
    Uses client IP as the key by default.
    """
    async def _rate_limit_dep(request: Request):
        client_ip = request.client.host if request.client else "unknown"
        key = f"rl:{client_ip}:{request.url.path}"
        window_sec = float(window)
        if not _check_limit(key, limit, window_sec):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per {window}s",
            )
    return _rate_limit_dep