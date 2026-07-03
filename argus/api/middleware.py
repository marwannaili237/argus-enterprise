from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging
import time
import uuid

logger = logging.getLogger("argus.api.middleware")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add a unique request ID to each request for tracing."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Add request ID to request state."""
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Handle uncaught exceptions and return proper error responses."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Catch exceptions and return JSON error responses."""
        try:
            response = await call_next(request)
            return response
        except HTTPException as exc:
            # Let FastAPI's own HTTPException handler handle this
            raise exc
        except Exception as exc:
            request_id = getattr(request.state, "request_id", "unknown")
            logger.error(
                f"Unhandled exception in {request.method} {request.url.path}",
                extra={
                    "request_id": request_id,
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                }
            )
            
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "request_id": request_id,
                },
            )


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """Monitor and log request performance."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Measure request processing time."""
        start_time = time.time()
        request_id = getattr(request.state, "request_id", "unknown")
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        
        # Log slow requests (> 1 second)
        if process_time > 1.0:
            logger.warning(
                f"Slow request: {request.method} {request.url.path}",
                extra={
                    "request_id": request_id,
                    "duration_seconds": process_time,
                    "status_code": response.status_code,
                }
            )
        else:
            logger.debug(
                f"Request completed: {request.method} {request.url.path}",
                extra={
                    "request_id": request_id,
                    "duration_seconds": process_time,
                    "status_code": response.status_code,
                }
            )
        
        response.headers["X-Process-Time"] = str(process_time)
        return response
