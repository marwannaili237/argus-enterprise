"""
Tests for the FastAPI application — health endpoints and app factory.
"""
import sys
import os
import pytest
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    from api.app import create_app
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "argus-api"


@pytest.mark.anyio
async def test_ready_endpoint():
    from api.app import create_app
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"


@pytest.mark.anyio
async def test_monitors_router_registered():
    """Verify the monitors router is accessible (returns 401, not 404)."""
    from api.app import create_app
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/monitors")
        # Should be 401 (auth required), not 404 (route not found)
        assert resp.status_code in (401, 403, 422)


@pytest.mark.anyio
async def test_investigations_router_registered():
    """Verify the investigations router is accessible."""
    from api.app import create_app
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/investigations")
        # Should be 401 (auth required), not 404 (route not found)
        assert resp.status_code in (401, 403, 422)