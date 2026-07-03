import aiohttp
import os
from config import get_settings

settings = get_settings()

# API endpoint configuration
API_BASE = os.getenv(
    "API_BASE_URL",
    getattr(settings, "api_base_url", None) or f"http://localhost:{settings.api_port}/api/v1"
).rstrip("/")

async def api_request(method: str, path: str, token: str = None, json_data: dict = None):
    """Centralized API requester for the bot."""
    url = f"{API_BASE}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if json_data:
        headers["Content-Type"] = "application/json"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, json=json_data, headers=headers, timeout=10) as resp:
                if resp.status in (200, 201):
                    return await resp.json(), None
                else:
                    text = await resp.text()
                    return None, f"API Error {resp.status}: {text}"
    except Exception as e:
        return None, f"Connection Error: {str(e)}"
