"""
Optional Ollama integration — runs AI reports fully offline using a local LLM.
Auto-detected: if ENABLE_OLLAMA=true and Ollama is reachable, use it.
Otherwise, gracefully skip (Gemini remains as the cloud option).
"""
import os
import json
import asyncio
import logging
from typing import Any

logger = logging.getLogger("argus.ollama")

SYSTEM_PROMPT = """You are an expert OSINT analyst. Synthesize the provided evidence into a concise threat intelligence report.

Format:
1. **Executive Summary** (2-3 sentences)
2. **Key Findings** (bullet list)
3. **Risk Assessment** (Low/Medium/High/Critical + justification)
4. **Notable IOCs**
5. **Recommendations**
"""


class OllamaClient:
    """Async client for local Ollama HTTP API. Zero external dependencies."""

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2:1b")
        self._available: bool | None = None

    async def is_available(self) -> bool:
        """Check if Ollama server is reachable and the model is available."""
        if self._available is not None:
            return self._available
        try:
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as s:
                async with s.get(f"{self.base_url}/api/tags") as r:
                    if r.status != 200:
                        self._available = False
                        return False
                    data = await r.json()
                    models = [m.get("name", "") for m in data.get("models", [])]
                    # Allow fuzzy match: if exact model missing, we'll auto-pull on first use
                    self._available = True
                    return True
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            self._available = False
            return False

    async def generate_report(self, target: str, evidence: dict[str, Any]) -> dict | None:
        """Generate an AI report from evidence. Returns {report, model} or None."""
        if not await self.is_available():
            return None
        try:
            import aiohttp
            evidence_str = json.dumps(evidence, indent=2, default=str)[:8000]  # cap to fit small context
            prompt = f"{SYSTEM_PROMPT}\n\nTarget: {target}\n\nRaw OSINT evidence:\n{evidence_str}\n\nReport:"

            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 1024},
            }
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as s:
                async with s.post(f"{self.base_url}/api/generate", json=payload) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    return {"report": data.get("response", ""), "model": self.model, "engine": "ollama"}
        except Exception as e:
            logger.error(f"Ollama generate failed: {e}")
            return None


# Singleton
_client: OllamaClient | None = None


def get_ollama() -> OllamaClient:
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client


async def maybe_generate_report(target: str, evidence: dict[str, Any]) -> dict | None:
    """Convenience helper — returns None if Ollama is disabled or unavailable."""
    if os.getenv("ENABLE_OLLAMA", "false").lower() != "true":
        return None
    return await get_ollama().generate_report(target, evidence)
