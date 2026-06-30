"""
Argus OSINT — Plugin retry with backoff.

Retries a failed plugin execution once with a 2-second delay.
"""
import asyncio
import logging

from plugins.base import PluginResult

logger = logging.getLogger("argus.retry")


async def run_with_retry(plugin, target: str, max_retries: int = 1) -> PluginResult:
    """
    Run a plugin, retrying on failure up to max_retries times.
    Waits 2 seconds between retries.
    Returns the last result whether success or failure.
    """
    last_result = None
    for attempt in range(max_retries + 1):
        result = await plugin.run(target)
        last_result = result
        if result.success:
            return result
        if attempt < max_retries:
            logger.info(f"Plugin {plugin.name} failed (attempt {attempt + 1}), retrying in 2s...")
            await asyncio.sleep(2)
    return last_result