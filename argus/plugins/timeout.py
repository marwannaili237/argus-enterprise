"""
Argus OSINT — Plugin timeout enforcement.

Wraps plugin.run() calls with asyncio.wait_for to enforce per-plugin timeouts.
"""
import asyncio
import logging

from plugins.base import PluginResult

logger = logging.getLogger("argus.timeout")


async def run_with_timeout(plugin, target: str, timeout_seconds: float) -> PluginResult:
    """
    Run a plugin with a timeout. If the plugin exceeds the timeout,
    return a failed PluginResult instead of raising.
    """
    try:
        result = await asyncio.wait_for(plugin.run(target), timeout=timeout_seconds)
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Plugin {plugin.name} timed out after {timeout_seconds}s for target {target}")
        return PluginResult(
            plugin_name=plugin.name,
            success=False,
            error=f"Plugin timed out after {timeout_seconds}s",
        )
    except Exception as e:
        logger.error(f"Plugin {plugin.name} failed for target {target}: {e}")
        return PluginResult(
            plugin_name=plugin.name,
            success=False,
            error=str(e),
        )