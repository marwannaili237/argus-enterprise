"""Discord webhook notifier — simple aiohttp-based sender for Discord webhooks."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("argus.discord")


async def send_to_discord(
    webhook_url: str,
    content: str | None = None,
    embed: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> bool:
    """Send a message to a Discord webhook.

    Args:
        webhook_url: The Discord webhook URL.
        content: Plain text message content.
        embed: A single Discord embed object (title, description, color, fields, etc.).
               If you need multiple embeds, pass them via the ``embeds`` key inside
               the payload by composing manually.
        timeout: Request timeout in seconds.

    Returns:
        True if the request succeeded (2xx), False otherwise.
    """
    import aiohttp

    payload: dict[str, Any] = {}
    if content:
        payload["content"] = content
    if embed:
        payload["embeds"] = [embed]

    # Discord requires at least one of content or embeds
    if not payload:
        logger.warning("Discord webhook called with no content or embed")
        return False

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.warning("Discord webhook returned %s: %s", resp.status, body[:200])
                    return False
                return True
    except Exception as e:
        logger.error("Failed to send Discord message: %s", e)
        return False
