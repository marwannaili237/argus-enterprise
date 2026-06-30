"""Slack webhook notifier — simple aiohttp-based sender for Slack incoming webhooks."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("argus.slack")


async def send_to_slack(
    webhook_url: str,
    text: str,
    blocks: list[dict[str, Any]] | None = None,
    timeout: float = 10.0,
) -> bool:
    """Send a message to a Slack incoming webhook.

    Args:
        webhook_url: The Slack webhook URL.
        text: Fallback text (shown if blocks are not supported).
        blocks: Optional list of Slack Block Kit blocks.
        timeout: Request timeout in seconds.

    Returns:
        True if the request succeeded (2xx), False otherwise.
    """
    import aiohttp

    payload: dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.warning("Slack webhook returned %s: %s", resp.status, body[:200])
                    return False
                return True
    except Exception as e:
        logger.error("Failed to send Slack message: %s", e)
        return False
