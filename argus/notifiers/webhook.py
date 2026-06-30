"""
Argus OSINT — Webhook Notification Service

POSTs JSON alerts to any configured URL for investigation
and monitor events.
"""
import logging
import aiohttp

logger = logging.getLogger("argus.notifier.webhook")


class WebhookNotifier:
    """Sends JSON notifications to a webhook URL."""

    def __init__(self, url: str):
        self.url = url.rstrip("/") if url else ""
        self._configured = bool(self.url)

    async def send(self, payload: dict):
        """POST a JSON payload to the configured webhook URL."""
        if not self._configured:
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status >= 400:
                        body = await resp.text()
                        logger.warning(f"Webhook returned {resp.status}: {body[:200]}")
                    else:
                        logger.info(f"Webhook notification sent to {self.url}")
        except Exception as e:
            logger.error(f"Failed to send webhook to {self.url}: {e}")

    async def notify_investigation_complete(self, target: str, status: str, investigation_id: int, threat_level: str = "UNKNOWN"):
        """Send an investigation completion notification."""
        await self.send({
            "event": "investigation_complete",
            "investigation_id": investigation_id,
            "target": target,
            "status": status,
            "threat_level": threat_level,
        })

    async def notify_monitor_alert(self, target: str, changes: list[str], monitor_id: int, investigation_id: int):
        """Send a monitor change alert notification."""
        await self.send({
            "event": "monitor_alert",
            "monitor_id": monitor_id,
            "investigation_id": investigation_id,
            "target": target,
            "changes": changes,
            "change_count": len(changes),
        })


def get_webhook_notifier(url: str | None) -> WebhookNotifier:
    """Create a WebhookNotifier instance. Returns a no-op if URL is None."""
    return WebhookNotifier(url or "")