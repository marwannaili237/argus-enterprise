"""
Argus OSINT — Webhook Notification Service

POSTs JSON alerts to any configured URL for investigation
and monitor events. All webhook URLs are validated for SSRF
protection before sending.
"""
import asyncio
import logging
import aiohttp
from intel.ssrf import is_safe_url

logger = logging.getLogger("argus.notifier.webhook")


class WebhookNotifier:
    """Sends JSON notifications to a webhook URL with SSRF protection."""

    def __init__(self, url: str):
        self.url = url.rstrip("/") if url else ""
        self._configured = bool(self.url)
        
        # Validate URL for SSRF on initialization
        if self._configured:
            safe, reason = is_safe_url(self.url)
            if not safe:
                logger.error(f"Webhook URL failed SSRF check: {reason}")
                self._configured = False

    async def send(self, payload: dict):
        """POST a JSON payload to the configured webhook URL."""
        if not self._configured:
            logger.debug("Webhook notifier not configured or URL is unsafe")
            return

        try:
            # Double-check URL safety before sending (defense in depth)
            safe, reason = is_safe_url(self.url)
            if not safe:
                logger.error(f"Webhook URL failed SSRF check at send time: {reason}")
                return
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": "ArgusOSINT/1.0"},
                ) as resp:
                    if resp.status >= 400:
                        body = await resp.text()
                        logger.warning(f"Webhook returned {resp.status}: {body[:200]}")
                    else:
                        logger.info(f"Webhook notification sent successfully")
        except asyncio.TimeoutError:
            logger.error(f"Webhook request timed out")
        except aiohttp.ClientError as e:
            logger.error(f"Webhook client error: {e}")
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")

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
