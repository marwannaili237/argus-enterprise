"""
Argus OSINT — Email Notification Service

Sends investigation completion and monitor alert emails
via SMTP using smtplib in a thread (asyncio.to_thread).
"""
import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("argus.notifier.email")


class EmailNotifier:
    """Sends emails via SMTP for investigation and monitor events."""

    def __init__(self, host: str, port: int, user: str, password: str, from_addr: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_addr = from_addr
        self._configured = bool(host and port and user and password and from_addr)

    def _send_sync(self, to_addr: str, subject: str, body: str):
        """Synchronous SMTP send — called via asyncio.to_thread."""
        if not self._configured:
            logger.warning("Email notifier not configured — skipping send")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = to_addr
        msg.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP(self.host, self.port) as server:
            server.starttls(context=context)
            server.login(self.user, self.password)
            server.sendmail(self.from_addr, to_addr, msg.as_string())

        logger.info(f"Email sent to {to_addr}: {subject}")

    async def send(self, to_addr: str, subject: str, body: str):
        """Send an email asynchronously."""
        import asyncio
        try:
            await asyncio.to_thread(self._send_sync, to_addr, subject, body)
        except Exception as e:
            logger.error(f"Failed to send email to {to_addr}: {e}")

    async def notify_investigation_complete(self, to_addr: str, target: str, status: str, investigation_id: int):
        """Send an investigation completion notification."""
        subject = f"[Argus] Investigation complete: {target}"
        body = (
            f"Your Argus OSINT investigation has completed.\n\n"
            f"  Target: {target}\n"
            f"  Status: {status}\n"
            f"  Investigation ID: {investigation_id}\n\n"
            f"Log in to the Argus platform for full details."
        )
        await self.send(to_addr, subject, body)

    async def notify_monitor_alert(self, to_addr: str, target: str, changes: list[str], monitor_id: int):
        """Send a monitor change alert notification."""
        subject = f"[Argus] Monitor Alert: {target}"
        changes_text = "\n".join(f"  • {c}" for c in changes)
        body = (
            f"Argus detected changes for a monitored target.\n\n"
            f"  Target: {target}\n"
            f"  Monitor ID: {monitor_id}\n\n"
            f"Changes detected:\n{changes_text}\n\n"
            f"Log in to the Argus platform for full details."
        )
        await self.send(to_addr, subject, body)


def get_email_notifier(settings) -> EmailNotifier:
    """Create an EmailNotifier instance from application settings."""
    return EmailNotifier(
        host=getattr(settings, "smtp_host", ""),
        port=getattr(settings, "smtp_port", 587),
        user=getattr(settings, "smtp_user", ""),
        password=getattr(settings, "smtp_password", ""),
        from_addr=getattr(settings, "from_email", ""),
    )