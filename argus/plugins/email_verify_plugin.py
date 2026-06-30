"""
Email verification plugin — SMTP mailbox existence check via MX server HELO/EHLO,
MAIL FROM, RCPT TO handshake. Gracefully handles timeouts and rejections.
"""
import asyncio
import re
import aiohttp
import dns.resolver
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}
SMTP_TIMEOUT = 10


class EmailVerifyPlugin(BasePlugin):
    name = "email_verify"
    description = "SMTP mailbox verification via direct MX server connection"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)

        # 1. Resolve MX records
        mx_hosts = []
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(domain, "MX")
            )
            mx_hosts = sorted([str(r.exchange).rstrip(".") for r in answers], key=lambda x: x)
        except Exception:
            # Fallback: try A record on the domain itself
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "A")
                )
                mx_hosts = [str(r) for r in answers]
            except Exception:
                return PluginResult(
                    plugin_name=self.name,
                    success=True,
                    data={
                        "email": target,
                        "domain": domain,
                        "mx_hosts": [],
                        "exists": None,
                        "status": "no_mx_records",
                        "details": "No MX or A records found for domain",
                    },
                )

        if not mx_hosts:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "email": target,
                    "domain": domain,
                    "mx_hosts": [],
                    "exists": None,
                    "status": "no_mx_records",
                    "details": "Domain has no MX records",
                },
            )

        # 2. Try SMTP verification against each MX host
        for mx_host in mx_hosts:
            result = await self._smtp_check(mx_host, domain, local)
            if result is not None:
                return PluginResult(
                    plugin_name=self.name,
                    success=True,
                    data={
                        "email": target,
                        "domain": domain,
                        "mx_hosts": mx_hosts,
                        "verified_with": mx_host,
                        **result,
                    },
                )

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "domain": domain,
                "mx_hosts": mx_hosts,
                "exists": None,
                "status": "all_mx_failed",
                "details": "Could not verify: all MX servers timed out or refused connection",
            },
        )

    async def _smtp_check(self, mx_host: str, domain: str, local: str) -> dict | None:
        """Attempt SMTP verification against a single MX host. Returns dict or None on failure."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(mx_host, 25), timeout=SMTP_TIMEOUT
            )

            try:
                # Read greeting
                greeting = await asyncio.wait_for(reader.read(1024), timeout=SMTP_TIMEOUT)
                if not greeting:
                    return None

                # Send EHLO
                writer.write(f"EHLO argus-osint.local\r\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(4096), timeout=SMTP_TIMEOUT)

                # Send MAIL FROM
                writer.write(f"MAIL FROM:<verify@argus-osint.local>\r\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=SMTP_TIMEOUT)
                mail_from_resp = resp.decode(errors="ignore")
                if not mail_from_resp.startswith(b"2" if isinstance(resp, bytes) else "2"):
                    code = mail_from_resp[:3] if mail_from_resp else "???"
                    return {
                        "exists": None,
                        "status": "mail_from_rejected",
                        "response_code": code,
                        "details": f"MAIL FROM rejected by {mx_host}",
                    }

                # Send RCPT TO
                writer.write(f"RCPT TO:<{local}@{domain}>\r\n".encode())
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=SMTP_TIMEOUT)
                rcpt_resp = resp.decode(errors="ignore")
                code = rcpt_resp[:3] if rcpt_resp else "???"

                # Send QUIT
                writer.write(b"QUIT\r\n")
                await writer.drain()
                await asyncio.wait_for(reader.read(1024), timeout=5)

                if code.startswith("2"):
                    return {
                        "exists": True,
                        "status": "mailbox_exists",
                        "response_code": code,
                        "details": "RCPT TO accepted — mailbox likely exists",
                    }
                elif code.startswith("5"):
                    return {
                        "exists": False,
                        "status": "mailbox_not_found",
                        "response_code": code,
                        "details": f"RCPT TO rejected ({code}) — mailbox does not exist",
                    }
                else:
                    # 4xx or unknown — indeterminate
                    return {
                        "exists": None,
                        "status": "indeterminate",
                        "response_code": code,
                        "details": f"RCPT TO returned {code} — result indeterminate (server may greylist)",
                    }
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except asyncio.TimeoutError:
            return {
                "exists": None,
                "status": "timeout",
                "details": f"Connection to {mx_host}:25 timed out",
            }
        except ConnectionRefusedError:
            return None  # Try next MX
        except OSError:
            return None  # Try next MX
        except Exception:
            return None