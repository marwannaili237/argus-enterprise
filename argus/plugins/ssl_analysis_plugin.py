import asyncio
import ssl
import socket
from datetime import datetime, timezone

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class SslAnalysisPlugin(BasePlugin):
    name = "ssl_analysis"
    description = "SSL/TLS certificate analysis with HSTS and chain validation"
    supported_target_types = ["domain", "url", "ip"]

    async def run(self, target: str) -> PluginResult:
        try:
            host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

            loop = asyncio.get_event_loop()

            def get_cert():
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
                conn.settimeout(8)
                try:
                    conn.connect((host, 443))
                except socket.timeout:
                    conn.close()
                    return None
                cert_der = conn.getpeercert(binary_form=True)
                cert_dict = conn.getpeercert()
                conn.close()
                return cert_dict

            cert_dict = await loop.run_in_executor(None, get_cert)

            if not cert_dict:
                return PluginResult(plugin_name=self.name, success=False, error="Could not retrieve SSL certificate")

            issuer = dict(x[0] for x in cert_dict.get("issuer", []))
            subject = dict(x[0] for x in cert_dict.get("subject", []))
            san_ext = None
            for ext in cert_dict.get("extensions", []):
                if ext[0] == "subjectAltName":
                    san_ext = ext[1]
                    break

            not_before = cert_dict.get("notBefore")
            not_after = cert_dict.get("notAfter")
            now = datetime.now(timezone.utc)

            def parse_date(d):
                try:
                    return datetime.strptime(d, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                except Exception:
                    return None

            nb = parse_date(not_before) if not_before else None
            na = parse_date(not_after) if not_after else None
            days_remaining = (na - now).days if na else None

            results: dict = {
                "host": host,
                "issuer": issuer,
                "subject": subject,
                "version": cert_dict.get("version"),
                "serial_number": cert_dict.get("serialNumber"),
                "signature_algorithm": cert_dict.get("signatureAlgorithm"),
                "not_before": not_before,
                "not_after": not_after,
                "days_remaining": days_remaining,
                "is_expired": days_remaining is not None and days_remaining < 0,
                "is_expiring_soon": days_remaining is not None and 0 <= days_remaining <= 30,
                "sans": san_ext,
                "hsts": None,
            }

            # Check HSTS
            try:
                async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=8)) as session:
                    async with session.head(f"https://{host}", ssl=False, allow_redirects=False) as resp:
                        hsts = resp.headers.get("Strict-Transport-Security", "")
                        results["hsts"] = {
                            "enabled": bool(hsts),
                            "value": hsts if hsts else None,
                        }
            except Exception:
                results["hsts"] = {"enabled": False, "error": "unreachable"}

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))