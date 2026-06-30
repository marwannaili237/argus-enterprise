"""
VirusTotal v3 plugin — requires a free API key (env VIRUSTOTAL_API_KEY).
Looks up domains, IPs, and URLs. If the key is missing, returns
success=False with a clear error so callers can skip gracefully.

URL lookups use VT's base64url-without-padding URL identifier.
"""
import os
import base64
import re
from datetime import datetime, timezone

import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class VirusTotalPlugin(BasePlugin):
    name = "virustotal"
    description = "VirusTotal v3 — domain / IP / URL reputation (free API key required)"
    supported_target_types = ["domain", "url", "ip"]

    @staticmethod
    def _vt_url_id(url: str) -> str:
        # VT v3 URL identifier = base64url without padding
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    async def run(self, target: str) -> PluginResult:
        try:
            api_key = os.environ.get("VIRUSTOTAL_API_KEY")
            if not api_key:
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error="VIRUSTOTAL_API_KEY not set",
                )

            t = target.strip()
            hdrs = {**HEADERS, "x-apikey": api_key}

            # Decide endpoint based on target shape
            if t.startswith("http://") or t.startswith("https://"):
                endpoint = f"https://www.virustotal.com/api/v3/urls/{self._vt_url_id(t)}"
            elif IP_RE.match(t):
                endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{t}"
            else:
                # treat as domain; strip any path just in case
                host = t.split("/")[0]
                endpoint = f"https://www.virustotal.com/api/v3/domains/{host}"

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(endpoint, headers=hdrs) as r:
                    if r.status == 404:
                        return PluginResult(
                            plugin_name=self.name,
                            success=True,
                            data={
                                "malicious": 0,
                                "harmless": 0,
                                "suspicious": 0,
                                "undetected": 0,
                                "total": 0,
                                "categories": {},
                                "last_analysis_date": None,
                                "summary": "VirusTotal: no record found",
                            },
                        )
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            attrs = ((data.get("data") or {}).get("attributes")) or {}
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0))
            harmless = int(stats.get("harmless", 0))
            suspicious = int(stats.get("suspicious", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + harmless + suspicious + undetected
            categories = attrs.get("categories") or {}

            last_ts = attrs.get("last_analysis_date")
            last_analysis_date = None
            if isinstance(last_ts, int):
                try:
                    last_analysis_date = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat()
                except Exception:
                    last_analysis_date = str(last_ts)

            if malicious > 0:
                summary = (
                    f"VirusTotal: {malicious}/{total} engine(s) flagged malicious"
                )
            else:
                summary = (
                    f"VirusTotal: 0/{total} malicious "
                    f"({harmless} harmless, {suspicious} suspicious, {undetected} undetected)"
                ) if total else "VirusTotal: no analysis available"

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "malicious": malicious,
                    "harmless": harmless,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "total": total,
                    "categories": categories,
                    "last_analysis_date": last_analysis_date,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e),
            )
