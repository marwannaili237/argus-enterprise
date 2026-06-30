"""
urlscan.io plugin — free anonymous search (limited rate).
Searches recent public scans by domain. If URLSCAN_API_KEY is set in env,
it is sent as `API-Key` header for higher rate limits.
Endpoint: https://urlscan.io/api/v1/search/?q=domain:<host>
"""
import os
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


class UrlScanPlugin(BasePlugin):
    name = "urlscan"
    description = "urlscan.io — search recent public scans for a domain (key optional)"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            # Extract host from URL if needed
            host = target.strip()
            if "://" in host:
                host = host.split("://", 1)[1].split("/", 1)[0]
            # Drop userinfo / port noise
            host = host.split("@")[-1]

            api_key = os.environ.get("URLSCAN_API_KEY")
            hdrs = dict(HEADERS)
            if api_key:
                hdrs["API-Key"] = api_key

            url = f"https://urlscan.io/api/v1/search/?q=domain:{host}"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=hdrs) as r:
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            total = int(data.get("total") or 0)
            results = data.get("results") or []

            scans = []
            malicious = 0
            for entry in results:
                page = entry.get("_page") or {}
                verdicts = entry.get("verdicts") or {}
                overall = verdicts.get("overall") or {}
                is_malicious = bool(overall.get("malicious"))
                if is_malicious:
                    malicious += 1
                scans.append({
                    "url": page.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "status": page.get("status"),
                    "task_time": (entry.get("task") or {}).get("time"),
                    "report_url": f"https://urlscan.io/result/{(entry.get('_id') or '')}/",
                    "malicious": is_malicious,
                    "verdict": overall.get("tags") or [],
                    "score": overall.get("score"),
                })

            summary = (
                f"urlscan.io: {total} scan(s) for {host}, {malicious} flagged malicious"
                if total
                else f"urlscan.io: no public scans for {host}"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "scans": scans,
                    "total": total,
                    "malicious": malicious,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e),
            )
