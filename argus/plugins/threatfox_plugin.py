"""
abuse.ch ThreatFox plugin — free, no API key required.
Queries the ThreatFox IOC database by domain, IP, URL, email, or hash.
Endpoint: https://threatfox-api.abuse.ch/api/v1/
"""
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


class ThreatFoxPlugin(BasePlugin):
    name = "threatfox"
    description = "abuse.ch ThreatFox — search IOC database for domains, IPs, URLs, emails"
    supported_target_types = ["domain", "url", "ip", "email"]

    async def run(self, target: str) -> PluginResult:
        try:
            # Strip URL scheme + path so we search the bare host where useful,
            # but ThreatFox also accepts full URLs/hashes, so pass target through.
            ioc = target.strip()
            payload = {"query": "search_ioc", "search_term": ioc}
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json=payload,
                    headers={**HEADERS, "Content-Type": "application/json"},
                ) as r:
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            status = data.get("query_status", "unknown")
            matches = data.get("data") or []

            # query_status "ok" with non-empty data => found
            found = bool(matches) and status == "ok"

            # Build a compact summary list per match
            compact = []
            for m in matches:
                compact.append({
                    "id": m.get("id"),
                    "ioc": m.get("ioc"),
                    "ioc_type": m.get("ioc_type"),
                    "threat_type": m.get("threat_type"),
                    "malware": m.get("malware_printable") or m.get("malware"),
                    "confidence": m.get("confidence_level"),
                    "first_seen": m.get("first_seen_utc"),
                    "reporter": m.get("reporter"),
                    "tags": m.get("tags", []),
                })

            summary = (
                f"ThreatFox: {len(compact)} IOC match(es), status={status}"
                if compact
                else f"ThreatFox: no matches (status={status})"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "query_status": status,
                    "matches": compact,
                    "found": found,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e),
            )
