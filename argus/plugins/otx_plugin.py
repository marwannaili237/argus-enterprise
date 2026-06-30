"""
AlienVault OTX plugin — free, no API key required (optional OTX_API_KEY
env var enables higher rate limits / private pulses).
Looks up domain / IP / URL against OTX pulses.

Endpoint: https://otx.alienvault.com/api/v1/indicators/{type}/{ioc}/general
  - domain -> /indicators/domain/<host>/general
  - ip     -> /indicators/IPv4/<ip>/general
  - url    -> extract host, query as domain
"""
import os
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class OtxPlugin(BasePlugin):
    name = "otx"
    description = "AlienVault OTX — pulses for domain / IP / URL (key optional)"
    supported_target_types = ["domain", "url", "ip"]

    @staticmethod
    def _extract_host(target: str) -> str:
        host = target.strip()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]
        host = host.split("@")[-1]
        host = host.split(":")[0]
        return host

    async def run(self, target: str) -> PluginResult:
        try:
            t = target.strip()
            host = self._extract_host(t)

            if IP_RE.match(host):
                endpoint = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{host}/general"
            else:
                endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"

            hdrs = dict(HEADERS)
            api_key = os.environ.get("OTX_API_KEY")
            if api_key:
                hdrs["X-OTX-API-KEY"] = api_key

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(endpoint, headers=hdrs) as r:
                    if r.status == 404:
                        return PluginResult(
                            plugin_name=self.name,
                            success=True,
                            data={
                                "pulse_count": 0,
                                "pulses": [],
                                "references": [],
                                "found": False,
                                "summary": f"OTX: no record for {host}",
                            },
                        )
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            pulse_info = data.get("pulse_info") or {}
            pulse_count = int(pulse_info.get("count") or 0)
            raw_pulses = pulse_info.get("pulses") or []

            pulses = []
            references = []
            for p in raw_pulses[:5]:
                pid = p.get("id") or p.get("_id")
                pulses.append({
                    "id": pid,
                    "title": p.get("name"),
                    "adversary": p.get("adversary"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "tags": p.get("tags", []),
                    "tlp": p.get("TLP"),
                    "subscriber_count": p.get("subscriber_count"),
                    "attack_ids": p.get("attack_ids", []),
                    "reporter": (p.get("author") or {}).get("username")
                        if isinstance(p.get("author"), dict) else p.get("author_name"),
                })
                # References may be list of strings OR list of dicts
                for ref in p.get("references", []) or []:
                    if isinstance(ref, str):
                        references.append(ref)
                    elif isinstance(ref, dict):
                        references.append(
                            ref.get("url")
                            or ref.get("link")
                            or ref.get("title")
                            or str(ref)[:200]
                        )

            # Dedupe references and cap
            seen = set()
            deduped_refs = []
            for r_ in references:
                if r_ and r_ not in seen:
                    seen.add(r_)
                    deduped_refs.append(r_)
            references = deduped_refs[:10]

            found = pulse_count > 0 or bool(pulses)
            summary = (
                f"OTX: {pulse_count} pulse(s) referencing {host}"
                if found
                else f"OTX: no pulses for {host}"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "pulse_count": pulse_count,
                    "pulses": pulses,
                    "references": references,
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
