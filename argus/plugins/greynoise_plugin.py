"""
GreyNoise Community API plugin — free, no API key required for the
community endpoint. Looks up an IP's classification (benign / malicious /
unknown), RIOT status, and internet-scanner noise.
Endpoint: https://api.greynoise.io/v3/community/<ip>
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class GreyNoisePlugin(BasePlugin):
    name = "greynoise"
    description = "GreyNoise Community — IP classification, RIOT, scanner noise (no key)"
    supported_target_types = ["ip"]

    async def run(self, target: str) -> PluginResult:
        try:
            ip = target.strip()
            # If given a URL, try to extract host and accept if it's an IP
            if "://" in ip:
                ip = ip.split("://", 1)[1].split("/", 1)[0]
            if not IP_RE.match(ip):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error=f"Not an IPv4 address: {ip}",
                )

            url = f"https://api.greynoise.io/v3/community/{ip}"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status == 404:
                        return PluginResult(
                            plugin_name=self.name,
                            success=True,
                            data={
                                "ip": ip,
                                "classification": "unknown",
                                "riot": False,
                                "last_seen": None,
                                "noise": False,
                                "link": None,
                                "summary": f"GreyNoise: no record for {ip}",
                            },
                        )
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            classification = data.get("classification", "unknown")
            riot = bool(data.get("riot", False))
            noise = bool(data.get("noise", False))
            last_seen = data.get("last_seen")
            link = data.get("link")
            name = data.get("name")
            message = data.get("message", "")

            summary_parts = [f"GreyNoise: {ip} -> {classification}"]
            if name:
                summary_parts.append(f"name={name}")
            if riot:
                summary_parts.append("RIOT (known benign)")
            if noise:
                summary_parts.append("internet scanner (noisy)")
            summary = ", ".join(summary_parts)
            if message:
                summary += f" | {message}"

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "ip": ip,
                    "classification": classification,
                    "riot": riot,
                    "last_seen": last_seen,
                    "noise": noise,
                    "name": name,
                    "link": link,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e),
            )
