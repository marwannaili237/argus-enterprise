"""
Passive DNS & domain history plugin — HackerTarget passive DNS,
ViewDNS IP history, reverse IP lookup, DNS record history, and MX history.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _extract_host(target: str) -> str:
    if "://" in target:
        return target.split("://")[1].split("/")[0]
    return target


class PassiveDnsPlugin(BasePlugin):
    name = "passive_dns"
    description = "DNS history, reverse IP, IP history, past nameservers via HackerTarget/ViewDNS"
    supported_target_types = ["domain", "url", "ip"]

    async def run(self, target: str) -> PluginResult:
        host = _extract_host(target)
        results = {}

        async def hackertarget_passive_dns():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://api.hackertarget.com/dnslookup/?q={host}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "error" not in text.lower():
                                results["dns_records_raw"] = text.strip()
            except Exception:
                pass

        async def hackertarget_reverse_ip():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://api.hackertarget.com/reverseiplookup/?q={host}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "error" not in text.lower():
                                domains = [d.strip() for d in text.strip().splitlines() if d.strip()]
                                results["reverse_ip_domains"] = domains[:50]
                                results["shared_hosting_count"] = len(domains)
            except Exception:
                pass

        async def hackertarget_whois_history():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://api.hackertarget.com/whois/?q={host}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "error" not in text.lower():
                                results["whois_raw"] = text.strip()[:1000]
            except Exception:
                pass

        async def hackertarget_nmap():
            """Quick port scan via HackerTarget nmap (limited to common ports)"""
            if IP_RE.match(host):
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                        async with s.get(
                            f"https://api.hackertarget.com/nmap/?q={host}",
                            headers=HEADERS,
                        ) as r:
                            if r.status == 200:
                                text = await r.text()
                                if "error" not in text.lower():
                                    results["nmap_scan"] = text.strip()[:1000]
                except Exception:
                    pass

        async def viewdns_ip_history():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://viewdns.info/iphistory/?domain={host}",
                        headers={**HEADERS, "Accept": "text/html"},
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Extract IP history from table
                            pattern = re.compile(
                                r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>.*?<td>([^<]+)</td>.*?<td>([^<]+)</td>',
                                re.DOTALL,
                            )
                            history = []
                            for match in pattern.finditer(text):
                                history.append({
                                    "ip": match.group(1),
                                    "location": match.group(2).strip(),
                                    "date": match.group(3).strip(),
                                })
                            if history:
                                results["ip_history"] = history[:10]
            except Exception:
                pass

        async def viewdns_reverse_mx():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://viewdns.info/reversemx/?mx={host}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            pattern = re.compile(r'<td>([a-zA-Z0-9\-\.]+)</td>')
                            domains = list({m.group(1) for m in pattern.finditer(text) if "." in m.group(1)})
                            results["reverse_mx_domains"] = domains[:20]
            except Exception:
                pass

        await asyncio.gather(
            hackertarget_passive_dns(),
            hackertarget_reverse_ip(),
            hackertarget_whois_history(),
            hackertarget_nmap(),
            viewdns_ip_history(),
        )

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "target": host,
                "dns_records_raw": results.get("dns_records_raw"),
                "reverse_ip_domains": results.get("reverse_ip_domains", []),
                "shared_hosting_count": results.get("shared_hosting_count", 0),
                "ip_history": results.get("ip_history", []),
                "nmap_scan": results.get("nmap_scan"),
                "whois_raw": results.get("whois_raw"),
            },
        )
