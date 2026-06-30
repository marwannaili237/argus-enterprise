"""
Shodan InternetDB plugin — completely free, no API key required.
Returns open ports, CPEs, CVEs, hostnames, and tags for any IP.
Also queries Shodan public search for domain exposure.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class ShodanPlugin(BasePlugin):
    name = "shodan"
    description = "Shodan InternetDB — open ports, CVEs, banners, tags (no key)"
    supported_target_types = ["ip", "domain", "url"]

    async def run(self, target: str) -> PluginResult:
        results = {}
        ips_to_check = []

        # Resolve domain → IP if needed
        if not IP_RE.match(target):
            hostname = target
            if "://" in hostname:
                hostname = hostname.split("://")[1].split("/")[0]
            try:
                import socket
                loop = asyncio.get_event_loop()
                info = await loop.run_in_executor(None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET))
                ips_to_check = list({r[4][0] for r in info})[:3]
            except Exception:
                pass
        else:
            ips_to_check = [target]

        async def check_internetdb(ip: str):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(f"https://internetdb.shodan.io/{ip}", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            return {
                                "ip": ip,
                                "open_ports": data.get("ports", []),
                                "hostnames": data.get("hostnames", []),
                                "cpes": data.get("cpes", []),
                                "vulns": data.get("vulns", []),
                                "tags": data.get("tags", []),
                            }
            except Exception:
                pass
            return None

        async def check_shodan_host_count(hostname: str):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    # HackerTarget Shodan-like data
                    async with s.get(
                        f"https://api.hackertarget.com/shodan/?q={hostname}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "error" not in text.lower() and text.strip():
                                results["hackertarget_shodan"] = text.strip()[:500]
            except Exception:
                pass

        tasks = [check_internetdb(ip) for ip in ips_to_check]
        if not IP_RE.match(target):
            hostname = target if "://" not in target else target.split("://")[1].split("/")[0]
            tasks.append(check_shodan_host_count(hostname))

        done = await asyncio.gather(*tasks, return_exceptions=True)

        ip_data = [r for r in done if isinstance(r, dict)]
        results["hosts"] = ip_data

        all_ports = []
        all_vulns = []
        all_cpes = []
        all_tags = []
        for host in ip_data:
            all_ports.extend(host.get("open_ports", []))
            all_vulns.extend(host.get("vulns", []))
            all_cpes.extend(host.get("cpes", []))
            all_tags.extend(host.get("tags", []))

        risk_flags = []
        if all_vulns:
            risk_flags.append(f"🚨 {len(all_vulns)} CVE(s) detected")
        if "honeypot" in all_tags:
            risk_flags.append("🍯 Tagged as HONEYPOT")
        if any(p in all_ports for p in [23, 445, 3389, 5900]):
            risky = [p for p in [23, 445, 3389, 5900] if p in all_ports]
            risk_flags.append(f"⚠️ High-risk ports open: {risky}")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "target": target,
                "ips_checked": ips_to_check,
                "hosts": ip_data,
                "all_open_ports": sorted(set(all_ports)),
                "all_vulns": list(set(all_vulns))[:10],
                "all_cpes": list(set(all_cpes))[:10],
                "all_tags": list(set(all_tags)),
                "risk_flags": risk_flags,
                "hackertarget_shodan": results.get("hackertarget_shodan"),
            },
        )
