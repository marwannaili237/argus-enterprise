"""
Subdomain enumeration plugin — multi-source: HackerTarget, crt.sh (extended),
DNSdumpster scraping, RapidDNS, ViewDNS, and common wordlist brute-force.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3",
    "vpn", "api", "dev", "staging", "test", "admin", "portal", "app", "mobile",
    "m", "shop", "store", "blog", "cdn", "static", "assets", "media", "img",
    "images", "upload", "downloads", "files", "support", "help", "docs", "wiki",
    "forum", "community", "status", "monitor", "dashboard", "panel", "cp",
    "webmail", "remote", "secure", "ssl", "mx", "mx1", "mx2", "email", "smtp2",
    "web", "web1", "web2", "server", "cloud", "aws", "azure", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "bitbucket", "grafana", "prometheus",
    "elastic", "kibana", "redis", "db", "database", "mysql", "postgres", "mongo",
    "dev2", "staging2", "beta", "alpha", "preview", "old", "legacy", "v1", "v2",
    "api2", "api-v1", "api-v2", "graphql", "ws", "websocket", "socket", "io",
    "metrics", "logs", "analytics", "tracking", "events", "webhook", "webhooks",
    "internal", "intranet", "corp", "private", "management", "ops", "devops",
]


def _extract_host(target: str) -> str:
    if "://" in target:
        return target.split("://")[1].split("/")[0]
    return target


class SubdomainPlugin(BasePlugin):
    name = "subdomains"
    description = "Multi-source subdomain enumeration: HackerTarget, RapidDNS, ViewDNS, brute-force"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        domain = _extract_host(target)
        all_subdomains: set = set()

        async def hackertarget():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                    async with s.get(
                        f"https://api.hackertarget.com/hostsearch/?q={domain}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if "error" not in text.lower():
                                for line in text.strip().splitlines():
                                    if "," in line:
                                        sub = line.split(",")[0].strip().lower()
                                        if sub.endswith(f".{domain}") or sub == domain:
                                            all_subdomains.add(sub)
            except Exception:
                pass

        async def rapiddns():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://rapiddns.io/subdomain/{domain}?full=1",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Parse HTML table
                            pattern = re.compile(r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')</td>')
                            for match in pattern.finditer(text):
                                all_subdomains.add(match.group(1).lower())
            except Exception:
                pass

        async def viewdns():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://viewdns.info/reverseip/?host={domain}&t=1",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            pattern = re.compile(r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')</td>')
                            for match in pattern.finditer(text):
                                all_subdomains.add(match.group(1).lower())
            except Exception:
                pass

        async def dnsdumpster():
            """DNSdumpster requires CSRF token — use hackertarget instead"""
            pass

        async def crt_sh_extended():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                    async with s.get(
                        f"https://crt.sh/?q=%.{domain}&output=json",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            for cert in data:
                                for name in cert.get("name_value", "").splitlines():
                                    name = name.strip().lower().lstrip("*.")
                                    if name.endswith(f".{domain}") or name == domain:
                                        all_subdomains.add(name)
            except Exception:
                pass

        async def brute_force_common():
            """DNS brute-force against common subdomain wordlist"""
            import socket
            loop = asyncio.get_event_loop()
            found = []
            sem = asyncio.Semaphore(20)

            async def check_sub(sub: str):
                async with sem:
                    fqdn = f"{sub}.{domain}"
                    try:
                        result = await loop.run_in_executor(
                            None, lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
                        )
                        ips = [r[4][0] for r in result]
                        return {"subdomain": fqdn, "ips": ips}
                    except Exception:
                        return None

            tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    all_subdomains.add(r["subdomain"])
                    found.append(r)
            return found

        brute_task = asyncio.create_task(brute_force_common())
        await asyncio.gather(hackertarget(), rapiddns(), crt_sh_extended())
        brute_results = await brute_task

        sorted_subs = sorted(all_subdomains)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "domain": domain,
                "total_found": len(sorted_subs),
                "subdomains": sorted_subs[:200],
                "brute_force_confirmed": brute_results,
                "sources": ["hackertarget", "rapiddns", "crt.sh", "dns-brute"],
            },
        )
