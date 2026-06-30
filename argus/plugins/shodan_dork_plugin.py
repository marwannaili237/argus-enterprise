import asyncio

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class ShodanDorkPlugin(BasePlugin):
    name = "shodan_dork"
    description = "Shodan search via InternetDB and HackerTarget for hosts and services"
    supported_target_types = ["domain", "url", "ip"]

    async def run(self, target: str) -> PluginResult:
        try:
            # Extract host for IP/domain
            host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

            results: dict = {"target": target, "internetdb": None, "hackertarget": None}

            # Try to resolve domain to IP for InternetDB
            import dns.resolver
            ip_address = host

            if not host.replace(".", "").isdigit():
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    answers = resolver.resolve(host, "A")
                    ip_address = str(answers[0])
                except Exception:
                    ip_address = None

            async def fetch_internetdb():
                nonlocal ip_address
                if not ip_address:
                    return
                try:
                    url = f"https://internetdb.shodan.io/{ip_address}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                results["internetdb"] = data
                                results["ip"] = ip_address
                except Exception as e:
                    results["internetdb_error"] = str(e)

            async def fetch_hackertarget():
                try:
                    url = f"https://api.hackertarget.com/shodansearch/?q={host}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                if not text.startswith("error"):
                                    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
                                    results["hackertarget"] = {
                                        "raw_results": text[:5000],
                                        "result_count": len(lines),
                                        "results": lines[:50],
                                    }
                                else:
                                    results["hackertarget"] = {"error": text.strip()}
                except Exception as e:
                    results["hackertarget_error"] = str(e)

            await asyncio.gather(fetch_internetdb(), fetch_hackertarget())

            has_data = results.get("internetdb") or (results.get("hackertarget") and not results["hackertarget"].get("error"))
            if not has_data:
                return PluginResult(plugin_name=self.name, success=False, error="No Shodan data found for target")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))