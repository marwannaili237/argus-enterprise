import asyncio

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}

ONION_PROXIES = [
    "https://onion.danwin1210.de",
    "https://tor2web.fi",
]


class OnionCheckerPlugin(BasePlugin):
    name = "onion_checker"
    description = "Check for .onion equivalent and Tor search engine indexing"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            onion_domain = domain.split(".")[0] + ".onion"

            results: dict = {
                "original_domain": domain,
                "onion_domain": onion_domain,
                "proxies": {},
                "search_engines": {},
            }

            async def check_proxy(proxy_base: str):
                try:
                    url = f"{proxy_base}/{onion_domain}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as session:
                        async with session.get(url, allow_redirects=False, ssl=False) as resp:
                            results["proxies"][proxy_base] = {
                                "status": resp.status,
                                "reachable": 200 <= resp.status < 400,
                                "server": resp.headers.get("Server", ""),
                            }
                except Exception as e:
                    results["proxies"][proxy_base] = {"reachable": False, "error": str(e)}

            async def check_ahmia():
                try:
                    url = f"https://ahmia.fi/search/?q={onion_domain}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url, ssl=False) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                # Look for results in the page
                                found = onion_domain.replace(".onion", "") in text.lower()
                                results["search_engines"]["ahmia"] = {
                                    "indexed": found,
                                    "url": url,
                                }
                            else:
                                results["search_engines"]["ahmia"] = {"indexed": False, "error": f"status {resp.status}"}
                except Exception as e:
                    results["search_engines"]["ahmia"] = {"indexed": False, "error": str(e)}

            async def check_tor66():
                try:
                    url = f"https://tor66.seweb.org/search?q={onion_domain}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url, ssl=False) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                found = onion_domain.replace(".onion", "") in text.lower()
                                results["search_engines"]["tor66"] = {
                                    "indexed": found,
                                    "url": url,
                                }
                            else:
                                results["search_engines"]["tor66"] = {"indexed": False, "error": f"status {resp.status}"}
                except Exception as e:
                    results["search_engines"]["tor66"] = {"indexed": False, "error": str(e)}

            tasks = [check_proxy(p) for p in ONION_PROXIES]
            tasks += [check_ahmia(), check_tor66()]
            await asyncio.gather(*tasks)

            reachable = any(v.get("reachable") for v in results["proxies"].values())
            indexed = any(v.get("indexed") for v in results["search_engines"].values())

            results["onion_exists"] = reachable
            results["is_indexed"] = indexed

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))