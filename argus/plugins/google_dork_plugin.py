import asyncio
import re
from html import unescape
from urllib.parse import quote_plus

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class GoogleDorkPlugin(BasePlugin):
    name = "google_dorks"
    description = "Automated Google dorking via DuckDuckGo for sensitive files and admin panels"
    supported_target_types = ["domain", "url", "email", "username"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            if "@" in domain:
                domain = domain.split("@")[-1]

            dorks = [
                f"site:{domain} filetype:pdf",
                f"site:{domain} filetype:xlsx",
                f"site:{domain} filetype:doc",
                f"site:{domain} inurl:admin",
                f"site:{domain} inurl:login",
                f"site:{domain} intitle:index.of",
            ]

            results: dict = {"domain": domain, "dorks": {}}
            all_findings: list[dict] = []

            async def search_dork(dork: str):
                try:
                    query = quote_plus(dork)
                    url = f"https://html.duckduckgo.com/html/?q={query}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as session:
                        async with session.get(url) as resp:
                            if resp.status != 200:
                                results["dorks"][dork] = []
                                return
                            html = await resp.text()

                    urls = re.findall(r'class="result__a"[^>]*href="([^"]+)"', html)
                    if not urls:
                        urls = re.findall(r'<a[^>]+class="result__a"[^>]*>(.*?)</a>', html)
                        cleaned = []
                        for u in urls:
                            link = re.search(r'href="(https?://[^"]+)"', u)
                            if link:
                                cleaned.append(unescape(link.group(1)))
                        urls = cleaned

                    if not urls:
                        url_matches = re.findall(r'https?://[^\s"\'<>]+', html)
                        urls = [u for u in url_matches if domain in u][:10]

                    urls = urls[:10]
                    results["dorks"][dork] = urls
                    for u in urls:
                        all_findings.append({"dork": dork, "url": u})
                except Exception:
                    results["dorks"][dork] = []

            await asyncio.gather(*[search_dork(d) for d in dorks])

            results["total_findings"] = len(all_findings)
            results["findings"] = all_findings

            if not all_findings:
                return PluginResult(plugin_name=self.name, success=False, error="No dork results found")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))