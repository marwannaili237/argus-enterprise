"""
Paste hunting plugin — searches multiple paste sites for mentions of the target:
Pastebin, GitHub Gists, paste.ee, ghostbin, and others via scraping.
Also checks IntelX public search for leaked data exposure.
"""
import asyncio
import re
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
}


class PastebinPlugin(BasePlugin):
    name = "pastes"
    description = "Paste hunting across Pastebin, Gists, IntelX, and public paste sites"
    supported_target_types = ["domain", "email", "ip", "username"]

    async def run(self, target: str) -> PluginResult:
        results = {}
        query = target.strip().lstrip("@")

        async def search_github_gists():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://api.github.com/search/code?q={urllib.parse.quote(query)}&type=code",
                        headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            items = data.get("items", [])
                            results["github_code"] = {
                                "total": data.get("total_count", 0),
                                "sample": [
                                    {
                                        "name": i.get("name"),
                                        "path": i.get("path"),
                                        "repo": i.get("repository", {}).get("full_name"),
                                        "url": i.get("html_url"),
                                    }
                                    for i in items[:5]
                                ],
                            }
            except Exception:
                pass

        async def search_pastebin_google():
            """Search Pastebin via DuckDuckGo (no API key needed)"""
            try:
                query_enc = urllib.parse.quote(f'site:pastebin.com "{query}"')
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://html.duckduckgo.com/html/?q={query_enc}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Extract result URLs
                            pattern = re.compile(r'href="(https?://pastebin\.com/[a-zA-Z0-9]+)"')
                            urls = list({m.group(1) for m in pattern.finditer(text)})[:10]
                            results["pastebin_results"] = urls
            except Exception:
                pass

        async def search_psbdmp():
            """psbdmp.ws - Pastebin search engine"""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://psbdmp.ws/api/search/{urllib.parse.quote(query)}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            pastes = data if isinstance(data, list) else data.get("data", [])
                            results["psbdmp"] = [
                                {
                                    "id": p.get("id"),
                                    "url": f"https://pastebin.com/{p.get('id')}",
                                    "time": p.get("time"),
                                }
                                for p in pastes[:10]
                            ]
            except Exception:
                pass

        async def search_intelx_public():
            """IntelX public search (free, rate-limited)"""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                    # Start search
                    search_payload = {
                        "term": query,
                        "buckets": [],
                        "lookuplevel": 0,
                        "maxresults": 10,
                        "timeout": 5,
                        "datefrom": "",
                        "dateto": "",
                        "sort": 2,
                        "media": 0,
                        "terminate": [],
                    }
                    async with s.post(
                        "https://2.intelx.io/intelligent/search",
                        json=search_payload,
                        headers={**HEADERS, "x-key": "null"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            search_id = data.get("id")
                            if search_id:
                                await asyncio.sleep(1)
                                async with s.get(
                                    f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=5&offset=0",
                                    headers={**HEADERS, "x-key": "null"},
                                ) as r2:
                                    if r2.status == 200:
                                        result_data = await r2.json(content_type=None)
                                        records = result_data.get("records", [])
                                        results["intelx"] = {
                                            "total": result_data.get("status", {}).get("found", 0),
                                            "sample": [
                                                {
                                                    "name": rec.get("name"),
                                                    "bucket": rec.get("bucket"),
                                                    "date": rec.get("date"),
                                                    "media": rec.get("media"),
                                                }
                                                for rec in records[:5]
                                            ],
                                        }
            except Exception:
                pass

        async def search_dehashed_public():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://dehashed.com/search?query={urllib.parse.quote(query)}",
                        headers={**HEADERS, "Accept": "text/html"},
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            match = re.search(r'([\d,]+)\s+results? found', text, re.IGNORECASE)
                            if match:
                                results["dehashed_count"] = match.group(1).replace(",", "")
            except Exception:
                pass

        await asyncio.gather(
            search_github_gists(),
            search_pastebin_google(),
            search_psbdmp(),
            search_intelx_public(),
            search_dehashed_public(),
        )

        total_exposure = 0
        if results.get("github_code", {}).get("total", 0):
            total_exposure += results["github_code"]["total"]
        if results.get("pastebin_results"):
            total_exposure += len(results["pastebin_results"])
        if results.get("psbdmp"):
            total_exposure += len(results["psbdmp"])
        if results.get("intelx", {}).get("total"):
            total_exposure += int(results["intelx"]["total"])
        if results.get("dehashed_count"):
            try:
                total_exposure += int(results["dehashed_count"])
            except Exception:
                pass

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "query": query,
                "exposure_score": total_exposure,
                "github_code_results": results.get("github_code", {}).get("total", 0),
                "github_code_sample": results.get("github_code", {}).get("sample", []),
                "pastebin_urls": results.get("pastebin_results", []),
                "psbdmp_pastes": results.get("psbdmp", []),
                "intelx": results.get("intelx"),
                "dehashed_count": results.get("dehashed_count"),
            },
        )
