import asyncio
import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/vnd.github.v3+json",
}


class GithubDorkPlugin(BasePlugin):
    name = "github_dorks"
    description = "GitHub code search for exposed secrets and sensitive files"
    supported_target_types = ["domain", "url", "email", "username"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            if "@" in domain:
                domain = domain.split("@")[-1]

            queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" .env',
                f'"{domain}" database_url',
            ]

            all_results: list[dict] = []
            results: dict = {"domain": domain, "queries": {}, "total_findings": 0}

            async def search_query(query: str):
                try:
                    url = f"https://api.github.com/search/code?q={query}"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            data = await resp.json()

                    items = data.get("items", [])
                    total = data.get("total_count", 0)
                    results["queries"][query] = {"total": total, "items": []}

                    for item in items[:5]:
                        repo_info = item.get("repository", {})
                        results["queries"][query]["items"].append({
                            "name": item.get("name"),
                            "path": item.get("path"),
                            "repo": repo_info.get("full_name", ""),
                            "url": item.get("html_url", ""),
                        })
                        all_results.append({
                            "query": query,
                            "file": item.get("path"),
                            "repo": repo_info.get("full_name", ""),
                            "url": item.get("html_url", ""),
                        })

                    await asyncio.sleep(6)
                except Exception as e:
                    results["queries"][query] = {"total": 0, "items": [], "error": str(e)}

            await asyncio.gather(*[search_query(q) for q in queries])

            results["total_findings"] = len(all_results)
            results["findings"] = all_results

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))