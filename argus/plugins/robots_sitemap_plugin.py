import asyncio
import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class RobotsSitemapPlugin(BasePlugin):
    name = "robots_sitemap"
    description = "Parse robots.txt and sitemap.xml for hidden paths and admin panels"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            base_url = f"https://{domain}"

            results: dict = {
                "domain": domain,
                "robots_txt": None,
                "sitemap": None,
            }

            async def fetch_robots():
                try:
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(f"{base_url}/robots.txt", ssl=False) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                disallow = re.findall(r"Disallow:\s*(.+)", text)
                                allow = re.findall(r"Allow:\s*(.+)", text)
                                sitemaps = re.findall(r"Sitemap:\s*(.+)", text)

                                sensitive_paths = [
                                    p.strip() for p in disallow
                                    if any(kw in p.lower() for kw in ["admin", "login", "secret", "private", "internal", "backup", ".env", "config"])
                                ]

                                results["robots_txt"] = {
                                    "found": True,
                                    "disallow_count": len(disallow),
                                    "allow_count": len(allow),
                                    "disallow_paths": [p.strip() for p in disallow[:50]],
                                    "allow_paths": [p.strip() for p in allow[:50]],
                                    "sitemaps_found": [s.strip() for s in sitemaps[:10]],
                                    "sensitive_paths": sensitive_paths,
                                }
                            else:
                                results["robots_txt"] = {"found": False, "status": resp.status}
                except Exception:
                    results["robots_txt"] = {"found": False, "error": "unreachable"}

            async def fetch_sitemap():
                try:
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(f"{base_url}/sitemap.xml", ssl=False) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                urls = re.findall(r"<loc>\s*(.*?)\s*</loc>", text)
                                results["sitemap"] = {
                                    "found": True,
                                    "url_count": len(urls),
                                    "sample_urls": urls[:20],
                                }
                            else:
                                results["sitemap"] = {"found": False, "status": resp.status}
                except Exception:
                    results["sitemap"] = {"found": False, "error": "unreachable"}

            await asyncio.gather(fetch_robots(), fetch_sitemap())

            has_data = (
                results["robots_txt"] and results["robots_txt"].get("found")
            ) or (
                results["sitemap"] and results["sitemap"].get("found")
            )

            if not has_data:
                return PluginResult(plugin_name=self.name, success=False, error="Neither robots.txt nor sitemap.xml found")

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))