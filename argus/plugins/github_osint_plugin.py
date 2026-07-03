"""
GitHub OSINT plugin — searches GitHub for mentions of the target:
code, commits, repos, users, issues, and gists.
Completely free, uses the public unauthenticated GitHub Search API.
"""
import asyncio
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "ArgusOSINT/1.0",
    "Accept": "application/vnd.github.v3+json",
}

BASE = "https://api.github.com"


class GithubOsintPlugin(BasePlugin):
    name = "github_osint"
    description = "GitHub code/commit/repo/user search for target mentions"
    supported_target_types = ["domain", "email", "username", "ip"]

    async def run(self, target: str) -> PluginResult:
        query = target.strip().lstrip("@")
        enc = urllib.parse.quote(f'"{query}"')
        results = {}

        async def search_code():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(f"{BASE}/search/code?q={enc}&per_page=5", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["code"] = {
                                "total": data.get("total_count", 0),
                                "items": [
                                    {
                                        "file": i.get("name"),
                                        "path": i.get("path"),
                                        "repo": i.get("repository", {}).get("full_name"),
                                        "url": i.get("html_url"),
                                        "score": i.get("score"),
                                    }
                                    for i in data.get("items", [])[:5]
                                ],
                            }
            except Exception:
                pass

        async def search_commits():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"{BASE}/search/commits?q={enc}&per_page=5",
                        headers={**HEADERS, "Accept": "application/vnd.github.cloak-preview"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["commits"] = {
                                "total": data.get("total_count", 0),
                                "items": [
                                    {
                                        "message": i.get("commit", {}).get("message", "")[:100],
                                        "author": i.get("commit", {}).get("author", {}).get("name"),
                                        "date": i.get("commit", {}).get("author", {}).get("date"),
                                        "repo": i.get("repository", {}).get("full_name"),
                                        "url": i.get("html_url"),
                                    }
                                    for i in data.get("items", [])[:5]
                                ],
                            }
            except Exception:
                pass

        async def search_repos():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(f"{BASE}/search/repositories?q={enc}&per_page=5&sort=updated", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["repos"] = {
                                "total": data.get("total_count", 0),
                                "items": [
                                    {
                                        "name": i.get("full_name"),
                                        "description": (i.get("description") or "")[:100],
                                        "stars": i.get("stargazers_count"),
                                        "url": i.get("html_url"),
                                        "updated": i.get("updated_at", "")[:10],
                                    }
                                    for i in data.get("items", [])[:5]
                                ],
                            }
            except Exception:
                pass

        async def search_users():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(f"{BASE}/search/users?q={urllib.parse.quote(query)}&per_page=5", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["users"] = {
                                "total": data.get("total_count", 0),
                                "items": [
                                    {
                                        "login": i.get("login"),
                                        "url": i.get("html_url"),
                                        "avatar": i.get("avatar_url"),
                                        "type": i.get("type"),
                                    }
                                    for i in data.get("items", [])[:5]
                                ],
                            }
            except Exception:
                pass

        async def search_issues():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(f"{BASE}/search/issues?q={enc}&per_page=3", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["issues"] = {
                                "total": data.get("total_count", 0),
                                "items": [
                                    {
                                        "title": i.get("title", "")[:100],
                                        "repo": i.get("repository_url", "").split("repos/")[-1],
                                        "url": i.get("html_url"),
                                        "state": i.get("state"),
                                    }
                                    for i in data.get("items", [])[:3]
                                ],
                            }
            except Exception:
                pass

        # Sequential to avoid hitting GitHub's 10 req/min unauthenticated limit
        for coro in [search_code, search_repos, search_users, search_commits, search_issues]:
            await coro()
            await asyncio.sleep(0.5)

        total_exposure = sum([
            results.get("code", {}).get("total", 0),
            results.get("commits", {}).get("total", 0),
            results.get("repos", {}).get("total", 0),
            results.get("issues", {}).get("total", 0),
        ])

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "query": query,
                "total_github_exposure": total_exposure,
                "code_mentions": results.get("code", {}),
                "commits": results.get("commits", {}),
                "repos": results.get("repos", {}),
                "users": results.get("users", {}),
                "issues": results.get("issues", {}),
            },
        )
