"""
Email reverse search plugin — search for the email across multiple sources:
paste sites (psbdmp.ws), DuckDuckGo HTML search (quoted email), GitHub code
search, and IntelX free search. Returns all found occurrences with URLs and
context snippets.
"""
import asyncio
import re
import aiohttp
from html import unescape
from urllib.parse import quote
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailReversePlugin(BasePlugin):
    name = "email_reverse"
    description = "Reverse search email across pastes, DuckDuckGo, GitHub code, and IntelX"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        occurrences: list[dict] = []
        results: dict = {}

        async def search_psbdmp():
            """Search psbdmp.ws for pastes containing the email."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://psbdmp.ws/api/v3/search/{target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            pastes = data.get("data", [])
                            for p in pastes[:15]:
                                occurrences.append({
                                    "source": "psbdmp",
                                    "title": p.get("title", "Untitled"),
                                    "url": f"https://psbdmp.ws/{p.get('id', '')}",
                                    "date": p.get("date"),
                                    "snippet": self._clean_html(p.get("text", ""))[:200],
                                })
                            results["psbdmp_total"] = data.get("count", len(pastes))
            except Exception:
                pass

        async def search_duckduckgo():
            """Search DuckDuckGo for the quoted email."""
            try:
                queries = [
                    f'"{target}"',
                    f'"{target}" password',
                    f'"{target}" leak',
                ]
                ddg_results: list[dict] = []
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    for q in queries:
                        try:
                            url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
                            async with s.get(url, headers=HEADERS) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    # Extract result URLs and snippets
                                    links = re.findall(
                                        r'class="result__a"[^>]*href="([^"]+)"',
                                        text
                                    )
                                    # Get snippets
                                    snippets = re.findall(
                                        r'class="result__snippet"[^>]*>(.*?)</a>',
                                        text, re.DOTALL
                                    )
                                    for i, link in enumerate(links[:10]):
                                        snippet = ""
                                        if i < len(snippets):
                                            snippet = self._clean_html(snippets[i])[:150]
                                        ddg_results.append({
                                            "url": unescape(link),
                                            "snippet": snippet,
                                            "query": q,
                                        })
                        except Exception:
                            pass

                for r_item in ddg_results[:15]:
                    occurrences.append({
                        "source": "duckduckgo",
                        "url": r_item["url"],
                        "snippet": r_item["snippet"],
                        "query": r_item.get("query"),
                    })
                results["duckduckgo_results"] = len(ddg_results)
            except Exception:
                pass

        async def search_github_code():
            """Search GitHub code for the email."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/code?q={quote(target)}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            items = data.get("items", [])
                            total = data.get("total_count", 0)
                            for item in items[:10]:
                                repo = item.get("repository", {})
                                occurrences.append({
                                    "source": "github_code",
                                    "repo": repo.get("full_name", ""),
                                    "path": item.get("path", ""),
                                    "url": item.get("html_url", ""),
                                    "snippet": f"Found in {repo.get('full_name', '')}/{item.get('path', '')}",
                                })
                            results["github_code_total"] = total
            except Exception:
                pass

        async def search_github_users():
            """Search GitHub users by email."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/users?q={quote(target)}+in:email"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            users = data.get("items", [])
                            for u in users[:5]:
                                occurrences.append({
                                    "source": "github_user",
                                    "login": u.get("login", ""),
                                    "url": u.get("html_url", ""),
                                    "snippet": f"GitHub user: {u.get('login', '')}",
                                })
                            results["github_users_found"] = len(users)
            except Exception:
                pass

        async def search_intelx():
            """Search IntelX (free tier) for the email."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = "https://2.intelx.io/public/search"
                    payload = {
                        "term": target,
                        "maxresults": 10,
                        "media": 0,
                        "sort": 2,
                    }
                    async with s.post(url, json=payload, headers={
                        **HEADERS,
                        "Content-Type": "application/json",
                        "x-key": "none",
                    }) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["intelx_id"] = data.get("id")
                            results["intelx_status"] = data.get("status")
                            # IntelX returns async — we note the search was initiated
                            if data.get("id"):
                                results["intelx_search_initiated"] = True
                                occurrences.append({
                                    "source": "intelx",
                                    "url": f"https://intelx.io/?s={quote(target)}",
                                    "snippet": f"IntelX search initiated (id: {data.get('id', '')[:16]}…)",
                                    "note": "Results available on IntelX website",
                                })
            except Exception:
                pass

        await asyncio.gather(
            search_psbdmp(),
            search_duckduckgo(),
            search_github_code(),
            search_github_users(),
            search_intelx(),
        )

        # Build risk assessment
        risk_flags = []
        total = len(occurrences)
        if total >= 10:
            risk_flags.append(f"🚨 HIGH EXPOSURE: {total} occurrences found")
        elif total >= 5:
            risk_flags.append(f"⚠️ Moderate exposure: {total} occurrences")
        elif total >= 1:
            risk_flags.append(f"📋 Low exposure: {total} occurrences")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "total_occurrences": total,
                "occurrences": occurrences[:30],
                "by_source": self._group_by_source(occurrences),
                "psbdmp_total": results.get("psbdmp_total", 0),
                "duckduckgo_results": results.get("duckduckgo_results", 0),
                "github_code_total": results.get("github_code_total", 0),
                "github_users_found": results.get("github_users_found", 0),
                "intelx_search_initiated": results.get("intelx_search_initiated", False),
                "risk_flags": risk_flags,
            },
        )

    def _clean_html(self, text: str) -> str:
        """Strip HTML tags and decode entities."""
        clean = re.sub(r"<[^>]+>", "", text)
        clean = unescape(clean)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

    def _group_by_source(self, occurrences: list[dict]) -> dict[str, int]:
        """Group occurrences by source and count."""
        counts: dict[str, int] = {}
        for o in occurrences:
            src = o.get("source", "unknown")
            counts[src] = counts.get(src, 0) + 1
        return counts