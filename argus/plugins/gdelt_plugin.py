"""
GDELT Project plugin — free global news/event tracking.
Queries the GDELT DOC 2.0 API (ArtList mode) for articles mentioning a
person, company, or domain. Aggregates languages, top source domains, and
produces a short summary.
"""
from collections import Counter
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
MAX_RECORDS = 20


class GdeltPlugin(BasePlugin):
    name = "gdelt"
    description = "GDELT Project — global news article search and event tracking"
    supported_target_types = ["person", "company", "domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            # Strip protocol/path for cleaner search if target is a URL/domain
            if "://" in query:
                query = query.split("://", 1)[1]
            query = query.split("/")[0] if query.startswith(("http", "www.")) else query

            params = {
                "query": f'"{query}"',
                "mode": "ArtList",
                "maxrecords": str(MAX_RECORDS),
                "format": "json",
                "sort": "DateDesc",
            }
            url = (
                "https://api.gdeltproject.org/api/v2/doc/doc?"
                + urllib.parse.urlencode(params)
            )

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    try:
                        data = await r.json(content_type=None)
                    except Exception:
                        # GDELT sometimes returns non-JSON errors as text
                        text = await r.text()
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"non-JSON response: {text[:120]}",
                        )

            articles_raw = data.get("articles", []) if isinstance(data, dict) else []
            articles = []
            languages = Counter()
            domains = Counter()
            for art in articles_raw:
                title = art.get("title") or ""
                link = art.get("url") or ""
                domain = art.get("domain") or ""
                lang = (art.get("language") or "unknown").lower()
                date = art.get("seendate") or art.get("date") or ""
                articles.append(
                    {
                        "title": title,
                        "url": link,
                        "domain": domain,
                        "language": lang,
                        "date": date,
                    }
                )
                if lang:
                    languages[lang] += 1
                if domain:
                    domains[domain] += 1

            total = len(articles)
            top_domains = [{"domain": d, "count": c} for d, c in domains.most_common(5)]
            lang_dist = {lang: cnt for lang, cnt in languages.most_common()}

            if total == 0:
                summary = f"No GDELT articles found for '{query}'."
            else:
                summary = (
                    f"Found {total} GDELT articles mentioning '{query}' "
                    f"across {len(domains)} source domains and "
                    f"{len(languages)} language(s)."
                )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "articles": articles,
                    "total": total,
                    "languages": lang_dist,
                    "top_domains": top_domains,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )
