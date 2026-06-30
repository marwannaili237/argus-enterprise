"""
Crossref plugin — free academic metadata API.
Searches Crossref works by free-text query and returns titles, authors,
publication year, DOI, publisher, type, and abstract (stripped of JATS XML).
"""
import re
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0 (mailto:contact@example.com)"}
JATS_TAG_RE = re.compile(r"<[^>]+>")


def _strip_jats(abstract: str | None) -> str | None:
    if not abstract:
        return None
    cleaned = JATS_TAG_RE.sub("", abstract)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or None


class CrossrefPlugin(BasePlugin):
    name = "crossref"
    description = "Crossref — academic publication metadata search"
    supported_target_types = ["person", "company", "domain"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            url = (
                "https://api.crossref.org/works?rows=10&query="
                + urllib.parse.quote(query)
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
                        text = await r.text()
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"non-JSON response: {text[:120]}",
                        )

            message = data.get("message", {}) if isinstance(data, dict) else {}
            items = message.get("items", []) or []
            total = message.get("total-results", len(items))

            works = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                title_list = it.get("title") or []
                title = title_list[0] if title_list else None
                authors = []
                for au in it.get("author", []) or []:
                    if not isinstance(au, dict):
                        continue
                    given = au.get("given") or ""
                    family = au.get("family") or ""
                    full = (given + " " + family).strip()
                    if full:
                        authors.append(full)
                year = None
                for key in ("published-print", "published-online", "published", "issued"):
                    dp = (it.get(key) or {}).get("date-parts")
                    if dp and isinstance(dp, list) and dp[0] and dp[0][0]:
                        year = dp[0][0]
                        break
                works.append(
                    {
                        "title": title,
                        "authors": authors,
                        "year": year,
                        "doi": it.get("DOI"),
                        "publisher": it.get("publisher"),
                        "type": it.get("type"),
                        "abstract": _strip_jats(it.get("abstract")),
                    }
                )

            if works:
                top = works[0]
                summary = (
                    f"Crossref: {len(works)} works matched '{query}' "
                    f"(total: {total}). Top: '{top.get('title')}' "
                    f"({top.get('year')})."
                )
            else:
                summary = f"Crossref: no works matched '{query}'."

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={"works": works, "total": total, "summary": summary},
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )
