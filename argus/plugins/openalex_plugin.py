"""
OpenAlex plugin — free open scholarly works database.
Searches OpenAlex works by free-text query (person/company name) or by
display_name.search filter (for domain-like targets). Reconstructs inverted
abstracts into readable text where present.
"""
import re
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0 (mailto:contact@example.com)"}
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def _reconstruct_abstract(inv: dict) -> str | None:
    """OpenAlex stores abstracts as inverted indices; reconstruct to plain text."""
    if not isinstance(inv, dict) or not inv:
        return None
    positions = []  # (pos, word)
    for word, locs in inv.items():
        for pos in locs or []:
            positions.append((pos, word))
    if not positions:
        return None
    positions.sort()
    return " ".join(w for _, w in positions)


class OpenAlexPlugin(BasePlugin):
    name = "openalex"
    description = "OpenAlex — open scholarly works search by name or topic"
    supported_target_types = ["person", "company", "domain"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            bare = query
            if "://" in bare:
                bare = bare.split("://", 1)[1]
            bare = bare.split("/")[0].strip()

            if DOMAIN_RE.match(bare):
                params = {"filter": f"display_name.search:{bare}", "per-page": "10"}
            else:
                params = {"search": query, "per-page": "10"}
            url = "https://api.openalex.org/works?" + urllib.parse.urlencode(params)

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

            results = data.get("results", []) if isinstance(data, dict) else []
            total = (
                data.get("meta", {}).get("count", len(results))
                if isinstance(data, dict)
                else len(results)
            )

            works = []
            for w in results:
                if not isinstance(w, dict):
                    continue
                authorships = w.get("authorships", []) or []
                authors = []
                for a in authorships[:5]:
                    au = a.get("author", {}) if isinstance(a, dict) else {}
                    nm = au.get("display_name")
                    if nm:
                        authors.append(nm)
                host = w.get("host_venue") or w.get("primary_location", {}) or {}
                if isinstance(host, dict):
                    venue_obj = host.get("source") or host
                    venue = (
                        venue_obj.get("display_name")
                        if isinstance(venue_obj, dict)
                        else None
                    )
                else:
                    venue = None
                works.append(
                    {
                        "title": w.get("display_name"),
                        "authors": authors,
                        "year": w.get("publication_year"),
                        "doi": w.get("doi"),
                        "venue": venue,
                        "cited_by_count": w.get("cited_by_count", 0),
                        "abstract": _reconstruct_abstract(
                            w.get("abstract_inverted_index")
                        ),
                    }
                )

            if works:
                top = works[0]
                summary = (
                    f"OpenAlex: {len(works)} works matched '{query}' "
                    f"(total: {total}). Top: '{top.get('title')}' "
                    f"({top.get('year')})."
                )
            else:
                summary = f"OpenAlex: no works matched '{query}'."

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={"works": works, "total": total, "summary": summary},
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )
