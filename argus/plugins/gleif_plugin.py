"""
GLEIF LEI Search plugin — fully free, no API key.
Queries the Global LEI Foundation API for Legal Entity Identifiers matching
a target legal name (companies) or website (domains). LEI applies to legal
entities only, so person-name targets typically return no results.
"""
import re
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0", "Accept": "application/vnd.api+json"}
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


class GleifPlugin(BasePlugin):
    name = "gleif"
    description = "GLEIF LEI Search — Legal Entity Identifier lookup by name or website"
    supported_target_types = ["company", "domain", "person"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            # Clean URL-style targets down to a bare host for website filter
            bare = query
            if "://" in bare:
                bare = bare.split("://", 1)[1]
            bare = bare.split("/")[0].strip()

            if DOMAIN_RE.match(bare):
                filter_key = "filter[entity.website]"
                filter_val = bare
            else:
                filter_key = "filter[entity.legalName]"
                filter_val = query

            url = (
                "https://api.gleif.org/api/v1/lei-records?"
                + urllib.parse.urlencode({filter_key: filter_val})
                + "&page[size]=10"
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

            items = data.get("data", []) if isinstance(data, dict) else []
            total = (
                data.get("meta", {}).get("pagination", {}).get("total", len(items))
                if isinstance(data, dict)
                else len(items)
            )

            entities = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                attrs = item.get("attributes", {}) or {}
                entity = attrs.get("entity", {}) or {}
                legal_addr = entity.get("legalAddress", {}) or {}
                address_str = ", ".join(
                    filter(
                        None,
                        [
                            legal_addr.get("addressLines"),
                            legal_addr.get("city"),
                            legal_addr.get("region"),
                            legal_addr.get("postalCode"),
                            legal_addr.get("country"),
                        ],
                    )
                )
                entities.append(
                    {
                        "legal_name": entity.get("legalName", {}).get("name")
                        if isinstance(entity.get("legalName"), dict)
                        else entity.get("legalName"),
                        "lei": attrs.get("lei") or item.get("id"),
                        "jurisdiction": entity.get("jurisdiction"),
                        "legal_address": address_str or None,
                        "status": entity.get("status"),
                    }
                )

            found = len(entities) > 0
            if found:
                top = entities[0]
                summary = (
                    f"GLEIF: {len(entities)} LEI records matched '{query}' "
                    f"(total: {total}). Top: {top.get('legal_name')} "
                    f"({top.get('jurisdiction')}, LEI {top.get('lei')})."
                )
            else:
                summary = f"GLEIF: no LEI records matched '{query}'."

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "entities": entities,
                    "total": total,
                    "found": found,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )
