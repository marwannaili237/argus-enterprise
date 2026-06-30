"""
OpenSanctions plugin — free matching API against global sanctions / PEP
datasets. Detects whether the target is an email, domain/URL, or a free
text name and selects the appropriate schema + properties.

Endpoint: https://data.opensanctions.org/api/2/match/default
Body: { "queries": { "q1": { "schema": ..., "properties": ... } },
        "fuzzy": false, "limit": 5 }
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
)
URL_RE = re.compile(r"^(https?|ftp)://", re.IGNORECASE)


class OpenSanctionsPlugin(BasePlugin):
    name = "opensanctions"
    description = "OpenSanctions — match Person/Company against global sanctions & PEP data"
    supported_target_types = ["person", "company", "email", "domain"]

    @staticmethod
    def _build_query(target: str) -> dict:
        t = target.strip()
        if EMAIL_RE.match(t):
            return {"schema": "Person", "properties": {"email": t}}
        if URL_RE.match(t):
            return {"schema": "Company", "properties": {"website": t}}
        if DOMAIN_RE.match(t):
            return {"schema": "Company", "properties": {"website": t}}
        # Default: treat as a person/company name -> LegalEntity
        return {"schema": "LegalEntity", "properties": {"name": t}}

    async def run(self, target: str) -> PluginResult:
        try:
            query = self._build_query(target)
            body = {
                "queries": {"q1": query},
                "fuzzy": False,
                "limit": 5,
            }
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.post(
                    "https://data.opensanctions.org/api/2/match/default",
                    json=body,
                    headers={**HEADERS, "Content-Type": "application/json"},
                ) as r:
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"HTTP {r.status}",
                        )
                    data = await r.json(content_type=None)

            responses = data.get("responses") or {}
            q1 = responses.get("q1") or {}
            results = q1.get("results") or []
            total = q1.get("total", len(results))

            matches = []
            sources = set()
            for res in results:
                props = res.get("properties") or {}
                # collect datasets that contributed to the match
                for d in res.get("datasets") or []:
                    if d:
                        sources.add(d)
                matches.append({
                    "id": res.get("id"),
                    "caption": res.get("caption"),
                    "schema": res.get("schema"),
                    "match_score": res.get("score") or res.get("match"),
                    "names": props.get("name", []),
                    "countries": props.get("country", []) or props.get("countryCode", []),
                    "birth_dates": props.get("birthDate", []),
                    "topics": res.get("topics", []),
                    "datasets": res.get("datasets", []),
                })

            found = bool(matches)
            src_list = sorted(sources)
            summary = (
                f"OpenSanctions: {len(matches)} match(es) across "
                f"{len(src_list)} dataset(s)"
                if found
                else "OpenSanctions: no matches"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "matches": matches,
                    "total": total,
                    "found": found,
                    "sources": src_list,
                    "query_schema": query.get("schema"),
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=str(e),
            )
