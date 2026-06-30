"""
OpenCorporates plugin — free corporate registry search (rate-limited, no key).
Searches the OpenCorporates v0.4 companies endpoint for matching entities
across many jurisdictions and aggregates name, jurisdiction, company number,
status, and registered address.
"""
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


class OpenCorporatesPlugin(BasePlugin):
    name = "opencorporates"
    description = "OpenCorporates — global corporate registry search (free, rate-limited)"
    supported_target_types = ["company"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            url = (
                "https://api.opencorporates.com/v0.4/companies/search?q="
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

            results = data.get("results", {}) if isinstance(data, dict) else {}
            companies_raw = results.get("companies", []) or []
            companies = []
            for entry in companies_raw:
                c = entry.get("company", {}) if isinstance(entry, dict) else {}
                addr = c.get("registered_address", {}) or {}
                address_str = ", ".join(
                    filter(
                        None,
                        [
                            addr.get("street_address"),
                            addr.get("locality"),
                            addr.get("region"),
                            addr.get("postal_code"),
                            addr.get("country"),
                        ],
                    )
                )
                companies.append(
                    {
                        "name": c.get("name"),
                        "jurisdiction": c.get("jurisdiction_code"),
                        "company_number": c.get("company_number"),
                        "status": c.get("current_status") or c.get("company_status"),
                        "address": address_str or None,
                    }
                )

            total = results.get("total_count") or len(companies)
            found = len(companies) > 0

            if found:
                top = companies[0]
                summary = (
                    f"OpenCorporates: {len(companies)} entities matched "
                    f"'{query}' (total reported: {total}). Top: "
                    f"{top.get('name')} ({top.get('jurisdiction')})."
                )
            else:
                summary = f"OpenCorporates: no entities matched '{query}'."

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "companies": companies,
                    "total": total,
                    "found": found,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )
