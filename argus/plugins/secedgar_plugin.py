"""
SEC EDGAR full-text search plugin — fully free, no API key required.
Uses the EFTS JSON endpoint to find recent SEC filings mentioning a company,
person, or domain. SEC requires a descriptive User-Agent with contact email.
"""
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0 (contact@example.com)"}


class SecEdgarPlugin(BasePlugin):
    name = "secedgar"
    description = "SEC EDGAR full-text search for filings mentioning a target"
    supported_target_types = ["company", "person", "domain"]

    async def run(self, target: str) -> PluginResult:
        try:
            query = target.strip()
            if not query:
                return PluginResult(
                    plugin_name=self.name, success=False, error="empty target"
                )
            # EFTS JSON endpoint
            url = (
                "https://efts.sec.gov/LATEST/search-index?q="
                + urllib.parse.quote(query)
            )
            # Some EFTS deployments use the path style below; try the primary,
            # then fall back if needed.
            fallback_url = (
                "https://efts.sec.gov/LATEST/search-index?q="
                + urllib.parse.quote(query)
            )

            data = None
            used_url = url
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as s:
                for candidate in (url, fallback_url):
                    try:
                        async with s.get(candidate, headers=HEADERS) as r:
                            if r.status != 200:
                                continue
                            try:
                                data = await r.json(content_type=None)
                            except Exception:
                                continue
                            used_url = candidate
                            break
                    except Exception:
                        continue

            if data is None:
                # Try the public full-text search endpoint as last resort
                try:
                    alt_url = (
                        "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company="
                        + urllib.parse.quote(query)
                        + "&output=atom&count=10"
                    )
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as s:
                        async with s.get(alt_url, headers=HEADERS) as r:
                            if r.status != 200:
                                return PluginResult(
                                    plugin_name=self.name,
                                    success=False,
                                    error=f"HTTP {r.status}",
                                )
                            text = await r.text()
                    filings = self._parse_atom(text)
                    return PluginResult(
                        plugin_name=self.name,
                        success=True,
                        data={
                            "filings": filings,
                            "total": len(filings),
                            "found": len(filings) > 0,
                            "summary": (
                                f"SEC EDGAR (atom fallback): {len(filings)} "
                                f"filings matched '{query}'."
                                if filings
                                else f"SEC EDGAR: no filings matched '{query}'."
                            ),
                        },
                    )
                except Exception as e:
                    return PluginResult(
                        plugin_name=self.name,
                        success=False,
                        error=f"no JSON and atom fallback failed: {e}",
                    )

            hits_root = data.get("hits") if isinstance(data, dict) else None
            if isinstance(hits_root, dict):
                hit_list = hits_root.get("hits", []) or []
                total = hits_root.get("total", {}).get("value", len(hit_list)) \
                    if isinstance(hits_root.get("total"), dict) else len(hit_list)
            else:
                hit_list = []
                total = 0

            filings = []
            for hit in hit_list:
                src = hit.get("_source", {}) if isinstance(hit, dict) else {}
                form = src.get("form") or src.get("form_type")
                display_names = src.get("display_names") or []
                company = display_names[0] if display_names else None
                date = src.get("file_date") or src.get("filing_date")
                adsh = src.get("adsh") or src.get("file_num")
                ciks = src.get("ciks") or []
                cik = ciks[0] if ciks else None
                if cik and adsh:
                    adsh_clean = adsh.replace("-", "")
                    link = (
                        f"https://www.sec.gov/Archives/edgar/data/"
                        f"{int(cik)}/{adsh_clean}/{src.get('primary_doc', 'index.htm')}"
                    )
                elif cik:
                    link = (
                        f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
                    )
                else:
                    link = None
                filings.append(
                    {
                        "form": form,
                        "company": company,
                        "date": date,
                        "url": link,
                        "description": (
                            f"{form or 'Filing'} filed by {company or 'unknown'}"
                            f" on {date or 'unknown date'}"
                        ),
                    }
                )

            found = len(filings) > 0
            if found:
                summary = (
                    f"SEC EDGAR: {len(filings)} filings matched '{query}' "
                    f"(total hits: {total})."
                )
            else:
                summary = f"SEC EDGAR: no filings matched '{query}'."

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "filings": filings,
                    "total": total,
                    "found": found,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )

    @staticmethod
    def _parse_atom(text: str) -> list:
        """Parse an EDGAR browse-edgar Atom feed into filing dicts."""
        try:
            import xml.etree.ElementTree as ET

            ns = {"a": "http://www.w3.org/2005/Atom"}
            root = ET.fromstring(text)
            filings = []
            for entry in root.findall("a:entry", ns):
                title = (entry.findtext("a:title", default="", namespaces=ns) or "").strip()
                updated = entry.findtext("a:updated", default="", namespaces=ns) or ""
                link_el = entry.find("a:link", ns)
                link = link_el.get("href") if link_el is not None else None
                # Title format: "Form 10-K - Filed: 2024-01-01 - Company"
                form = None
                date = updated[:10]
                company = None
                if title:
                    parts = [p.strip() for p in title.split("-")]
                    if parts:
                        form = parts[0]
                    if len(parts) >= 3:
                        company = parts[-1]
                filings.append(
                    {
                        "form": form,
                        "company": company,
                        "date": date,
                        "url": link,
                        "description": title,
                    }
                )
            return filings
        except Exception:
            return []
