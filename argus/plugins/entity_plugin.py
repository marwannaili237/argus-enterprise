"""
Entity OSINT plugin — investigates people and companies using free public sources.
Covers: OpenCorporates (company registry), Google News RSS, DuckDuckGo people search,
SEC EDGAR, LinkedIn public profiles, and Pipl/Spokeo-style public records scraping.
Supports target types: person, company, domain.
"""
import asyncio
import re
import urllib.parse
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}


class EntityPlugin(BasePlugin):
    name = "entity"
    description = "Person/company OSINT: OpenCorporates, news, SEC EDGAR, public records"
    supported_target_types = ["person", "company", "domain"]

    async def run(self, target: str) -> PluginResult:
        results = {}
        query = target.strip()

        async def news_search():
            """Google News RSS — completely free, no auth"""
            try:
                enc = urllib.parse.quote(query)
                urls = [
                    f"https://news.google.com/rss/search?q={enc}&hl=en-US&gl=US&ceid=US:en",
                    f"https://feeds.search.yahoo.com/search/news?p={enc}",
                ]
                for url in urls:
                    try:
                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                            async with s.get(url, headers=HEADERS) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    items = re.findall(
                                        r'<item>.*?<title>(.*?)</title>.*?<link>(.*?)</link>.*?<pubDate>(.*?)</pubDate>.*?</item>',
                                        text, re.DOTALL
                                    )
                                    news = [
                                        {
                                            "title": re.sub(r'<[^>]+>', '', i[0]).strip()[:150],
                                            "url": i[1].strip(),
                                            "date": i[2].strip()[:32],
                                        }
                                        for i in items[:10]
                                    ]
                                    if news:
                                        results["news"] = news
                                        return
                    except Exception:
                        continue
            except Exception:
                pass

        async def opencorporates_search():
            """OpenCorporates — free company registry, 100+ jurisdictions"""
            try:
                enc = urllib.parse.quote(query)
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://api.opencorporates.com/v0.4/companies/search?q={enc}&per_page=5",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            companies = data.get("results", {}).get("companies", [])
                            results["opencorporates"] = [
                                {
                                    "name": c["company"].get("name"),
                                    "jurisdiction": c["company"].get("jurisdiction_code"),
                                    "company_number": c["company"].get("company_number"),
                                    "company_type": c["company"].get("company_type"),
                                    "incorporation_date": c["company"].get("incorporation_date"),
                                    "dissolution_date": c["company"].get("dissolution_date"),
                                    "status": c["company"].get("current_status"),
                                    "registered_address": c["company"].get("registered_address_in_full"),
                                    "url": c["company"].get("opencorporates_url"),
                                }
                                for c in companies[:5]
                                if "company" in c
                            ]
            except Exception:
                pass

        async def sec_edgar_search():
            """SEC EDGAR — free US company/person filing search"""
            try:
                enc = urllib.parse.quote(query)
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://efts.sec.gov/LATEST/search-index?q=%22{enc}%22&dateRange=custom&startdt=2015-01-01&hits.hits._source=period_of_report,file_date,display_names,form_type",
                        headers={**HEADERS, "Accept": "application/json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            hits = data.get("hits", {}).get("hits", [])
                            results["sec_edgar"] = {
                                "total": data.get("hits", {}).get("total", {}).get("value", 0),
                                "filings": [
                                    {
                                        "names": h.get("_source", {}).get("display_names", [])[:3],
                                        "form": h.get("_source", {}).get("form_type"),
                                        "date": h.get("_source", {}).get("file_date"),
                                    }
                                    for h in hits[:5]
                                ],
                            }
                    # Company lookup by name
                    async with s.get(
                        f"https://efts.sec.gov/LATEST/search-index?q=%22{enc}%22&forms=10-K,10-Q,8-K",
                        headers={**HEADERS, "Accept": "application/json"},
                    ) as r:
                        pass
            except Exception:
                pass

        async def duckduckgo_search():
            """DuckDuckGo HTML scrape — people search, public records"""
            try:
                enc = urllib.parse.quote(f'"{query}" site:linkedin.com OR site:twitter.com OR site:facebook.com OR filetype:pdf')
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://html.duckduckgo.com/html/?q={enc}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            results_data = re.findall(
                                r'class="result__title"[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                                text, re.DOTALL
                            )
                            snippets = re.findall(
                                r'class="result__snippet"[^>]*>(.*?)</(?:div|span)>',
                                text, re.DOTALL
                            )
                            ddg_results = []
                            for i, (url, title) in enumerate(results_data[:8]):
                                clean_url = urllib.parse.unquote(url.split("uddg=")[-1].split("&")[0]) if "uddg=" in url else url
                                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                                snippet = re.sub(r'<[^>]+>', '', snippets[i]).strip()[:200] if i < len(snippets) else ""
                                ddg_results.append({"title": clean_title, "url": clean_url, "snippet": snippet})
                            results["web_search"] = ddg_results
            except Exception:
                pass

        async def linkedin_public():
            """LinkedIn public profile search via Google cache"""
            try:
                enc = urllib.parse.quote(f'site:linkedin.com/in "{query}"')
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://html.duckduckgo.com/html/?q={enc}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            li_urls = re.findall(r'linkedin\.com/in/([a-zA-Z0-9\-]+)', text)
                            li_names = re.findall(r'class="result__title"[^>]*>.*?>(.*?)</a>', text, re.DOTALL)
                            profiles = []
                            seen = set()
                            for slug in li_urls[:5]:
                                if slug not in seen:
                                    seen.add(slug)
                                    profiles.append({
                                        "url": f"https://linkedin.com/in/{slug}",
                                        "slug": slug,
                                    })
                            if profiles:
                                results["linkedin_profiles"] = profiles
            except Exception:
                pass

        async def pipl_style_search():
            """Free people search via Spokeo/TruePeopleSearch scraping"""
            try:
                enc = urllib.parse.quote(query.replace(" ", "-"))
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://www.truepeoplesearch.com/results?name={enc}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Extract result cards
                            names = re.findall(r'class="h4"[^>]*>(.*?)</div>', text, re.DOTALL)
                            locations = re.findall(r'class="content-value"[^>]*>(.*?)</div>', text, re.DOTALL)
                            if names:
                                results["public_records"] = [
                                    {
                                        "name": re.sub(r'<[^>]+>', '', n).strip(),
                                        "location": re.sub(r'<[^>]+>', '', locations[i]).strip() if i < len(locations) else "",
                                    }
                                    for i, n in enumerate(names[:5])
                                ]
            except Exception:
                pass

        async def github_person_search():
            """GitHub user/org search by name"""
            try:
                enc = urllib.parse.quote(query)
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://api.github.com/search/users?q={enc}&type=user&per_page=5",
                        headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["github_users"] = {
                                "total": data.get("total_count", 0),
                                "users": [
                                    {
                                        "login": u.get("login"),
                                        "url": u.get("html_url"),
                                        "type": u.get("type"),
                                    }
                                    for u in data.get("items", [])[:5]
                                ],
                            }
            except Exception:
                pass

        await asyncio.gather(
            news_search(),
            opencorporates_search(),
            sec_edgar_search(),
            duckduckgo_search(),
            linkedin_public(),
            pipl_style_search(),
            github_person_search(),
        )

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "query": query,
                "news": results.get("news", []),
                "companies": results.get("opencorporates", []),
                "sec_filings": results.get("sec_edgar"),
                "web_results": results.get("web_search", []),
                "linkedin_profiles": results.get("linkedin_profiles", []),
                "public_records": results.get("public_records", []),
                "github_users": results.get("github_users", {}),
            },
        )
