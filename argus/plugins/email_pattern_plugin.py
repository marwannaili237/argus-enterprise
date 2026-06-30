"""
Email pattern plugin — discover email addresses associated with a domain using
Google dorks, GitHub search, and Gravatar API enumeration.
"""
import asyncio
import hashlib
import re
import xml.etree.ElementTree as ET
import aiohttp
from urllib.parse import quote, urlparse
from plugins.base import BasePlugin, PluginResult

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


def _extract_domain(target: str) -> str:
    """Extract clean domain from URL or domain string."""
    t = target.strip().lower()
    if t.startswith(("http://", "https://")):
        t = urlparse(t).netloc
    # Remove port
    t = t.split(":")[0]
    # Remove www
    if t.startswith("www."):
        t = t[4:]
    return t


class EmailPatternPlugin(BasePlugin):
    name = "email_patterns"
    description = "Find email addresses at a domain via dorks, GitHub, and Gravatar enumeration"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        domain = _extract_domain(target)
        if not DOMAIN_RE.match(domain):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid domain or URL")

        results: dict = {}
        all_emails: set[str] = set()
        sources: list[dict] = []

        async def search_google_dorks():
            """Search Google for emails using dork queries."""
            try:
                dorks = [
                    f'site:{domain} "@"',
                    f'site:{domain} "@{domain}"',
                    f'site:linkedin.com/in "{domain}"',
                    f'"@{domain}" email',
                ]
                found: list[str] = []
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    for dork in dorks:
                        try:
                            url = f"https://html.duckduckgo.com/html/?q={quote(dork)}"
                            async with s.get(url, headers=HEADERS) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    emails = set(EMAIL_RE.findall(text))
                                    # Filter to only emails at the target domain
                                    domain_emails = {e for e in emails if e.lower().endswith(f"@{domain}")}
                                    found.extend(domain_emails)
                        except Exception:
                            pass
                results["duckduckgo_emails"] = list(set(found))
                all_emails.update(found)
                if found:
                    sources.append({"source": "duckduckgo_dorks", "count": len(set(found))})
            except Exception:
                pass

        async def search_github():
            """Search GitHub for emails at the domain."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/code?q={quote(f'@{domain}')}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            items = data.get("items", [])
                            found: list[str] = []
                            for item in items[:10]:
                                repo = item.get("repository", {}).get("full_name", "")
                                path = item.get("path", "")
                                found.append(f"{repo}/{path}")
                            results["github_code_hits"] = found
                            sources.append({"source": "github_code", "count": len(found), "sample": found[:3]})
            except Exception:
                pass

        async def search_github_users():
            """Search GitHub users by domain in email field."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/users?q={quote(f'{domain} in:email')}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            users = data.get("items", [])
                            results["github_users"] = [
                                {"login": u["login"], "url": u["html_url"]}
                                for u in users[:5]
                            ]
                            if users:
                                sources.append({"source": "github_users", "count": len(users)})
            except Exception:
                pass

        async def gravatar_enumeration():
            """Try common name patterns against Gravatar."""
            try:
                # Common first names to generate likely email patterns
                common_prefixes = [
                    "admin", "info", "contact", "support", "sales", "hello",
                    "team", "noreply", "postmaster", "webmaster", "abuse",
                    "root", "hostmaster", "news", "marketing", "hr",
                    "jobs", "careers", "press", "legal", "security",
                ]
                found_profiles: list[dict] = []
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    tasks = []
                    for prefix in common_prefixes:
                        email = f"{prefix}@{domain}"
                        md5 = hashlib.md5(email.lower().encode()).hexdigest()
                        url = f"https://www.gravatar.com/avatar/{md5}?d=404"
                        tasks.append(self._check_gravatar(s, url, email, found_profiles))

                    await asyncio.gather(*tasks, return_exceptions=True)

                results["gravatar_profiles"] = found_profiles
                for p in found_profiles:
                    all_emails.add(p["email"])
                if found_profiles:
                    sources.append({"source": "gravatar_enumeration", "count": len(found_profiles)})
            except Exception:
                pass

        await asyncio.gather(
            search_google_dorks(),
            search_github(),
            search_github_users(),
            gravatar_enumeration(),
        )

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "domain": domain,
                "emails_found": sorted(all_emails),
                "total_emails": len(all_emails),
                "duckduckgo_emails": results.get("duckduckgo_emails", []),
                "github_code_hits": results.get("github_code_hits", []),
                "github_users": results.get("github_users", []),
                "gravatar_profiles": results.get("gravatar_profiles", []),
                "sources": sources,
            },
        )

    async def _check_gravatar(self, session, url: str, email: str, results: list):
        try:
            async with session.get(url) as r:
                if r.status == 200:
                    results.append({
                        "email": email,
                        "gravatar_url": url,
                    })
        except Exception:
            pass