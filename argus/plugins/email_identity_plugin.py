"""
Email identity plugin — extract associated identities from breach data cross-references.
Searches GitHub (code + users), LinkedIn via DuckDuckGo, and extracts username
from the email local part for username correlation.
"""
import asyncio
import re
import aiohttp
from urllib.parse import quote
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailIdentityPlugin(BasePlugin):
    name = "email_identity"
    description = "Extract associated identities from breach cross-references and social search"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)
        results: dict = {}
        identities: list[dict] = []

        async def search_github_code():
            """Search GitHub code for the email address."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/code?q={quote(target)}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            items = data.get("items", [])
                            total = data.get("total_count", 0)
                            hits = []
                            for item in items[:5]:
                                repo = item.get("repository", {})
                                hits.append({
                                    "repo": repo.get("full_name", ""),
                                    "path": item.get("path", ""),
                                    "url": item.get("html_url", ""),
                                })
                            results["github_code"] = hits
                            results["github_code_total"] = total
                            if hits:
                                identities.append({
                                    "platform": "GitHub (code)",
                                    "detail": f"Found in {total} code snippets",
                                    "matches": [h["repo"] for h in hits[:3]],
                                })
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
                            user_details = []
                            for u in users[:3]:
                                login = u.get("login", "")
                                user_details.append({
                                    "login": login,
                                    "url": u.get("html_url", ""),
                                    "avatar": u.get("avatar_url", ""),
                                })
                                identities.append({
                                    "platform": "GitHub",
                                    "detail": f"User: {login}",
                                    "url": u.get("html_url", ""),
                                })
                            results["github_users"] = user_details
            except Exception:
                pass

        async def search_linkedin():
            """Search LinkedIn profiles via DuckDuckGo."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    queries = [
                        f'site:linkedin.com/in "{local}"',
                        f'"{target}" site:linkedin.com',
                    ]
                    linkedin_hits: list[dict] = []
                    for q in queries:
                        try:
                            url = f"https://html.duckduckgo.com/html/?q={quote(q)}"
                            async with s.get(url, headers=HEADERS) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    # Extract LinkedIn profile URLs
                                    profile_urls = re.findall(
                                        r'(https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9\-]+)',
                                        text
                                    )
                                    for pu in set(profile_urls[:5]):
                                        linkedin_hits.append({"url": pu, "query": q})
                        except Exception:
                            pass

                    results["linkedin_profiles"] = linkedin_hits
                    if linkedin_hits:
                        identities.append({
                            "platform": "LinkedIn",
                            "detail": f"{len(linkedin_hits)} potential profiles found",
                            "matches": [h["url"] for h in linkedin_hits[:3]],
                        })
            except Exception:
                pass

        async def search_hudson_rock():
            """Check Hudson Rock for identity/stealer data."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            logs = data.get("stealer_logs", [])
                            if logs:
                                for log in logs[:3]:
                                    identities.append({
                                        "platform": "Hudson Rock (Stealer Log)",
                                        "detail": f"Infected PC: {log.get('computer_name', 'N/A')}",
                                        "country": log.get("country"),
                                        "date": log.get("date"),
                                    })
                                results["hudson_rock_logs"] = len(logs)
            except Exception:
                pass

        async def extract_username_patterns():
            """Extract likely usernames from the email local part."""
            patterns: list[dict] = []

            # Direct local part
            if re.match(r"^[a-zA-Z0-9_]+$", local):
                patterns.append({"username": local, "type": "direct", "confidence": "high"})
            # Dot-separated: firstname.lastname or first.last
            if "." in local:
                parts = local.split(".")
                if len(parts) == 2:
                    patterns.append({"username": parts[0] + parts[1], "type": "concatenated", "confidence": "medium"})
                    patterns.append({"username": parts[1] + parts[0], "type": "reversed", "confidence": "low"})
                    patterns.append({"username": local.replace(".", "_"), "type": "underscore_variant", "confidence": "medium"})
            # Plus addressing
            if "+" in local:
                base = local.split("+")[0]
                patterns.append({"username": base, "type": "plus_addressing_base", "confidence": "high"})

            # Numeric suffix detection
            num_suffix = re.search(r"(\d+)$", local)
            if num_suffix:
                base = local[:num_suffix.start()]
                patterns.append({"username": base, "type": "base_without_numbers", "confidence": "medium"})

            results["username_patterns"] = patterns

        await asyncio.gather(
            search_github_code(),
            search_github_users(),
            search_linkedin(),
            search_hudson_rock(),
            extract_username_patterns(),
        )

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "local_part": local,
                "domain": domain,
                "identities_found": identities,
                "identity_count": len(identities),
                "github_code_total": results.get("github_code_total", 0),
                "github_code": results.get("github_code", []),
                "github_users": results.get("github_users", []),
                "linkedin_profiles": results.get("linkedin_profiles", []),
                "hudson_rock_logs": results.get("hudson_rock_logs", 0),
                "username_patterns": results.get("username_patterns", []),
            },
        )