"""
Email username plugin — extract likely usernames from the email local part
and auto-check them on GitHub. Generates common variations.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailUsernamePlugin(BasePlugin):
    name = "email_username"
    description = "Extract usernames from email and check them on GitHub and other platforms"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)

        # Generate username variations
        variations = self._generate_variations(local)
        unique_variations = list(dict.fromkeys(variations))  # Preserve order, deduplicate

        # Check usernames in parallel
        check_results: list[dict] = []
        tasks = [self._check_github_username(v, check_results) for v in unique_variations[:15]]
        await asyncio.gather(*tasks, return_exceptions=True)

        found = [r for r in check_results if r.get("exists")]

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "local_part": local,
                "domain": domain,
                "username_variations": unique_variations,
                "total_variations": len(unique_variations),
                "checks_performed": len(check_results),
                "found_usernames": found,
                "found_count": len(found),
                "risk_flags": [
                    f"👤 {len(found)} username(s) found on GitHub"
                    for _ in ([0] if found else [])
                ],
            },
        )

    def _generate_variations(self, local: str) -> list[str]:
        """Generate common username variations from the email local part."""
        variations = [local]

        # Handle plus addressing: user+tag@domain → user
        if "+" in local:
            base = local.split("+")[0]
            variations.append(base)

        # Handle dot-separated: first.last → firstlast, first_last
        if "." in local:
            nodot = local.replace(".", "")
            underscore = local.replace(".", "_")
            variations.extend([nodot, underscore])

            # Reverse: first.last → lastfirst, last_first
            parts = local.split(".")
            if len(parts) >= 2:
                reversed_name = "".join(reversed(parts))
                reversed_us = "_".join(reversed(parts))
                variations.extend([reversed_name, reversed_us])

        # Handle underscores: first_last → firstlast, first.last
        if "_" in local:
            nous = local.replace("_", "")
            dotted = local.replace("_", ".")
            variations.extend([nous, dotted])

        # Strip numeric suffixes
        num_match = re.search(r"(\d+)$", local)
        if num_match:
            base = local[:num_match.start()]
            variations.append(base)
            # Also try base with dot if it looks like first.last
            if "." in base:
                variations.append(base.replace(".", ""))

        # Filter: only alphanumeric + underscore + dot, 2-39 chars
        valid = []
        seen = set()
        for v in variations:
            v = v.strip().lower()
            if v and 2 <= len(v) <= 39 and re.match(r"^[a-z0-9._]+$", v):
                if v not in seen:
                    seen.add(v)
                    valid.append(v)

        return valid

    async def _check_github_username(self, username: str, results: list):
        """Check if a username exists on GitHub."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                url = f"https://api.github.com/users/{username}"
                async with s.get(url, headers=HEADERS) as r:
                    if r.status == 200:
                        data = await r.json()
                        results.append({
                            "username": username,
                            "exists": True,
                            "platform": "github",
                            "url": data.get("html_url", f"https://github.com/{username}"),
                            "name": data.get("name"),
                            "bio": data.get("bio"),
                            "public_repos": data.get("public_repos", 0),
                            "followers": data.get("followers", 0),
                            "created_at": data.get("created_at"),
                        })
                    else:
                        results.append({
                            "username": username,
                            "exists": False,
                            "platform": "github",
                        })
        except Exception:
            results.append({
                "username": username,
                "exists": None,
                "platform": "github",
                "error": "check_failed",
            })