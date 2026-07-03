"""
Email age estimation plugin — estimates how old an email address is by checking
the earliest breach appearance, GitHub account creation date, and Gravatar
creation date.
"""
import asyncio
import hashlib
import re
import xml.etree.ElementTree as ET
import aiohttp
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailAgePlugin(BasePlugin):
    name = "email_age"
    description = "Estimate email age from earliest breach, GitHub, and Gravatar creation dates"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)
        md5_hash = hashlib.md5(target.lower().encode()).hexdigest()
        results: dict = {}
        age_signals: list[dict] = []

        async def check_hudson_rock():
            """Hudson Rock often includes the date of stealer log infection."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            logs = data.get("stealer_logs", [])
                            if logs:
                                dates = [log.get("date") for log in logs if log.get("date")]
                                if dates:
                                    earliest = min(dates)
                                    results["hudson_rock_earliest"] = earliest
                                    age_signals.append({
                                        "source": "Hudson Rock (stealer log)",
                                        "date": earliest,
                                        "type": "first_seen",
                                    })
            except Exception:
                pass

        async def check_emailrep():
            """EmailRep.io may include days_since_domain_creation and breach data."""
            try:
                headers = {"User-Agent": "ArgusOSINT/1.0", "Key": "none"}
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    url = f"https://emailrep.io/query/{target}"
                    async with s.get(url, headers=headers) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            details = data.get("details", {})
                            days_since = details.get("days_since_domain_creation")
                            if days_since and isinstance(days_since, (int, float)):
                                results["days_since_domain_creation"] = days_since
                                age_signals.append({
                                    "source": "EmailRep (domain age)",
                                    "date": f"~{int(days_since)} days ago",
                                    "type": "domain_age",
                                })
            except Exception:
                pass

        async def check_github_user():
            """Check if a GitHub user exists with this email, get creation date."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://api.github.com/search/users?q={target}+in:email"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            users = data.get("items", [])
                            if users:
                                login = users[0].get("login", "")
                                # Get detailed user info for creation date
                                user_url = f"https://api.github.com/users/{login}"
                                async with s.get(user_url, headers=HEADERS) as ur:
                                    if ur.status == 200:
                                        udata = await ur.json()
                                        created = udata.get("created_at")
                                        if created:
                                            results["github_user"] = login
                                            results["github_created_at"] = created
                                            age_signals.append({
                                                "source": "GitHub account",
                                                "date": created,
                                                "type": "account_creation",
                                                "url": udata.get("html_url", ""),
                                            })
            except Exception:
                pass

        async def check_gravatar_date():
            """Check Gravatar profile page for any date information."""
            try:
                # Gravatar profile URL (not avatar)
                profile_url = f"https://www.gravatar.com/{md5_hash}.json"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(profile_url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            entry = data.get("entry", [])
                            if entry:
                                profile = entry[0]
                                # Gravatar doesn't expose creation date directly,
                                # but we can note the profile exists
                                results["gravatar_profile"] = True
                                results["gravatar_display_name"] = profile.get("displayName")
                                results["gravatar_preferred_username"] = profile.get("preferredUsername")
                                age_signals.append({
                                    "source": "Gravatar",
                                    "date": None,
                                    "type": "profile_exists",
                                    "note": "Profile exists but Gravatar doesn't expose creation date",
                                })
            except Exception:
                pass

        async def check_leakcheck():
            """LeakCheck.io may include breach dates."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://leakcheck.io/api/v2/query/{target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if data.get("success") or data.get("found"):
                                breaches = data.get("results", [])
                                dates = []
                                for b in breaches:
                                    d = b.get("date") or b.get("breach_date")
                                    if d:
                                        dates.append(d)
                                if dates:
                                    earliest = min(d for d in dates if d)
                                    results["leakcheck_earliest_breach"] = earliest
                                    age_signals.append({
                                        "source": "LeakCheck (earliest breach)",
                                        "date": earliest,
                                        "type": "breach_appearance",
                                    })
            except Exception:
                pass

        await asyncio.gather(
            check_hudson_rock(),
            check_emailrep(),
            check_github_user(),
            check_gravatar_date(),
            check_leakcheck(),
        )

        # Determine earliest known date
        earliest_date = None
        earliest_source = None
        for signal in age_signals:
            d = signal.get("date")
            if d and d not in (None, ""):
                if earliest_date is None or d < earliest_date:
                    earliest_date = d
                    earliest_source = signal["source"]

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "local_part": local,
                "domain": domain,
                "earliest_known_date": earliest_date,
                "earliest_known_source": earliest_source,
                "age_signals": age_signals,
                "signal_count": len(age_signals),
                "hudson_rock_earliest": results.get("hudson_rock_earliest"),
                "leakcheck_earliest_breach": results.get("leakcheck_earliest_breach"),
                "github_user": results.get("github_user"),
                "github_created_at": results.get("github_created_at"),
                "gravatar_profile": results.get("gravatar_profile", False),
                "gravatar_display_name": results.get("gravatar_display_name"),
                "days_since_domain_creation": results.get("days_since_domain_creation"),
                "estimation_note": (
                    f"Earliest known appearance: {earliest_date} (from {earliest_source})"
                    if earliest_date else
                    "No date signals found — email age could not be estimated"
                ),
            },
        )