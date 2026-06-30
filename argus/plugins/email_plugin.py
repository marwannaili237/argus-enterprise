"""
Email OSINT plugin — breach checks, email reputation, Gravatar, MX validation,
dark web exposure, social presence, and domain intelligence.
"""
import asyncio
import hashlib
import re
import aiohttp
import dns.resolver
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "maildrop.cc", "sharklasers.com",
    "guerrillamailblock.com", "grr.la", "guerrillamail.info", "guerrillamail.biz",
    "guerrillamail.de", "guerrillamail.net", "guerrillamail.org", "spam4.me",
    "trashmail.com", "trashmail.io", "fakeinbox.com", "dispostable.com",
}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailPlugin(BasePlugin):
    name = "email"
    description = "Email OSINT: breach exposure, reputation, Gravatar, MX, social presence"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)
        md5_hash = hashlib.md5(target.lower().encode()).hexdigest()
        sha1_hash = hashlib.sha1(target.lower().encode()).hexdigest()

        results = {}

        async def check_mx():
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "MX")
                )
                results["mx_records"] = sorted([str(r.exchange) for r in answers])
                results["domain_valid"] = True
            except Exception:
                results["mx_records"] = []
                results["domain_valid"] = False

        async def check_gravatar():
            try:
                url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.get(url) as r:
                        results["gravatar"] = r.status == 200
                        if r.status == 200:
                            results["gravatar_url"] = f"https://www.gravatar.com/avatar/{md5_hash}"
            except Exception:
                results["gravatar"] = False

        async def check_emailrep():
            try:
                url = f"https://emailrep.io/{target}"
                headers = {"User-Agent": "ArgusOSINT/1.0", "Key": "none"}
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers=headers) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["reputation"] = data.get("reputation", "unknown")
                            results["suspicious"] = data.get("suspicious", False)
                            results["references"] = data.get("references", 0)
                            details = data.get("details", {})
                            results["blacklisted"] = details.get("blacklisted", False)
                            results["malicious_activity"] = details.get("malicious_activity", False)
                            results["credentials_leaked"] = details.get("credentials_leaked", False)
                            results["data_breach"] = details.get("data_breach", False)
                            results["days_since_domain_creation"] = details.get("days_since_domain_creation")
                            results["spam"] = details.get("spam", False)
                            results["free_provider"] = details.get("free_provider", False)
                            results["disposable"] = details.get("disposable", False) or domain in DISPOSABLE_DOMAINS
                            results["deliverable"] = details.get("deliverable", None)
                            results["profiles"] = details.get("profiles", [])
            except Exception:
                pass

        async def check_github():
            try:
                url = f"https://api.github.com/search/users?q={target}+in:email"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json()
                            users = data.get("items", [])
                            if users:
                                results["github_users"] = [
                                    {"login": u["login"], "url": u["html_url"]}
                                    for u in users[:3]
                                ]
            except Exception:
                pass

        async def check_hunter():
            try:
                # Hunter.io email finder (free tier, no key for format check)
                url = f"https://api.hunter.io/v2/email-verifier?email={target}&api_key=none"
                # Use emailhippo free check instead
                url2 = f"https://api.trumail.io/v2/lookups/json?address={target}"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.get(url2, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["deliverable_check"] = data.get("deliverable")
                            results["full_inbox"] = data.get("fullInbox")
                            results["host_exists"] = data.get("hostExists")
            except Exception:
                pass

        await asyncio.gather(check_mx(), check_gravatar(), check_emailrep(), check_github(), check_hunter())

        # Build summary flags
        risk_flags = []
        if results.get("blacklisted"):
            risk_flags.append("🚨 BLACKLISTED")
        if results.get("credentials_leaked") or results.get("data_breach"):
            risk_flags.append("🔓 CREDENTIALS LEAKED")
        if results.get("malicious_activity"):
            risk_flags.append("⚠️ MALICIOUS ACTIVITY")
        if results.get("spam"):
            risk_flags.append("📧 SPAM SENDER")
        if results.get("disposable") or domain in DISPOSABLE_DOMAINS:
            risk_flags.append("🗑️ DISPOSABLE EMAIL")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "local_part": local,
                "domain": domain,
                "md5_hash": md5_hash,
                "sha1_hash": sha1_hash,
                "domain_has_mx": results.get("domain_valid", False),
                "mx_records": results.get("mx_records", []),
                "gravatar": results.get("gravatar", False),
                "gravatar_url": results.get("gravatar_url"),
                "reputation": results.get("reputation", "unknown"),
                "suspicious": results.get("suspicious", False),
                "blacklisted": results.get("blacklisted", False),
                "credentials_leaked": results.get("credentials_leaked", False),
                "data_breach": results.get("data_breach", False),
                "spam": results.get("spam", False),
                "disposable": results.get("disposable", False) or domain in DISPOSABLE_DOMAINS,
                "free_provider": results.get("free_provider", False),
                "profiles": results.get("profiles", []),
                "github_users": results.get("github_users", []),
                "references": results.get("references", 0),
                "risk_flags": risk_flags,
            },
        )
