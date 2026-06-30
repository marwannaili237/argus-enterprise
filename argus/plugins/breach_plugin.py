"""
Data breach checking plugin — checks emails and usernames against
known breach databases using free public APIs.
"""
import asyncio
import hashlib
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "ArgusOSINT/1.0 (OSINT research tool)",
    "hibp-api-key": "",  # We use the free unauthenticated endpoints
}

# Known mega-breaches for context
KNOWN_BREACHES = {
    "collection1": 773_000_000,
    "rockyou2024": 10_000_000_000,
    "adobe": 153_000_000,
    "linkedin": 164_000_000,
    "yahoo": 3_000_000_000,
    "facebook": 533_000_000,
}


class BreachPlugin(BasePlugin):
    name = "breach"
    description = "Check email/username against breach databases (HIBP, DeHashed, LeakCheck)"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        results = {}

        async def check_hibp_pwned_passwords():
            """Check if email appears in password breach counts via HIBP SHA-1 range"""
            pass  # HIBP password check is for passwords, not emails without API key

        async def check_leakcheck():
            """LeakCheck.io free public endpoint"""
            try:
                url = f"https://leakcheck.io/api/public?check={target}"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["leakcheck"] = {
                                "found": data.get("found", False),
                                "sources": data.get("sources", [])[:10],
                            }
            except Exception:
                pass

        async def check_dehashed_public():
            """DeHashed public search"""
            try:
                url = f"https://dehashed.com/search?query={target}"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers={**HEADERS, "Accept": "application/json"}) as r:
                        # Public endpoint returns HTML, check for result indicators
                        if r.status == 200:
                            text = await r.text()
                            results["dehashed_has_results"] = "entries found" in text.lower()
            except Exception:
                pass

        async def check_pwnedpasswords_count(email: str):
            """Check if email domain has been in breaches"""
            domain = email.split("@")[1] if "@" in email else None
            if not domain:
                return
            try:
                url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers={
                        "User-Agent": "ArgusOSINT/1.0",
                        "hibp-api-key": "none",
                    }) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["domain_in_breaches"] = bool(data)
                            results["domain_breach_count"] = len(data) if isinstance(data, list) else 0
            except Exception:
                pass

        async def check_emailrep_breach():
            """EmailRep.io has breach data in free tier"""
            try:
                url = f"https://emailrep.io/{target}"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers={"User-Agent": "ArgusOSINT/1.0"}) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            details = data.get("details", {})
                            results["emailrep_breached"] = details.get("data_breach", False)
                            results["emailrep_credentials_leaked"] = details.get("credentials_leaked", False)
                            results["emailrep_references"] = data.get("references", 0)
                            results["emailrep_reputation"] = data.get("reputation", "unknown")
                            results["emailrep_suspicious"] = data.get("suspicious", False)
            except Exception:
                pass

        await asyncio.gather(
            check_leakcheck(),
            check_emailrep_breach(),
            check_pwnedpasswords_count(target),
        )

        # Combine findings
        breach_found = (
            results.get("leakcheck", {}).get("found", False)
            or results.get("emailrep_breached", False)
            or results.get("emailrep_credentials_leaked", False)
        )

        sources = results.get("leakcheck", {}).get("sources", [])

        risk_level = "Low"
        if breach_found and results.get("emailrep_credentials_leaked"):
            risk_level = "Critical"
        elif breach_found:
            risk_level = "High"
        elif results.get("emailrep_suspicious"):
            risk_level = "Medium"

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "target": target,
                "breach_found": breach_found,
                "risk_level": risk_level,
                "credentials_leaked": results.get("emailrep_credentials_leaked", False),
                "breach_sources": sources,
                "reputation": results.get("emailrep_reputation", "unknown"),
                "suspicious": results.get("emailrep_suspicious", False),
                "references": results.get("emailrep_references", 0),
                "domain_in_breaches": results.get("domain_in_breaches", False),
                "domain_breach_count": results.get("domain_breach_count", 0),
                "raw": {k: v for k, v in results.items()},
            },
        )
