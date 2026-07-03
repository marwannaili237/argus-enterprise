"""
Email breach timeline plugin — detailed breach history from LeakCheck.io,
EmailRep.io breach section, and Hudson Rock free breach API. Includes breach
name, date, data types exposed, and severity.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}


class EmailBreachTimelinePlugin(BasePlugin):
    name = "breach_timeline"
    description = "Detailed breach timeline from LeakCheck, EmailRep, and Hudson Rock"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        results: dict = {}
        all_breaches: list[dict] = []
        sources_checked: list[str] = []

        async def check_leakcheck():
            """Check LeakCheck.io free API for breach data."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://leakcheck.io/api/v2/query/{target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if data.get("success") or data.get("found"):
                                breaches = data.get("results", [])
                                for b in breaches[:20]:
                                    all_breaches.append({
                                        "breach_name": b.get("source", b.get("name", "Unknown")),
                                        "date": b.get("date", b.get("breach_date", None)),
                                        "data_types": b.get("types", b.get("data_types", [])),
                                        "severity": self._assess_severity(b.get("types", b.get("data_types", []))),
                                        "source": "leakcheck",
                                    })
                                sources_checked.append("LeakCheck.io")
            except Exception:
                pass

        async def check_emailrep():
            """Check EmailRep.io breach section."""
            try:
                url = f"https://emailrep.io/query/{target}"
                headers = {"User-Agent": "ArgusOSINT/1.0", "Key": "none"}
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(url, headers=headers) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            details = data.get("details", {})
                            if details.get("data_breach"):
                                references = data.get("references", [])
                                if references:
                                    for ref_url in references[:10]:
                                        name = self._extract_name_from_url(ref_url)
                                        all_breaches.append({
                                            "breach_name": name,
                                            "date": None,
                                            "data_types": ["credentials"],
                                            "severity": "high",
                                            "source": "emailrep",
                                            "reference_url": ref_url,
                                        })
                                sources_checked.append("EmailRep.io")
            except Exception:
                pass

        async def check_hudson_rock():
            """Check Hudson Rock free breach/stealer log API."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={target}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            stealer_logs = data.get("stealer_logs", [])
                            if stealer_logs:
                                for log in stealer_logs[:15]:
                                    data_types = []
                                    if log.get("passwords"):
                                        data_types.append("password")
                                    if log.get("cookies"):
                                        data_types.append("cookies")
                                    if log.get("autofill"):
                                        data_types.append("autofill")
                                    if log.get("credit_cards"):
                                        data_types.append("credit_cards")
                                    if not data_types:
                                        data_types = ["credentials"]
                                    all_breaches.append({
                                        "breach_name": f"Stealer Log — {log.get('computer_name', 'Unknown')}",
                                        "date": log.get("date", None),
                                        "data_types": data_types,
                                        "severity": "critical" if "credit_cards" in data_types else "high",
                                        "source": "hudson_rock",
                                        "ip": log.get("ip"),
                                        "country": log.get("country"),
                                        "malware": log.get("malware_path"),
                                    })
                                sources_checked.append("Hudson Rock")
            except Exception:
                pass

        await asyncio.gather(check_leakcheck(), check_emailrep(), check_hudson_rock())

        # Sort by date if possible
        all_breaches.sort(key=lambda b: b.get("date") or "0000-00-00")

        # Compute overall severity
        severities = [b.get("severity", "unknown") for b in all_breaches]
        overall_severity = "none"
        if "critical" in severities:
            overall_severity = "critical"
        elif "high" in severities:
            overall_severity = "high"
        elif "medium" in severities:
            overall_severity = "medium"
        elif "low" in severities:
            overall_severity = "low"
        elif all_breaches:
            overall_severity = "low"

        # Collect all unique data types
        all_data_types: set[str] = set()
        for b in all_breaches:
            for dt in b.get("data_types", []):
                all_data_types.add(dt)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "total_breaches": len(all_breaches),
                "overall_severity": overall_severity,
                "breaches": all_breaches[:30],
                "data_types_exposed": sorted(all_data_types),
                "sources_checked": sources_checked,
                "risk_flags": self._build_flags(all_breaches, overall_severity),
            },
        )

    def _assess_severity(self, data_types: list) -> str:
        """Assess breach severity based on data types exposed."""
        if not data_types:
            return "medium"
        types_lower = [t.lower() for t in data_types]
        critical_indicators = ["password", "hash", "credit_card", "ssn", "social_security", "bank"]
        high_indicators = ["email", "phone", "address", "dob", "date_of_birth", "ip"]

        for t in types_lower:
            for ci in critical_indicators:
                if ci in t:
                    return "critical"
        for t in types_lower:
            for hi in high_indicators:
                if hi in t:
                    return "high"
        return "medium"

    def _extract_name_from_url(self, url: str) -> str:
        """Extract a readable breach name from a reference URL."""
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.replace("www.", "")
            return host
        except Exception:
            return url

    def _build_flags(self, breaches: list, severity: str) -> list[str]:
        flags = []
        if not breaches:
            return flags
        if severity == "critical":
            flags.append("🚨 CRITICAL: Credit cards or passwords in stealer logs")
        elif severity == "high":
            flags.append("⚠️ HIGH: Credentials or PII exposed in breaches")
        if len(breaches) >= 5:
            flags.append(f"🔓 Extensive breach history: {len(breaches)}+ incidents")
        return flags