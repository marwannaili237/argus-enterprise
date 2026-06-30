"""
Email security plugin — SPF, DMARC, DKIM validation for an email's domain.
Fetches and parses DNS TXT records, checks MX records, and evaluates
email security best practices. Also checks blacklists.
"""
import asyncio
import re
import aiohttp
import dns.resolver
from urllib.parse import urlparse
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}

BLACKLIST_DNS_SERVERS = [
    "2.0.0.127.zen.spamhaus.org",     # Spamhaus ZEN
]


def _extract_domain(target: str) -> str:
    t = target.strip().lower()
    if EMAIL_RE.match(t):
        return t.rsplit("@", 1)[1]
    if t.startswith(("http://", "https://")):
        t = urlparse(t).netloc.split(":")[0]
        if t.startswith("www."):
            t = t[4:]
    return t


class EmailSecurityPlugin(BasePlugin):
    name = "email_security"
    description = "SPF/DMARC/DKIM validation and email security analysis for a domain"
    supported_target_types = ["email", "domain"]

    async def run(self, target: str) -> PluginResult:
        domain = _extract_domain(target)
        if not DOMAIN_RE.match(domain):
            return PluginResult(plugin_name=self.name, success=False, error="Could not extract a valid domain")

        results: dict = {}
        issues: list[str] = []
        score = 100  # Start with perfect score, deduct for issues

        async def check_spf():
            """Fetch and parse SPF record."""
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "TXT")
                )
                spf_records = []
                for r in answers:
                    txt = str(r).strip('"')
                    if txt.startswith("v=spf1"):
                        spf_records.append(txt)

                if spf_records:
                    spf = spf_records[0]
                    results["spf"] = {
                        "found": True,
                        "record": spf,
                        "mechanisms": self._parse_spf(spf),
                    }
                    # Check for issues
                    if "+all" in spf:
                        issues.append("🚨 SPF allows all (open relay)")
                        score -= 40
                    elif "?all" in spf or "~all" in spf:
                        issues.append("⚠️ SPF softfail/neutral — not strict")
                        score -= 10
                    if len(spf_records) > 1:
                        issues.append("⚠️ Multiple SPF records detected")
                        score -= 10
                else:
                    results["spf"] = {"found": False, "record": None}
                    issues.append("🚨 No SPF record found")
                    score -= 30
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results["spf"] = {"found": False, "record": None}
                issues.append("🚨 No SPF record found")
                score -= 30
            except Exception:
                results["spf"] = {"found": None, "record": None, "error": "DNS lookup failed"}

        async def check_dmarc():
            """Fetch and parse DMARC record from _dmarc.domain."""
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                )
                dmarc_records = []
                for r in answers:
                    txt = str(r).strip('"')
                    if txt.startswith("v=DMARC1"):
                        dmarc_records.append(txt)

                if dmarc_records:
                    dmarc = dmarc_records[0]
                    policy = self._extract_dmarc_tag(dmarc, "p")
                    rua = self._extract_dmarc_tag(dmarc, "rua")
                    pct = self._extract_dmarc_tag(dmarc, "pct")
                    results["dmarc"] = {
                        "found": True,
                        "record": dmarc,
                        "policy": policy,
                        "rua": rua,
                        "pct": pct,
                    }
                    if policy == "none":
                        issues.append("⚠️ DMARC policy is 'none' (monitoring only)")
                        score -= 10
                    elif policy in ("quarantine", "reject"):
                        score += 5  # Bonus for strong DMARC
                    if not rua:
                        issues.append("⚠️ No DMARC reporting address (rua)")
                else:
                    results["dmarc"] = {"found": False, "record": None}
                    issues.append("🚨 No DMARC record found")
                    score -= 25
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results["dmarc"] = {"found": False, "record": None}
                issues.append("🚨 No DMARC record found")
                score -= 25
            except Exception:
                results["dmarc"] = {"found": None, "record": None, "error": "DNS lookup failed"}

        async def check_dkim():
            """Check for common DKIM selectors."""
            selectors = ["google", "selector1", "selector2", "k1", "default", "s1", "mail", "smtp"]
            found_selectors = []
            try:
                loop = asyncio.get_event_loop()
                for sel in selectors:
                    try:
                        answers = await loop.run_in_executor(
                            None, lambda s=sel: dns.resolver.resolve(
                                f"{s}._domainkey.{domain}", "TXT"
                            )
                        )
                        for r in answers:
                            txt = str(r).strip('"')
                            if "DKIM" in txt or "v=" in txt:
                                found_selectors.append(sel)
                                break
                    except Exception:
                        continue
            except Exception:
                pass

            results["dkim"] = {
                "found": len(found_selectors) > 0,
                "selectors_found": found_selectors,
                "selectors_checked": selectors,
            }
            if not found_selectors:
                issues.append("⚠️ No DKIM records found (checked common selectors)")
                score -= 15

        async def check_mx():
            """Check MX records."""
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "MX")
                )
                mx_records = sorted([str(r.exchange).rstrip(".") for r in answers])
                results["mx"] = {
                    "found": True,
                    "records": mx_records,
                    "provider": self._detect_mx_provider(mx_records),
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results["mx"] = {"found": False, "records": []}
                issues.append("🚨 No MX records — domain cannot receive email")
                score -= 20
            except Exception:
                results["mx"] = {"found": None, "records": [], "error": "DNS lookup failed"}

        async def check_blacklists():
            """Check if the domain's IP is on email blacklists via DNSBL."""
            try:
                # First resolve the domain to an IP
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "A")
                )
                ip = str(answers[0])
                results["ip"] = ip

                # Check against Spamhaus ZEN
                reversed_ip = ".".join(reversed(ip.split(".")))
                blacklist_results = {}
                for bl in BLACKLIST_DNS_SERVERS:
                    try:
                        await loop.run_in_executor(
                            None,
                            lambda b=bl: dns.resolver.resolve(
                                f"{reversed_ip}.{b}", "A"
                            ),
                        )
                        blacklist_results[bl.split(".")[1]] = "listed"
                        issues.append(f"🚨 Listed on {bl.split('.')[1]}")
                        score -= 20
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        blacklist_results[bl.split(".")[1]] = "clean"
                    except Exception:
                        blacklist_results[bl.split(".")[1]] = "error"

                results["blacklists"] = blacklist_results
            except Exception:
                results["blacklists"] = {}
                results["ip"] = None

        await asyncio.gather(check_spf(), check_dmarc(), check_dkim(), check_mx(), check_blacklists())

        score = max(0, min(100, score))

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "domain": domain,
                "security_score": score,
                "grade": self._score_to_grade(score),
                "spf": results.get("spf"),
                "dmarc": results.get("dmarc"),
                "dkim": results.get("dkim"),
                "mx": results.get("mx"),
                "blacklists": results.get("blacklists", {}),
                "ip": results.get("ip"),
                "issues": issues,
                "risk_flags": issues,
            },
        )

    def _parse_spf(self, record: str) -> list[dict]:
        """Parse SPF mechanisms from the record."""
        mechanisms = []
        parts = record.split()
        for p in parts[1:]:  # Skip "v=spf1"
            if p in ("~all", "-all", "?all", "+all"):
                mechanisms.append({"mechanism": "all", "qualifier": p[0], "value": p})
            elif ":" in p:
                qual = p[0] if p[0] in "+-~?" else "+"
                parts_split = p.split(":", 1)
                mechanisms.append({"mechanism": parts_split[0][1:], "qualifier": qual, "value": parts_split[1]})
            else:
                qual = p[0] if p[0] in "+-~?" else "+"
                mechanisms.append({"mechanism": p[1:] if p[0] in "+-~?" else p, "qualifier": qual})
        return mechanisms

    def _extract_dmarc_tag(self, record: str, tag: str) -> str | None:
        """Extract a DMARC tag value from the record."""
        for part in record.split(";"):
            part = part.strip()
            if part.startswith(f"{tag}="):
                return part.split("=", 1)[1].strip()
        return None

    def _detect_mx_provider(self, mx_records: list[str]) -> str:
        """Detect the email provider from MX records."""
        mx_lower = " ".join(mx_records).lower()
        if any(x in mx_lower for x in ["google", "gmail"]):
            return "Google Workspace"
        if any(x in mx_lower for x in ["outlook", "microsoft", "exchange", "office365", "onmicrosoft"]):
            return "Microsoft 365"
        if any(x in mx_lower for x in ["amazon", "ses", "aws"]):
            return "Amazon SES"
        if any(x in mx_lower for x in ["sendgrid", "smtp.sendgrid"]):
            return "SendGrid"
        if any(x in mx_lower for x in ["mailchimp", "mandrill"]):
            return "Mailchimp"
        if any(x in mx_lower for x in ["zoho", "mx.zoho"]):
            return "Zoho Mail"
        if any(x in mx_lower for x in ["protonmail", "pm.me"]):
            return "ProtonMail"
        if any(x in mx_lower for x in ["icloud", "apple"]):
            return "iCloud"
        return "Self-hosted / Unknown"

    def _score_to_grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"