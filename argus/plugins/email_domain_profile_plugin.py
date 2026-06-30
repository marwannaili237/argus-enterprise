"""
Email domain profile plugin — full domain analysis for the email's domain.
Extracts domain registration info via RDAP, MX record analysis (provider detection),
domain age, and free provider status.
"""
import asyncio
import json
import re
import aiohttp
import dns.resolver
from urllib.parse import urlparse
from plugins.base import BasePlugin, PluginResult

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)"}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr",
    "hotmail.com", "outlook.com", "live.com", "msn.com", "protonmail.com",
    "proton.me", "icloud.com", "me.com", "mac.com", "aol.com", "zoho.com",
    "mail.com", "gmx.com", "gmx.net", "yandex.com", "yandex.ru", "tutanota.com",
    "tuta.io", "fastmail.com", "hushmail.com", "rocketmail.com", "mail.ru",
    "qq.com", "163.com", "126.com", "sina.com", "hotmail.co.uk", "outlook.co.uk",
    "yahoo.co.jp", "yahoo.de", "yahoo.it", "yahoo.es", "yahoo.in", "live.co.uk",
    "live.fr", "live.de", "gmail.fr", "gmail.de", "protonmail.ch", "pm.me",
}


class EmailDomainProfilePlugin(BasePlugin):
    name = "email_domain_profile"
    description = "Full domain profile: RDAP registration, MX provider, domain age, free provider check"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        if not EMAIL_RE.match(target):
            return PluginResult(plugin_name=self.name, success=False, error="Not a valid email address")

        local, domain = target.lower().rsplit("@", 1)
        results: dict = {}

        async def check_rdap():
            """Fetch domain registration info via RDAP."""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    url = f"https://rdap.org/domain/{domain}"
                    async with s.get(url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            events = data.get("events", [])
                            creation_date = None
                            expiration_date = None
                            for ev in events:
                                if ev.get("eventAction") == "registration":
                                    creation_date = ev.get("eventDate")
                                elif ev.get("eventAction") == "expiration":
                                    expiration_date = ev.get("eventDate")

                            registrant = data.get("entities", [])
                            registrar = None
                            for ent in registrant:
                                roles = ent.get("roles", [])
                                if "registrar" in roles:
                                    vcard = ent.get("vcardArray", [])
                                    if vcard and len(vcard) > 1:
                                        for entry in vcard[1]:
                                            if isinstance(entry, list) and entry[0] == "fn":
                                                registrar = entry[3]

                            nameservers = [
                                ns.get("ldhName", "")
                                for ns in data.get("nameservers", [])
                            ]

                            results["rdap"] = {
                                "creation_date": creation_date,
                                "expiration_date": expiration_date,
                                "registrar": registrar,
                                "nameservers": nameservers,
                                "status": data.get("status", []),
                                "handle": data.get("handle"),
                            }
            except Exception:
                results["rdap"] = {"error": "RDAP lookup failed"}

        async def check_mx():
            """Analyze MX records and detect the email provider."""
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, "MX")
                )
                mx_records = []
                for r in answers:
                    mx_records.append({
                        "exchange": str(r.exchange).rstrip("."),
                        "priority": r.priority,
                    })
                mx_records.sort(key=lambda x: x["priority"])
                mx_names = [m["exchange"] for m in mx_records]

                results["mx"] = {
                    "found": True,
                    "records": mx_records,
                    "provider": self._detect_provider(mx_names),
                }
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results["mx"] = {"found": False, "records": [], "provider": "None"}
            except Exception:
                results["mx"] = {"found": None, "records": [], "provider": "Unknown", "error": "DNS failed"}

        async def check_dns_records():
            """Fetch additional DNS records for domain profiling."""
            try:
                loop = asyncio.get_event_loop()
                record_types = ["A", "NS", "TXT"]
                dns_results = {}
                for rtype in record_types:
                    try:
                        answers = await loop.run_in_executor(
                            None, lambda rt=rtype: dns.resolver.resolve(domain, rt)
                        )
                        dns_results[rtype] = [str(r) for r in answers]
                    except Exception:
                        dns_results[rtype] = []
                results["dns"] = dns_results
            except Exception:
                results["dns"] = {}

        await asyncio.gather(check_rdap(), check_mx(), check_dns_records())

        rdap = results.get("rdap", {})
        mx = results.get("mx", {})
        dns = results.get("dns", {})

        is_free = domain in FREE_EMAIL_PROVIDERS
        creation_date = rdap.get("creation_date") if isinstance(rdap, dict) else None
        expiration_date = rdap.get("expiration_date") if isinstance(rdap, dict) else None

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": target,
                "domain": domain,
                "is_free_provider": is_free,
                "provider_name": self._known_provider_name(domain) if is_free else mx.get("provider", "Unknown"),
                "registration": {
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "registrar": rdap.get("registrar") if isinstance(rdap, dict) else None,
                    "nameservers": rdap.get("nameservers", []) if isinstance(rdap, dict) else [],
                    "status": rdap.get("status", []) if isinstance(rdap, dict) else [],
                },
                "mx": mx,
                "dns": dns,
                "a_records": dns.get("A", []),
                "ns_records": dns.get("NS", []),
                "txt_records": dns.get("TXT", []),
            },
        )

    def _detect_provider(self, mx_records: list[str]) -> str:
        mx_lower = " ".join(mx_records).lower()
        providers = [
            (["google", "gmail"], "Google Workspace"),
            (["outlook", "microsoft", "exchange", "office365", "onmicrosoft"], "Microsoft 365"),
            (["amazon", "ses", "aws"], "Amazon SES"),
            (["sendgrid"], "SendGrid"),
            (["mailchimp", "mandrill"], "Mailchimp"),
            (["zoho"], "Zoho Mail"),
            (["protonmail"], "ProtonMail"),
            (["icloud", "apple"], "iCloud"),
            (["yandex"], "Yandex Mail"),
            (["mail.ru"], "Mail.ru"),
            (["qq.com", "tencent"], "Tencent/QQ Mail"),
        ]
        for keywords, name in providers:
            if any(k in mx_lower for k in keywords):
                return name
        return "Self-hosted / Unknown"

    def _known_provider_name(self, domain: str) -> str:
        mapping = {
            "gmail.com": "Google (Gmail)", "googlemail.com": "Google (Gmail)",
            "yahoo.com": "Yahoo Mail", "hotmail.com": "Microsoft (Hotmail)",
            "outlook.com": "Microsoft (Outlook)", "live.com": "Microsoft (Live)",
            "protonmail.com": "ProtonMail", "proton.me": "ProtonMail",
            "icloud.com": "Apple (iCloud)", "aol.com": "AOL Mail",
            "zoho.com": "Zoho Mail", "mail.com": "Mail.com",
            "gmx.com": "GMX", "yandex.com": "Yandex Mail",
            "tutanota.com": "Tutanota", "tuta.io": "Tutanota",
            "fastmail.com": "Fastmail", "hushmail.com": "Hushmail",
            "mail.ru": "Mail.ru", "qq.com": "QQ Mail",
        }
        return mapping.get(domain, domain)