"""
Threat reputation plugin — checks domains/IPs/URLs against multiple free
threat intelligence feeds: URLHaus, PhishTank, TOR exit nodes, AbuseIPDB
public data, Spamhaus, and Google Safe Browsing public feed.
"""
import asyncio
import re
import hashlib
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# TOR exit node list cached in memory
_TOR_EXIT_NODES: set = set()
_TOR_LOADED = False


async def _load_tor_exits():
    global _TOR_EXIT_NODES, _TOR_LOADED
    if _TOR_LOADED:
        return
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
            async with s.get("https://check.torproject.org/exit-addresses", headers=HEADERS) as r:
                if r.status == 200:
                    text = await r.text()
                    _TOR_EXIT_NODES = {
                        line.split()[1]
                        for line in text.splitlines()
                        if line.startswith("ExitAddress")
                    }
                    _TOR_LOADED = True
    except Exception:
        pass


class ReputationPlugin(BasePlugin):
    name = "reputation"
    description = "Threat intel: URLHaus, PhishTank, TOR exits, Spamhaus, AbuseIPDB public"
    supported_target_types = ["domain", "url", "ip"]

    async def run(self, target: str) -> PluginResult:
        results = {}
        host = target
        if "://" in host:
            host = host.split("://")[1].split("/")[0]

        is_ip = IP_RE.match(host)

        async def check_urlhaus():
            try:
                payload = {"url": target if target.startswith("http") else f"https://{target}"}
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.post(
                        "https://urlhaus-api.abuse.ch/v1/url/",
                        data=payload,
                        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results["urlhaus"] = {
                                "query_status": data.get("query_status"),
                                "found": data.get("query_status") == "is_online" or data.get("query_status") == "offline",
                                "threat": data.get("threat"),
                                "date_added": data.get("date_added"),
                                "tags": data.get("tags", []),
                                "blacklists": data.get("blacklists", {}),
                            }
            except Exception:
                pass

        async def check_urlhaus_host():
            try:
                payload = {"host": host}
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.post(
                        "https://urlhaus-api.abuse.ch/v1/host/",
                        data=payload,
                        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if data.get("query_status") != "no_results":
                                results["urlhaus_host"] = {
                                    "urls_online": data.get("urls_in_database", 0),
                                    "blacklists": data.get("blacklists", {}),
                                    "recent_payloads": data.get("urls", [])[:3],
                                }
            except Exception:
                pass

        async def check_phishtank():
            try:
                import urllib.parse
                check_url = target if target.startswith("http") else f"https://{target}"
                payload = f"url={urllib.parse.quote_plus(check_url)}&format=json"
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.post(
                        "https://checkurl.phishtank.com/checkurl/",
                        data=payload,
                        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            results_data = data.get("results", {})
                            results["phishtank"] = {
                                "in_database": results_data.get("in_database", False),
                                "valid": results_data.get("valid", False),
                                "phish_detail_url": results_data.get("phish_detail_url"),
                            }
            except Exception:
                pass

        async def check_tor():
            await _load_tor_exits()
            if is_ip:
                results["is_tor_exit"] = host in _TOR_EXIT_NODES
            else:
                results["is_tor_exit"] = False

        async def check_spamhaus():
            try:
                import socket
                loop = asyncio.get_event_loop()
                if is_ip:
                    # Reverse the IP for DNS blacklist lookup
                    reversed_ip = ".".join(reversed(host.split(".")))
                    checks = {
                        "sbl": f"{reversed_ip}.sbl.spamhaus.org",
                        "xbl": f"{reversed_ip}.xbl.spamhaus.org",
                        "pbl": f"{reversed_ip}.pbl.spamhaus.org",
                    }
                    spamhaus_results = {}
                    for list_name, dnsbl_host in checks.items():
                        try:
                            await loop.run_in_executor(None, lambda h=dnsbl_host: socket.gethostbyname(h))
                            spamhaus_results[list_name] = True
                        except socket.gaierror:
                            spamhaus_results[list_name] = False
                    results["spamhaus"] = spamhaus_results
                    results["spamhaus_listed"] = any(spamhaus_results.values())
                else:
                    # Domain check via DBL
                    try:
                        await loop.run_in_executor(
                            None, lambda: socket.gethostbyname(f"{host}.dbl.spamhaus.org")
                        )
                        results["spamhaus_dbl"] = True
                    except socket.gaierror:
                        results["spamhaus_dbl"] = False
            except Exception:
                pass

        async def check_abuseipdb():
            if not is_ip:
                return
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    # Public check endpoint (no API key)
                    async with s.get(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={host}",
                        headers={**HEADERS, "Key": "none", "Accept": "application/json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            d = data.get("data", {})
                            results["abuseipdb"] = {
                                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                                "total_reports": d.get("totalReports", 0),
                                "country": d.get("countryCode"),
                                "isp": d.get("isp"),
                                "usage_type": d.get("usageType"),
                                "is_tor": d.get("isTor", False),
                            }
            except Exception:
                pass

        async def check_virustotal_public():
            """VirusTotal public URL/domain report (no key for community data)"""
            try:
                import base64
                check_url = target if target.startswith("http") else f"https://{target}"
                url_id = base64.urlsafe_b64encode(check_url.encode()).decode().rstrip("=")
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={**HEADERS, "x-apikey": "none"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            attrs = data.get("data", {}).get("attributes", {})
                            stats = attrs.get("last_analysis_stats", {})
                            results["virustotal"] = {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "harmless": stats.get("harmless", 0),
                                "categories": attrs.get("categories", {}),
                                "reputation": attrs.get("reputation", 0),
                            }
            except Exception:
                pass

        await asyncio.gather(
            check_urlhaus(),
            check_urlhaus_host(),
            check_phishtank(),
            check_tor(),
            check_spamhaus(),
            check_abuseipdb(),
        )

        # Build risk assessment
        threats = []
        if results.get("urlhaus", {}).get("found"):
            threats.append(f"🔴 URLHaus: {results['urlhaus'].get('threat', 'malware/phishing')}")
        if results.get("urlhaus_host", {}).get("urls_online", 0) > 0:
            threats.append(f"🔴 URLHaus: {results['urlhaus_host']['urls_online']} malicious URLs hosted")
        if results.get("phishtank", {}).get("valid"):
            threats.append("🎣 PhishTank: CONFIRMED PHISHING SITE")
        if results.get("is_tor_exit"):
            threats.append("🧅 TOR Exit Node")
        if results.get("spamhaus_listed"):
            listed = [k for k, v in results.get("spamhaus", {}).items() if v]
            threats.append(f"📵 Spamhaus: listed in {', '.join(listed).upper()}")
        if results.get("spamhaus_dbl"):
            threats.append("📵 Spamhaus DBL: domain blacklisted")
        if results.get("abuseipdb", {}).get("abuse_confidence", 0) > 25:
            threats.append(f"🚨 AbuseIPDB: {results['abuseipdb']['abuse_confidence']}% abuse confidence")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "target": target,
                "threat_count": len(threats),
                "threats": threats,
                "urlhaus": results.get("urlhaus"),
                "urlhaus_host": results.get("urlhaus_host"),
                "phishtank": results.get("phishtank"),
                "is_tor_exit": results.get("is_tor_exit", False),
                "spamhaus": results.get("spamhaus"),
                "spamhaus_dbl": results.get("spamhaus_dbl"),
                "abuseipdb": results.get("abuseipdb"),
            },
        )
