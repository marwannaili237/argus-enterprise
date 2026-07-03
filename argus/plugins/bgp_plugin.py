"""
BGP/ASN intelligence plugin — bgpview.io free API + RIPE NCC.
Returns ASN details, prefixes, peers, upstreams, IX presence,
and abuse contacts for any IP or ASN.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)


class BgpPlugin(BasePlugin):
    name = "bgp"
    description = "BGP/ASN intelligence — prefix, peers, upstreams, IX presence, abuse contacts"
    supported_target_types = ["ip", "domain", "url"]

    async def run(self, target: str) -> PluginResult:
        ip = target
        if not IP_RE.match(target):
            hostname = target
            if "://" in hostname:
                hostname = hostname.split("://")[1].split("/")[0]
            try:
                import socket
                loop = asyncio.get_event_loop()
                info = await loop.run_in_executor(None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET))
                ip = list({r[4][0] for r in info})[0]
            except Exception:
                return PluginResult(plugin_name=self.name, success=False, error="Could not resolve IP")

        results = {}

        async def bgpview_ip():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(f"https://api.bgpview.io/ip/{ip}", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            payload = data.get("data", {})
                            results["rir_allocation"] = payload.get("rir_allocation", {})
                            results["country_codes"] = payload.get("country_codes", [])
                            results["ptr"] = payload.get("ptr_record")
                            prefixes = payload.get("prefixes", [])
                            if prefixes:
                                p = prefixes[0]
                                results["prefix"] = p.get("prefix")
                                results["prefix_name"] = p.get("name")
                                results["prefix_description"] = p.get("description")
                                results["prefix_country"] = p.get("country_code")
                                asns = p.get("asns", [])
                                if asns:
                                    results["asn"] = asns[0].get("asn")
                                    results["asn_name"] = asns[0].get("name")
                                    results["asn_description"] = asns[0].get("description")
            except Exception:
                pass

        async def bgpview_asn(asn_num: int):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    # ASN details
                    async with s.get(f"https://api.bgpview.io/asn/{asn_num}", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            payload = data.get("data", {})
                            results["asn_info"] = {
                                "name": payload.get("name"),
                                "description_short": payload.get("description_short"),
                                "description_full": payload.get("description_full", [""]),
                                "country_code": payload.get("country_code"),
                                "website": payload.get("website"),
                                "email_contacts": payload.get("email_contacts", [])[:3],
                                "abuse_contacts": payload.get("abuse_contacts", [])[:3],
                                "rir_allocation": payload.get("rir_allocation", {}),
                                "ixs": payload.get("ixs", [])[:5],
                            }

                    # Peers
                    async with s.get(f"https://api.bgpview.io/asn/{asn_num}/peers", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            payload = data.get("data", {})
                            results["ipv4_peers"] = [
                                {"asn": p["asn"], "name": p.get("name")}
                                for p in payload.get("ipv4_peers", [])[:5]
                            ]
                            results["peer_count"] = len(payload.get("ipv4_peers", []))

                    # Upstreams
                    async with s.get(f"https://api.bgpview.io/asn/{asn_num}/upstreams", headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            payload = data.get("data", {})
                            results["upstreams"] = [
                                {"asn": u["asn"], "name": u.get("name")}
                                for u in payload.get("ipv4_upstreams", [])[:5]
                            ]

            except Exception:
                pass

        async def ripe_abuse(ip_addr: str):
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={ip_addr}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            contacts = data.get("data", {}).get("abuse_contacts", [])
                            results["ripe_abuse_contacts"] = contacts[:5]
            except Exception:
                pass

        await asyncio.gather(bgpview_ip(), ripe_abuse(ip))

        # After getting ASN, fetch ASN details
        asn_num = results.get("asn")
        if asn_num:
            await bgpview_asn(asn_num)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "ip": ip,
                "ptr": results.get("ptr"),
                "asn": results.get("asn"),
                "asn_name": results.get("asn_name"),
                "asn_description": results.get("asn_description"),
                "prefix": results.get("prefix"),
                "prefix_name": results.get("prefix_name"),
                "country": results.get("prefix_country"),
                "asn_info": results.get("asn_info", {}),
                "peers": results.get("ipv4_peers", []),
                "peer_count": results.get("peer_count", 0),
                "upstreams": results.get("upstreams", []),
                "abuse_contacts": (
                    results.get("asn_info", {}).get("abuse_contacts", [])
                    or results.get("ripe_abuse_contacts", [])
                ),
                "ix_presence": results.get("asn_info", {}).get("ixs", []),
            },
        )
