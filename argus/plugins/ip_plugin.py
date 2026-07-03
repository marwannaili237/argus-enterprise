import aiohttp
import re
from plugins.base import BasePlugin, PluginResult


IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class IpPlugin(BasePlugin):
    name = "ip_geo"
    description = "IP geolocation and ASN lookup via ip-api.com (free)"
    supported_target_types = ["ip", "domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            host = target.replace("https://", "").replace("http://", "").split("/")[0]

            if not IP_RE.match(host):
                import dns.resolver
                try:
                    answers = dns.resolver.resolve(host, "A")
                    host = str(answers[0])
                except Exception:
                    return PluginResult(plugin_name=self.name, success=False, error="Could not resolve hostname to IP")

            url = f"http://ip-api.com/json/{host}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    data = await resp.json()

            if data.get("status") == "fail":
                return PluginResult(plugin_name=self.name, success=False, error=data.get("message", "Lookup failed"))

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "asn_name": data.get("asname"),
                    "reverse_dns": data.get("reverse"),
                    "is_mobile": data.get("mobile"),
                    "is_proxy": data.get("proxy"),
                    "is_hosting": data.get("hosting"),
                    "continent": data.get("continent"),
                },
            )

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
