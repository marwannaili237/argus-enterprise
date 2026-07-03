import asyncio
import dns.resolver
import dns.reversename
from plugins.base import BasePlugin, PluginResult


class DnsPlugin(BasePlugin):
    name = "dns"
    description = "DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME)"
    supported_target_types = ["domain", "url", "ip"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            results: dict = {"domain": domain, "records": {}}

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

            async def query_type(rtype: str):
                try:
                    answers = await loop.run_in_executor(None, resolver.resolve, domain, rtype)
                    records = []
                    for r in answers:
                        records.append(str(r))
                    results["records"][rtype] = records
                except Exception:
                    pass

            await asyncio.gather(*[query_type(rt) for rt in record_types])

            if not results["records"]:
                return PluginResult(plugin_name=self.name, success=False, error="No DNS records found")

            a_records = results["records"].get("A", [])
            if a_records:
                results["primary_ip"] = a_records[0]

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
