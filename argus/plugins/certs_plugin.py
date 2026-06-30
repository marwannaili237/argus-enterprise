import aiohttp
from plugins.base import BasePlugin, PluginResult


class CertsPlugin(BasePlugin):
    name = "certs"
    description = "Certificate Transparency log search via crt.sh"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain

            url = f"https://crt.sh/?q=%.{base_domain}&output=json"

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
                async with session.get(url, headers={"User-Agent": "Argus-OSINT/1.0"}) as resp:
                    if resp.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"crt.sh returned {resp.status}")
                    certs = await resp.json(content_type=None)

            if not certs:
                return PluginResult(plugin_name=self.name, success=True, data={"domain": domain, "subdomains": [], "total_certs": 0})

            subdomains = set()
            issuers = set()
            for cert in certs[:500]:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and base_domain in sub:
                        subdomains.add(sub)
                issuer = cert.get("issuer_name", "")
                if "CN=" in issuer:
                    cn = [p.split("=", 1)[1] for p in issuer.split(",") if p.strip().startswith("CN=")]
                    if cn:
                        issuers.add(cn[0])

            sorted_subs = sorted(subdomains)

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "domain": domain,
                    "subdomains": sorted_subs[:50],
                    "total_subdomains": len(sorted_subs),
                    "total_certs": len(certs),
                    "issuers": list(issuers)[:10],
                },
            )

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
