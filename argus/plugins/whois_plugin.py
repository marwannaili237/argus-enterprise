import asyncio
import whois
from plugins.base import BasePlugin, PluginResult


class WhoisPlugin(BasePlugin):
    name = "whois"
    description = "WHOIS domain registration lookup"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)

            if not w or not w.domain_name:
                return PluginResult(plugin_name=self.name, success=False, error="No WHOIS data found")

            registrar = w.registrar if isinstance(w.registrar, str) else (w.registrar[0] if w.registrar else None)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]

            name_servers = w.name_servers
            if isinstance(name_servers, set):
                name_servers = list(name_servers)
            elif isinstance(name_servers, str):
                name_servers = [name_servers]

            emails = w.emails
            if isinstance(emails, str):
                emails = [emails]
            elif not emails:
                emails = []

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "domain": domain,
                    "registrar": registrar,
                    "creation_date": str(creation) if creation else None,
                    "expiration_date": str(expiration) if expiration else None,
                    "name_servers": [ns.lower() for ns in (name_servers or [])],
                    "emails": list(set(emails)) if emails else [],
                    "country": w.country if isinstance(w.country, str) else (w.country[0] if w.country else None),
                    "status": w.status if isinstance(w.status, str) else (w.status[0] if w.status else None),
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
