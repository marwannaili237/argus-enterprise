"""
ENS resolver plugin — 100% free, uses the public ENS metadata API.
Resolves .eth names to avatar/metadata; the resolved address is extracted
from the metadata attributes when present.
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
ENS_API = "https://metadata.ens.domains/mainnet/"
ETH_RE = re.compile(r"^[A-Za-z0-9\-]+\.eth$", re.IGNORECASE)


class EnsResolverPlugin(BasePlugin):
    name = "ens_resolver"
    description = "ENS (.eth) name resolver via public ENS metadata API"
    supported_target_types = ["domain", "username"]

    async def run(self, target: str) -> PluginResult:
        try:
            name = target.strip().lower()
            if not name.endswith(".eth") or not ETH_RE.match(name):
                return PluginResult(plugin_name=self.name, success=False, error="Not an ENS name")

            url = f"{ENS_API}{name}/"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status == 404:
                        return PluginResult(plugin_name=self.name, success=False,
                                            error=f"ENS name not registered: {name}")
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    data = await r.json(content_type=None)

            image = data.get("image") or ""
            description = data.get("description") or ""
            attributes = data.get("attributes", []) or []

            # Try to find the resolved address in attributes (trait_type 'address' or similar)
            resolved_address = None
            for attr in attributes:
                trait_type = (attr.get("trait_type") or "").lower()
                value = attr.get("value")
                if trait_type in ("address", "eth address", "resolved address") and value:
                    resolved_address = str(value)
                    break

            summary_parts = [f"ENS name: {name}"]
            if resolved_address:
                summary_parts.append(f"address={resolved_address}")
            else:
                summary_parts.append("address=unresolved")
            if image:
                summary_parts.append("has_avatar=yes")
            summary = ", ".join(summary_parts)

            return PluginResult(plugin_name=self.name, success=True, data={
                "ens_name": name,
                "resolved_address": resolved_address,
                "image": image,
                "description": description,
                "attributes": attributes,
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
