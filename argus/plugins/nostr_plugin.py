"""
Nostr profile lookup plugin — 100% free, uses the public nostr.band REST API.
Only triggers for targets that look like Nostr npubs (start with 'npub1').
"""
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
NOSTR_API = "https://api.nostr.band/v0/npub/"


class NostrPlugin(BasePlugin):
    name = "nostr"
    description = "Nostr profile metadata lookup via public nostr.band API"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        try:
            npub = target.strip()
            if not (npub.startswith("npub1") and len(npub) > 10):
                return PluginResult(plugin_name=self.name, success=False, error="Not a Nostr npub")

            url = f"{NOSTR_API}{npub}"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status == 404:
                        return PluginResult(plugin_name=self.name, success=False,
                                            error=f"Nostr profile not found: {npub}")
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    data = await r.json(content_type=None)

            # nostr.band returns {profiles: {<npub>: {profile: {...}, ...}}}
            profiles = data.get("profiles", {}) or {}
            entry = profiles.get(npub) or {}
            profile = entry.get("profile", {}) or {}

            name = profile.get("name") or ""
            about = profile.get("about") or ""
            picture = profile.get("picture") or ""
            website = profile.get("website") or ""
            nip05 = profile.get("nip05") or ""

            if not (name or about or picture):
                return PluginResult(plugin_name=self.name, success=False,
                                    error=f"No profile metadata for {npub}")

            summary_parts = [f"Nostr {npub[:16]}..."]
            if name:
                summary_parts.append(f"name={name}")
            if nip05:
                summary_parts.append(f"nip05={nip05}")
            summary = ", ".join(summary_parts)

            return PluginResult(plugin_name=self.name, success=True, data={
                "npub": npub,
                "name": name,
                "about": about,
                "picture": picture,
                "website": website,
                "nip05": nip05,
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
