"""
Mastodon federated account lookup plugin — 100% free, no API key.
Decomposes @user@instance.social and queries the instance's public search API.
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
HANDLE_RE = re.compile(r"^@?([A-Za-z0-9_]+)@([A-Za-z0-9.\-]+)$")
DEFAULT_INSTANCE = "mastodon.social"


class MastodonPlugin(BasePlugin):
    name = "mastodon"
    description = "Mastodon federated profile lookup via public search API"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        try:
            t = target.strip()
            m = HANDLE_RE.match(t)
            if m:
                user, instance = m.group(1), m.group(2)
            else:
                # Bare @user or user — default to mastodon.social
                bare = t.lstrip("@")
                if not bare or "/" in bare or " " in bare:
                    return PluginResult(plugin_name=self.name, success=False, error="Invalid Mastodon handle")
                user, instance = bare, DEFAULT_INSTANCE

            handle = f"@{user}@{instance}"
            url = f"https://{instance}/api/v2/search?q={user}&type=accounts&limit=1"

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    data = await r.json(content_type=None)

            accounts = data.get("accounts", []) or []
            if not accounts:
                return PluginResult(plugin_name=self.name, success=False,
                                    error=f"No Mastodon account found for {handle}")

            acc = accounts[0]
            followers = int(acc.get("followers_count", 0))
            following = int(acc.get("following_count", 0))
            statuses = int(acc.get("statuses_count", 0))
            summary = (f"Mastodon {acc.get('acct', handle)}: {followers} followers, "
                       f"{following} following, {statuses} statuses")

            return PluginResult(plugin_name=self.name, success=True, data={
                "handle": handle,
                "instance": instance,
                "account_id": acc.get("id"),
                "username": acc.get("username"),
                "display_name": acc.get("display_name"),
                "bio": acc.get("note"),
                "followers_count": followers,
                "following_count": following,
                "statuses_count": statuses,
                "created_at": acc.get("created_at"),
                "url": acc.get("url"),
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
