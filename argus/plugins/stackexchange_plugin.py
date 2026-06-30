"""
Stack Exchange / Stack Overflow user search plugin — 100% free, no API key.
"""
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


class StackExchangePlugin(BasePlugin):
    name = "stackexchange"
    description = "Stack Overflow / Stack Exchange user search by display name"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        try:
            name = target.strip().lstrip("@")
            if not name:
                return PluginResult(plugin_name=self.name, success=False, error="Empty username")

            url = (f"https://api.stackexchange.com/2.3/users?inname={name}"
                   f"&site=stackoverflow&order=desc&sort=reputation&pagesize=5")
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    data = await r.json(content_type=None)

            items = data.get("items", []) or []
            total = int(data.get("total", len(items)))

            users = []
            for it in items[:5]:
                users.append({
                    "display_name": it.get("display_name"),
                    "user_id": it.get("user_id"),
                    "reputation": it.get("reputation", 0),
                    "location": it.get("location"),
                    "website": it.get("website_url"),
                    "profile_image": it.get("profile_image"),
                    "creation_date": it.get("creation_date"),
                    "profile_url": it.get("link"),
                })

            found = len(users) > 0
            top = users[0] if users else {}
            summary = (f"Stack Overflow: {len(users)} matching users (total {total}); "
                       f"top: {top.get('display_name', 'n/a')} rep={top.get('reputation', 0)}") if found \
                else f"Stack Overflow: no users matching '{name}'"

            return PluginResult(plugin_name=self.name, success=True, data={
                "users": users,
                "total": total,
                "found": found,
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
