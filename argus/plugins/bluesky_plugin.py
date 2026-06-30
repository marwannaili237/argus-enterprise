"""
Bluesky (AT Protocol) profile lookup plugin — 100% free, no auth for public reads.
"""
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


class BlueskyPlugin(BasePlugin):
    name = "bluesky"
    description = "Bluesky profile lookup via public AT Protocol API"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        try:
            handle = target.strip().lstrip("@")
            if not handle or "/" in handle or " " in handle:
                return PluginResult(plugin_name=self.name, success=False, error="Invalid Bluesky handle")

            url = f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                async with s.get(url, headers=HEADERS) as r:
                    if r.status == 404:
                        return PluginResult(plugin_name=self.name, success=False,
                                            error=f"Bluesky handle not found: {handle}")
                    if r.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {r.status}")
                    data = await r.json(content_type=None)

            did = data.get("did")
            if not did:
                return PluginResult(plugin_name=self.name, success=False, error="No DID returned")

            followers = int(data.get("followersCount", 0))
            follows = int(data.get("followsCount", 0))
            posts = int(data.get("postsCount", 0))
            summary = (f"Bluesky @{data.get('handle', handle)}: {followers} followers, "
                       f"{follows} following, {posts} posts")

            return PluginResult(plugin_name=self.name, success=True, data={
                "did": did,
                "handle": data.get("handle"),
                "display_name": data.get("displayName"),
                "description": data.get("description"),
                "followers_count": followers,
                "follows_count": follows,
                "posts_count": posts,
                "created_at": data.get("createdAt"),
                "avatar_url": data.get("avatar"),
                "summary": summary,
            })
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
