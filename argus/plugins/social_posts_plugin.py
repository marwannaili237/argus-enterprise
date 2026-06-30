import asyncio
from xml.etree import ElementTree

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class SocialPostsPlugin(BasePlugin):
    name = "social_posts"
    description = "Recent social media posts and activity for a username"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        try:
            username = target.strip().lstrip("@")
            results: dict = {
                "username": username,
                "reddit": None,
                "github": None,
                "hackernews": None,
                "total_posts": 0,
            }

            async def fetch_reddit():
                try:
                    url = f"https://www.reddit.com/user/{username}/submitted/.rss?limit=10"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                root = ElementTree.fromstring(text)
                                ns = {"atom": "http://www.w3.org/2005/Atom", "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"}
                                entries = root.findall(".//{http://www.w3.org/2005/Atom}entry")
                                posts = []
                                for entry in entries[:10]:
                                    title_el = entry.find("{http://www.w3.org/2005/Atom}title")
                                    link_el = entry.find("{http://www.w3.org/2005/Atom}link")
                                    updated_el = entry.find("{http://www.w3.org/2005/Atom}updated")
                                    posts.append({
                                        "title": title_el.text if title_el is not None else "",
                                        "url": link_el.get("href", "") if link_el is not None else "",
                                        "date": updated_el.text if updated_el is not None else "",
                                        "platform": "reddit",
                                    })
                                results["reddit"] = {
                                    "found": True,
                                    "post_count": len(posts),
                                    "posts": posts,
                                }
                            elif resp.status == 404:
                                results["reddit"] = {"found": False}
                            else:
                                results["reddit"] = {"found": False, "error": f"HTTP {resp.status}"}
                except ElementTree.ParseError:
                    results["reddit"] = {"found": False, "error": "parse error"}
                except Exception as e:
                    results["reddit"] = {"found": False, "error": str(e)}

            async def fetch_github():
                try:
                    url = f"https://api.github.com/users/{username}/events/public?per_page=10"
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                events = []
                                for ev in data[:10]:
                                    events.append({
                                        "type": ev.get("type", ""),
                                        "repo": ev.get("repo", {}).get("name", ""),
                                        "created_at": ev.get("created_at", ""),
                                        "url": ev.get("repo", {}).get("url", ""),
                                        "platform": "github",
                                    })
                                results["github"] = {
                                    "found": True,
                                    "event_count": len(events),
                                    "events": events,
                                }
                            elif resp.status == 404:
                                results["github"] = {"found": False}
                            else:
                                results["github"] = {"found": False, "error": f"HTTP {resp.status}"}
                except Exception as e:
                    results["github"] = {"found": False, "error": str(e)}

            async def fetch_hackernews():
                try:
                    async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                        # Lookup user profile
                        async with session.get(f"https://hn.algolia.com/api/v1/users/{username}") as resp:
                            if resp.status != 200:
                                results["hackernews"] = {"found": False, "error": f"HTTP {resp.status}"}
                                return
                            user_data = await resp.json()
                            username_hn = user_data.get("username", username)
                            karma = user_data.get("karma", 0)

                        # Fetch recent submissions
                        url2 = f"https://hn.algolia.com/api/v1/search_by_date?tags=author_{username_hn}&hitsPerPage=10"
                        async with session.get(url2) as resp2:
                            if resp2.status != 200:
                                results["hackernews"] = {"found": False, "error": f"HTTP {resp2.status}"}
                                return
                            data = await resp2.json()
                            hits = data.get("hits", [])
                            submissions = []
                            for h in hits[:10]:
                                submissions.append({
                                    "title": h.get("title", "") or h.get("story_title", ""),
                                    "url": h.get("url", "") or f"https://news.ycombinator.com/item?id={h.get('objectID', '')}",
                                    "date": h.get("created_at", ""),
                                    "points": h.get("points", 0),
                                    "platform": "hackernews",
                                })
                            results["hackernews"] = {
                                "found": True,
                                "karma": karma,
                                "submission_count": len(submissions),
                                "submissions": submissions,
                            }
                except Exception as e:
                    results["hackernews"] = {"found": False, "error": str(e)}

            await asyncio.gather(fetch_reddit(), fetch_github(), fetch_hackernews())

            # Count total
            total = 0
            if results.get("reddit") and results["reddit"].get("post_count"):
                total += results["reddit"]["post_count"]
            if results.get("github") and results["github"].get("event_count"):
                total += results["github"]["event_count"]
            if results.get("hackernews") and results["hackernews"].get("submission_count"):
                total += results["hackernews"]["submission_count"]
            results["total_posts"] = total

            platforms_found = []
            for p in ["reddit", "github", "hackernews"]:
                if results.get(p) and results[p].get("found"):
                    platforms_found.append(p)

            if not platforms_found:
                return PluginResult(plugin_name=self.name, success=False, error="No social activity found for this username")

            results["platforms_found"] = platforms_found
            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))