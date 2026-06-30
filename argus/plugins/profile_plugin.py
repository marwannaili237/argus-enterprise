"""
Public profile deep-dive plugin — scrapes public data from social platforms
without API keys. Covers GitHub, Reddit, HackerNews, Nitter (Twitter/X),
and aggregates profile metadata, activity stats, and bio intel.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}


class ProfilePlugin(BasePlugin):
    name = "profile"
    description = "Deep profile scrape: GitHub, Reddit, HackerNews, Twitter/X (Nitter)"
    supported_target_types = ["username", "person"]

    async def run(self, target: str) -> PluginResult:
        username = target.strip().lstrip("@")
        profiles = {}

        async def github_profile():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://api.github.com/users/{username}",
                        headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                    ) as r:
                        if r.status == 200:
                            d = await r.json(content_type=None)
                            profiles["github"] = {
                                "login": d.get("login"),
                                "name": d.get("name"),
                                "bio": d.get("bio"),
                                "company": d.get("company"),
                                "location": d.get("location"),
                                "email": d.get("email"),
                                "blog": d.get("blog"),
                                "twitter": d.get("twitter_username"),
                                "public_repos": d.get("public_repos", 0),
                                "public_gists": d.get("public_gists", 0),
                                "followers": d.get("followers", 0),
                                "following": d.get("following", 0),
                                "created_at": d.get("created_at", "")[:10],
                                "updated_at": d.get("updated_at", "")[:10],
                                "avatar": d.get("avatar_url"),
                                "url": d.get("html_url"),
                                "hireable": d.get("hireable"),
                                "type": d.get("type"),
                            }
                    # Top repos
                    async with s.get(
                        f"https://api.github.com/users/{username}/repos?sort=stars&per_page=5",
                        headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                    ) as r:
                        if r.status == 200:
                            repos = await r.json(content_type=None)
                            if "github" in profiles:
                                profiles["github"]["top_repos"] = [
                                    {
                                        "name": repo.get("name"),
                                        "description": (repo.get("description") or "")[:100],
                                        "stars": repo.get("stargazers_count", 0),
                                        "language": repo.get("language"),
                                        "url": repo.get("html_url"),
                                        "fork": repo.get("fork", False),
                                    }
                                    for repo in repos[:5]
                                ]
                    # Languages breakdown
                    async with s.get(
                        f"https://api.github.com/users/{username}/events/public?per_page=10",
                        headers={**HEADERS, "Accept": "application/vnd.github.v3+json"},
                    ) as r:
                        if r.status == 200:
                            events = await r.json(content_type=None)
                            event_types = {}
                            for ev in events:
                                t = ev.get("type", "")
                                event_types[t] = event_types.get(t, 0) + 1
                            if "github" in profiles:
                                profiles["github"]["recent_activity"] = event_types
            except Exception:
                pass

        async def reddit_profile():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://www.reddit.com/user/{username}/about.json",
                        headers={**HEADERS, "Accept": "application/json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            d = data.get("data", {})
                            profiles["reddit"] = {
                                "name": d.get("name"),
                                "karma_post": d.get("link_karma", 0),
                                "karma_comment": d.get("comment_karma", 0),
                                "cake_day": d.get("created_utc"),
                                "is_gold": d.get("is_gold", False),
                                "is_mod": d.get("is_mod", False),
                                "verified": d.get("verified", False),
                                "icon": d.get("icon_img"),
                                "url": f"https://reddit.com/u/{username}",
                            }
                    # Recent posts
                    async with s.get(
                        f"https://www.reddit.com/user/{username}/submitted.json?limit=5",
                        headers={**HEADERS, "Accept": "application/json"},
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            posts = data.get("data", {}).get("children", [])
                            if "reddit" in profiles:
                                profiles["reddit"]["recent_posts"] = [
                                    {
                                        "title": p["data"].get("title", "")[:100],
                                        "subreddit": p["data"].get("subreddit"),
                                        "score": p["data"].get("score", 0),
                                        "url": f"https://reddit.com{p['data'].get('permalink', '')}",
                                    }
                                    for p in posts
                                    if "data" in p
                                ]
            except Exception:
                pass

        async def hackernews_profile():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    async with s.get(
                        f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
                    ) as r:
                        if r.status == 200:
                            d = await r.json(content_type=None)
                            if d:
                                profiles["hackernews"] = {
                                    "id": d.get("id"),
                                    "karma": d.get("karma", 0),
                                    "created": d.get("created"),
                                    "about": re.sub(r'<[^>]+>', '', d.get("about") or "")[:300],
                                    "submitted_count": len(d.get("submitted", [])),
                                    "url": f"https://news.ycombinator.com/user?id={username}",
                                }
            except Exception:
                pass

        async def nitter_twitter():
            """Scrape Twitter/X profile via Nitter (public mirror)"""
            nitter_instances = [
                "https://nitter.privacydev.net",
                "https://nitter.poast.org",
                "https://nitter.lucahammer.com",
            ]
            for instance in nitter_instances:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                        async with s.get(f"{instance}/{username}", headers=HEADERS) as r:
                            if r.status == 200:
                                text = await r.text()
                                profile = {"url": f"https://x.com/{username}", "source": "nitter"}

                                # Parse bio
                                bio_match = re.search(r'class="profile-bio"[^>]*>(.*?)</div>', text, re.DOTALL)
                                if bio_match:
                                    profile["bio"] = re.sub(r'<[^>]+>', '', bio_match.group(1)).strip()[:300]

                                # Parse stats
                                for stat in ["Tweets", "Following", "Followers", "Likes"]:
                                    m = re.search(rf'<span class="profile-stat-num"[^>]*>([^<]+)</span>.*?{stat}', text, re.DOTALL)
                                    if m:
                                        profile[stat.lower()] = m.group(1).strip()

                                # Location
                                loc = re.search(r'class="profile-location"[^>]*>.*?<span>(.*?)</span>', text, re.DOTALL)
                                if loc:
                                    profile["location"] = re.sub(r'<[^>]+>', '', loc.group(1)).strip()

                                # Join date
                                joined = re.search(r'class="profile-joindate"[^>]*>.*?<span[^>]*>(.*?)</span>', text, re.DOTALL)
                                if joined:
                                    profile["joined"] = re.sub(r'<[^>]+>', '', joined.group(1)).strip()

                                # Name
                                name = re.search(r'class="profile-card-fullname"[^>]*>(.*?)</a>', text, re.DOTALL)
                                if name:
                                    profile["name"] = re.sub(r'<[^>]+>', '', name.group(1)).strip()

                                if len(profile) > 3:
                                    profiles["twitter"] = profile
                                    return
                except Exception:
                    continue

        async def devto_profile():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.get(
                        f"https://dev.to/api/users/by_username?url={username}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            d = await r.json(content_type=None)
                            profiles["devto"] = {
                                "name": d.get("name"),
                                "summary": (d.get("summary") or "")[:200],
                                "location": d.get("location"),
                                "twitter": d.get("twitter_username"),
                                "github": d.get("github_username"),
                                "website": d.get("website_url"),
                                "joined": d.get("joined_at", "")[:10],
                                "url": f"https://dev.to/{username}",
                            }
            except Exception:
                pass

        async def keybase_profile():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as s:
                    async with s.get(
                        f"https://keybase.io/_/api/1.0/user/lookup.json?username={username}&fields=profile,proofs_summary",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            them = data.get("them")
                            if them and isinstance(them, list) and them:
                                u = them[0]
                                p = u.get("profile", {})
                                proofs = u.get("proofs_summary", {})
                                profiles["keybase"] = {
                                    "username": u.get("basics", {}).get("username"),
                                    "full_name": p.get("full_name"),
                                    "bio": (p.get("bio") or "")[:200],
                                    "location": p.get("location"),
                                    "verified_accounts": {
                                        k: [{"username": a.get("nametag")} for a in v[:3]]
                                        for k, v in proofs.items()
                                        if v
                                    },
                                    "url": f"https://keybase.io/{username}",
                                }
            except Exception:
                pass

        await asyncio.gather(
            github_profile(),
            reddit_profile(),
            hackernews_profile(),
            nitter_twitter(),
            devto_profile(),
            keybase_profile(),
        )

        # Extract cross-platform intel
        known_emails = set()
        known_locations = set()
        known_names = set()
        known_linked_accounts = {}

        for platform, data in profiles.items():
            if isinstance(data, dict):
                if data.get("email"):
                    known_emails.add(data["email"])
                if data.get("location"):
                    known_locations.add(data["location"])
                if data.get("name"):
                    known_names.add(data["name"])
                if data.get("twitter"):
                    known_linked_accounts["twitter"] = data["twitter"]
                if data.get("github"):
                    known_linked_accounts["github"] = data["github"]
                if data.get("blog") or data.get("website"):
                    known_linked_accounts["website"] = data.get("blog") or data.get("website")

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "username": username,
                "platforms_found": list(profiles.keys()),
                "profiles": profiles,
                "cross_platform": {
                    "emails": list(known_emails),
                    "locations": list(known_locations),
                    "names": list(known_names),
                    "linked_accounts": known_linked_accounts,
                },
            },
        )
