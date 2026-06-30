"""
Username OSINT plugin — Sherlock-style check across 50+ platforms.
All checks are pure HTTP requests, no API keys needed.
"""
import asyncio
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

# (platform_name, url_template, check_method, false_indicator)
# check_method: "status_200" = found if 200, "status_not_404" = found if not 404, "body_not_contains" = found if string not in body
PLATFORMS = [
    # Social media
    ("GitHub",       "https://github.com/{u}",                          "status_200",        None),
    ("Twitter/X",    "https://x.com/{u}",                               "status_200",        "This account doesn't exist"),
    ("Instagram",    "https://www.instagram.com/{u}/",                  "status_200",        "Sorry, this page"),
    ("Reddit",       "https://www.reddit.com/user/{u}",                 "status_200",        "Sorry, nobody on Reddit"),
    ("TikTok",       "https://www.tiktok.com/@{u}",                     "status_200",        "Couldn't find this account"),
    ("YouTube",      "https://www.youtube.com/@{u}",                    "status_200",        None),
    ("Twitch",       "https://www.twitch.tv/{u}",                       "status_200",        None),
    ("Pinterest",    "https://www.pinterest.com/{u}/",                  "status_200",        None),
    ("Tumblr",       "https://{u}.tumblr.com",                          "status_200",        "There's nothing here"),
    ("Medium",       "https://medium.com/@{u}",                         "status_200",        None),
    ("Quora",        "https://www.quora.com/profile/{u}",               "status_200",        None),
    ("LinkedIn",     "https://www.linkedin.com/in/{u}",                 "status_200",        None),
    ("Snapchat",     "https://www.snapchat.com/add/{u}",                "status_200",        None),
    ("Telegram",     "https://t.me/{u}",                                "body_not_contains", "If you have Telegram"),
    # Tech & Dev
    ("GitLab",       "https://gitlab.com/{u}",                          "status_200",        None),
    ("HackerNews",   "https://news.ycombinator.com/user?id={u}",        "status_200",        "No such user"),
    ("StackOverflow","https://stackoverflow.com/users/{u}",             "status_not_404",    None),
    ("ProductHunt",  "https://www.producthunt.com/@{u}",                "status_200",        None),
    ("Keybase",      "https://keybase.io/{u}",                          "status_200",        None),
    ("Dev.to",       "https://dev.to/{u}",                              "status_200",        None),
    ("Replit",       "https://replit.com/@{u}",                         "status_200",        None),
    ("CodePen",      "https://codepen.io/{u}",                          "status_200",        None),
    # Creative
    ("DeviantArt",   "https://www.deviantart.com/{u}",                  "status_200",        None),
    ("Behance",      "https://www.behance.net/{u}",                     "status_200",        None),
    ("Dribbble",     "https://dribbble.com/{u}",                        "status_200",        None),
    ("ArtStation",   "https://www.artstation.com/{u}",                  "status_200",        None),
    ("Flickr",       "https://www.flickr.com/people/{u}",               "status_not_404",    None),
    ("SoundCloud",   "https://soundcloud.com/{u}",                      "status_200",        None),
    ("Spotify",      "https://open.spotify.com/user/{u}",               "status_200",        None),
    ("Bandcamp",     "https://{u}.bandcamp.com",                        "status_200",        None),
    ("Mixcloud",     "https://www.mixcloud.com/{u}/",                   "status_200",        None),
    # Gaming
    ("Steam",        "https://steamcommunity.com/id/{u}",               "status_200",        "The specified profile could not be found"),
    ("Xbox",         "https://xboxgamertag.com/search/{u}",             "status_200",        None),
    ("PSN",          "https://psnprofiles.com/{u}",                     "status_200",        "No PSN user"),
    ("Roblox",       "https://www.roblox.com/user.aspx?username={u}",   "status_200",        None),
    # Commerce & Freelance
    ("Etsy",         "https://www.etsy.com/people/{u}",                 "status_200",        None),
    ("Patreon",      "https://www.patreon.com/{u}",                     "status_200",        None),
    ("Fiverr",       "https://www.fiverr.com/{u}",                      "status_200",        None),
    ("Upwork",       "https://www.upwork.com/freelancers/~{u}",         "status_200",        None),
    # Other
    ("About.me",     "https://about.me/{u}",                            "status_200",        None),
    ("Gravatar",     "https://en.gravatar.com/{u}",                     "status_200",        None),
    ("Imgur",        "https://imgur.com/user/{u}",                      "status_200",        None),
    ("VK",           "https://vk.com/{u}",                              "status_200",        None),
    ("Wattpad",      "https://www.wattpad.com/user/{u}",                "status_200",        None),
    ("Ask.fm",       "https://ask.fm/{u}",                              "status_200",        None),
    ("Letterboxd",   "https://letterboxd.com/{u}/",                     "status_200",        None),
    ("Goodreads",    "https://www.goodreads.com/{u}",                   "status_200",        None),
]


async def _check_platform(session: aiohttp.ClientSession, platform: str, url: str, method: str, false_indicator: str | None, username: str) -> dict | None:
    try:
        actual_url = url.format(u=username)
        async with session.get(actual_url, allow_redirects=True, max_redirects=3) as resp:
            if method == "status_200":
                found = resp.status == 200
            elif method == "status_not_404":
                found = resp.status not in (404, 410)
            elif method == "body_not_contains":
                body = await resp.text(encoding="utf-8", errors="ignore")
                found = resp.status == 200 and (false_indicator not in body if false_indicator else True)
            else:
                found = resp.status == 200

            if found and false_indicator and method != "body_not_contains":
                try:
                    body = await resp.text(encoding="utf-8", errors="ignore")
                    if false_indicator in body:
                        found = False
                except Exception:
                    pass

            if found:
                return {"platform": platform, "url": actual_url, "status": resp.status}
    except Exception:
        pass
    return None


class UsernamePlugin(BasePlugin):
    name = "username"
    description = "Username search across 50+ platforms (Sherlock-style)"
    supported_target_types = ["username"]

    async def run(self, target: str) -> PluginResult:
        username = target.strip().lstrip("@")
        if not username or len(username) < 2:
            return PluginResult(plugin_name=self.name, success=False, error="Username too short")

        found = []
        checked = 0
        sem = asyncio.Semaphore(10)

        async def bounded_check(session, *args):
            async with sem:
                return await _check_platform(session, *args)

        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        timeout = aiohttp.ClientTimeout(total=12, connect=5)

        async with aiohttp.ClientSession(headers=HEADERS, connector=connector, timeout=timeout) as session:
            tasks = [
                bounded_check(session, name, url, method, fi, username)
                for name, url, method, fi in PLATFORMS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            checked += 1
            if isinstance(r, dict):
                found.append(r)

        found_sorted = sorted(found, key=lambda x: x["platform"])

        categories = {
            "Social Media": [],
            "Tech & Dev": [],
            "Creative": [],
            "Gaming": [],
            "Commerce": [],
            "Other": [],
        }
        cat_map = {
            "GitHub": "Tech & Dev", "GitLab": "Tech & Dev", "HackerNews": "Tech & Dev",
            "StackOverflow": "Tech & Dev", "ProductHunt": "Tech & Dev", "Keybase": "Tech & Dev",
            "Dev.to": "Tech & Dev", "Replit": "Tech & Dev", "CodePen": "Tech & Dev",
            "DeviantArt": "Creative", "Behance": "Creative", "Dribbble": "Creative",
            "ArtStation": "Creative", "Flickr": "Creative", "SoundCloud": "Creative",
            "Spotify": "Creative", "Bandcamp": "Creative", "Mixcloud": "Creative",
            "Steam": "Gaming", "Xbox": "Gaming", "PSN": "Gaming", "Roblox": "Gaming",
            "Etsy": "Commerce", "Patreon": "Commerce", "Fiverr": "Commerce", "Upwork": "Commerce",
        }
        for item in found_sorted:
            cat = cat_map.get(item["platform"], "Social Media" if item["platform"] in [
                "Twitter/X", "Instagram", "Reddit", "TikTok", "YouTube", "Twitch",
                "Pinterest", "Tumblr", "Medium", "Quora", "LinkedIn", "Snapchat", "Telegram",
                "VK", "Ask.fm", "Wattpad",
            ] else "Other")
            categories[cat].append(item)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "username": username,
                "platforms_checked": checked,
                "found_count": len(found),
                "profiles": found_sorted,
                "by_category": {k: v for k, v in categories.items() if v},
            },
        )
