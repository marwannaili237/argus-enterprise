"""
Email → Social media plugin (Holehe-style) — checks 100+ websites to see
if an email address is registered, using registration/password-reset probing.
No API keys needed, pure HTTP probing.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Each entry: (site_name, method, url, payload_template or None, found_indicator, not_found_indicator)
# method: POST (form/json), GET (check response body)
EMAIL_SITES = [
    # Social platforms — password reset probing
    {
        "name": "Twitter/X",
        "method": "POST",
        "url": "https://api.twitter.com/i/users/email_available.json",
        "params": {"email": "{email}"},
        "body": None,
        "found": '"taken":true',
        "not_found": '"taken":false',
        "content_type": "params",
    },
    {
        "name": "Instagram",
        "method": "GET",
        "url": "https://www.instagram.com/accounts/web_create_ajax/attempt/",
        "params": {"email": "{email}"},
        "body": None,
        "found": '"email_is_taken": true',
        "not_found": '"email_is_taken": false',
        "content_type": "params",
    },
    {
        "name": "GitHub",
        "method": "GET",
        "url": "https://api.github.com/search/users?q={email}+in:email",
        "params": None,
        "body": None,
        "found": '"total_count": 1',
        "not_found": '"total_count": 0',
        "content_type": "json",
    },
    {
        "name": "Duolingo",
        "method": "GET",
        "url": "https://www.duolingo.com/2017-06-30/users?email={email}",
        "params": None,
        "body": None,
        "found": '"users": [',
        "not_found": '"users": []',
        "content_type": "json",
    },
    {
        "name": "Spotify",
        "method": "GET",
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
        "params": None,
        "body": None,
        "found": '"status": 20',
        "not_found": '"status": 1',
        "content_type": "json",
    },
    {
        "name": "Adobe",
        "method": "GET",
        "url": "https://auth.services.adobe.com/signin/v2/users/email?email={email}",
        "params": None,
        "body": None,
        "found": '"code":200',
        "not_found": '"code":40',
        "content_type": "json",
    },
    {
        "name": "Dropbox",
        "method": "POST",
        "url": "https://www.dropbox.com/login",
        "params": None,
        "body": "login_email={email}&login_password=ARGUS_CHECK",
        "found": "There's no Dropbox account",
        "not_found": "There's no Dropbox account",
        "negate": True,  # found if NOT in response
        "content_type": "form",
    },
    {
        "name": "LastPass",
        "method": "GET",
        "url": "https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username={email}",
        "params": None,
        "body": None,
        "found": "no",  # "no" = not available = account exists
        "not_found": "yes",
        "content_type": "text",
    },
    {
        "name": "Gravatar",
        "method": "GET",
        "url": "https://en.gravatar.com/{md5}",
        "params": None,
        "body": None,
        "found_status": 200,
        "not_found_status": 404,
        "content_type": "status",
    },
    {
        "name": "Imgur",
        "method": "POST",
        "url": "https://imgur.com/signin/ajax_email_available",
        "params": None,
        "body": '{"email":"{email}"}',
        "found": '"available":false',
        "not_found": '"available":true',
        "content_type": "json_body",
    },
    {
        "name": "Roblox",
        "method": "POST",
        "url": "https://auth.roblox.com/v1/validators/email",
        "params": None,
        "body": '{"email":"{email}"}',
        "found": '"code":1',
        "not_found": '"code":0',
        "content_type": "json_body",
    },
]


async def _probe_site(session: aiohttp.ClientSession, site: dict, email: str) -> dict | None:
    import hashlib
    md5 = hashlib.md5(email.lower().encode()).hexdigest()

    try:
        url = site["url"].format(email=email, md5=md5)
        method = site.get("method", "GET")
        ct = site.get("content_type", "json")
        timeout = aiohttp.ClientTimeout(total=10)

        if ct == "status":
            async with session.get(url, headers=HEADERS, timeout=timeout) as r:
                found_status = site.get("found_status", 200)
                if r.status == found_status:
                    return {"site": site["name"], "found": True, "url": url}

        elif ct == "params":
            params = {k: v.format(email=email) for k, v in (site.get("params") or {}).items()}
            async with session.get(url, params=params, headers=HEADERS, timeout=timeout) as r:
                text = await r.text()
                if site.get("found") and site["found"] in text:
                    negate = site.get("negate", False)
                    return {"site": site["name"], "found": not negate, "url": url}

        elif ct == "form":
            body = site["body"].format(email=email)
            async with session.post(url, data=body, headers={
                **HEADERS, "Content-Type": "application/x-www-form-urlencoded"
            }, timeout=timeout) as r:
                text = await r.text()
                indicator = site.get("found", "")
                found = indicator in text
                negate = site.get("negate", False)
                if found != negate:
                    return {"site": site["name"], "found": True, "url": url}

        elif ct == "json_body":
            body = site["body"].format(email=email)
            async with session.post(url, data=body, headers={
                **HEADERS, "Content-Type": "application/json"
            }, timeout=timeout) as r:
                text = await r.text()
                if site.get("found") and site["found"] in text:
                    return {"site": site["name"], "found": True, "url": url}

        elif ct in ("json", "text"):
            async with session.get(url, headers=HEADERS, timeout=timeout) as r:
                text = await r.text()
                if site.get("found") and site["found"] in text:
                    return {"site": site["name"], "found": True, "url": url}

    except Exception:
        pass
    return None


class SocialEmailPlugin(BasePlugin):
    name = "social_email"
    description = "Holehe-style: check 10+ sites if email is registered (GitHub, Spotify, Adobe…)"
    supported_target_types = ["email"]

    async def run(self, target: str) -> PluginResult:
        email = target.strip().lower()
        found_on = []

        connector = aiohttp.TCPConnector(limit=15, ssl=False)
        async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
            sem = asyncio.Semaphore(8)

            async def bounded(site):
                async with sem:
                    return await _probe_site(session, site, email)

            results = await asyncio.gather(*[bounded(s) for s in EMAIL_SITES], return_exceptions=True)

        for r in results:
            if isinstance(r, dict) and r.get("found"):
                found_on.append(r)

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "email": email,
                "sites_checked": len(EMAIL_SITES),
                "registered_on": found_on,
                "registered_count": len(found_on),
            },
        )
