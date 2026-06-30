import aiohttp
import re
from plugins.base import BasePlugin, PluginResult
from intel.ssrf import is_safe_url

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


class HttpPlugin(BasePlugin):
    name = "http"
    description = "HTTP metadata fetch (title, headers, status, technologies)"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        try:
            if not target.startswith(("http://", "https://")):
                urls_to_try = [f"https://{target}", f"http://{target}"]
            else:
                urls_to_try = [target]

            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; ArgusBot/1.0)",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }

            for url in urls_to_try:
                # SSRF guard: skip unsafe URLs
                safe, reason = is_safe_url(url)
                if not safe:
                    continue
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.get(url, headers=headers, allow_redirects=True, max_redirects=5) as resp:
                            # Re-check final URL after redirects (defense in depth)
                            final_url = str(resp.url)
                            safe_final, _ = is_safe_url(final_url)
                            if not safe_final:
                                return PluginResult(plugin_name=self.name, success=False,
                                                    error="Final URL after redirect is blocked (SSRF guard)")
                            status = resp.status
                            resp_headers = dict(resp.headers)
                            body = await resp.text(encoding="utf-8", errors="ignore")

                    title_match = TITLE_RE.search(body[:5000])
                    title = title_match.group(1).strip() if title_match else None

                    desc_match = META_DESC_RE.search(body[:5000])
                    description = desc_match.group(1).strip() if desc_match else None

                    techs = []
                    server = resp_headers.get("Server", resp_headers.get("server"))
                    powered_by = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by"))
                    if server:
                        techs.append(server)
                    if powered_by:
                        techs.append(powered_by)

                    tech_patterns = {
                        "WordPress": "wp-content",
                        "Drupal": "Drupal.settings",
                        "Joomla": "/components/com_",
                        "React": "react",
                        "Next.js": "__NEXT_DATA__",
                        "Vue.js": "vue",
                        "Angular": "ng-version",
                        "Bootstrap": "bootstrap",
                        "jQuery": "jquery",
                        "Cloudflare": "cloudflare",
                    }
                    body_lower = body[:20000].lower()
                    for tech, pattern in tech_patterns.items():
                        if pattern.lower() in body_lower:
                            if tech not in techs:
                                techs.append(tech)

                    security_headers = {}
                    for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                        val = resp_headers.get(h) or resp_headers.get(h.lower())
                        if val:
                            security_headers[h] = val

                    return PluginResult(
                        plugin_name=self.name,
                        success=True,
                        data={
                            "url": final_url,
                            "status_code": status,
                            "title": title,
                            "description": description,
                            "technologies": techs[:10],
                            "security_headers": security_headers,
                            "content_type": resp_headers.get("Content-Type", resp_headers.get("content-type")),
                        },
                    )
                except aiohttp.ClientConnectorError:
                    continue

            return PluginResult(plugin_name=self.name, success=False, error="Could not connect to target")

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
