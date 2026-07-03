import asyncio
import time

import aiohttp

from plugins.base import BasePlugin, PluginResult
from intel.ssrf import is_safe_url

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}


class RedirectChainPlugin(BasePlugin):
    name = "redirect_chain"
    description = "Follow HTTP redirect chains, detect loops and tracker intermediaries"
    supported_target_types = ["url"]

    async def run(self, target: str) -> PluginResult:
        try:
            url = target
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            # SSRF guard
            safe, reason = is_safe_url(url)
            if not safe:
                return PluginResult(plugin_name=self.name, success=False,
                                    error=f"URL blocked by SSRF guard: {reason}")

            chain: list[dict] = []
            visited: set[str] = set()
            max_hops = 20
            current_url = url

            TRACKER_DOMAINS = {
                "google.com", "facebook.com", "doubleclick.net", "googlesyndication.com",
                "googleadservices.com", "facebook.net", "amazon-adsystem.com",
                "outbrain.com", "taboola.com", "criteo.com", "adnxs.com",
                "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
            }

            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=12)) as session:
                for _ in range(max_hops):
                    if current_url in visited:
                        chain.append({
                            "url": current_url,
                            "status": "LOOP_DETECTED",
                            "server": None,
                            "time_ms": 0,
                            "is_tracker": False,
                        })
                        break

                    visited.add(current_url)
                    start = time.monotonic()

                    try:
                        async with session.get(current_url, allow_redirects=False, ssl=False) as resp:
                            elapsed = int((time.monotonic() - start) * 1000)
                            server = resp.headers.get("Server", "")
                            location = resp.headers.get("Location", "")

                            domain = current_url.split("://")[1].split("/")[0].split(":")[0].lower()
                            base_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain
                            is_tracker = base_domain in TRACKER_DOMAINS

                            chain.append({
                                "url": current_url,
                                "status": resp.status,
                                "server": server,
                                "time_ms": elapsed,
                                "location": location,
                                "is_tracker": is_tracker,
                            })

                            if resp.status in (301, 302, 303, 307, 308) and location:
                                if location.startswith("/"):
                                    from urllib.parse import urlparse
                                    parsed = urlparse(current_url)
                                    current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                                else:
                                    current_url = location
                                # SSRF guard on redirect target
                                safe_redirect, redirect_reason = is_safe_url(current_url)
                                if not safe_redirect:
                                    chain.append({
                                        "url": current_url,
                                        "status": "BLOCKED_SSRF",
                                        "error": f"Redirect blocked by SSRF guard: {redirect_reason}",
                                        "time_ms": 0,
                                        "is_tracker": False,
                                    })
                                    break
                            else:
                                break
                    except Exception as e:
                        elapsed = int((time.monotonic() - start) * 1000)
                        chain.append({
                            "url": current_url,
                            "status": "ERROR",
                            "error": str(e),
                            "time_ms": elapsed,
                            "is_tracker": False,
                        })
                        break

            results: dict = {
                "original_url": url,
                "total_hops": len(chain),
                "final_url": chain[-1]["url"] if chain else url,
                "has_loop": any(h.get("status") == "LOOP_DETECTED" for h in chain),
                "tracker_intermediaries": [h["url"] for h in chain if h.get("is_tracker")],
                "chain": chain,
            }

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))