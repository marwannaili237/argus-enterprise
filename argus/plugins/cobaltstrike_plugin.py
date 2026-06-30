import asyncio

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

# Known Cobalt Strike beacon URIs and team-server endpoints.
# The classic CS stager uses /dpixel, /submit.php, /api/, /login / /favicon.ico etc.
# Each URI's checksum8 must equal 92 for the URI to be a valid CS stager path.
CS_BEACON_URIS = [
    "/dpixel",
    "/submit.php",
    "/api/get.php",
    "/api/sets.php",
    "/api/log.php",
    "/api/proxy",
    "/api/junction",
    "/api/beacon",
    "/favicon.ico",
    "/login/process.php",
    "/badges.php",
]

# Beacon-config markers sometimes present in staged responses
CS_CONFIG_MARKERS = [
    b"BeaconType",
    b"Port",
    b"Sleeptime",
    b"Jitter",
    b"C2Server",
    b"UserAgent",
    b"PublicKey",
    b"killdate",
    b"watermark",
    b"bStageCleanup",
]


def checksum8(uri: str) -> int:
    """Compute CS checksum8 (sum of ASCII codes mod 256). CS beacons expect 92."""
    return sum(ord(c) for c in uri) % 256


class CobaltstrikePlugin(BasePlugin):
    name = "cobaltstrike"
    description = "Cobalt Strike C2 beacon / team-server heuristic detector"
    supported_target_types = ["domain", "url", "ip"]

    @staticmethod
    def _normalize(target: str) -> tuple[str, list[str]]:
        # Strip scheme/path, but remember if user supplied a URL with a path
        scheme = "https"
        t = target.strip()
        if "://" in t:
            scheme = t.split("://", 1)[0].lower()
            t = t.split("://", 1)[1]
        host = t.split("/")[0]
        # Try both http and https for breadth
        bases = [f"https://{host}", f"http://{host}"]
        return host, bases

    async def run(self, target: str) -> PluginResult:
        try:
            host, bases = self._normalize(target)
            if not host:
                return PluginResult(plugin_name=self.name, success=False, error="No host parsed from target")

            checked_uris: list[dict] = []
            indicators: list[str] = []

            timeout = aiohttp.ClientTimeout(total=10)

            async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
                for base in bases:
                    for uri in CS_BEACON_URIS:
                        url = f"{base}{uri}"
                        try:
                            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                                status = resp.status
                                body = await resp.read()
                                body_preview = body[:512]

                                cksum = checksum8(uri)
                                # CS stager expects checksum8==92 for triggered URI.
                                # Many default malleable profiles return 200 with empty/specific body
                                suspicious = False
                                notes = []

                                if status == 200 and len(body) <= 64:
                                    suspicious = True
                                    notes.append("200-with-tiny-body")
                                if cksum == 92:
                                    notes.append("checksum8==92 (classic CS)")
                                # Look for beacon config markers
                                marker_hits = [m.decode(errors="ignore") for m in CS_CONFIG_MARKERS if m in body]
                                if marker_hits:
                                    suspicious = True
                                    notes.append(f"config_markers={marker_hits}")

                                # CS team server often returns 404 for non-beacon paths with empty body
                                if status == 404 and not body:
                                    notes.append("404-empty-body")

                                rec = {
                                    "url": url,
                                    "status": status,
                                    "body_len": len(body),
                                    "checksum8": cksum,
                                    "suspicious": suspicious,
                                    "notes": notes,
                                }
                                checked_uris.append(rec)

                                if suspicious:
                                    ind = f"{url} -> {notes}"
                                    if ind not in indicators:
                                        indicators.append(ind)
                        except Exception as e:
                            checked_uris.append({"url": url, "error": str(e)})

            detected = bool(indicators)
            summary = (
                f"Scanned {len(checked_uris)} CS beacon URIs on {host}; "
                f"{'detected suspicious indicators: ' + str(len(indicators)) if detected else 'no Cobalt Strike indicators found.'}"
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "host": host,
                    "checked_uris": checked_uris,
                    "detected": detected,
                    "indicators": indicators,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
