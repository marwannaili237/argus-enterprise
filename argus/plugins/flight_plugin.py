import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

# Conservative callsign matcher: 2 letters + 1-5 digits (e.g. UAL123, BA1234, DL45678)
CALLSIGN_REGEX = re.compile(r"^[A-Z]{2}\d{1,5}$")


class FlightPlugin(BasePlugin):
    name = "flight_tracker"
    description = "Live flight tracker via OpenSky Network public API (free, no key)"
    supported_target_types: list[str] = []

    @staticmethod
    def _normalize(target: str) -> tuple[str, str]:
        t = target.strip().upper().replace(" ", "")
        # Allow an optional "flight:" or "callsign:" prefix
        for prefix in ("FLIGHT:", "CALLSIGN:"):
            if t.startswith(prefix):
                t = t[len(prefix):]
                break
        return t, t

    async def run(self, target: str) -> PluginResult:
        try:
            callsign, normalized = self._normalize(target)
            if not CALLSIGN_REGEX.match(normalized):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error="Target does not look like a flight callsign (^[A-Z]{2}\\d{1,5}$). "
                          "Prefix with 'flight:' to force.",
                )

            # OpenSky public API: /states/own?icao24=... — but for callsign we use the all endpoint with a query.
            # The anonymous endpoint is /states/all?icao24=... but callsign lookup requires laminar search.
            # Use: https://opensky-network.org/api/states/all?icao24=<icao> — but we don't have ICAO from callsign.
            # Best anonymous route: /callsign/<callsign>/ — only available to authenticated users.
            # Fallback: /states/all returns the most recent states; we filter by callsign client-side.
            url = "https://opensky-network.org/api/states/all"

            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {resp.status}")
                    payload = await resp.json(content_type=None)

            states = payload.get("states") or []
            match = None
            for st in states:
                # State vector layout per OpenSky docs; index 0 is icao24, 1 is callsign
                if isinstance(st, list) and len(st) > 1:
                    cs = (st[1] or "").strip().upper()
                    if cs == normalized:
                        match = st
                        break

            if not match:
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error=f"No active flight found for callsign {normalized} (may be inactive or rate-limited).",
                )

            # Indices per OpenSky State Vectors API
            def _g(i: int):
                try:
                    return match[i]
                except Exception:
                    return None

            icao24 = _g(0)
            origin_country = _g(2)
            lon = _g(5)
            lat = _g(6)
            altitude = _g(7) if _g(7) is not None else _g(13)  # baro or geo
            velocity = _g(9)
            on_ground = bool(_g(8))
            last_seen = _g(4)  # last_contact (unix seconds)

            summary = (
                f"Flight {normalized} (ICAO24 {icao24}) from {origin_country} at "
                f"({lat}, {lon}), alt={altitude}m, vel={velocity}m/s, "
                f"{'on ground' if on_ground else 'airborne'}."
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "callsign": normalized,
                    "icao24": icao24,
                    "origin_country": origin_country,
                    "longitude": lon,
                    "latitude": lat,
                    "altitude": altitude,
                    "velocity": velocity,
                    "on_ground": on_ground,
                    "last_seen": last_seen,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
