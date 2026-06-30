import re

import aiohttp

from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}

# VIN: 17 chars, no I/O/Q
VIN_REGEX = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")

# Variables we care about from the vPIC Results array
VINS_OF_INTEREST = {
    "Make": "make",
    "Model": "model",
    "Model Year": "year",
    "Plant Country": "plant_country",
    "Plant City": "plant_city",
    "Vehicle Type": "vehicle_type",
    "Engine Model": "engine",
    "Displacement (L)": "engine_displacement_l",
    "Number of Cylinders": "engine_cylinders",
    "Manufacturer Name": "manufacturer",
    "Series": "series",
    "Trim": "trim",
}


class VinPlugin(BasePlugin):
    name = "vin_decoder"
    description = "VIN decoder via NHTSA vPIC API (free, no key)"
    supported_target_types: list[str] = []

    async def run(self, target: str) -> PluginResult:
        try:
            vin = target.strip().upper().replace(" ", "").replace("-", "")
            if not VIN_REGEX.match(vin):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error="Target does not match VIN format ^[A-HJ-NPR-Z0-9]{17}$",
                )

            url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{vin}?format=json"

            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {resp.status}")
                    payload = await resp.json(content_type=None)

            results_arr = payload.get("Results", []) if isinstance(payload, dict) else []
            decoded: dict[str, str | None] = {k: None for k in VINS_OF_INTEREST.values()}

            for entry in results_arr:
                if not isinstance(entry, dict):
                    continue
                var_name = entry.get("Variable")
                value = entry.get("Value")
                if var_name in VINS_OF_INTEREST and value and str(value).strip():
                    decoded[VINS_OF_INTEREST[var_name]] = str(value).strip()

            # Treat an all-None response as a soft failure
            if not any(decoded.values()):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error="VIN format OK but no data returned by vPIC",
                )

            make = decoded.get("make")
            model = decoded.get("model")
            year = decoded.get("year")
            summary = f"{year or ''} {make or ''} {model or ''}".strip()
            if not summary:
                summary = f"VIN {vin} decoded but make/model not available"

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "vin": vin,
                    "make": make,
                    "model": model,
                    "year": year,
                    "plant_country": decoded.get("plant_country"),
                    "plant_city": decoded.get("plant_city"),
                    "vehicle_type": decoded.get("vehicle_type"),
                    "engine": decoded.get("engine"),
                    "engine_displacement_l": decoded.get("engine_displacement_l"),
                    "engine_cylinders": decoded.get("engine_cylinders"),
                    "manufacturer": decoded.get("manufacturer"),
                    "series": decoded.get("series"),
                    "trim": decoded.get("trim"),
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
