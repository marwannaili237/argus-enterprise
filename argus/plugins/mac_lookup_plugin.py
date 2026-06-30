import re

from plugins.base import BasePlugin, PluginResult

# Common OUI vendor table (first 3 octets -> vendor)
OUI_TABLE: dict[str, dict] = {
    "00:50:56": {"vendor": "VMware", "type": "virtual"},
    "00:0C:29": {"vendor": "VMware", "type": "virtual"},
    "00:05:69": {"vendor": "VMware", "type": "virtual"},
    "00:1C:42": {"vendor": "Parallels", "type": "virtual"},
    "08:00:27": {"vendor": "VirtualBox", "type": "virtual"},
    "00:15:5D": {"vendor": "Microsoft Hyper-V", "type": "virtual"},
    "00:03:FF": {"vendor": "Microsoft Virtual PC", "type": "virtual"},
    "F8:4D:89": {"vendor": "Docker", "type": "virtual"},
    "02:42:AC": {"vendor": "Docker", "type": "virtual"},
    "54:EF:44": {"vendor": "Amazon AWS", "type": "virtual"},
    "40:31:3C": {"vendor": "Amazon AWS", "type": "virtual"},
    "02:00:00": {"vendor": "XenSource (random)", "type": "random"},
    "EE:FF:FF": {"vendor": "Random (locally administered)", "type": "random"},
    "00:1A:2B": {"vendor": "Intel", "type": "physical"},
    "00:26:B0": {"vendor": "Intel", "type": "physical"},
    "3C:97:0E": {"vendor": "Intel", "type": "physical"},
    "F0:DE:F1": {"vendor": "Intel", "type": "physical"},
    "8C:EC:4B": {"vendor": "Intel", "type": "physical"},
    "B4:2E:99": {"vendor": "Intel", "type": "physical"},
    "A4:4C:C8": {"vendor": "Intel", "type": "physical"},
    "AC:1F:6B": {"vendor": "Intel", "type": "physical"},
    "D8:CB:8A": {"vendor": "Apple", "type": "physical"},
    "A4:83:E7": {"vendor": "Apple", "type": "physical"},
    "78:CA:39": {"vendor": "Apple", "type": "physical"},
    "F8:FF:0A": {"vendor": "Apple", "type": "physical"},
    "3C:22:FB": {"vendor": "Apple", "type": "physical"},
    "A8:60:B6": {"vendor": "Apple", "type": "physical"},
    "00:25:BC": {"vendor": "Apple", "type": "physical"},
    "00:1E:52": {"vendor": "Apple", "type": "physical"},
    "DC:A6:32": {"vendor": "Raspberry Pi Foundation", "type": "physical"},
    "B8:27:EB": {"vendor": "Raspberry Pi Foundation", "type": "physical"},
    "E4:5F:01": {"vendor": "Raspberry Pi Foundation", "type": "physical"},
    "28:CD:C1": {"vendor": "Raspberry Pi Foundation", "type": "physical"},
    "D8:BB:C1": {"vendor": "Samsung", "type": "physical"},
    "A0:CB:FD": {"vendor": "Samsung", "type": "physical"},
    "EC:1F:72": {"vendor": "Samsung", "type": "physical"},
    "AC:84:C6": {"vendor": "Samsung", "type": "physical"},
    "00:1A:4D": {"vendor": "ASUS", "type": "physical"},
    "04:D4:C4": {"vendor": "ASUS", "type": "physical"},
    "1C:69:7A": {"vendor": "ASUS", "type": "physical"},
    "2C:F0:5D": {"vendor": "ASUS", "type": "physical"},
    "60:45:CB": {"vendor": "ASUS", "type": "physical"},
    "00:0D:3A": {"vendor": "Dell", "type": "physical"},
    "F8:BC:12": {"vendor": "Dell", "type": "physical"},
    "B8:AC:6F": {"vendor": "Dell", "type": "physical"},
    "18:C0:4D": {"vendor": "Dell", "type": "physical"},
    "EC:F4:BB": {"vendor": "Dell", "type": "physical"},
    "AC:DE:48": {"vendor": "Dell", "type": "physical"},
    "A4:5E:60": {"vendor": "Cisco", "type": "physical"},
    "00:1B:54": {"vendor": "Cisco", "type": "physical"},
    "00:23:AC": {"vendor": "Cisco", "type": "physical"},
    "FC:99:47": {"vendor": "Cisco", "type": "physical"},
    "70:81:05": {"vendor": "Cisco", "type": "physical"},
    "54:75:D0": {"vendor": "Microsoft", "type": "physical"},
    "7C:1E:52": {"vendor": "Microsoft", "type": "physical"},
    "00:15:5D": {"vendor": "Microsoft", "type": "physical"},
    "48:5B:39": {"vendor": "Hewlett Packard", "type": "physical"},
    "2C:41:A1": {"vendor": "Hewlett Packard", "type": "physical"},
    "B0:26:28": {"vendor": "Hewlett Packard", "type": "physical"},
    "1C:C1:DE": {"vendor": "Hewlett Packard", "type": "physical"},
    "A0:D3:C1": {"vendor": "Hewlett Packard", "type": "physical"},
    "D4:BE:D9": {"vendor": "Hewlett Packard", "type": "physical"},
    "DC:4A:3E": {"vendor": "Hewlett Packard", "type": "physical"},
    "E8:48:B8": {"vendor": "Netgear", "type": "physical"},
    "60:38:E0": {"vendor": "Netgear", "type": "physical"},
    "A4:CF:12": {"vendor": "Netgear", "type": "physical"},
    "C0:3F:D5": {"vendor": "Netgear", "type": "physical"},
    "00:8E:F2": {"vendor": "Netgear", "type": "physical"},
    "B0:95:75": {"vendor": "TP-Link", "type": "physical"},
    "A8:42:A1": {"vendor": "TP-Link", "type": "physical"},
    "EC:17:2F": {"vendor": "TP-Link", "type": "physical"},
    "50:C7:BF": {"vendor": "TP-Link", "type": "physical"},
    "78:8A:20": {"vendor": "TP-Link", "type": "physical"},
}

# Check if MAC is locally administered (second bit of first octet)
def _is_locally_administered(mac_octets: list[str]) -> bool:
    first_byte = int(mac_octets[0], 16)
    return bool(first_byte & 0x02)


class MacLookupPlugin(BasePlugin):
    name = "mac_lookup"
    description = "MAC address OUI vendor lookup with virtual/random MAC detection"
    supported_target_types = ["mac"]

    async def run(self, target: str) -> PluginResult:
        try:
            mac = target.strip().upper()
            mac = mac.replace("-", ":")
            octets = mac.split(":")

            if len(octets) != 12 and len(octets) != 6:
                return PluginResult(plugin_name=self.name, success=False, error="Invalid MAC address format")

            if len(octets) == 12:
                octets = [f"{octets[i]}{octets[i+1]}" for i in range(0, 12, 2)]

            oui = f"{octets[0]}:{octets[1]}:{octets[2]}"
            normalized_mac = ":".join(octets)
            locally_admin = _is_locally_administered(octets)
            multicast = bool(int(octets[0], 16) & 0x01)

            oui_info = OUI_TABLE.get(oui)
            vendor = oui_info["vendor"] if oui_info else None
            mac_type = oui_info["type"] if oui_info else ("random" if locally_admin else "physical")

            import asyncio
            ieee_info = None

            async def fetch_ieee():
                nonlocal ieee_info
                try:
                    import aiohttp
                    oui_hex = oui.replace(":", "").lower()
                    url = f"https://services13.ieee.org/RST/standards-ra-web/rest/assignments/download/?registry=MA-L&format=txt&search={oui_hex}"
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=8)
                    ) as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                # Parse first matching line
                                for line in text.strip().splitlines():
                                    if oui_hex.lower() in line.lower():
                                        parts = line.strip().split("\t")
                                        if len(parts) >= 3:
                                            ieee_info = {
                                                "vendor": parts[2].strip(),
                                                "address": parts[1].strip() if len(parts) > 1 else "",
                                            }
                                        break
                except Exception:
                    pass

            await asyncio.create_task(fetch_ieee())

            final_vendor = vendor or (ieee_info["vendor"] if ieee_info else None)

            results = {
                "mac": normalized_mac,
                "oui": oui,
                "vendor": final_vendor,
                "address_block": f"{oui}:00:00 - {oui}:FF:FF",
                "type": mac_type,
                "is_locally_administered": locally_admin,
                "is_multicast": multicast,
                "is_virtual": mac_type == "virtual",
                "is_random": mac_type == "random" or locally_admin,
                "ieee_lookup": ieee_info,
            }

            return PluginResult(plugin_name=self.name, success=True, data=results)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))