r"""
EU VIES VAT validation plugin — fully free, no API key.
Validates a European VAT number against the official VIES service using the
newer REST API (falls back to SOAP if REST is unavailable). Targets must
match the pattern `^[A-Z]{2}\d{8,12}$` (country code + numeric VAT number).
"""
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}
VAT_RE = re.compile(r"^[A-Z]{2}\d{8,12}$")


class ViesPlugin(BasePlugin):
    name = "vies"
    description = "EU VIES VAT number validation (REST, official EC endpoint)"
    supported_target_types = []  # triggered only when target looks like a VAT number

    async def run(self, target: str) -> PluginResult:
        try:
            vat = (target or "").strip().upper().replace(" ", "")
            if not VAT_RE.match(vat):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error=(
                        f"target '{target}' is not a valid VAT number "
                        f"(expected format: XX12345678, e.g. IE6388047V is NOT "
                        f"supported — only letters for country + digits)"
                    ),
                )
            country = vat[:2]
            number = vat[2:]

            # Try REST API first (introduced 2023)
            rest_url = (
                f"https://ec.europa.eu/taxation_customs/vies/rest-api/ms/"
                f"{country}/vat/{number}"
            )
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as s:
                    async with s.get(rest_url, headers=HEADERS) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            return self._build_result(
                                country, number, data, source="rest"
                            )
            except Exception:
                pass

            # Fallback to SOAP
            return await self._soap_check(country, number)
        except Exception as e:
            return PluginResult(
                plugin_name=self.name, success=False, error=str(e)
            )

    def _build_result(
        self, country: str, number: str, data: dict, source: str
    ) -> PluginResult:
        valid = bool(data.get("isValid", False))
        name = data.get("name")
        address = data.get("address")
        if valid:
            summary = (
                f"VIES: VAT number {country}{number} is VALID. "
                f"Registered to: {name or 'unknown'}."
            )
        else:
            summary = f"VIES: VAT number {country}{number} is NOT valid."
        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "country": country,
                "vat_number": f"{country}{number}",
                "valid": valid,
                "name": name,
                "address": address,
                "source": source,
                "summary": summary,
            },
        )

    async def _soap_check(self, country: str, number: str) -> PluginResult:
        soap_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:urn="urn:ec.europa.eu:taxud:vies:services:checkVat:types">'
            "<soapenv:Header/><soapenv:Body>"
            f"<urn:checkVat><urn:countryCode>{country}</urn:countryCode>"
            f"<urn:vatNumber>{number}</urn:vatNumber></urn:checkVat>"
            "</soapenv:Body></soapenv:Envelope>"
        )
        url = "https://ec.europa.eu/taxation_customs/vies/services/checkVatService"
        headers = {
            **HEADERS,
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "",
        }
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as s:
                async with s.post(url, data=soap_body, headers=headers) as r:
                    if r.status != 200:
                        return PluginResult(
                            plugin_name=self.name,
                            success=False,
                            error=f"VIES SOAP HTTP {r.status}",
                        )
                    text = await r.text()
            import xml.etree.ElementTree as ET

            # Namespaced response; grab fields by local name for robustness
            root = ET.fromstring(text)
            valid = False
            name = None
            address = None
            for elem in root.iter():
                tag = elem.tag.split("}")[-1]
                if tag == "valid":
                    valid = (elem.text or "").strip().lower() == "true"
                elif tag == "name":
                    name = (elem.text or "").strip() or None
                elif tag == "address":
                    address = (elem.text or "").strip() or None
            if valid:
                summary = (
                    f"VIES: VAT number {country}{number} is VALID (SOAP). "
                    f"Registered to: {name or 'unknown'}."
                )
            else:
                summary = f"VIES: VAT number {country}{number} is NOT valid (SOAP)."
            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "country": country,
                    "vat_number": f"{country}{number}",
                    "valid": valid,
                    "name": name,
                    "address": address,
                    "source": "soap",
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"VIES SOAP request failed: {e}",
            )
