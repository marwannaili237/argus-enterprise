import re

from plugins.base import BasePlugin, PluginResult

IBAN_REGEX = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")

# 30 major European banks by BIC prefix (bank code, first 4 chars of BIC).
# Keys are the 4-letter bank-code portion of the BIC, value is bank name.
BIC_BANK_TABLE: dict[str, str] = {
    # Germany
    "COBA": "Commerzbank",
    "DEUT": "Deutsche Bank",
    "DRES": "Dresdner Bank / Commerzbank",
    "POST": "Deutsche Postbank",
    "SPKA": "Sparkasse",
    "GENO": "Genossenschaftsbank (Volksbank / Raiffeisen)",
    # France
    "BNPA": "BNP Paribas",
    "SOGE": "Société Générale",
    "CREG": "Crédit Agricole",
    "CMCI": "Crédit Mutuel",
    "BCMA": "Banque Populaire",
    # United Kingdom
    "BARC": "Barclays Bank",
    "HSBC": "HSBC Bank",
    "LOYD": "Lloyds Bank",
    "NATW": "NatWest",
    "RBOS": "Royal Bank of Scotland",
    # Spain
    "ESPA": "Banco Santander",
    "BBVA": "BBVA",
    "CAIX": "La Caixa",
    # Italy
    "INTB": "Intesa Sanpaolo",
    "UCIT": "UniCredit",
    "CRIT": "Credito Emiliano",
    # Netherlands
    "ABNA": "ABN AMRO",
    "INGB": "ING Bank",
    "RABO": "Rabobank",
    # Switzerland
    "UBSW": "UBS Switzerland",
    "CRES": "Credit Suisse",
    # Sweden
    "SWED": "Swedbank",
    "SEBK": "SEB",
    # Austria
    "OBKL": "Oberbank",
    "BKAU": "Bank Austria / UniCredit Bank Austria",
}

# Approximate country codes (ISO 3166-1 alpha-2) — used for display
COUNTRY_NAMES: dict[str, str] = {
    "DE": "Germany", "FR": "France", "GB": "United Kingdom", "ES": "Spain",
    "IT": "Italy", "NL": "Netherlands", "CH": "Switzerland", "SE": "Sweden",
    "AT": "Austria", "BE": "Belgium", "IE": "Ireland", "PT": "Portugal",
    "PL": "Poland", "FI": "Finland", "DK": "Denmark", "NO": "Norway",
    "LU": "Luxembourg", "CZ": "Czech Republic", "HU": "Hungary", "RO": "Romania",
}


def _iban_valid(iban: str) -> bool:
    """Validate IBAN checksum using mod-97 algorithm."""
    s = iban.replace(" ", "").upper()
    if not IBAN_REGEX.match(s):
        return False
    # Move first 4 chars to end
    rearranged = s[4:] + s[:4]
    # Replace letters: A=10, B=11, ... Z=35
    digits = []
    for ch in rearranged:
        if ch.isdigit():
            digits.append(ch)
        else:
            digits.append(str(ord(ch) - 55))
    num_str = "".join(digits)
    # Python int can handle arbitrarily large numbers
    try:
        return int(num_str) % 97 == 1
    except ValueError:
        return False


class IbanPlugin(BasePlugin):
    name = "iban"
    description = "IBAN checksum validator + bank identifier lookup (mod-97, no external calls)"
    supported_target_types: list[str] = []

    async def run(self, target: str) -> PluginResult:
        try:
            iban = target.strip().upper().replace(" ", "")
            if not IBAN_REGEX.match(iban):
                return PluginResult(
                    plugin_name=self.name,
                    success=False,
                    error="Target does not match IBAN format ^[A-Z]{2}\\d{2}[A-Z0-9]{10,30}$",
                )

            valid = _iban_valid(iban)
            country_code = iban[:2]
            country_name = COUNTRY_NAMES.get(country_code, "Unknown")

            # The bank identifier in an IBAN is country-specific.
            # For most SEPA countries it is the first 4 chars after the check digits.
            bank_code = iban[4:8] if len(iban) >= 8 else None
            bic_prefix = bank_code
            bank_name = BIC_BANK_TABLE.get(bank_code) if bank_code else None

            summary = (
                f"IBAN {iban[:4]}…{iban[-4:]} from {country_name} is "
                f"{'VALID' if valid else 'INVALID'}."
                + (f" Likely bank: {bank_name} (BIC prefix {bic_prefix})." if bank_name else "")
            )

            return PluginResult(
                plugin_name=self.name,
                success=valid,
                data={
                    "iban": f"{iban[:4]}…{iban[-4:]}",
                    "country": country_code,
                    "country_name": country_name,
                    "valid": valid,
                    "bank_name": bank_name,
                    "bic_prefix": bic_prefix,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
