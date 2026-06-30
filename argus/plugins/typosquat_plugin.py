import asyncio

import dns.resolver

from plugins.base import BasePlugin, PluginResult

# QWERTY adjacent-key map
QWERTY_ADJACENT: dict[str, str] = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "i": "ujklo",
    "j": "huikmn",
    "k": "jijolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
}

HOMOGLYPHS: dict[str, str] = {
    "o": "0",
    "l": "1",
    "e": "3",
    "i": "1",
    "a": "@",
    "s": "5",
    "g": "9",
    "t": "7",
    "b": "8",
}

VOWELS = "aeiou"

TLD_SWAPS = ["com", "co", "net", "org", "io", "app", "xyz", "info", "biz"]


class TyposquatPlugin(BasePlugin):
    name = "typosquat"
    description = "Typosquatting domain variant generator with DNS resolution check"
    supported_target_types = ["domain"]

    def _generate_variants(self, domain: str) -> list[tuple[str, str]]:
        """Generate (variant, type) pairs for a domain."""
        variants: list[tuple[str, str]] = []
        seen: set[str] = set()

        if "." not in domain:
            return variants

        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return variants
        sld, tld = parts[0].lower(), parts[1].lower()
        full = f"{sld}.{tld}"
        seen.add(full)

        def add(v: str, vtype: str):
            if v and v != full and "." in v and v not in seen:
                seen.add(v)
                variants.append((v, vtype))

        # (a) missing char
        for i in range(len(sld)):
            cand = sld[:i] + sld[i + 1:]
            add(f"{cand}.{tld}", "missing_char")

        # (b) extra char (a-z)
        for c in "abcdefghijklmnopqrstuvwxyz":
            for i in range(len(sld) + 1):
                cand = sld[:i] + c + sld[i:]
                add(f"{cand}.{tld}", "extra_char")

        # (c) adjacent-key substitution
        for i, c in enumerate(sld):
            for repl in QWERTY_ADJACENT.get(c, ""):
                cand = sld[:i] + repl + sld[i + 1:]
                add(f"{cand}.{tld}", "adjacent_key")

        # (d) homoglyph substitution
        for i, c in enumerate(sld):
            if c in HOMOGLYPHS:
                cand = sld[:i] + HOMOGLYPHS[c] + sld[i + 1:]
                add(f"{cand}.{tld}", "homoglyph")

        # (e) vowel swap
        for i, c in enumerate(sld):
            if c in VOWELS:
                for v in VOWELS:
                    if v != c:
                        cand = sld[:i] + v + sld[i + 1:]
                        add(f"{cand}.{tld}", "vowel_swap")

        # (f) TLD swap
        for new_tld in TLD_SWAPS:
            if new_tld != tld:
                add(f"{sld}.{new_tld}", "tld_swap")

        return variants

    def _resolve(self, domain: str) -> tuple[bool, str | None]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = resolver.resolve(domain, "A", raise_on_no_answer=False)
            for r in answers:
                return True, str(r)
            return False, None
        except Exception:
            return False, None

    async def run(self, target: str) -> PluginResult:
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0].lower().strip()
            if not domain or "." not in domain:
                return PluginResult(plugin_name=self.name, success=False, error="Invalid domain")

            raw_variants = self._generate_variants(domain)
            # Cap at 50 to keep memory/DNS lookups bounded
            raw_variants = raw_variants[:50]

            loop = asyncio.get_event_loop()

            async def check_variant(v: str, vtype: str) -> dict:
                resolves, ip = await loop.run_in_executor(None, self._resolve, v)
                return {"domain": v, "type": vtype, "resolves": resolves, "ip": ip}

            results = await asyncio.gather(*[check_variant(v, t) for v, t in raw_variants])
            registered = [r for r in results if r["resolves"]]
            registered_count = len(registered)

            summary = (
                f"Generated {len(results)} typosquat variants for {domain}; "
                f"{registered_count} resolved to an A record."
            )

            return PluginResult(
                plugin_name=self.name,
                success=True,
                data={
                    "original": domain,
                    "variants": results,
                    "registered_count": registered_count,
                    "summary": summary,
                },
            )
        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))
