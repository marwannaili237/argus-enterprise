"""
Regex-based entity extractor (lightweight NER, no spaCy/transformers).
Extracts IOCs and entities from investigation evidence for graphing and IOC DB.
"""
import re
from typing import Any

# ─── Patterns ──────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"\bhttps?://[^\s<>'\"{}|\\^`]+", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "asn": re.compile(r"\bAS\d{1,10}\b"),
    "btc": re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "cidr": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b"),
    "port": re.compile(r"\bport[ _-]?(\d{1,5})\b", re.IGNORECASE),
    "useragent": re.compile(r"\b(?:Mozilla|curl|wget|python-requests)/[\d.]+[^\s]*"),
    "phone_e164": re.compile(r"\+\d{6,15}\b"),
    "mac": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
}

# Subdomain heuristics to skip false positives
_SUSPICIOUS_DOMAINS = {"example.com", "example.org", "yourdomain.com", "domain.com"}


def _is_likely_domain(s: str) -> bool:
    if s.lower() in _SUSPICIOUS_DOMAINS:
        return False
    if s.count(".") < 1:
        return False
    return True


def _extract_from_text(text: str) -> list[dict]:
    """Extract all entities from a text snippet."""
    found = []
    seen = set()
    for etype, pat in PATTERNS.items():
        for m in pat.finditer(text):
            val = m.group(0)
            key = (etype, val)
            if key in seen:
                continue
            seen.add(key)
            if etype == "domain" and not _is_likely_domain(val):
                continue
            if etype == "md5":
                # MD5 conflicts with SHA1/SHA256 prefixes; we'll dedupe later
                pass
            found.append({"type": etype, "value": val, "context": text[max(0, m.start()-40):m.end()+40]})
    return found


def extract_entities(target: str, target_type: str, combined_data: dict[str, Any]) -> list[dict]:
    """
    Extract entities from all plugin evidence. Returns a deduplicated list of
    {type, value, source, context, confidence}.
    """
    import json
    # Flatten combined_data into text
    text_parts = [f"target:{target}"]
    for plugin_name, data in combined_data.items():
        try:
            text_parts.append(f"[{plugin_name}] {json.dumps(data, default=str)}")
        except Exception:
            text_parts.append(f"[{plugin_name}] {str(data)[:500]}")

    full_text = "\n".join(text_parts)
    raw = _extract_from_text(full_text)

    # Dedupe by (type, value), keep first context
    dedup = {}
    for ent in raw:
        key = (ent["type"], ent["value"].lower())
        if key not in dedup:
            ent["source"] = "regex"
            ent["confidence"] = 75
            dedup[key] = ent

    # Add the original target as an entity
    if target_type in ("domain", "url", "ip", "email", "username", "phone", "mac", "crypto"):
        type_map = {"crypto": "btc"}  # crypto maps to btc/eth, regex will catch
        target_type_norm = type_map.get(target_type, target_type)
        if target_type_norm in PATTERNS or target_type_norm == "username":
            dedup[(target_type_norm, target.lower())] = {
                "type": target_type_norm,
                "value": target,
                "source": "target",
                "context": "Investigation target",
                "confidence": 100,
            }

    return list(dedup.values())
