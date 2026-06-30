"""
Auto-tagger — suggests tags for an investigation based on its evidence.
"""
import re
from typing import Any


# Rule → tag (evaluated against evidence dict)
TAG_RULES: list[tuple[str, Any]] = [
    ("tor", lambda d: (d.get("reputation", {}) or {}).get("is_tor_exit")),
    ("proxy", lambda d: (d.get("ip_geo", {}) or {}).get("is_proxy")),
    ("vpn", lambda d: any("vpn" in str(t).lower() for t in (d.get("reputation", {}) or {}).get("threats", []))),
    ("breached", lambda d: (d.get("breach", {}) or {}).get("breach_found")),
    ("credentials-leaked", lambda d: (d.get("breach", {}) or {}).get("credentials_leaked")),
    ("disposable-email", lambda d: (d.get("email", {}) or {}).get("disposable")),
    ("blacklisted", lambda d: (d.get("email", {}) or {}).get("blacklisted")),
    ("vulnerable", lambda d: bool((d.get("shodan", {}) or {}).get("all_vulns"))),
    ("exposed-ports", lambda d: bool((d.get("shodan", {}) or {}).get("all_open_ports"))),
    ("subdomain-sprawl", lambda d: len((d.get("subdomains", {}) or {}).get("subdomains", [])) > 20),
    ("cdn-hosted", lambda d: (d.get("ip_geo", {}) or {}).get("is_hosting")),
    ("new-domain", lambda d: "202" in str((d.get("whois", {}) or {}).get("creation_date", "")[:5])),
    ("sanctions-hit", lambda d: (d.get("opensanctions", {}) or {}).get("matches")),
    ("threatfox-listed", lambda d: (d.get("threatfox", {}) or {}).get("matches")),
    ("otx-flagged", lambda d: (d.get("otx", {}) or {}).get("indicators")),
    ("malware-associated", lambda d: (d.get("malwarebazaar", {}) or {}).get("samples")),
    ("phishing-suspected", lambda d: "phish" in str((d.get("reputation", {}) or {}).get("threats", [])).lower() or
                                          any(k in str((d.get("http", {}) or {}).get("title", "")).lower()
                                              for k in ["login", "verify", "account", "secure"])),
    ("c2-suspected", lambda d: (d.get("cobaltstrike", {}) or {}).get("detected") or
                                  (d.get("jarm", {}) or {}).get("c2_match")),
    ("ssl-misconfigured", lambda d: bool((d.get("ssl_analysis", {}) or {}).get("issues"))),
    ("has-cve", lambda d: bool((d.get("shodan", {}) or {}).get("all_vulns"))),
    ("high-entropy", lambda d: bool((d.get("secret_scanner", {}) or {}).get("secrets_found"))),
    ("ico-or-sto", lambda d: bool((d.get("cryptoscamdb", {}) or {}).get("matches"))),
]


def suggest_tags(combined_data: dict[str, Any]) -> list[dict]:
    """Return list of {tag, color, reason} based on evidence."""
    suggestions = []
    color_palette = {
        "tor": "#9b59b6", "proxy": "#9b59b6", "vpn": "#9b59b6",
        "breached": "#e94560", "credentials-leaked": "#e94560",
        "disposable-email": "#f39c12", "blacklisted": "#e94560",
        "vulnerable": "#e94560", "exposed-ports": "#e94560",
        "subdomain-sprawl": "#3498db", "cdn-hosted": "#7f8c8d",
        "new-domain": "#f39c12", "sanctions-hit": "#e94560",
        "threatfox-listed": "#e94560", "otx-flagged": "#e94560",
        "malware-associated": "#e94560", "phishing-suspected": "#e94560",
        "c2-suspected": "#e94560", "ssl-misconfigured": "#f39c12",
        "has-cve": "#e94560", "high-entropy": "#e94560",
        "ico-or-sto": "#e94560",
    }
    for tag, rule in TAG_RULES:
        try:
            if rule(combined_data):
                suggestions.append({
                    "tag": tag,
                    "color": color_palette.get(tag, "#e94560"),
                    "reason": f"Auto-detected by rule '{tag}'",
                })
        except Exception:
            continue
    return suggestions
