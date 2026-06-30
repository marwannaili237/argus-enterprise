"""
Enhanced threat scoring — combines signals from multiple plugins into a
composite score, MITRE-like kill-chain stage, and recommended actions.
Pure rule-based, no API calls.
"""
from typing import Any


def compute_threat_score(target: str, target_type: str, combined_data: dict[str, Any]) -> dict:
    """
    Returns:
    {
        "score": 0-100,
        "level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
        "indicators": [...],         # list of {category, severity, detail}
        "kill_chain_stages": [...],  # which Lockheed kill-chain stages this target touches
        "recommendations": [...],    # actionable next steps
        "tlp": "AMBER",              # suggested TLP label
    }
    """
    indicators = []
    score = 0

    # ─── Reputation ─────────────────────────────────────────────────────
    rep = combined_data.get("reputation", {}) or {}
    threats = rep.get("threats", []) or []
    if threats:
        sev = min(len(threats), 3)
        score += sev * 8
        indicators.append({
            "category": "Reputation",
            "severity": ["", "low", "medium", "high"][min(sev, 3)],
            "detail": f"Threats flagged: {', '.join(threats[:5])}",
        })
    if rep.get("is_tor_exit"):
        score += 15
        indicators.append({
            "category": "Reputation",
            "severity": "high",
            "detail": "TOR exit node",
        })

    # ─── Shodan / Vulns ─────────────────────────────────────────────────
    sh = combined_data.get("shodan", {}) or {}
    vulns = sh.get("all_vulns", []) or []
    if vulns:
        sev = min(len(vulns), 3)
        score += sev * 10
        indicators.append({
            "category": "Vulnerabilities",
            "severity": ["", "low", "medium", "high"][min(sev, 3)],
            "detail": f"Known CVEs: {', '.join(vulns[:5])}",
        })
    ports = sh.get("all_open_ports", []) or []
    risky_ports = {22, 23, 445, 3389, 5900, 6379, 27017, 9200}
    risky_open = [p for p in ports if p in risky_ports]
    if risky_open:
        score += len(risky_open) * 5
        indicators.append({
            "category": "Exposure",
            "severity": "high" if len(risky_open) >= 2 else "medium",
            "detail": f"Risky open ports: {risky_open}",
        })

    # ─── Breach / Credentials ──────────────────────────────────────────
    breach = combined_data.get("breach", {}) or {}
    if breach.get("breach_found"):
        score += 12
        indicators.append({
            "category": "Breach Exposure",
            "severity": "high",
            "detail": "Target appears in breach databases",
        })
    if breach.get("credentials_leaked"):
        score += 20
        indicators.append({
            "category": "Credential Leak",
            "severity": "critical",
            "detail": "Credentials/passwords exposed in breach",
        })

    # ─── Email reputation ──────────────────────────────────────────────
    em = combined_data.get("email", {}) or {}
    if em.get("blacklisted"):
        score += 15
        indicators.append({
            "category": "Email Reputation",
            "severity": "high",
            "detail": "Email is blacklisted",
        })
    if em.get("disposable"):
        score += 6
        indicators.append({
            "category": "Email Reputation",
            "severity": "low",
            "detail": "Disposable email provider",
        })
    if em.get("malicious_activity"):
        score += 18
        indicators.append({
            "category": "Email Reputation",
            "severity": "high",
            "detail": "Malicious activity history",
        })

    # ─── IP / Proxy ────────────────────────────────────────────────────
    ip = combined_data.get("ip_geo", {}) or {}
    if ip.get("is_proxy"):
        score += 10
        indicators.append({
            "category": "Anonymization",
            "severity": "medium",
            "detail": "Proxy/VPN detected",
        })

    # ─── Subdomain sprawl ──────────────────────────────────────────────
    sub = combined_data.get("subdomains", {}) or {}
    sub_count = sub.get("total_found", len(sub.get("subdomains", [])))
    if sub_count > 50:
        score += 8
        indicators.append({
            "category": "Attack Surface",
            "severity": "medium",
            "detail": f"Large subdomain sprawl: {sub_count}",
        })

    # ─── SSL / Certificate issues ──────────────────────────────────────
    ssl = combined_data.get("ssl_analysis", {}) or {}
    if ssl.get("issues"):
        score += 5
        indicators.append({
            "category": "SSL/TLS",
            "severity": "medium",
            "detail": f"SSL issues: {ssl.get('issues', [])[:3]}",
        })

    # ─── Threat intel hits (new abuse.ch / OTX plugins) ────────────────
    for src in ("threatfox", "otx", "malwarebazaar", "urlscan", "virustotal", "opensanctions", "greynoise"):
        d = combined_data.get(src, {}) or {}
        if d.get("malicious") or d.get("found") or d.get("matches"):
            score += 15
            indicators.append({
                "category": "Threat Intelligence",
                "severity": "high",
                "detail": f"Flagged by {src}: {d.get('summary', 'matches found')}",
            })

    # ─── Clamp ─────────────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 75:
        level, tlp = "CRITICAL", "RED"
    elif score >= 50:
        level, tlp = "HIGH", "AMBER"
    elif score >= 25:
        level, tlp = "MEDIUM", "AMBER"
    else:
        level, tlp = "LOW", "GREEN"

    # Kill chain stages touched
    stages = []
    if sub_count:
        stages.append("Reconnaissance")
    if vulns or risky_open:
        stages.append("Weaponization")
    if em.get("malicious_activity") or threats:
        stages.append("Delivery")
    if breach.get("credentials_leaked"):
        stages.append("Exploitation")
    if rep.get("is_tor_exit") or ip.get("is_proxy"):
        stages.append("Command and Control")
    if not stages:
        stages.append("Reconnaissance")

    # Recommendations
    recs = []
    if level == "CRITICAL":
        recs.append("Isolate target from production network immediately; engage IR team.")
    if vulns:
        recs.append(f"Patch or mitigate CVEs: {', '.join(vulns[:5])}")
    if risky_open:
        recs.append(f"Close or restrict risky ports: {risky_open}")
    if breach.get("credentials_leaked"):
        recs.append("Force password reset for affected accounts; enable MFA.")
    if em.get("disposable"):
        recs.append("Block disposable email domain in registration forms.")
    if sub_count > 50:
        recs.append("Audit subdomains for forgotten/shadow IT; remove unused.")
    if rep.get("is_tor_exit") or ip.get("is_proxy"):
        recs.append("Add to anomaly detection watchlist; flag for proxy/Tor traffic.")
    if not recs:
        recs.append("No critical action required; continue monitoring.")

    return {
        "score": score,
        "level": level,
        "tlp": tlp,
        "indicators": indicators,
        "kill_chain_stages": stages,
        "recommendations": recs,
    }
