"""
MITRE ATT&CK mapping — rule-based, no external API.
Maps OSINT findings to ATT&CK techniques based on indicators detected.
"""
from typing import Any

# (T-ID, name, tactic) — small curated subset of ATT&CK Enterprise techniques
# relevant to what OSINT investigations typically surface.
ATTACK_TECHNIQUES = {
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1071.004": ("DNS", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1090.003": ("Tor Routing", "Command and Control"),
    "T1090.004": ("Domain Fronting", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1204": ("User Execution", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1583": ("Acquire Infrastructure", "Resource Development"),
    "T1583.001": ("Domains", "Resource Development"),
    "T1583.002": ("DNS Server", "Resource Development"),
    "T1583.004": ("Server", "Resource Development"),
    "T1584": ("Compromise Infrastructure", "Resource Development"),
    "T1589": ("Gather Victim Host Information", "Reconnaissance"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1590": ("Gather Victim Host Information", "Reconnaissance"),
    "T1590.004": ("Network Topology", "Reconnaissance"),
    "T1590.005": ("IP Addresses", "Reconnaissance"),
    "T1590.006": ("Network Trust Dependencies", "Reconnaissance"),
    "T1591": ("Gather Victim Org Information", "Reconnaissance"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.001": ("Scanning IP Blocks", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1592.002": ("Software", "Reconnaissance"),
    "T1592.004": "Client Configurations",
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1049": ("System Network Connections", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1087": ("Account Discovery", "Discovery"),
    "T1087.001": ("Local Account", "Discovery"),
    "T1087.002": ("Domain Account", "Discovery"),
    "T1588": ("Obtain Capabilities", "Resource Development"),
    "T1588.006": ("Vulnerabilities", "Resource Development"),
    "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1133": ("External Remote Services", "Initial Access, Persistence"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),
    "T1199": ("Trusted Relationship", "Initial Access"),
}


def map_to_attack(target: str, target_type: str, combined_data: dict[str, Any]) -> list[dict]:
    """
    Analyze evidence and return list of {technique_id, name, tactic, evidence_source}.
    Pure rule-based; no network calls.
    """
    findings = []

    def _add(tid, source, evidence=""):
        tech = ATTACK_TECHNIQUES.get(tid)
        if not tech:
            return
        name, tactic = tech if isinstance(tech, tuple) else (tech, "Reconnaissance")
        findings.append({
            "technique_id": tid,
            "name": name,
            "tactic": tactic,
            "source": source,
            "evidence": evidence[:200],
        })

    # Reputation: TOR / malicious / proxy
    rep = combined_data.get("reputation", {}) or {}
    if rep.get("is_tor_exit"):
        _add("T1090.003", "reputation", "TOR exit node detected")
    if rep.get("threats"):
        threats = rep.get("threats", [])
        if any("proxy" in str(t).lower() for t in threats):
            _add("T1090", "reputation", "Proxy indicator")
        if any("vpn" in str(t).lower() for t in threats):
            _add("T1090", "reputation", "VPN indicator")

    # Shodan: open ports → service discovery; vulns → vulnerability scanning
    sh = combined_data.get("shodan", {}) or {}
    if sh.get("all_open_ports"):
        ports = sh.get("all_open_ports", [])
        _add("T1046", "shodan", f"Open ports: {ports[:8]}")
        if 80 in ports or 443 in ports or 8080 in ports:
            _add("T1071.001", "shodan", "HTTP(S) services exposed")
        if 53 in ports:
            _add("T1071.004", "shodan", "DNS service exposed")
        if 22 in ports or 3389 in ports:
            _add("T1133", "shodan", "External remote services (SSH/RDP)")
    if sh.get("all_vulns"):
        _add("T1190", "shodan", f"Vulnerabilities: {sh.get('all_vulns', [])[:5]}")

    # Phishing indicators from URL/HTTP
    http = combined_data.get("http", {}) or {}
    if http.get("title") and any(kw in http.get("title", "").lower() for kw in ["login", "verify", "secure", "account"]):
        _add("T1566.002", "http", f"Suspicious title: {http.get('title')}")

    # Subdomains indicate infrastructure
    sub = combined_data.get("subdomains", {}) or {}
    if sub.get("subdomains") and len(sub.get("subdomains", [])) > 5:
        _add("T1583.001", "subdomains", f"Subdomain sprawl: {len(sub.get('subdomains', []))} found")

    # Email breach → valid accounts
    breach = combined_data.get("breach", {}) or {}
    if breach.get("credentials_leaked"):
        _add("T1078", "breach", "Credentials leaked — valid accounts risk")

    # Tech stack discovery
    tech = combined_data.get("technology", {}) or {}
    if tech.get("technologies"):
        _add("T1592.002", "technology", f"Tech: {tech.get('technologies', [])[:8]}")

    # Active scanning indicators
    certs = combined_data.get("certs", {}) or {}
    if certs.get("total_certs", 0) > 50:
        _add("T1595.001", "certs", f"Large cert count: {certs.get('total_certs')}")

    # Dedupe by technique_id
    seen = set()
    result = []
    for f in findings:
        if f["technique_id"] in seen:
            continue
        seen.add(f["technique_id"])
        result.append(f)
    return result


def to_attack_matrix(findings: list[dict]) -> dict:
    """Group findings by tactic for a matrix-style display."""
    matrix: dict[str, list[dict]] = {}
    for f in findings:
        tactic = f["tactic"]
        matrix.setdefault(tactic, []).append(f)
    return matrix
