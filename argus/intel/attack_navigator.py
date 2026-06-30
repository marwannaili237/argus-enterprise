"""
MITRE ATT&CK Navigator layer export — JSON format compatible with
https://mitre-attack.github.io/attack-navigator/

Also generates a risk matrix (technique × severity) for dashboard display.
"""
from typing import Any


# tactic → list of (technique_id, name) — small curated Enterprise ATT&CK subset
TACTIC_TECHNIQUES = {
    "Reconnaissance": [
        ("T1590", "Gather Victim Host Information"),
        ("T1590.004", "Network Topology"),
        ("T1590.005", "IP Addresses"),
        ("T1591", "Gather Victim Org Information"),
        ("T1592", "Gather Victim Host Information"),
        ("T1595", "Active Scanning"),
        ("T1595.001", "Scanning IP Blocks"),
        ("T1595.002", "Vulnerability Scanning"),
        ("T1592.002", "Software"),
        ("T1589", "Gather Victim Identity Information"),
    ],
    "Resource Development": [
        ("T1583", "Acquire Infrastructure"),
        ("T1583.001", "Domains"),
        ("T1583.002", "DNS Server"),
        ("T1583.004", "Server"),
        ("T1584", "Compromise Infrastructure"),
        ("T1588", "Obtain Capabilities"),
        ("T1588.006", "Vulnerabilities"),
    ],
    "Initial Access": [
        ("T1566", "Phishing"),
        ("T1566.002", "Spearphishing Link"),
        ("T1190", "Exploit Public-Facing Application"),
        ("T1133", "External Remote Services"),
        ("T1195", "Supply Chain Compromise"),
        ("T1199", "Trusted Relationship"),
    ],
    "Execution": [
        ("T1059", "Command and Scripting Interpreter"),
        ("T1059.007", "JavaScript"),
        ("T1204", "User Execution"),
        ("T1204.002", "Malicious File"),
    ],
    "Discovery": [
        ("T1046", "Network Service Discovery"),
        ("T1049", "System Network Connections"),
        ("T1057", "Process Discovery"),
        ("T1082", "System Information Discovery"),
        ("T1087", "Account Discovery"),
        ("T1087.001", "Local Account"),
        ("T1087.002", "Domain Account"),
    ],
    "Command and Control": [
        ("T1071", "Application Layer Protocol"),
        ("T1071.001", "Web Protocols"),
        ("T1071.004", "DNS"),
        ("T1090", "Proxy"),
        ("T1090.003", "Tor Routing"),
        ("T1090.004", "Domain Fronting"),
        ("T1105", "Ingress Tool Transfer"),
    ],
    "Defense Evasion, Persistence, Privilege Escalation": [
        ("T1078", "Valid Accounts"),
    ],
}


def to_navigator_layer(findings: list[dict], target: str = "Argus Investigation") -> dict:
    """
    Convert MITRE ATT&CK findings to a Navigator layer JSON.

    Navigator layer format: https://github.com/MITRE-ATTACK/attack-navigator/blob/master/layers/LAYERFORMATv4_1.md
    """
    # Build a technique -> score map (score = severity weight)
    technique_scores: dict[str, int] = {}
    technique_comments: dict[str, str] = {}
    for f in findings:
        tid = f.get("technique_id", "")
        if not tid:
            continue
        # Score based on presence: detected = 100, candidate = 50
        technique_scores[tid] = 100
        evidence = f.get("evidence", "")
        technique_comments[tid] = f"Source: {f.get('source', 'unknown')}. Evidence: {evidence[:150]}"

    # Build technique list for the layer
    techniques = []
    for tid, score in technique_scores.items():
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "comment": technique_comments.get(tid, ""),
            "enabled": True,
        })

    # Also include all known techniques as enabled:false for context
    seen = set(technique_scores.keys())
    for tactic, techs in TACTIC_TECHNIQUES.items():
        for tid, name in techs:
            if tid not in seen:
                techniques.append({
                    "techniqueID": tid,
                    "score": 0,
                    "comment": f"Not detected — {name}",
                    "enabled": False,
                })
                seen.add(tid)

    return {
        "versions": {
            "attack": "14",
            "navigator": "4.8.0",
            "layer": "4.5",
        },
        "name": target,
        "domain": "enterprise-attack",
        "description": f"Argus OSINT ATT&CK layer for {target}. Detected techniques scored 100; not-detected shown as 0.",
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Network", "PRE"],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": False,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Detected", "color": "#8ec843"},
            {"label": "Not detected", "color": "#ff6666"},
        ],
        "metadata": [
            {"name": "Generated by", "value": "Argus OSINT Platform"},
            {"name": "Techniques detected", "value": str(sum(1 for t in techniques if t.get("score", 0) > 0))},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def to_risk_matrix(findings: list[dict]) -> dict:
    """
    Generate a risk matrix: tactic → list of (technique_id, name, severity, evidence).
    Severity is computed from evidence weight (high if multiple sources confirm).
    """
    # Group by tactic
    by_tactic: dict[str, list[dict]] = {}
    for f in findings:
        tactic = f.get("tactic", "Unknown")
        by_tactic.setdefault(tactic, []).append(f)

    matrix = []
    for tactic, items in by_tactic.items():
        for item in items:
            # Severity heuristic: 1 source = medium, 2+ = high, 3+ = critical
            sources = item.get("source", "")
            sev = "medium"
            if isinstance(sources, list):
                n = len(sources)
            elif isinstance(sources, str):
                n = 1 if sources else 0
            else:
                n = 0
            if n >= 3:
                sev = "critical"
            elif n >= 2:
                sev = "high"
            elif n == 1:
                sev = "medium"
            else:
                sev = "low"

            matrix.append({
                "tactic": tactic,
                "technique_id": item.get("technique_id"),
                "name": item.get("name"),
                "severity": sev,
                "evidence": item.get("evidence", "")[:200],
                "source": item.get("source"),
            })

    # Sort by severity descending
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matrix.sort(key=lambda x: sev_order.get(x["severity"], 4))
    return matrix
