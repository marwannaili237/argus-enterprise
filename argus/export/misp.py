"""
MISP event export — pure Python (no pymisp dependency needed for export).
Generates a JSON MISP event that can be imported by any MISP instance.
"""
import json
import uuid
import hashlib
from datetime import datetime, timezone


# Argus's org UUID (deterministic, generated from "Argus OSINT")
ARGUS_ORG_UUID = str(uuid.uuid5(uuid.NAMESPACE_DNS, "argus-osint.local"))


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _map_type(ioc_type: str) -> tuple[str, str]:
    """Map Argus IOC type to (MISP type, category)."""
    mapping = {
        "ipv4": ("ip-src", "Network activity"),
        "ipv6": ("ip-src", "Network activity"),
        "domain": ("domain", "Network activity"),
        "url": ("url", "Network activity"),
        "email": ("email-src", "Payload delivery"),
        "md5": ("md5", "Payload delivery"),
        "sha1": ("sha1", "Payload delivery"),
        "sha256": ("sha256", "Payload delivery"),
        "cve": ("vulnerability", "External analysis"),
        "btc": ("btc", "Financial fraud"),
        "eth": ("text", "Financial fraud"),
        "asn": ("AS", "Network activity"),
        "user": ("text", "Social network"),
    }
    return mapping.get(ioc_type, ("text", "Other"))


def _galaxy_tags(combined_data: dict) -> list[str]:
    """Generate MISP galaxy tags (MITRE ATT&CK) from evidence."""
    tags = []
    try:
        from intel.mitre_attack import map_to_attack
        findings = map_to_attack("", "", combined_data)
        for f in findings:
            tags.append(f"misp-galaxy:mitre-attack-pattern=\"{f['technique_id']} - {f['name']}\"")
    except Exception:
        pass
    return tags


def export_misp_event(
    target: str,
    target_type: str,
    evidence_list: list,
    entities: list | None = None,
    threat_score: dict | None = None,
    user_email: str = "argus@local",
) -> dict:
    """
    Build a MISP event dict suitable for JSON export.
    evidence_list: list of dicts with at least {plugin_name, data}.
    """
    event_uuid = str(uuid.uuid4())
    attributes = []

    # Target as primary attribute
    target_attr_type, target_attr_cat = _map_type(target_type if target_type != "ip" else "ipv4")
    attributes.append({
        "uuid": str(uuid.uuid4()),
        "type": target_attr_type,
        "category": target_attr_cat,
        "value": target,
        "to_ids": False,
        "comment": "Investigation target",
        "distribution": "0",
    })

    # Entities as additional attributes
    if entities:
        for ent in entities:
            attr_type, attr_cat = _map_type(ent["type"])
            attributes.append({
                "uuid": str(uuid.uuid4()),
                "type": attr_type,
                "category": attr_cat,
                "value": ent["value"],
                "to_ids": ent.get("confidence", 50) >= 80,
                "comment": f"Extracted by {ent.get('source', 'regex')} — {ent.get('context', '')[:200]}",
                "distribution": "0",
            })

    # Plugin results as attributes (text type with comment)
    for ev in evidence_list:
        plugin_name = ev.get("plugin_name") if isinstance(ev, dict) else getattr(ev, "plugin_name", "")
        data = ev.get("data") if isinstance(ev, dict) else getattr(ev, "data", {})
        if not plugin_name:
            continue
        attributes.append({
            "uuid": str(uuid.uuid4()),
            "type": "text",
            "category": "External analysis",
            "value": f"[{plugin_name}] {str(data)[:280]}",
            "to_ids": False,
            "comment": f"Plugin: {plugin_name}",
            "distribution": "0",
        })

    # Tags
    tags = [
        {"name": "type:OSINT", "colour": "#0088cc"},
        {"name": "source:argus", "colour": "#e94560"},
        {"name": "tlp:amber", "colour": "#FFBF00"},
    ]
    if threat_score:
        level = threat_score.get("level", "LOW")
        tags.append({"name": f"threat-level:{level.lower()}", "colour": "#FF0000" if level in ("HIGH", "CRITICAL") else "#FFBF00"})
        # Galaxy tags from MITRE ATT&CK mapping
        combined_data = {ev.get("plugin_name", ""): ev.get("data", {}) for ev in evidence_list if isinstance(ev, dict)}
        for galaxy_tag in _galaxy_tags(combined_data):
            tags.append({"name": galaxy_tag, "colour": "#0088cc"})

    event = {
        "Event": {
            "uuid": event_uuid,
            "info": f"Argus OSINT Investigation: {target}",
            "threat_level_id": "1" if (threat_score or {}).get("level") in ("HIGH", "CRITICAL") else "3",
            "analysis": "2",  # 2 = completed
            "distribution": "0",  # 0 = your org only
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "published": False,
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "orgc": {
                "name": "Argus OSINT",
                "uuid": ARGUS_ORG_UUID,
            },
            "Org": {
                "name": "Argus OSINT",
                "uuid": ARGUS_ORG_UUID,
            },
            "Attribute": attributes,
            "Tag": tags,
        }
    }
    return event


def export_misp_json(target: str, target_type: str, evidence_list: list, entities: list | None = None,
                     threat_score: dict | None = None, user_email: str = "argus@local") -> str:
    return json.dumps(export_misp_event(target, target_type, evidence_list, entities, threat_score, user_email),
                      indent=2, default=str)
