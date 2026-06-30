"""
STIX 2.1 bundle export — pure Python (stix2 lib is lightweight, no API calls).
Falls back to a minimal hand-rolled STIX bundle if the library is missing.
"""
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_id(entity_type: str, value: str) -> str:
    """Deterministic STIX ID via UUIDv5 (namespace = Argus)."""
    NAMESPACE = uuid.UUID("6c8e1b0a-1c2d-4e3f-8a4b-5c6d7e8f9a0b")
    return f"{entity_type}--{uuid.uuid5(NAMESPACE, value)}"


def _make_observation(inv_target: str, plugin_name: str, data: dict) -> dict:
    """Wrap a plugin result as a STIX 2.1 Observed Data object."""
    return {
        "type": "observed-data",
        "id": _make_id("observed-data", f"{inv_target}-{plugin_name}"),
        "created": _now(),
        "modified": _now(),
        "first_observed": _now(),
        "last_observed": _now(),
        "number_observed": 1,
        "created_by_ref": "identity--argus",
        "objects": {
            "0": {
                "type": "x-argus-plugin-result",
                "plugin_name": plugin_name,
                "target": inv_target,
                "data": data,
            }
        },
    }


def _make_indicator(value: str, ioc_type: str) -> dict:
    """Map IOC value to STIX Indicator with appropriate pattern."""
    type_map = {
        "ipv4": ("ipv4-addr", "ipv4-addr:value"),
        "ipv6": ("ipv6-addr", "ipv6-addr:value"),
        "domain": ("domain-name", "domain-name:value"),
        "url": ("url", "url:value"),
        "email": ("email-addr", "email-addr:value"),
        "md5": ("file", "file:hashes.MD5"),
        "sha1": ("file", "file:hashes.SHA-1"),
        "sha256": ("file", "file:hashes.SHA-256"),
        "cve": ("vulnerability", "vulnerability:name"),
        "btc": ("x-cryptocurrency-transaction", "x-cryptocurrency-transaction:value"),
    }
    stix_type, pattern_key = type_map.get(ioc_type, ("x-argus-ioc", "x-argus-ioc:value"))
    return {
        "type": "indicator",
        "id": _make_id("indicator", f"{ioc_type}-{value}"),
        "created": _now(),
        "modified": _now(),
        "name": value,
        "pattern": f"[{pattern_key} = '{value}']",
        "pattern_type": "stix",
        "valid_from": _now(),
        "labels": ["malicious-activity"],
        "x_argus_ioc_type": ioc_type,
    }


def export_stix_bundle(target: str, target_type: str, evidence_list: list, entities: list | None = None) -> dict:
    """
    Build a STIX 2.1 bundle from an investigation.
    `evidence_list` is a list of (plugin_name, data) tuples or PluginResult-like objects.
    `entities` is optional list of extracted entities (from intel.entity_extractor).
    Returns a STIX bundle dict that can be JSON-serialized.
    """
    # Identity (Argus itself)
    identity = {
        "type": "identity",
        "id": "identity--argus",
        "created": _now(),
        "modified": _now(),
        "name": "Argus OSINT Platform",
        "identity_class": "system",
    }

    # Target SDO (the thing being investigated)
    target_sdo_type_map = {
        "domain": "domain-name",
        "url": "url",
        "ip": "ipv4-addr",
        "email": "email-addr",
        "username": "user-account",
    }
    target_sdo_type = target_sdo_type_map.get(target_type, "x-argus-target")
    target_sdo = {
        "type": target_sdo_type,
        "id": _make_id(target_sdo_type, target),
        "value": target,
    }
    # STIX 2.1 SDOs need created/modified; but SCO (cyber observable) do not.
    if target_sdo_type in ("user-account",):
        target_sdo["created"] = _now()
        target_sdo["modified"] = _now()
        target_sdo["account_login"] = target

    objects = [identity, target_sdo]

    # Observed-data for each plugin result
    for ev in evidence_list:
        plugin_name = ev.get("plugin_name") if isinstance(ev, dict) else getattr(ev, "plugin_name", "")
        data = ev.get("data") if isinstance(ev, dict) else getattr(ev, "data", {})
        if not plugin_name:
            continue
        objects.append(_make_observation(target, plugin_name, data or {}))

    # Indicators from extracted entities
    if entities:
        for ent in entities:
            try:
                objects.append(_make_indicator(ent["value"], ent["type"]))
            except Exception:
                continue

    # Investigation-level report SDO
    report = {
        "type": "report",
        "id": _make_id("report", f"{target}-{_now()}"),
        "created": _now(),
        "modified": _now(),
        "name": f"Argus OSINT Investigation: {target}",
        "published": _now(),
        "report_types": ["threat-report"],
        "created_by_ref": "identity--argus",
        "object_refs": [o["id"] for o in objects if o.get("id")],
    }
    objects.append(report)

    return {
        "type": "bundle",
        "id": _make_id("bundle", f"{target}-{_now()}"),
        "objects": objects,
    }


def export_stix_json(target: str, target_type: str, evidence_list: list, entities: list | None = None) -> str:
    return json.dumps(export_stix_bundle(target, target_type, evidence_list, entities), indent=2, default=str)
