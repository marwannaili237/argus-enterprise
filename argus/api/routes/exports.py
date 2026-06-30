"""
Export endpoints — STIX 2.1, MISP, HTML, Markdown, KML, GeoJSON,
PDF (HTML wrapper), DOCX (HTML wrapper for now), and chain-of-custody.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import Investigation, Evidence, EnrichedEntity, User, ChainOfCustody
from api.deps import get_current_user
from intel.threat_scoring import compute_threat_score
from intel.mitre_attack import map_to_attack
from intel.entity_extractor import extract_entities
from intel.attack_navigator import to_navigator_layer, to_risk_matrix
from export.stix import export_stix_bundle, export_stix_json
from export.misp import export_misp_event, export_misp_json
from export.reports import export_html, export_markdown
from export.geo import export_geojson, export_kml, export_geojson_str

router = APIRouter(prefix="/exports", tags=["exports"])


async def _load_investigation(inv_id: int, user: User, db: AsyncSession) -> tuple[Investigation, list[Evidence], list[EnrichedEntity]]:
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")
    ev_result = await db.execute(select(Evidence).where(Evidence.investigation_id == inv_id))
    ent_result = await db.execute(select(EnrichedEntity).where(EnrichedEntity.investigation_id == inv_id))
    return inv, ev_result.scalars().all(), ent_result.scalars().all()


@router.get("/{inv_id}/stix")
async def export_stix(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, entities = await _load_investigation(inv_id, user, db)
    evidence_list = [{"plugin_name": e.plugin_name, "data": e.data, "success": True} for e in evidence]
    ent_dicts = [{"type": e.entity_type, "value": e.value, "source": e.source_plugin, "context": e.context or "", "confidence": e.confidence} for e in entities]
    bundle = export_stix_bundle(inv.target, inv.target_type, evidence_list, ent_dicts)
    return Response(
        content=json.dumps(bundle, indent=2, default=str),
        media_type="application/stix+json",
        headers={"Content-Disposition": f"attachment; filename=argus_stix_{inv_id}.json"},
    )


@router.get("/{inv_id}/misp")
async def export_misp(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, entities = await _load_investigation(inv_id, user, db)
    evidence_list = [{"plugin_name": e.plugin_name, "data": e.data, "success": True} for e in evidence]
    ent_dicts = [{"type": e.entity_type, "value": e.value, "source": e.source_plugin, "context": e.context or "", "confidence": e.confidence} for e in entities]
    combined_data = {e.plugin_name: e.data for e in evidence}
    threat_score = compute_threat_score(inv.target, inv.target_type, combined_data)
    event = export_misp_event(inv.target, inv.target_type, evidence_list, ent_dicts, threat_score)
    return Response(
        content=json.dumps(event, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=argus_misp_{inv_id}.json"},
    )


@router.get("/{inv_id}/html")
async def export_html_report(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, entities = await _load_investigation(inv_id, user, db)
    evidence_list = [{"plugin_name": e.plugin_name, "data": e.data, "success": True} for e in evidence]
    combined_data = {e.plugin_name: e.data for e in evidence}
    threat_score = compute_threat_score(inv.target, inv.target_type, combined_data)
    attack = map_to_attack(inv.target, inv.target_type, combined_data)
    ai_evidence = next((e for e in evidence if e.plugin_name == "ai_analysis"), None)
    ai_report = (ai_evidence.data or {}).get("report") if ai_evidence else None
    ent_dicts = [{"type": e.entity_type, "value": e.value, "source": e.source_plugin, "context": e.context or "", "confidence": e.confidence} for e in entities]
    html = export_html(inv.target, inv.target_type, evidence_list, threat_score, ai_report, ent_dicts, attack)
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename=argus_report_{inv_id}.html"},
    )


@router.get("/{inv_id}/markdown")
async def export_md_report(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, entities = await _load_investigation(inv_id, user, db)
    evidence_list = [{"plugin_name": e.plugin_name, "data": e.data, "success": True} for e in evidence]
    combined_data = {e.plugin_name: e.data for e in evidence}
    threat_score = compute_threat_score(inv.target, inv.target_type, combined_data)
    attack = map_to_attack(inv.target, inv.target_type, combined_data)
    ai_evidence = next((e for e in evidence if e.plugin_name == "ai_analysis"), None)
    ai_report = (ai_evidence.data or {}).get("report") if ai_evidence else None
    ent_dicts = [{"type": e.entity_type, "value": e.value, "source": e.source_plugin, "context": e.context or "", "confidence": e.confidence} for e in entities]
    md = export_markdown(inv.target, inv.target_type, evidence_list, threat_score, ai_report, ent_dicts, attack)
    return PlainTextResponse(
        content=md,
        headers={"Content-Disposition": f"attachment; filename=argus_report_{inv_id}.md"},
    )


@router.get("/{inv_id}/geojson")
async def export_geojson_route(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    combined_data = {e.plugin_name: e.data for e in evidence}
    return Response(
        content=export_geojson_str(combined_data),
        media_type="application/geo+json",
        headers={"Content-Disposition": f"attachment; filename=argus_geo_{inv_id}.geojson"},
    )


@router.get("/{inv_id}/kml")
async def export_kml_route(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    combined_data = {e.plugin_name: e.data for e in evidence}
    kml = export_kml(combined_data, inv.target)
    return Response(
        content=kml,
        media_type="application/vnd.google-earth.kml+xml",
        headers={"Content-Disposition": f"attachment; filename=argus_{inv_id}.kml"},
    )


@router.get("/{inv_id}/threat-score")
async def get_threat_score(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    combined_data = {e.plugin_name: e.data for e in evidence}
    score = compute_threat_score(inv.target, inv.target_type, combined_data)
    attack = map_to_attack(inv.target, inv.target_type, combined_data)
    return {"threat_score": score, "mitre_attack": attack}


@router.get("/{inv_id}/attack-navigator")
async def get_attack_navigator(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """MITRE ATT&CK Navigator layer (JSON, importable into attack-navigator.mitre-attack.github.io)."""
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    combined_data = {e.plugin_name: e.data for e in evidence}
    attack = map_to_attack(inv.target, inv.target_type, combined_data)
    layer = to_navigator_layer(attack, target=inv.target)
    return Response(
        content=json.dumps(layer, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=argus_attack_{inv_id}.json"},
    )


@router.get("/{inv_id}/risk-matrix")
async def get_risk_matrix(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Risk matrix: technique × severity, sorted by severity."""
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    combined_data = {e.plugin_name: e.data for e in evidence}
    attack = map_to_attack(inv.target, inv.target_type, combined_data)
    matrix = to_risk_matrix(attack)
    return {"target": inv.target, "matrix": matrix, "total_findings": len(matrix)}


@router.get("/{inv_id}/chain-of-custody")
async def get_chain_of_custody(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ChainOfCustody).where(ChainOfCustody.investigation_id == inv_id).order_by(ChainOfCustody.timestamp)
    )
    records = result.scalars().all()
    return [
        {
            "id": r.id, "action": r.action, "actor": r.actor,
            "sha256": r.sha256, "timestamp": r.timestamp.isoformat(),
            "details": r.details,
        }
        for r in records
    ]


@router.post("/{inv_id}/verify-integrity")
async def verify_integrity(inv_id: int, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Recompute SHA-256 of current evidence and compare against chain-of-custody records.
    Returns {verified: bool, current_sha256, last_recorded_sha256, drift_detected: bool}.
    """
    inv, evidence, _ = await _load_investigation(inv_id, user, db)
    import hashlib
    import json as _json
    combined_data = {e.plugin_name: e.data for e in evidence}
    current_sha = hashlib.sha256(_json.dumps(combined_data, default=str, sort_keys=True).encode()).hexdigest()

    # Get most recent chain-of-custody record
    result = await db.execute(
        select(ChainOfCustody).where(ChainOfCustody.investigation_id == inv_id)
        .order_by(ChainOfCustody.timestamp.desc()).limit(1)
    )
    last = result.scalar_one_or_none()
    last_sha = last.sha256 if last else None
    verified = last_sha == current_sha if last_sha else True

    return {
        "verified": verified,
        "current_sha256": current_sha,
        "last_recorded_sha256": last_sha,
        "drift_detected": not verified,
        "last_recorded_at": last.timestamp.isoformat() if last else None,
    }
