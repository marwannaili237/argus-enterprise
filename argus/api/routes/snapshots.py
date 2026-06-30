"""
Snapshot endpoints — capture HTML + screenshot of a URL, store as evidence.
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from database import get_db
from models import Investigation, Evidence, User
from api.deps import get_current_user
from api.rate_limit import rate_limit
from fastapi import Depends as _Depends
from intel.snapshot import capture_html_snapshot, capture_screenshot, snapshot_to_pdf_metadata

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


class CaptureRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    include_screenshot: bool = False


@router.post("/capture", dependencies=[_Depends(rate_limit(limit=10, window=60))])
async def capture_snapshot(
    req: CaptureRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Capture an HTML + optional screenshot snapshot of a URL.
    Does NOT auto-attach to any investigation — caller can attach via
    POST /investigations/{id}/notes or store the returned sha256 as an IOC.

    Returns:
      {html: {...}, screenshot: {...}, pdf_metadata: {...}}
    """
    html = await capture_html_snapshot(req.url)
    if "error" in html:
        raise HTTPException(400, html["error"])

    screenshot = None
    if req.include_screenshot:
        screenshot = await capture_screenshot(req.url)

    pdf_meta = snapshot_to_pdf_metadata(html)

    return {
        "html": html,
        "screenshot": screenshot,
        "pdf_metadata": pdf_meta,
    }


@router.post("/investigations/{inv_id}", dependencies=[_Depends(rate_limit(limit=10, window=60))])
async def attach_snapshot_to_investigation(
    inv_id: int,
    req: CaptureRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Capture a snapshot and store it as Evidence on an existing investigation.
    """
    # Verify investigation ownership
    result = await db.execute(
        select(Investigation).where(Investigation.id == inv_id, Investigation.user_id == current_user.id)
    )
    inv = result.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "Investigation not found")

    html = await capture_html_snapshot(req.url)
    if "error" in html:
        raise HTTPException(400, html["error"])

    # Store as evidence
    ev = Evidence(
        investigation_id=inv_id,
        plugin_name="snapshot",
        data={
            "url": req.url,
            "html_snapshot": {k: v for k, v in html.items() if k != "html_base64"},
            "html_size_bytes": html.get("size_bytes", 0),
            "html_sha256": html.get("sha256"),
            "fetched_at": html.get("fetched_at"),
        },
    )
    db.add(ev)

    # Optional screenshot
    if req.include_screenshot:
        screenshot = await capture_screenshot(req.url)
        if "error" not in screenshot:
            ev_screenshot = Evidence(
                investigation_id=inv_id,
                plugin_name="screenshot",
                data={
                    "url": req.url,
                    "sha256": screenshot.get("sha256"),
                    "size_bytes": screenshot.get("size_bytes"),
                    "captured_at": screenshot.get("captured_at"),
                    "width": screenshot.get("width"),
                    "height": screenshot.get("height"),
                    # Note: screenshot_base64 stored separately to avoid bloating evidence JSON
                },
            )
            db.add(ev_screenshot)

    await db.commit()
    return {"ok": True, "investigation_id": inv_id, "html_sha256": html.get("sha256")}
