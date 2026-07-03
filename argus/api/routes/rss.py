"""RSS 2.0 feed of a user's recent investigations."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, HTTPException, Response, Depends, Path
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import User, Investigation
from api.deps import get_current_user

router = APIRouter(tags=["rss"])

VALID_EVENTS = {"investigation_complete", "monitor_alert"}


def _esc(s: str) -> str:
    return escape(s or "")


def _build_rxml(items: list[dict], base_url: str) -> str:
    """Build an RSS 2.0 XML string (no external library)."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    xml_items = ""
    for it in items:
        xml_items += f"""    <item>
      <title>{_esc(it['title'])}</title>
      <link>{_esc(base_url)}/#/investigation/{it['id']}</link>
      <guid>{_esc(base_url)}/api/v1/investigations/{it['id']}</guid>
      <pubDate>{_esc(it['pub_date'])}</pubDate>
      <description>{_esc(it['description'])}</description>
      <category>{_esc(it['type'])}</category>
    </item>
"""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Argus OSINT Investigations</title>
    <link>{_esc(base_url)}</link>
    <description>Latest OSINT investigation results from Argus</description>
    <language>en-us</language>
    <lastBuildDate>{now_iso}</lastBuildDate>
    <generator>Argus OSINT</generator>
{xml_items}  </channel>
</rss>"""


@router.get("/users/{user_id}/rss")
async def user_rss_feed(
    user_id: int = Path(..., description="User ID"),
    current_user: User = Depends(get_current_user),
):
    """Return RSS 2.0 XML feed of the user's last 20 investigations.

    Authentication is via the Authorization header (Bearer token).
    Users can only access their own RSS feed.
    """
    # Ensure user can only access their own RSS feed
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Cannot access another user's RSS feed")

    from database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Investigation)
            .where(Investigation.user_id == current_user.id)
            .order_by(desc(Investigation.created_at))
            .limit(20)
        )
        investigations = result.scalars().all()

    base_url = ""  # callers can prepend their host
    items = []
    for inv in investigations:
        ts = inv.created_at.strftime("%a, %d %b %Y %H:%M:%S +0000") if inv.created_at else ""
        summary_excerpt = (inv.summary or "")[:300]
        items.append(
            {
                "id": inv.id,
                "title": f"[{inv.status.upper()}] {inv.target}",
                "type": inv.target_type,
                "status": inv.status,
                "description": f"Target: {inv.target}\nType: {inv.target_type}\nStatus: {inv.status}\n\n{summary_excerpt}",
                "pub_date": ts,
            }
        )

    xml = _build_rxml(items, base_url)
    return Response(content=xml, media_type="application/rss+xml")
