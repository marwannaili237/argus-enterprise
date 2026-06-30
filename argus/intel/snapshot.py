"""
Snapshot archiver — captures HTML + screenshot of a URL at investigation time
and stores them as Evidence rows. Uses aiohttp for HTML fetch (with SSRF guard)
and optionally Playwright for screenshots (if installed).

For low-end/free-tier deployments, Playwright is optional — we always save
the HTML snapshot, and add a screenshot only if Playwright is available.
"""
import base64
import hashlib
import logging
from datetime import datetime, timezone
import aiohttp
from intel.ssrf import is_safe_url

logger = logging.getLogger("argus.snapshot")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


async def capture_html_snapshot(url: str, max_bytes: int = 1024 * 1024) -> dict:
    """
    Fetch HTML body of a URL with SSRF guard.
    Returns {url, status, html_base64, sha256, fetched_at, content_type, size_bytes} or {error}.
    """
    safe, reason = is_safe_url(url)
    if not safe:
        return {"error": f"URL blocked by SSRF guard: {reason}", "url": url}

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), headers=HEADERS) as s:
            async with s.get(url, allow_redirects=True, max_redirects=5, ssl=False) as r:
                if r.status >= 500:
                    return {"error": f"HTTP {r.status}", "url": url}
                body = await r.content.read(max_bytes)
                if not body:
                    return {"error": "Empty body", "url": url}
                sha = hashlib.sha256(body).hexdigest()
                return {
                    "url": url,
                    "final_url": str(r.url),
                    "status": r.status,
                    "html_base64": base64.b64encode(body).decode(),
                    "sha256": sha,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "content_type": r.headers.get("Content-Type", ""),
                    "size_bytes": len(body),
                }
    except Exception as e:
        return {"error": str(e), "url": url}


async def capture_screenshot(url: str, width: int = 1280, height: int = 800) -> dict:
    """
    Capture a PNG screenshot of a URL via Playwright (if installed).
    Returns {url, screenshot_base64, sha256, captured_at} or {error, skipped: true} if Playwright missing.
    """
    safe, reason = is_safe_url(url)
    if not safe:
        return {"error": f"URL blocked by SSRF guard: {reason}", "url": url, "skipped": True}

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "error": "Playwright not installed — install with `pip install playwright && playwright install chromium`",
            "url": url,
            "skipped": True,
        }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx = await browser.new_context(viewport={"width": width, "height": height})
            page = await ctx.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                png = await page.screenshot(full_page=False)
                sha = hashlib.sha256(png).hexdigest()
                return {
                    "url": url,
                    "screenshot_base64": base64.b64encode(png).decode(),
                    "sha256": sha,
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "width": width,
                    "height": height,
                    "size_bytes": len(png),
                }
            finally:
                await browser.close()
    except Exception as e:
        return {"error": str(e), "url": url}


def snapshot_to_pdf_metadata(html_snapshot: dict) -> dict:
    """
    Generate a 'PDF snapshot' metadata record (we don't actually convert HTML to PDF
    without wkhtmltopdf/playwright; instead we record a metadata stub pointing to the
    HTML base64 that can be rendered client-side via print-to-PDF in the dashboard).
    """
    return {
        "url": html_snapshot.get("url"),
        "html_sha256": html_snapshot.get("sha256"),
        "fetched_at": html_snapshot.get("fetched_at"),
        "note": "PDF snapshot is the HTML base64 — open in browser and use Print to PDF for archival.",
        "size_bytes": html_snapshot.get("size_bytes", 0),
    }
