"""
Wayback Machine / Web Archive plugin — completely free archive.org API.
Returns first/last snapshot dates, total snapshot count, availability,
and interesting historical snapshots for investigation context.
"""
import asyncio
import re
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {"User-Agent": "ArgusOSINT/1.0"}


def _extract_host(target: str) -> str:
    if "://" in target:
        return target.split("://")[1].split("/")[0]
    return target


class WaybackPlugin(BasePlugin):
    name = "wayback"
    description = "Wayback Machine — archive history, first seen, snapshot count"
    supported_target_types = ["domain", "url"]

    async def run(self, target: str) -> PluginResult:
        host = _extract_host(target)
        url_to_check = target if target.startswith("http") else f"https://{target}"

        results = {}

        async def check_availability():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12)) as s:
                    async with s.get(
                        f"https://archive.org/wayback/available?url={url_to_check}",
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            snap = data.get("archived_snapshots", {}).get("closest", {})
                            results["available"] = snap.get("available", False)
                            results["closest_snapshot"] = snap.get("url")
                            results["closest_timestamp"] = snap.get("timestamp")
                            results["closest_status"] = snap.get("status")
            except Exception:
                pass

        async def check_cdx_stats():
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as s:
                    # CDX API — get full snapshot history
                    params = {
                        "url": f"*.{host}/*",
                        "output": "json",
                        "limit": "5",
                        "fl": "timestamp,original,statuscode,length",
                        "collapse": "timestamp:6",
                        "from": "19960101",
                    }
                    async with s.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params=params,
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if isinstance(data, list) and len(data) > 1:
                                results["snapshots_sample"] = data[1:6]  # Skip header row

                    # Get count
                    count_params = {
                        "url": f"*.{host}/*",
                        "output": "json",
                        "limit": "1",
                        "showNumPages": "true",
                    }
                    async with s.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params=count_params,
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            try:
                                results["page_count"] = int(text.strip())
                            except Exception:
                                pass

                    # Get first and last snapshot
                    for limit_type, key in [("asc", "first"), ("desc", "last")]:
                        snap_params = {
                            "url": f"{host}",
                            "output": "json",
                            "limit": "1",
                            "fl": "timestamp,original,statuscode",
                            "filter": "statuscode:200",
                        }
                        if limit_type == "asc":
                            snap_params["from"] = "19960101"
                        else:
                            snap_params["to"] = "21000101"
                            snap_params["limit"] = "-1"

                        async with s.get(
                            "https://web.archive.org/cdx/search/cdx",
                            params=snap_params,
                            headers=HEADERS,
                        ) as r:
                            if r.status == 200:
                                data = await r.json(content_type=None)
                                if isinstance(data, list) and len(data) > 1:
                                    row = data[1] if limit_type == "asc" else data[-1]
                                    ts = row[0] if row else ""
                                    results[f"{key}_snapshot_ts"] = ts
                                    if ts and len(ts) >= 8:
                                        results[f"{key}_snapshot_date"] = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
                                    results[f"{key}_snapshot_url"] = f"https://web.archive.org/web/{ts}/{row[1]}" if row else None

            except Exception:
                pass

        async def check_changes():
            """Detect recent content changes via snapshot diffs"""
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
                    params = {
                        "url": host,
                        "output": "json",
                        "limit": "10",
                        "fl": "timestamp,statuscode",
                        "from": "20230101",
                        "collapse": "timestamp:6",
                    }
                    async with s.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params=params,
                        headers=HEADERS,
                    ) as r:
                        if r.status == 200:
                            data = await r.json(content_type=None)
                            if isinstance(data, list) and len(data) > 1:
                                results["recent_snapshots"] = [
                                    {"date": f"{row[0][0:4]}-{row[0][4:6]}-{row[0][6:8]}", "status": row[1]}
                                    for row in data[1:]
                                    if len(row) >= 2
                                ]
            except Exception:
                pass

        await asyncio.gather(check_availability(), check_cdx_stats(), check_changes())

        has_archive = results.get("available", False) or results.get("first_snapshot_date") is not None

        return PluginResult(
            plugin_name=self.name,
            success=True,
            data={
                "target": host,
                "has_archive": has_archive,
                "available": results.get("available", False),
                "closest_snapshot": results.get("closest_snapshot"),
                "closest_timestamp": results.get("closest_timestamp"),
                "first_seen": results.get("first_snapshot_date"),
                "first_snapshot_url": results.get("first_snapshot_url"),
                "last_seen": results.get("last_snapshot_date"),
                "last_snapshot_url": results.get("last_snapshot_url"),
                "snapshot_pages": results.get("page_count"),
                "recent_snapshots": results.get("recent_snapshots", []),
                "samples": results.get("snapshots_sample", []),
            },
        )
