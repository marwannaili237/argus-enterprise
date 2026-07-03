"""
Image OSINT plugin — EXIF metadata extraction, GPS location, camera info,
reverse image search links, and image fingerprinting.
"""
import asyncio
import io
import hashlib
import aiohttp
from plugins.base import BasePlugin, PluginResult

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; ArgusOSINT/1.0)",
}


class ImagePlugin(BasePlugin):
    name = "image"
    description = "Image OSINT: EXIF metadata, GPS location, camera info, reverse search links"
    supported_target_types = ["image"]

    async def run(self, target: str) -> PluginResult:
        try:
            from PIL import Image, ExifTags
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            return PluginResult(plugin_name=self.name, success=False, error="Pillow not installed")

        # Determine if it's a URL or local path
        is_url = target.startswith(("http://", "https://"))

        try:
            if is_url:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
                    async with s.get(target, headers=HEADERS) as resp:
                        if resp.status != 200:
                            return PluginResult(plugin_name=self.name, success=False, error=f"HTTP {resp.status} fetching image")
                        content_type = resp.headers.get("Content-Type", "")
                        if not any(t in content_type for t in ["image/", "jpeg", "png", "gif", "webp"]):
                            return PluginResult(plugin_name=self.name, success=False, error=f"Not an image (Content-Type: {content_type})")
                        raw = await resp.read()
            else:
                with open(target, "rb") as f:
                    raw = f.read()

            # Hashes
            md5 = hashlib.md5(raw).hexdigest()
            sha256 = hashlib.sha256(raw).hexdigest()
            sha1 = hashlib.sha1(raw).hexdigest()

            loop = asyncio.get_event_loop()
            img_data = await loop.run_in_executor(None, _extract_image_data, raw, target, md5, sha256, sha1)

            return PluginResult(plugin_name=self.name, success=True, data=img_data)

        except Exception as e:
            return PluginResult(plugin_name=self.name, success=False, error=str(e))


def _extract_image_data(raw: bytes, source: str, md5: str, sha256: str, sha1: str) -> dict:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import struct

    img = Image.open(io.BytesIO(raw))
    width, height = img.size
    fmt = img.format or "UNKNOWN"
    mode = img.mode

    data = {
        "source": source,
        "format": fmt,
        "mode": mode,
        "width": width,
        "height": height,
        "file_size_bytes": len(raw),
        "file_size_kb": round(len(raw) / 1024, 1),
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "exif": {},
        "gps": None,
        "camera": {},
        "software": None,
        "datetime": None,
        "thumbnail": None,
        "reverse_search_links": _reverse_search_links(source, md5),
    }

    # Extract EXIF
    try:
        raw_exif = img._getexif()
        if raw_exif:
            gps_info = {}
            for tag_id, value in raw_exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    for gps_tag_id, gps_val in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag] = str(gps_val)

                    # Try to decode GPS coordinates
                    try:
                        lat = _convert_gps(value.get(2), value.get(1))
                        lon = _convert_gps(value.get(4), value.get(3))
                        if lat is not None and lon is not None:
                            data["gps"] = {
                                "latitude": round(lat, 6),
                                "longitude": round(lon, 6),
                                "maps_url": f"https://maps.google.com/maps?q={lat},{lon}",
                                "altitude": _safe_rational(value.get(6)),
                            }
                    except Exception:
                        pass

                elif tag in ("Make", "Model", "LensModel", "LensMake"):
                    data["camera"][tag] = str(value)
                elif tag == "Software":
                    data["software"] = str(value)
                elif tag in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                    data["datetime"] = str(value)
                elif tag not in ("MakerNote", "UserComment") and isinstance(value, (str, int, float)):
                    data["exif"][str(tag)] = str(value)[:200]

    except (AttributeError, Exception):
        pass

    # Try XMP/IPTC for non-JPEG
    try:
        if hasattr(img, "info"):
            info = img.info
            for k in ("xmp", "comment", "description", "author", "copyright"):
                if k in info:
                    data["exif"][k] = str(info[k])[:200]
    except Exception:
        pass

    return data


def _convert_gps(coord, ref) -> float | None:
    if not coord or len(coord) < 3:
        return None
    try:
        def _r(v):
            if hasattr(v, "numerator"):
                return v.numerator / v.denominator
            if isinstance(v, tuple) and len(v) == 2:
                return v[0] / v[1]
            return float(v)

        degrees = _r(coord[0])
        minutes = _r(coord[1])
        seconds = _r(coord[2])
        val = degrees + minutes / 60 + seconds / 3600
        if ref and str(ref).upper() in ("S", "W"):
            val = -val
        return val
    except Exception:
        return None


def _safe_rational(v) -> float | None:
    try:
        if hasattr(v, "numerator"):
            return v.numerator / v.denominator
        if isinstance(v, tuple) and len(v) == 2:
            return v[0] / v[1]
        return float(v)
    except Exception:
        return None


def _reverse_search_links(source: str, md5: str) -> dict:
    links = {}
    if source.startswith("http"):
        import urllib.parse
        enc = urllib.parse.quote_plus(source)
        links["Google"] = f"https://www.google.com/searchbyimage?image_url={enc}"
        links["TinEye"] = f"https://tineye.com/search?url={enc}"
        links["Bing"] = f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}"
        links["Yandex"] = f"https://yandex.com/images/search?rpt=imageview&url={enc}"
    return links
