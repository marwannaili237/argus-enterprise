"""
GeoJSON / KML export for evidence with geolocation data.
Pure stdlib, no external deps.
"""
import json
from datetime import datetime, timezone


def _extract_geo_points(combined_data: dict) -> list[dict]:
    """Pull all (lat, lon, label, source) tuples from evidence."""
    points = []

    ip = combined_data.get("ip_geo", {}) or {}
    if ip.get("lat") and ip.get("lon"):
        points.append({
            "lat": ip["lat"], "lon": ip["lon"],
            "label": ip.get("ip", ""),
            "description": f"IP: {ip.get('ip', '')}\n{ip.get('city','')}, {ip.get('country','')}\nISP: {ip.get('isp','')}",
            "source": "ip_geo",
        })

    # Subdomain IPs → geo (from subdomain plugin if it includes IPs)
    sub = combined_data.get("subdomains", {}) or {}
    for sd in (sub.get("subdomains") or [])[:20]:
        if isinstance(sd, dict) and sd.get("lat") and sd.get("lon"):
            points.append({
                "lat": sd["lat"], "lon": sd["lon"],
                "label": sd.get("name", ""),
                "description": f"Subdomain: {sd.get('name','')}\nIP: {sd.get('ip','')}",
                "source": "subdomains",
            })

    # BGP / ASN location
    bgp = combined_data.get("bgp", {}) or {}
    if bgp.get("prefix_location"):
        loc = bgp["prefix_location"]
        if loc.get("lat") and loc.get("lon"):
            points.append({
                "lat": loc["lat"], "lon": loc["lon"],
                "label": f"AS{bgp.get('asn','')}",
                "description": f"ASN: AS{bgp.get('asn','')}\nPrefix: {bgp.get('prefix','')}",
                "source": "bgp",
            })

    return points


def export_geojson(combined_data: dict) -> dict:
    """Build a GeoJSON FeatureCollection from evidence."""
    points = _extract_geo_points(combined_data)
    features = []
    for p in points:
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [p["lon"], p["lat"]]},
            "properties": {
                "name": p["label"],
                "description": p["description"],
                "source": p["source"],
            },
        })
    return {"type": "FeatureCollection", "features": features}


def export_kml(combined_data: dict, target: str = "") -> str:
    """Build a KML document string for Google Earth import."""
    points = _extract_geo_points(combined_data)
    placemarks = []
    for p in points:
        placemarks.append(f"""    <Placemark>
      <name>{_xml(p['label'])}</name>
      <description>{_xml(p['description'])}</description>
      <Point><coordinates>{p['lon']},{p['lat']},0</coordinates></Point>
    </Placemark>""")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Argus OSINT — {_xml(target)}</name>
    <description>Investigation geo-points for {_xml(target)}</description>
{''.join(placemarks)}
  </Document>
</kml>"""


def _xml(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def export_geojson_str(combined_data: dict) -> str:
    return json.dumps(export_geojson(combined_data), indent=2)
