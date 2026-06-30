"""
SSRF protection — block requests to private/internal IPs and link-local ranges.

Used by all plugins that fetch URLs (http, redirect_chain, secret_scanner,
cobaltstrike, etc.) to prevent attackers from using Argus as a proxy to
internal services (AWS metadata, internal admin panels, etc.).
"""
import ipaddress
import socket
from urllib.parse import urlparse


# IPv4 ranges to block (RFC 1918 + special-use)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This host"
    ipaddress.ip_network("10.0.0.0/8"),         # Private
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (AWS metadata!)
    ipaddress.ip_network("172.16.0.0/12"),      # Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
]

# Hostnames to always block
BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",  # GCP metadata
    "metadata.aws.internal",
    "169.254.169.254",           # AWS/Azure metadata IP
    "metadata.azure.com",
}


def is_blocked_ip(ip_str: str) -> bool:
    """Check if an IP string is in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Block all IPv6 loopback, link-local, private, unique-local
        if ip.version == 6:
            if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_multicast or ip.is_reserved:
                return True
            return False
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP strings. Returns [] on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except Exception:
        return []


def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Check if a URL is safe to fetch.
    Returns (is_safe, reason).
    Unsafe = points to a private/internal/loopback/link-local address.
    """
    if not url:
        return False, "empty URL"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"invalid URL: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "no hostname"

    if hostname.lower() in BLOCKED_HOSTNAMES:
        return False, f"blocked hostname: {hostname}"

    # If hostname is already an IP literal, check directly
    try:
        ipaddress.ip_address(hostname)
        if is_blocked_ip(hostname):
            return False, f"blocked IP: {hostname}"
        return True, "ok"
    except ValueError:
        pass

    # Hostname: resolve and check all IPs
    ips = resolve_hostname(hostname)
    if not ips:
        return False, f"could not resolve: {hostname}"

    for ip in ips:
        if is_blocked_ip(ip):
            return False, f"hostname {hostname} resolves to blocked IP {ip}"

    return True, "ok"


def sanitize_url(url: str) -> str | None:
    """
    Return the URL if safe, else None.
    Convenience wrapper around is_safe_url.
    """
    safe, _ = is_safe_url(url)
    return url if safe else None
