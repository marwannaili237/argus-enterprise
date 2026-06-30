"""
Entity value normalizer.

Each normalize_* method takes a raw value as seen by a plugin and
returns the canonical form. The canonical form is what gets stored in
canonical_entities.normalized_value and is the basis for the
(type, normalized_value) uniqueness constraint.

Rules are intentionally conservative: we only apply transformations
that are lossless and unambiguous. Anything that could lose information
(e.g. stripping subdomains) is NOT done here.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException


# ─── Pre-compiled regexes ─────────────────────────────────────────────

_WHITESPACE_RE = re.compile(r"\s+")
_LEADING_AT_RE = re.compile(r"^@+")
_WWW_PREFIX_RE = re.compile(r"^www\.", re.IGNORECASE)
_HEX_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")


class Normalizer:
    """
    All methods are static — this is a pure-function utility class.

    Usage:
        normalized = Normalizer.normalize("email", "User@Example.COM ")
        # -> "user@example.com"
    """

    # ─── Email ────────────────────────────────────────────────────────

    @staticmethod
    def normalize_email(value: str) -> str:
        """
        Lowercase, strip whitespace. Does NOT validate the email —
        that's the validator's job. We do strip a leading 'mailto:'.
        """
        if value is None:
            return ""
        s = str(value).strip().lower()
        if s.startswith("mailto:"):
            s = s[7:]
        # Collapse internal whitespace (rare but happens with copy-paste)
        s = _WHITESPACE_RE.sub("", s)
        return s

    # ─── Domain ───────────────────────────────────────────────────────

    @staticmethod
    def normalize_domain(value: str) -> str:
        """
        Strip whitespace, lowercase, strip leading 'www.', punycode
        IDN domains (e.g. 'café.com' -> 'xn--caf-dma.com').
        Also strips a trailing dot (DNS root label).
        """
        if value is None:
            return ""
        s = str(value).strip().lower().rstrip(".")
        # Strip protocol if someone passed a URL by mistake
        if "://" in s:
            parsed = urlparse(s)
            s = parsed.netloc or s
        s = _WWW_PREFIX_RE.sub("", s)
        # Punycode IDN — only if the string contains non-ASCII
        try:
            if any(ord(c) > 127 for c in s):
                # Use idna() per label (it chokes on dots)
                labels = s.split(".")
                encoded = []
                for label in labels:
                    if any(ord(c) > 127 for c in label):
                        encoded.append(label.encode("idna").decode("ascii"))
                    else:
                        encoded.append(label)
                s = ".".join(encoded)
        except (UnicodeError, UnicodeDecodeError):
            # If idna fails, leave as-is — the validator will flag it
            pass
        return s

    # ─── Phone ────────────────────────────────────────────────────────

    @staticmethod
    def normalize_phone(value: str, default_region: str | None = None) -> str:
        """
        Parse to E.164 format using libphonenumber.

        If no default_region is given and the number has no country code,
        we attempt a few common regions (US, GB, DE) and return the
        first parse that succeeds. If all fail, returns the stripped
        digits-only form (better than nothing for dedup).
        """
        if value is None:
            return ""
        s = str(value).strip()
        if not s:
            return ""

        # Fast path: try with provided region or no region
        regions_to_try = [default_region, None, "US", "GB", "DE"] if not default_region else [default_region, None]
        seen_regions = set()
        for region in regions_to_try:
            if region in seen_regions:
                continue
            seen_regions.add(region)
            try:
                # parse expects a region (None is OK for fully-qualified numbers)
                num = phonenumbers.parse(s, region)
                if phonenumbers.is_valid_number(num):
                    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
            except NumberParseException:
                continue

        # Fallback: digits only, with leading + if present
        digits = re.sub(r"[^\d+]", "", s)
        if digits.startswith("+"):
            return digits
        if digits:
            return f"+{digits}" if not digits.startswith("00") else f"+{digits[2:]}"
        return s

    # ─── Username ─────────────────────────────────────────────────────

    @staticmethod
    def normalize_username(value: str) -> str:
        """
        Lowercase, strip leading '@', strip whitespace. Preserves
        internal dots/underscores (these are significant on most
        platforms). Does NOT strip platform-specific prefixes like
        'github:' — that's the caller's job.
        """
        if value is None:
            return ""
        s = str(value).strip().lower()
        s = _LEADING_AT_RE.sub("", s)
        # Strip whitespace inside (rare)
        s = _WHITESPACE_RE.sub("", s)
        return s

    # ─── Hash ────────────────────────────────────────────────────────

    @staticmethod
    def normalize_hash(value: str) -> str:
        """
        Uppercase hex, strip whitespace, strip common prefixes like
        'sha256:' or 'md5='. Does NOT validate length — the validator
        does that based on the declared hash type.
        """
        if value is None:
            return ""
        s = str(value).strip().lower()
        # Strip common prefixes
        for prefix in ("sha256:", "sha-256:", "sha1:", "sha-1:", "md5:", "hash:"):
            if s.startswith(prefix):
                s = s[len(prefix):]
                break
        # Strip 0x prefix (sometimes used for hashes)
        if s.startswith("0x"):
            s = s[2:]
        # Keep only hex chars
        s = re.sub(r"[^a-fA-F0-9]", "", s)
        return s.upper()

    # ─── IP ───────────────────────────────────────────────────────────

    @staticmethod
    def normalize_ip(value: str) -> str:
        """
        Compress IPv6 (remove leading zeros, use ::), keep IPv4 dotted
        form. Strips brackets from [IPv6] notation. Does NOT validate
        — the validator does that.
        """
        if value is None:
            return ""
        s = str(value).strip()
        # Strip brackets from [IPv6] notation
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        # Strip port if present (e.g. 1.2.3.4:80 or [::1]:80)
        # Be careful: IPv6 contains colons. Use ipaddress to parse first.
        try:
            ip = ipaddress.ip_address(s)
            return str(ip)  # compressed form
        except ValueError:
            # Maybe it has a port — try splitting
            if s.count(":") == 1:
                host, _, _port = s.partition(":")
                try:
                    return str(ipaddress.ip_address(host))
                except ValueError:
                    pass
            elif s.startswith("["):
                # [host]:port
                end = s.find("]")
                if end > 0:
                    host = s[1:end]
                    try:
                        return str(ipaddress.ip_address(host))
                    except ValueError:
                        pass
            return s

    # ─── URL ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize_url(value: str) -> str:
        """
        Lowercase scheme + host, strip default ports, strip fragment,
        strip trailing slash on root paths. Preserves query string.
        """
        if value is None:
            return ""
        s = str(value).strip()
        if not s:
            return ""
        # Add scheme if missing
        if "://" not in s:
            s = "https://" + s
        try:
            parsed = urlparse(s)
        except Exception:
            return s

        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        host = host.lower()
        port = parsed.port

        # Strip default ports
        netloc = host
        if port and not (
            (scheme == "http" and port == 80) or
            (scheme == "https" and port == 443)
        ):
            netloc = f"{host}:{port}"

        # Normalize path: empty path -> "/", strip trailing slash on root
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Drop fragment, keep query
        return urlunparse((scheme, netloc, path, "", parsed.query, ""))

    # ─── Wallet (BTC/ETH) ─────────────────────────────────────────────

    @staticmethod
    def normalize_wallet(value: str) -> str:
        """
        BTC: strip whitespace, preserve case (Bech32 is case-sensitive).
        ETH: lowercase, strip 0x prefix is NOT done (EIP-55 checksums
        rely on specific casing, so we preserve).
        Bottom line: just strip whitespace, preserve case.
        """
        if value is None:
            return ""
        return str(value).strip()

    # ─── CVE ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize_cve(value: str) -> str:
        """Uppercase, strip whitespace, strip 'cve-' prefix? No — keep it."""
        if value is None:
            return ""
        s = str(value).strip().upper()
        if not s.startswith("CVE-"):
            # Maybe they wrote CVE2021-1234 (missing dash)
            m = re.match(r"^CVE\s*(?:-)?\s*(.+)$", s, re.IGNORECASE)
            if m:
                s = f"CVE-{m.group(1).strip()}"
        return s

    # ─── ASN ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize_asn(value: str) -> str:
        """Normalize to 'AS<number>' form, no leading zeros."""
        if value is None:
            return ""
        s = str(value).strip().upper()
        # Strip 'AS' prefix if present, then re-add
        m = re.match(r"^(?:AS)?(\d+)$", s)
        if m:
            n = int(m.group(1))
            return f"AS{n}"
        return s

    # ─── MAC ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize_mac(value: str) -> str:
        """Normalize to AA:BB:CC:DD:EE:FF (colons, uppercase)."""
        if value is None:
            return ""
        s = str(value).strip().upper().replace("-", ":").replace(".", ":")
        # Remove any non-hex-non-colon chars
        s = re.sub(r"[^A-F0-9:]", "", s)
        return s

    # ─── IBAN ─────────────────────────────────────────────────────────

    @staticmethod
    def normalize_iban(value: str) -> str:
        """Uppercase, strip whitespace."""
        if value is None:
            return ""
        return _WHITESPACE_RE.sub("", str(value).strip().upper())

    # ─── VAT ──────────────────────────────────────────────────────────

    @staticmethod
    def normalize_vat(value: str) -> str:
        """Uppercase, strip whitespace, strip 'EU' prefix if present."""
        if value is None:
            return ""
        s = _WHITESPACE_RE.sub("", str(value).strip().upper())
        # Some sources prefix with 'EU' — strip it
        if s.startswith("EU") and len(s) > 4:
            s = s[2:]
        return s

    # ─── User agent ───────────────────────────────────────────────────

    @staticmethod
    def normalize_user_agent(value: str) -> str:
        """Strip leading/trailing whitespace, collapse internal whitespace."""
        if value is None:
            return ""
        return _WHITESPACE_RE.sub(" ", str(value).strip())

    # ─── Dispatcher ───────────────────────────────────────────────────

    @staticmethod
    def normalize(type: str, value: str, **kwargs: Any) -> str:
        """
        Dispatch to the right normalize_* method based on entity type.

        Unknown types: return value.strip() (best-effort dedup).
        """
        if value is None:
            return ""
        t = (type or "").strip().lower()

        dispatch = {
            "email": Normalizer.normalize_email,
            "domain": Normalizer.normalize_domain,
            "phone": Normalizer.normalize_phone,
            "username": Normalizer.normalize_username,
            "user": Normalizer.normalize_username,  # alias
            "hash": Normalizer.normalize_hash,
            "md5": Normalizer.normalize_hash,
            "sha1": Normalizer.normalize_hash,
            "sha256": Normalizer.normalize_hash,
            "ip": Normalizer.normalize_ip,
            "ipv4": Normalizer.normalize_ip,
            "ipv6": Normalizer.normalize_ip,
            "url": Normalizer.normalize_url,
            "wallet": Normalizer.normalize_wallet,
            "btc": Normalizer.normalize_wallet,
            "eth": Normalizer.normalize_wallet,
            "cve": Normalizer.normalize_cve,
            "asn": Normalizer.normalize_asn,
            "mac": Normalizer.normalize_mac,
            "iban": Normalizer.normalize_iban,
            "vat": Normalizer.normalize_vat,
            "user_agent": Normalizer.normalize_user_agent,
            # Pass-through types (no normalization beyond strip)
            "certificate": lambda v: str(v).strip(),
            "person": lambda v: str(v).strip(),
            "company": lambda v: str(v).strip(),
            "image": lambda v: str(v).strip(),
        }
        fn = dispatch.get(t)
        if fn is None:
            return str(value).strip()
        # Phone takes an extra kwarg
        if t == "phone":
            return fn(value, **{k: v for k, v in kwargs.items() if k == "default_region"})
        return fn(value)


__all__ = ["Normalizer"]
