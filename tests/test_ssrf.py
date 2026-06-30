"""
Tests for SSRF protection — intel/ssrf.py
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from intel.ssrf import is_safe_url, is_blocked_ip, sanitize_url


class TestSSRFProtection:
    def test_aws_metadata_blocked(self):
        safe, reason = is_safe_url("http://169.254.169.254/latest/meta-data/")
        assert safe is False
        assert "169.254" in reason or "blocked" in reason.lower()

    def test_localhost_blocked(self):
        safe, _ = is_safe_url("http://localhost/admin")
        assert safe is False
        safe, _ = is_safe_url("http://127.0.0.1/admin")
        assert safe is False

    def test_private_ip_blocked(self):
        safe, _ = is_safe_url("http://192.168.1.1/")
        assert safe is False
        safe, _ = is_safe_url("http://10.0.0.1/")
        assert safe is False
        safe, _ = is_safe_url("http://172.16.0.1/")
        assert safe is False

    def test_public_ip_allowed(self):
        safe, _ = is_safe_url("http://8.8.8.8/")
        assert safe is True

    def test_public_domain_allowed(self):
        safe, _ = is_safe_url("https://example.com/")
        assert safe is True

    def test_blocked_scheme(self):
        safe, _ = is_safe_url("file:///etc/passwd")
        assert safe is False
        safe, _ = is_safe_url("ftp://example.com/")
        assert safe is False

    def test_empty_url(self):
        safe, _ = is_safe_url("")
        assert safe is False

    def test_gcp_metadata_blocked(self):
        safe, _ = is_safe_url("http://metadata.google.internal/computeMetadata/")
        assert safe is False

    def test_is_blocked_ip_directly(self):
        assert is_blocked_ip("169.254.169.254") is True
        assert is_blocked_ip("192.168.0.1") is True
        assert is_blocked_ip("127.0.0.1") is True
        assert is_blocked_ip("8.8.8.8") is False
        assert is_blocked_ip("1.1.1.1") is False

    def test_sanitize_url_returns_none_for_blocked(self):
        assert sanitize_url("http://169.254.169.254/") is None
        assert sanitize_url("https://example.com/") == "https://example.com/"

    def test_ipv6_loopback_blocked(self):
        safe, _ = is_safe_url("http://[::1]/")
        assert safe is False
