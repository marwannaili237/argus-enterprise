"""
Unit tests for the Normalizer class.

Covers every normalize_* method with edge cases: empty input, None,
whitespace, IDN domains, E164 phone parsing, IPv6 compression, etc.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.normalizer import Normalizer


class TestNormalizeEmail:
    def test_lowercases(self):
        assert Normalizer.normalize_email("User@EXAMPLE.com") == "user@example.com"

    def test_strips_whitespace(self):
        assert Normalizer.normalize_email("  user@example.com  ") == "user@example.com"

    def test_strips_internal_whitespace(self):
        assert Normalizer.normalize_email("user @ example . com") == "user@example.com"

    def test_strips_mailto_prefix(self):
        assert Normalizer.normalize_email("mailto:user@example.com") == "user@example.com"

    def test_none_input(self):
        assert Normalizer.normalize_email(None) == ""

    def test_empty_input(self):
        assert Normalizer.normalize_email("") == ""

    def test_preserves_plus_addressing(self):
        assert Normalizer.normalize_email("User+Tag@Example.com") == "user+tag@example.com"


class TestNormalizeDomain:
    def test_lowercases(self):
        assert Normalizer.normalize_domain("Example.COM") == "example.com"

    def test_strips_www(self):
        assert Normalizer.normalize_domain("www.example.com") == "example.com"

    def test_preserves_subdomains(self):
        assert Normalizer.normalize_domain("api.sub.example.com") == "api.sub.example.com"

    def test_strips_trailing_dot(self):
        assert Normalizer.normalize_domain("example.com.") == "example.com"

    def test_strips_protocol(self):
        assert Normalizer.normalize_domain("https://example.com/path") == "example.com"

    def test_idn_punycode(self):
        # café.com -> xn--caf-dma.com
        assert Normalizer.normalize_domain("café.com") == "xn--caf-dma.com"

    def test_idn_preserves_ascii(self):
        assert Normalizer.normalize_domain("example.com") == "example.com"

    def test_none_input(self):
        assert Normalizer.normalize_domain(None) == ""


class TestNormalizePhone:
    def test_us_number_e164(self):
        assert Normalizer.normalize_phone("+1 415-555-2671") == "+14155552671"

    def test_us_no_country_code(self):
        # Without explicit +1, default region US
        assert Normalizer.normalize_phone("(415) 555-2671") == "+14155552671"

    def test_uk_number(self):
        assert Normalizer.normalize_phone("+44 20 7946 0958") == "+442079460958"

    def test_strips_dots_dashes_spaces(self):
        assert Normalizer.normalize_phone("+1.415.555.2671") == "+14155552671"

    def test_invalid_number_returns_best_effort(self):
        # Not a valid number — should return digits-only fallback
        result = Normalizer.normalize_phone("abc")
        assert result == "abc"  # No digits, returns stripped input

    def test_none_input(self):
        assert Normalizer.normalize_phone(None) == ""

    def test_empty_input(self):
        assert Normalizer.normalize_phone("") == ""

    def test_double_zero_prefix(self):
        # 00 is the international prefix in many regions
        result = Normalizer.normalize_phone("00 1 415 555 2671")
        assert result == "+14155552671"

    def test_with_default_region(self):
        # German number without country code
        result = Normalizer.normalize_phone("030 1234567", default_region="DE")
        assert result.startswith("+49")


class TestNormalizeUsername:
    def test_lowercases(self):
        assert Normalizer.normalize_username("JohnDoe") == "johndoe"

    def test_strips_leading_at(self):
        assert Normalizer.normalize_username("@johndoe") == "johndoe"

    def test_strips_multiple_leading_at(self):
        assert Normalizer.normalize_username("@@johndoe") == "johndoe"

    def test_preserves_internal_dots_underscores(self):
        assert Normalizer.normalize_username("John.Doe_123") == "john.doe_123"

    def test_strips_whitespace(self):
        assert Normalizer.normalize_username("  johndoe  ") == "johndoe"

    def test_none_input(self):
        assert Normalizer.normalize_username(None) == ""


class TestNormalizeHash:
    def test_uppercases(self):
        assert Normalizer.normalize_hash("deadbeef") == "DEADBEEF"

    def test_strips_sha256_prefix(self):
        assert Normalizer.normalize_hash("sha256:abcdef1234") == "ABCDEF1234"

    def test_strips_md5_prefix(self):
        assert Normalizer.normalize_hash("md5:abcdef1234") == "ABCDEF1234"

    def test_strips_0x_prefix(self):
        assert Normalizer.normalize_hash("0xabcdef") == "ABCDEF"

    def test_strips_whitespace_and_dashes(self):
        assert Normalizer.normalize_hash("  AB-CD-EF  ") == "ABCDEF"

    def test_none_input(self):
        assert Normalizer.normalize_hash(None) == ""

    def test_empty_input(self):
        assert Normalizer.normalize_hash("") == ""

    def test_preserves_full_hex(self):
        h = "a" * 64
        assert Normalizer.normalize_hash(h) == "A" * 64


class TestNormalizeIP:
    def test_ipv4_preserved(self):
        assert Normalizer.normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_ipv6_compressed(self):
        # Full form -> compressed
        assert Normalizer.normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"

    def test_ipv6_loopback(self):
        assert Normalizer.normalize_ip("::1") == "::1"

    def test_ipv6_strips_brackets(self):
        assert Normalizer.normalize_ip("[::1]") == "::1"

    def test_ipv4_with_port(self):
        assert Normalizer.normalize_ip("1.2.3.4:80") == "1.2.3.4"

    def test_ipv6_with_port(self):
        assert Normalizer.normalize_ip("[::1]:80") == "::1"

    def test_none_input(self):
        assert Normalizer.normalize_ip(None) == ""

    def test_invalid_returns_input(self):
        # Not an IP — should return input as-is
        assert Normalizer.normalize_ip("not-an-ip") == "not-an-ip"


class TestNormalizeURL:
    def test_lowercases_scheme_and_host(self):
        assert Normalizer.normalize_url("HTTPS://EXAMPLE.COM/Path").startswith("https://example.com")

    def test_strips_default_port(self):
        assert Normalizer.normalize_url("https://example.com:443/path") == "https://example.com/path"

    def test_preserves_nondefault_port(self):
        assert Normalizer.normalize_url("https://example.com:8443/path") == "https://example.com:8443/path"

    def test_strips_trailing_slash_on_root(self):
        assert Normalizer.normalize_url("https://example.com/") == "https://example.com/"

    def test_strips_trailing_slash_on_path(self):
        assert Normalizer.normalize_url("https://example.com/path/") == "https://example.com/path"

    def test_strips_fragment(self):
        assert "#" not in Normalizer.normalize_url("https://example.com/path#section")

    def test_preserves_query(self):
        result = Normalizer.normalize_url("https://example.com/path?q=1&r=2")
        assert "q=1" in result and "r=2" in result

    def test_adds_scheme_if_missing(self):
        result = Normalizer.normalize_url("example.com")
        assert result.startswith("https://")


class TestNormalizeCVE:
    def test_uppercases(self):
        assert Normalizer.normalize_cve("cve-2021-1234") == "CVE-2021-1234"

    def test_strips_whitespace(self):
        assert Normalizer.normalize_cve("  CVE-2021-1234  ") == "CVE-2021-1234"

    def test_inserts_dash_if_missing(self):
        assert Normalizer.normalize_cve("CVE2021-1234") == "CVE-2021-1234"

    def test_none_input(self):
        assert Normalizer.normalize_cve(None) == ""


class TestNormalizeASN:
    def test_strips_AS_prefix(self):
        assert Normalizer.normalize_asn("AS12345") == "AS12345"

    def test_adds_AS_prefix(self):
        assert Normalizer.normalize_asn("12345") == "AS12345"

    def test_strips_leading_zeros(self):
        assert Normalizer.normalize_asn("AS012345") == "AS12345"

    def test_none_input(self):
        assert Normalizer.normalize_asn(None) == ""


class TestNormalizeMAC:
    def test_uppercases(self):
        assert Normalizer.normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_converts_dashes_to_colons(self):
        assert Normalizer.normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_converts_dots_to_colons(self):
        # Cisco-style aabb.ccdd.eeff
        assert Normalizer.normalize_mac("aabb.ccdd.eeff") == "AABB:CCDD:EEFF"

    def test_none_input(self):
        assert Normalizer.normalize_mac(None) == ""


class TestNormalizeIBAN:
    def test_uppercases(self):
        assert Normalizer.normalize_iban("gb29nwbk60161331926819") == "GB29NWBK60161331926819"

    def test_strips_whitespace(self):
        assert Normalizer.normalize_iban("GB29 NWBK 6016 1331 9268 19") == "GB29NWBK60161331926819"

    def test_none_input(self):
        assert Normalizer.normalize_iban(None) == ""


class TestNormalizeVAT:
    def test_uppercases(self):
        assert Normalizer.normalize_vat("gb123456782") == "GB123456782"

    def test_strips_whitespace(self):
        assert Normalizer.normalize_vat("GB 1234 56782") == "GB123456782"

    def test_strips_EU_prefix(self):
        assert Normalizer.normalize_vat("EUGB123456782") == "GB123456782"

    def test_none_input(self):
        assert Normalizer.normalize_vat(None) == ""


class TestNormalizeUserAgent:
    def test_strips_whitespace(self):
        assert Normalizer.normalize_user_agent("  Mozilla/5.0  ") == "Mozilla/5.0"

    def test_collapses_internal_whitespace(self):
        assert Normalizer.normalize_user_agent("Mozilla/5.0  (Windows  10)") == "Mozilla/5.0 (Windows 10)"

    def test_none_input(self):
        assert Normalizer.normalize_user_agent(None) == ""


class TestNormalizeWallet:
    def test_strips_whitespace(self):
        assert Normalizer.normalize_wallet("  0xAbC123  ") == "0xAbC123"

    def test_preserves_case(self):
        # ETH addresses have EIP-55 checksums — preserve case
        addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f0b51"
        assert Normalizer.normalize_wallet(addr) == addr

    def test_none_input(self):
        assert Normalizer.normalize_wallet(None) == ""


class TestNormalizeDispatcher:
    def test_dispatches_to_email(self):
        assert Normalizer.normalize("email", "User@Example.COM") == "user@example.com"

    def test_dispatches_to_domain(self):
        assert Normalizer.normalize("domain", "WWW.example.com") == "example.com"

    def test_dispatches_to_phone(self):
        assert Normalizer.normalize("phone", "+1 415-555-2671") == "+14155552671"

    def test_dispatches_to_username(self):
        assert Normalizer.normalize("username", "@JohnDoe") == "johndoe"

    def test_dispatches_to_hash(self):
        assert Normalizer.normalize("sha256", "deadbeef") == "DEADBEEF"

    def test_dispatches_to_ip(self):
        assert Normalizer.normalize("ipv6", "2001:0db8::0001") == "2001:db8::1"

    def test_dispatches_to_url(self):
        result = Normalizer.normalize("url", "example.com")
        assert result.startswith("https://example.com")

    def test_dispatches_to_cve(self):
        assert Normalizer.normalize("cve", "cve-2021-1234") == "CVE-2021-1234"

    def test_dispatches_to_asn(self):
        assert Normalizer.normalize("asn", "12345") == "AS12345"

    def test_dispatches_to_mac(self):
        assert Normalizer.normalize("mac", "aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_unknown_type_falls_back_to_strip(self):
        assert Normalizer.normalize("unknown_type", "  hello  ") == "hello"

    def test_none_value(self):
        assert Normalizer.normalize("email", None) == ""

    def test_empty_value(self):
        assert Normalizer.normalize("email", "") == ""

    def test_user_alias_for_username(self):
        # 'user' is an alias for 'username'
        assert Normalizer.normalize("user", "@JohnDoe") == "johndoe"

    def test_case_insensitive_type(self):
        assert Normalizer.normalize("EMAIL", "User@Example.COM") == "user@example.com"
        assert Normalizer.normalize("Domain", "WWW.example.com") == "example.com"
