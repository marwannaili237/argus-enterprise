"""
Tests for the target classifier in plugins/runner.py.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from plugins.runner import classify_target, get_plugins_for_type, ALL_PLUGINS


class TestClassifyTarget:
    """Target classification logic tests."""

    def test_domain(self):
        assert classify_target("example.com") == "domain"
        assert classify_target("sub.example.co.uk") == "domain"
        assert classify_target("google.com") == "domain"

    def test_url(self):
        assert classify_target("https://example.com/path") == "url"
        assert classify_target("http://example.com") == "url"
        assert classify_target("https://example.com?q=1") == "url"

    def test_ip(self):
        assert classify_target("192.168.1.1") == "ip"
        assert classify_target("8.8.8.8") == "ip"
        assert classify_target("10.0.0.1") == "ip"

    def test_email(self):
        assert classify_target("user@example.com") == "email"
        assert classify_target("test.name@domain.org") == "email"

    def test_phone_with_plus(self):
        assert classify_target("+14155552671") == "phone"
        assert classify_target("+44 20 7946 0958") == "phone"

    def test_phone_digits_only(self):
        assert classify_target("14155552671") == "phone"
        assert classify_target("2025551234") == "phone"

    def test_username(self):
        assert classify_target("johndoe") == "username"
        assert classify_target("@johndoe") == "username"
        assert classify_target("user_123") == "username"
        # "john.doe" matches domain regex before username — this is expected behavior

    def test_image_url(self):
        assert classify_target("https://example.com/photo.jpg") == "image"
        assert classify_target("https://i.imgur.com/abc123.png") == "image"
        assert classify_target("https://example.com/img.webp") == "image"

    def test_person_name(self):
        assert classify_target("John Smith") == "person"
        assert classify_target("Jane Mary Doe") == "person"
        assert classify_target("O'Brien Patrick") == "person"

    def test_unknown(self):
        assert classify_target("") == "unknown"
        assert classify_target("a") == "unknown"
        assert classify_target("!!!invalid") == "unknown"


class TestPluginRegistry:
    """Plugin registration tests."""

    @pytest.mark.parametrize("target_type", ["domain", "url", "ip", "email", "username", "phone", "image", "person", "company"])
    def test_all_target_types_have_plugins(self, target_type):
        plugins = get_plugins_for_type(target_type)
        assert len(plugins) > 0, f"No plugins registered for target type: {target_type}"

    def test_domain_has_whois_plugin(self):
        plugins = get_plugins_for_type("domain")
        names = [p.name for p in plugins]
        assert "whois" in names

    def test_domain_has_dns_plugin(self):
        plugins = get_plugins_for_type("domain")
        names = [p.name for p in plugins]
        assert "dns" in names

    def test_email_has_breach_plugin(self):
        plugins = get_plugins_for_type("email")
        names = [p.name for p in plugins]
        assert "breach" in names

    def test_username_has_profile_plugin(self):
        plugins = get_plugins_for_type("username")
        names = [p.name for p in plugins]
        assert "profile" in names
        assert "username" in names

    def test_person_has_entity_plugin(self):
        plugins = get_plugins_for_type("person")
        names = [p.name for p in plugins]
        assert "entity" in names

    def test_company_has_entity_plugin(self):
        plugins = get_plugins_for_type("company")
        names = [p.name for p in plugins]
        assert "entity" in names

    def test_phone_only_has_phone_plugin(self):
        plugins = get_plugins_for_type("phone")
        assert len(plugins) == 1
        assert plugins[0].name == "phone"

    def test_ip_plugins_include_reputation(self):
        plugins = get_plugins_for_type("ip")
        names = [p.name for p in plugins]
        assert "reputation" in names
        assert "bgp" in names

    def test_unknown_type_has_no_plugins(self):
        plugins = get_plugins_for_type("unknown")
        assert len(plugins) == 0

    def test_url_plugins_overlap_domain(self):
        url_names = {p.name for p in get_plugins_for_type("url")}
        domain_names = {p.name for p in get_plugins_for_type("domain")}
        # URL and domain should share core plugins (whois, dns, http, etc.)
        overlap = domain_names & url_names
        assert "whois" in overlap
        assert "dns" in overlap
        assert "http" in overlap
        assert "reputation" in overlap


class TestPluginResult:
    """PluginResult dataclass tests."""

    def test_success_result(self):
        from plugins.base import PluginResult
        r = PluginResult(plugin_name="test", success=True, data={"key": "value"})
        assert r.plugin_name == "test"
        assert r.success is True
        assert r.data == {"key": "value"}
        assert r.error is None

    def test_failure_result(self):
        from plugins.base import PluginResult
        r = PluginResult(plugin_name="test", success=False, error="Something went wrong")
        assert r.success is False
        assert r.error == "Something went wrong"
        assert r.data == {}


class TestBasePlugin:
    """BasePlugin ABC tests."""

    def test_supports_method(self):
        from plugins.base import BasePlugin
        # Create a concrete implementation for testing
        class DummyPlugin(BasePlugin):
            name = "dummy"
            description = "Test plugin"
            supported_target_types = ["domain", "url"]

            async def run(self, target: str):
                return PluginResult(plugin_name=self.name, success=True)

        plugin = DummyPlugin()
        assert plugin.supports("domain") is True
        assert plugin.supports("url") is True
        assert plugin.supports("email") is False
        assert plugin.supports("ip") is False
