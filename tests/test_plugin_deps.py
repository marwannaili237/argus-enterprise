"""
Tests for plugin dependency graph and entity extractor follow-ups.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from intel.plugin_deps import yield_follow_ups, detect_dependencies, topological_sort
from intel.entity_extractor import extract_entities
from plugins.runner import ALL_PLUGINS
from plugins.base import BasePlugin


class TestPluginDependencyGraph:
    def test_dns_yields_ips_from_a_records(self):
        follow_ups = list(yield_follow_ups(
            "dns",
            {"records": {"A": ["1.2.3.4", "5.6.7.8"], "NS": ["ns1.example.com"]}},
            "example.com",
        ))
        targets = [t for t, _, _ in follow_ups]
        assert "1.2.3.4" in targets
        assert "5.6.7.8" in targets
        assert "ns1.example.com" in targets

    def test_subdomains_yields_domains(self):
        follow_ups = list(yield_follow_ups(
            "subdomains",
            {"subdomains": ["api.example.com", "www.example.com"]},
            "example.com",
        ))
        targets = [(t, tt) for t, tt, _ in follow_ups]
        assert ("api.example.com", "domain") in targets
        assert ("www.example.com", "domain") in targets

    def test_subdomains_with_ip_yields_ip(self):
        follow_ups = list(yield_follow_ups(
            "subdomains",
            {"subdomains": [{"name": "api.example.com", "ip": "1.2.3.4"}]},
            "example.com",
        ))
        ips = [t for t, tt, _ in follow_ups if tt == "ip"]
        assert "1.2.3.4" in ips

    def test_certs_yields_subdomains(self):
        follow_ups = list(yield_follow_ups(
            "certs",
            {"subdomains": ["a.example.com", "b.example.com"]},
            "example.com",
        ))
        assert len(follow_ups) == 2

    def test_bgp_yields_asn(self):
        follow_ups = list(yield_follow_ups(
            "bgp",
            {"asn": "12345"},
            "1.2.3.4",
        ))
        assert follow_ups == [("AS12345", "asn", "bgp")]

    def test_email_yields_domain(self):
        follow_ups = list(yield_follow_ups(
            "email",
            {"domain": "example.com"},
            "user@example.com",
        ))
        assert follow_ups == [("example.com", "domain", "email")]

    def test_unknown_plugin_yields_nothing(self):
        follow_ups = list(yield_follow_ups("nonexistent", {"foo": "bar"}, "x"))
        assert follow_ups == []


class TestTopologicalSort:
    def test_sort_preserves_independent_order(self):
        class A(BasePlugin):
            name = "a"
            description = "a"
            supported_target_types = []
            async def run(self, target): pass
        class B(BasePlugin):
            name = "b"
            description = "b"
            supported_target_types = []
            async def run(self, target): pass
        plugins = [A(), B()]
        sorted_plugins = topological_sort(plugins)
        # Both have no deps, so both should appear in some order
        assert len(sorted_plugins) == 2
        assert {p.name for p in sorted_plugins} == {"a", "b"}

    def test_sort_with_known_dependency(self):
        # ip_geo depends on dns — dns should come first
        class Dns(BasePlugin):
            name = "dns"
            description = "dns"
            supported_target_types = []
            async def run(self, target): pass
        class IpGeo(BasePlugin):
            name = "ip_geo"
            description = "ip_geo"
            supported_target_types = []
            async def run(self, target): pass
        plugins = [IpGeo(), Dns()]  # input reversed
        sorted_plugins = topological_sort(plugins)
        names = [p.name for p in sorted_plugins]
        assert names.index("dns") < names.index("ip_geo")


class TestEntityExtractor:
    def test_extract_ips_from_evidence(self):
        entities = extract_entities("example.com", "domain",
                                    {"dns": {"records": {"A": ["1.2.3.4"]}}})
        ips = [e for e in entities if e["type"] == "ipv4"]
        assert any(e["value"] == "1.2.3.4" for e in ips)

    def test_extract_emails(self):
        entities = extract_entities("test@example.com", "email",
                                    {"email": {"data": "contact: admin@example.com"}})
        emails = [e for e in entities if e["type"] == "email"]
        assert any(e["value"] == "admin@example.com" for e in emails)

    def test_extract_cves(self):
        entities = extract_entities("example.com", "domain",
                                    {"shodan": {"all_vulns": ["CVE-2021-1234"]}})
        cves = [e for e in entities if e["type"] == "cve"]
        assert any(e["value"] == "CVE-2021-1234" for e in cves)

    def test_target_included_as_entity(self):
        entities = extract_entities("example.com", "domain", {})
        # Target itself should be included
        targets = [e for e in entities if e["source"] == "target"]
        assert len(targets) == 1
        assert targets[0]["value"] == "example.com"

    def test_deduplication(self):
        entities = extract_entities("example.com", "domain",
                                    {"dns": {"records": {"A": ["1.2.3.4"]}},
                                     "shodan": {"ip": "1.2.3.4"}})
        # 1.2.3.4 should appear only once
        ips = [e for e in entities if e["type"] == "ipv4" and e["value"] == "1.2.3.4"]
        assert len(ips) == 1
