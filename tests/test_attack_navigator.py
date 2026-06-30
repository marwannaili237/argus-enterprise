"""
Tests for the ATT&CK Navigator + risk matrix exports.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from intel.mitre_attack import map_to_attack, to_attack_matrix
from intel.attack_navigator import to_navigator_layer, to_risk_matrix


class TestAttackNavigator:
    def test_empty_findings(self):
        layer = to_navigator_layer([], target="test")
        assert layer["name"] == "test"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        # Should still include known techniques as enabled:false
        assert len(layer["techniques"]) > 0

    def test_with_findings(self):
        findings = [
            {"technique_id": "T1071", "name": "Application Layer Protocol",
             "tactic": "Command and Control", "source": "shodan", "evidence": "HTTP open"},
            {"technique_id": "T1090.003", "name": "Tor Routing",
             "tactic": "Command and Control", "source": "reputation", "evidence": "TOR exit"},
        ]
        layer = to_navigator_layer(findings, target="example.com")
        assert layer["name"] == "example.com"
        # Detected techniques scored 100
        scored = [t for t in layer["techniques"] if t.get("score", 0) == 100]
        assert len(scored) == 2
        # Verify metadata
        meta = {m["name"]: m["value"] for m in layer["metadata"]}
        assert meta["Techniques detected"] == "2"

    def test_navigator_format_compliance(self):
        """Verify the layer JSON conforms to Navigator v4.5 expectations."""
        layer = to_navigator_layer([], target="test")
        assert "versions" in layer
        assert "navigator" in layer["versions"]
        assert "layer" in layer["versions"]
        assert "gradient" in layer
        assert "legendItems" in layer
        assert layer["filters"]["platforms"]


class TestRiskMatrix:
    def test_empty_findings(self):
        matrix = to_risk_matrix([])
        assert matrix == []

    def test_severity_ordering(self):
        findings = [
            {"technique_id": "T1", "name": "A", "tactic": "X", "source": "s1", "evidence": "e1"},
            {"technique_id": "T2", "name": "B", "tactic": "Y", "source": ["s1", "s2", "s3"], "evidence": "e2"},
        ]
        matrix = to_risk_matrix(findings)
        # T2 should be first (critical) since it has 3 sources
        assert matrix[0]["technique_id"] == "T2"
        assert matrix[0]["severity"] == "critical"
        assert matrix[1]["technique_id"] == "T1"
        assert matrix[1]["severity"] == "medium"

    def test_severity_thresholds(self):
        findings = [
            {"technique_id": "T1", "name": "A", "tactic": "X", "source": [], "evidence": ""},
            {"technique_id": "T2", "name": "B", "tactic": "X", "source": "s1", "evidence": ""},
            {"technique_id": "T3", "name": "C", "tactic": "X", "source": ["s1", "s2"], "evidence": ""},
            {"technique_id": "T4", "name": "D", "tactic": "X", "source": ["s1", "s2", "s3"], "evidence": ""},
        ]
        matrix = to_risk_matrix(findings)
        sevs = {m["technique_id"]: m["severity"] for m in matrix}
        assert sevs["T1"] == "low"
        assert sevs["T2"] == "medium"
        assert sevs["T3"] == "high"
        assert sevs["T4"] == "critical"


class TestMitreAttackMapping:
    def test_tor_exit_maps_to_tor_routing(self):
        findings = map_to_attack("1.2.3.4", "ip", {"reputation": {"is_tor_exit": True}})
        tids = [f["technique_id"] for f in findings]
        assert "T1090.003" in tids

    def test_open_ports_map_to_service_discovery(self):
        findings = map_to_attack("example.com", "domain",
                                 {"shodan": {"all_open_ports": [80, 443, 22]}})
        tids = [f["technique_id"] for f in findings]
        assert "T1046" in tids  # Network Service Discovery
        assert "T1071.001" in tids  # Web Protocols (ports 80/443)

    def test_cves_map_to_exploit_public_app(self):
        findings = map_to_attack("example.com", "domain",
                                 {"shodan": {"all_vulns": ["CVE-2021-1234"]}})
        tids = [f["technique_id"] for f in findings]
        assert "T1190" in tids  # Exploit Public-Facing Application

    def test_subdomain_sprawl_maps_to_acquire_infra(self):
        findings = map_to_attack("example.com", "domain",
                                 {"subdomains": {"subdomains": [f"s{i}.x.com" for i in range(10)]}})
        tids = [f["technique_id"] for f in findings]
        assert "T1583.001" in tids  # Domains

    def test_no_findings_for_empty_data(self):
        findings = map_to_attack("example.com", "domain", {})
        assert findings == []

    def test_attack_matrix_grouping(self):
        findings = [
            {"technique_id": "T1", "name": "A", "tactic": "X", "source": "s", "evidence": ""},
            {"technique_id": "T2", "name": "B", "tactic": "X", "source": "s", "evidence": ""},
            {"technique_id": "T3", "name": "C", "tactic": "Y", "source": "s", "evidence": ""},
        ]
        matrix = to_attack_matrix(findings)
        assert "X" in matrix
        assert "Y" in matrix
        assert len(matrix["X"]) == 2
        assert len(matrix["Y"]) == 1
