"""
Tests for the adapter framework: registry, base adapter, default adapter,
compliance checker, plugin health, and golden fixtures.
"""
import os
import sys
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.adapters.base import BaseAdapter, AdapterContext, AdapterError
from canonical.adapters.registry import AdapterRegistry, registry
from canonical.adapters.default_adapter import DefaultLegacyAdapter
from canonical.adapters.fixtures import (
    GoldenFixture, FixtureDiff, FixtureCheckResult,
    load_fixture, load_fixtures_dir, diff_canonical_results,
    FIXTURE_SCHEMA_VERSION,
)
from canonical.adapters.compliance import (
    ComplianceReport,
    compliance_check_fixture, compliance_check_plugin, compliance_check_all,
)
from canonical.adapters.health import (
    FailureKind, PluginStatus, PluginHealthTracker, health_tracker,
    classify_exception,
)
from canonical.schemas import PluginResult, ExtractedEntity, Observation as ObservationSchema


# ─── Registry tests ──────────────────────────────────────────────────

class TestAdapterRegistry:
    def setup_method(self):
        """Each test gets a fresh registry."""
        self.reg = AdapterRegistry()

    def test_register_and_get(self):
        adapter = DefaultLegacyAdapter()
        self.reg.register(adapter)
        assert self.reg.get(adapter.plugin_id) is adapter

    def test_register_empty_plugin_id_raises(self):
        class BadAdapter(BaseAdapter):
            plugin_id = ""
            async def adapt(self, legacy_result, context):
                pass
        with pytest.raises(ValueError, match="empty plugin_id"):
            self.reg.register(BadAdapter())

    def test_duplicate_register_raises(self):
        adapter = DefaultLegacyAdapter()
        self.reg.register(adapter)
        with pytest.raises(ValueError, match="already registered"):
            self.reg.register(DefaultLegacyAdapter())

    def test_duplicate_register_with_overwrite(self):
        adapter = DefaultLegacyAdapter()
        self.reg.register(adapter)
        # Should not raise
        self.reg.register(DefaultLegacyAdapter(), overwrite=True)
        assert self.reg.is_registered(adapter.plugin_id)

    def test_get_unregistered_raises(self):
        with pytest.raises(KeyError, match="No adapter registered"):
            self.reg.get("nonexistent")

    def test_try_get_returns_none_for_unregistered(self):
        assert self.reg.try_get("nonexistent") is None

    def test_list_registered(self):
        self.reg.register(DefaultLegacyAdapter())
        listed = self.reg.list_registered()
        assert "_default_legacy" in listed

    def test_clear(self):
        self.reg.register(DefaultLegacyAdapter())
        assert len(self.reg) == 1
        self.reg.clear()
        assert len(self.reg) == 0

    def test_iter(self):
        self.reg.register(DefaultLegacyAdapter())
        items = list(self.reg)
        assert len(items) == 1
        assert items[0][0] == "_default_legacy"

    def test_len(self):
        assert len(self.reg) == 0
        self.reg.register(DefaultLegacyAdapter())
        assert len(self.reg) == 1


# ─── Default adapter tests ───────────────────────────────────────────

class TestDefaultLegacyAdapter:
    def setup_method(self):
        self.adapter = DefaultLegacyAdapter()

    def _make_legacy(self, success=True, data=None, error=None):
        """Build a stub that quacks like plugins.base.PluginResult."""
        class _Stub:
            def __init__(self):
                self.plugin_name = "test_plugin"
                self.success = success
                self.data = data or {}
                self.error = error
        return _Stub()

    def _make_context(self, **overrides):
        defaults = dict(
            plugin_id="test_plugin",
            plugin_version="1.0.0",
            target="example.com",
            target_type="domain",
            investigation_id="00000000-0000-0000-0000-000000000001",
        )
        defaults.update(overrides)
        return AdapterContext(**defaults)

    def test_adapt_success_basic(self):
        legacy = self._make_legacy(data={"key": "value"})
        ctx = self._make_context()
        result = self.adapter.adapt(legacy, ctx)
        assert isinstance(result, PluginResult)
        assert result.plugin_id == "test_plugin"
        assert result.target == "example.com"
        assert result.errors == []
        assert result.raw == {"key": "value"}

    def test_adapt_failure_records_error(self):
        legacy = self._make_legacy(success=False, error="timeout")
        ctx = self._make_context()
        result = self.adapter.adapt(legacy, ctx)
        assert "timeout" in result.errors[0]

    def test_adapt_failure_no_error_message(self):
        legacy = self._make_legacy(success=False, error=None)
        ctx = self._make_context()
        result = self.adapter.adapt(legacy, ctx)
        assert len(result.errors) == 1
        assert "success=False" in result.errors[0]

    def test_adapt_extracts_entities(self):
        legacy = self._make_legacy(data={
            "ip": "1.2.3.4",
            "email": "admin@example.com",
            "nested": {"key": "value"},
        })
        ctx = self._make_context()
        result = self.adapter.adapt(legacy, ctx)
        # Should have extracted at least the IP and email
        entity_types = [e.type for e in result.entities]
        assert "ipv4" in entity_types
        assert "email" in entity_types

    def test_adapt_builds_observations(self):
        legacy = self._make_legacy(data={
            "registrar": "GoDaddy",
            "created": "2020-01-01",
            "nested": {"should_be_skipped": True},
        })
        ctx = self._make_context()
        result = self.adapter.adapt(legacy, ctx)
        # One observation per top-level scalar key (nested dict skipped)
        obs_types = [o.observation_type for o in result.observations]
        assert "field:registrar" in obs_types
        assert "field:created" in obs_types
        assert "field:nested" not in obs_types

    def test_adapt_rejects_non_legacy_input(self):
        ctx = self._make_context()
        with pytest.raises(AdapterError, match="not a plugins.base.PluginResult"):
            self.adapter.adapt({"not": "a legacy result"}, ctx)

    def test_adapt_is_deterministic(self):
        """Same input → same output (modulo timestamps/UUIDs)."""
        legacy = self._make_legacy(data={"email": "user@example.com"})
        ctx = self._make_context(
            request_id="11111111-1111-1111-1111-111111111111",
            execution_id="22222222-2222-2222-2222-222222222222",
        )
        r1 = self.adapter.adapt(legacy, ctx)
        r2 = self.adapter.adapt(legacy, ctx)
        assert r1.model_dump(exclude={"executed_at"}) == r2.model_dump(exclude={"executed_at"})

    def test_adapt_plugin_name_mismatch_uses_context(self):
        """If legacy.plugin_name doesn't match context.plugin_id, context wins."""
        legacy = self._make_legacy(data={})
        legacy.plugin_name = "different_name"
        ctx = self._make_context(plugin_id="context_name")
        result = self.adapter.adapt(legacy, ctx)
        assert result.plugin_id == "context_name"


# ─── Fixture tests ───────────────────────────────────────────────────

class TestGoldenFixtures:
    def test_fixture_schema_version(self):
        assert FIXTURE_SCHEMA_VERSION == 1

    def test_load_fixture_valid(self, tmp_path):
        fixture_data = {
            "plugin_id": "test_plugin",
            "fixture_name": "basic",
            "input": "example.com",
            "legacy_result": {"success": True, "data": {"key": "value"}},
            "expected_canonical": {"plugin_id": "test_plugin", "target": "example.com"},
            "schema_version": 1,
        }
        f = tmp_path / "test.json"
        f.write_text(json.dumps(fixture_data))
        fixture = load_fixture(f)
        assert fixture.plugin_id == "test_plugin"
        assert fixture.fixture_name == "basic"
        assert fixture.input_target == "example.com"

    def test_load_fixture_missing_file(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            load_fixture(tmp_path / "nonexistent.json")

    def test_load_fixture_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_fixture(f)

    def test_load_fixture_missing_required_fields(self, tmp_path):
        f = tmp_path / "incomplete.json"
        f.write_text(json.dumps({"plugin_id": "test"}))
        with pytest.raises(ValueError, match="missing required fields"):
            load_fixture(f)

    def test_load_fixtures_dir(self, tmp_path):
        for i in range(3):
            (tmp_path / f"f{i}.json").write_text(json.dumps({
                "plugin_id": "test",
                "fixture_name": f"f{i}",
                "input": "example.com",
                "legacy_result": {"success": True, "data": {}},
                "expected_canonical": {},
            }))
        fixtures = load_fixtures_dir(tmp_path)
        assert len(fixtures) == 3

    def test_load_fixtures_nonexistent_dir(self):
        assert load_fixtures_dir("/nonexistent/path") == []


class TestDiffCanonicalResults:
    def test_no_diffs_when_equal(self):
        expected = {"a": 1, "b": "two"}
        actual = {"a": 1, "b": "two"}
        diffs = diff_canonical_results(expected, actual)
        assert diffs == []

    def test_diff_scalar_mismatch(self):
        diffs = diff_canonical_results({"a": 1}, {"a": 2})
        assert len(diffs) == 1
        assert diffs[0].path == "a"
        assert diffs[0].expected == 1
        assert diffs[0].actual == 2

    def test_diff_missing_key_in_actual(self):
        diffs = diff_canonical_results({"a": 1, "b": 2}, {"a": 1})
        assert len(diffs) == 1
        assert diffs[0].expected == 2
        assert diffs[0].actual == "<missing>"

    def test_diff_missing_key_in_expected(self):
        diffs = diff_canonical_results({"a": 1}, {"a": 1, "b": 2})
        assert len(diffs) == 1
        assert diffs[0].expected == "<missing>"
        assert diffs[0].actual == 2

    def test_diff_ignored_fields(self):
        diffs = diff_canonical_results(
            {"request_id": "abc", "data": 1},
            {"request_id": "xyz", "data": 1},
        )
        assert diffs == []  # request_id is in the default ignore list

    def test_diff_nested_dict(self):
        diffs = diff_canonical_results(
            {"a": {"b": 1}},
            {"a": {"b": 2}},
        )
        assert len(diffs) == 1
        assert diffs[0].path == "a.b"

    def test_diff_list_length_mismatch(self):
        diffs = diff_canonical_results([1, 2, 3], [1, 2])
        assert len(diffs) == 1

    def test_diff_list_element_mismatch(self):
        diffs = diff_canonical_results([1, 2, 3], [1, 4, 3])
        assert len(diffs) == 1
        assert diffs[0].path == "[1]"

    def test_diff_type_mismatch(self):
        diffs = diff_canonical_results({"a": 1}, {"a": "1"})
        assert len(diffs) == 1


# ─── Compliance checker tests ────────────────────────────────────────

class TestComplianceChecker:
    def _make_fixture(self, plugin_id="test_plugin", expected_canonical=None):
        return GoldenFixture(
            plugin_id=plugin_id,
            fixture_name="basic",
            input_target="example.com",
            legacy_result={"success": True, "data": {"key": "value"}},
            expected_canonical=expected_canonical or {},
        )

    def test_compliance_pass_when_no_diffs(self):
        """Build expected_canonical dynamically from the adapter's own output,
        then verify compliance passes with no diffs.

        Uses the SAME plugin_instance ('compliance_check') in both calls
        so they match — the compliance checker hardcodes that instance name.
        """
        adapter = DefaultLegacyAdapter()
        ctx = AdapterContext(
            plugin_id="_default_legacy",
            plugin_version="1.0.0",
            plugin_instance="compliance_check",  # Match what compliance_check_fixture uses
            target="example.com",
            target_type="domain",
        )
        class Stub:
            plugin_name = "_default_legacy"
            success = True
            data = {"key": "value"}
            error = None
        result = adapter.adapt(Stub(), ctx)
        expected = result.model_dump(mode="json")
        fixture = self._make_fixture(
            plugin_id="_default_legacy",
            expected_canonical=expected,
        )
        check = compliance_check_fixture(adapter, fixture)
        assert check.passed, f"Expected pass, got diffs: {[(d.path, d.expected, d.actual) for d in check.diffs]}"
        assert check.diffs == []

    def test_compliance_fail_on_diff(self):
        adapter = DefaultLegacyAdapter()
        fixture = self._make_fixture(
            plugin_id="_default_legacy",
            expected_canonical={"plugin_id": "WRONG"},
        )
        check = compliance_check_fixture(adapter, fixture)
        assert not check.passed
        assert len(check.diffs) > 0

    def test_compliance_error_on_adapter_exception(self):
        class BrokenAdapter(BaseAdapter):
            plugin_id = "broken"
            def adapt(self, legacy_result, context):
                raise AdapterError("broken", "boom")
        adapter = BrokenAdapter()
        fixture = self._make_fixture(plugin_id="broken")
        check = compliance_check_fixture(adapter, fixture)
        assert not check.passed
        assert check.error is not None
        assert "boom" in check.error

    def test_compliance_check_all_skips_unregistered(self, tmp_path):
        # Write a fixture for a plugin with no adapter
        fixture_data = {
            "plugin_id": "unregistered_plugin",
            "fixture_name": "basic",
            "input": "example.com",
            "legacy_result": {"success": True, "data": {}},
            "expected_canonical": {},
        }
        (tmp_path / "unregistered.json").write_text(json.dumps(fixture_data))
        report = compliance_check_all(tmp_path)
        assert report.total == 0  # skipped
        assert report.is_clean

    def test_compliance_report_summary(self):
        report = ComplianceReport(total=3, passed=2, failed=1, errors=0)
        lines = report.summary_lines()
        assert "2/3 passed" in lines[0]
        assert "1 failed" in lines[0]


# ─── Plugin health tests ─────────────────────────────────────────────

class TestRegisterDefaultAdapters:
    """Tests for register_default_adapters() — the explicit registration helper."""

    def setup_method(self):
        """Clear the global registry before each test."""
        from canonical.adapters.registry import registry
        registry.clear()

    def teardown_method(self):
        """Restore default state by re-registering."""
        from canonical.adapters.registry import registry
        registry.clear()

    def test_registers_all_default_plugins(self):
        from canonical.adapters import register_default_adapters, DEFAULT_ADAPTED_PLUGINS, registry
        count = register_default_adapters()
        assert count == len(DEFAULT_ADAPTED_PLUGINS)
        for plugin_id in DEFAULT_ADAPTED_PLUGINS:
            assert registry.is_registered(plugin_id)

    def test_idempotent(self):
        """Calling twice doesn't duplicate registrations."""
        from canonical.adapters import register_default_adapters
        c1 = register_default_adapters()
        c2 = register_default_adapters()
        assert c1 > 0
        assert c2 == 0  # All already registered

    def test_custom_plugin_list(self):
        from canonical.adapters import register_default_adapters, registry
        count = register_default_adapters(frozenset({"whois", "dns"}))
        assert count == 2
        assert registry.is_registered("whois")
        assert registry.is_registered("dns")
        assert not registry.is_registered("certs")

    def test_no_fallback_for_unregistered_plugin(self):
        """A plugin NOT in the default list has no adapter — ingestion skips it."""
        from canonical.adapters import register_default_adapters, registry
        register_default_adapters()
        # "some_custom_plugin" is not in DEFAULT_ADAPTED_PLUGINS
        assert not registry.is_registered("some_custom_plugin")
        with pytest.raises(KeyError):
            registry.get("some_custom_plugin")

    def test_overwrite_flag(self):
        from canonical.adapters import register_default_adapters, registry
        register_default_adapters(frozenset({"whois"}))
        # Re-register with overwrite=True should not raise
        register_default_adapters(frozenset({"whois"}), overwrite=True)
        assert registry.is_registered("whois")


class TestPluginHealthTracker:
    def setup_method(self):
        self.tracker = PluginHealthTracker()

    def test_record_success(self):
        self.tracker.record_success("plugin_a")
        rec = self.tracker.get_record("plugin_a")
        assert rec.total_runs == 1
        assert rec.successful_runs == 1
        assert rec.status == PluginStatus.ACTIVE

    def test_record_transient_failure_does_not_quarantine(self):
        exc = TimeoutError("request timed out")
        kind = self.tracker.record_failure("plugin_a", exc)
        assert kind == FailureKind.TRANSIENT
        assert not self.tracker.is_quarantined("plugin_a")

    def test_record_structural_failure_classified_correctly(self):
        exc = ValueError("schema mismatch")
        kind = self.tracker.record_failure("plugin_a", exc)
        assert kind == FailureKind.STRUCTURAL

    def test_quarantine_after_threshold(self, monkeypatch):
        # Lower threshold for test
        import canonical.confidence as conf
        monkeypatch.setattr(conf, "QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD", 2)
        monkeypatch.setattr(conf, "QUARANTINE_WINDOW_HOURS", 24)

        exc = ValueError("schema error")
        self.tracker.record_failure("plugin_a", exc)
        assert not self.tracker.is_quarantined("plugin_a")
        self.tracker.record_failure("plugin_a", exc)
        assert self.tracker.is_quarantined("plugin_a")
        rec = self.tracker.get_record("plugin_a")
        assert rec.quarantined_at is not None

    def test_reactivate_clears_history(self):
        exc = ValueError("error")
        self.tracker.record_failure("plugin_a", exc)
        self.tracker.record_failure("plugin_a", exc)
        # Import here to pick up the monkeypatched threshold
        from canonical.confidence import QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD
        if QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD <= 2:
            assert self.tracker.is_quarantined("plugin_a")
        self.tracker.reactivate("plugin_a")
        assert not self.tracker.is_quarantined("plugin_a")
        rec = self.tracker.get_record("plugin_a")
        assert len(rec.structural_failures) == 0

    def test_get_or_create_creates_record(self):
        rec = self.tracker.get_or_create("new_plugin")
        assert rec.plugin_id == "new_plugin"
        assert rec.status == PluginStatus.ACTIVE

    def test_all_records(self):
        self.tracker.record_success("a")
        self.tracker.record_success("b")
        records = self.tracker.all_records()
        assert "a" in records
        assert "b" in records


class TestClassifyException:
    def test_timeout_is_transient(self):
        import asyncio
        assert classify_exception(asyncio.TimeoutError()) == FailureKind.TRANSIENT

    def test_connection_error_is_transient(self):
        assert classify_exception(ConnectionError("refused")) == FailureKind.TRANSIENT

    def test_oserror_is_transient(self):
        assert classify_exception(OSError("network down")) == FailureKind.TRANSIENT

    def test_adapter_error_is_structural(self):
        err = AdapterError("plugin", "boom")
        assert classify_exception(err) == FailureKind.STRUCTURAL

    def test_key_error_is_structural(self):
        assert classify_exception(KeyError("missing")) == FailureKind.STRUCTURAL

    def test_attribute_error_is_structural(self):
        assert classify_exception(AttributeError("no attr")) == FailureKind.STRUCTURAL

    def test_type_error_is_structural(self):
        assert classify_exception(TypeError("wrong type")) == FailureKind.STRUCTURAL

    def test_value_error_is_structural(self):
        assert classify_exception(ValueError("bad value")) == FailureKind.STRUCTURAL

    def test_unknown_exception_defaults_to_structural(self):
        """Unknown failures should be investigated, not hidden."""
        class WeirdError(Exception):
            pass
        assert classify_exception(WeirdError("???")) == FailureKind.STRUCTURAL

    def test_aiohttp_429_is_transient(self):
        """Simulate aiohttp.ClientResponseError with status=429."""
        class FakeClientResponseError(Exception):
            status = 429
        assert classify_exception(FakeClientResponseError()) == FailureKind.TRANSIENT

    def test_aiohttp_500_is_transient(self):
        class FakeClientResponseError(Exception):
            status = 500
        assert classify_exception(FakeClientResponseError()) == FailureKind.TRANSIENT

    def test_aiohttp_404_is_structural(self):
        """404 is not in the transient set — it's a structural issue (wrong URL)."""
        class FakeClientResponseError(Exception):
            status = 404
        assert classify_exception(FakeClientResponseError()) == FailureKind.STRUCTURAL
