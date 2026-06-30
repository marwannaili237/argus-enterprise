"""
Compliance checker — runs an adapter against golden fixtures and reports
any field-level diffs.

Used in two modes:
  1. At startup (compliance_check_all): verify all registered adapters
     still produce expected output for their fixtures.
  2. On-demand (compliance_check_plugin): verify one plugin after a
     code change.

A compliance failure is a STRUCTURAL failure (affects plugin health).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from canonical.adapters.base import BaseAdapter, AdapterContext, AdapterError
from canonical.adapters.registry import registry
from canonical.adapters.fixtures import (
    GoldenFixture, FixtureCheckResult, FixtureDiff,
    load_fixtures_dir, diff_canonical_results,
)
from canonical.schemas import PluginResult as CanonicalPluginResult

logger = logging.getLogger("argus.adapters.compliance")


@dataclass
class ComplianceReport:
    """Aggregate report across all checked fixtures."""
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    results: list[FixtureCheckResult] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return self.failed == 0 and self.errors == 0

    def summary_lines(self) -> list[str]:
        lines = [
            f"Compliance Report: {self.passed}/{self.total} passed, "
            f"{self.failed} failed, {self.errors} errors",
        ]
        for r in self.results:
            fixture_id = f"{r.fixture.plugin_id}/{r.fixture.fixture_name}"
            lines.append(f"  [{r.summary}] {fixture_id}")
        return lines


def compliance_check_fixture(
    adapter: BaseAdapter,
    fixture: GoldenFixture,
) -> FixtureCheckResult:
    """
    Run the adapter against a single fixture and return the diff result.

    Steps:
      1. Build an AdapterContext from the fixture's input.
      2. Construct a fake legacy result from fixture.legacy_result.
      3. Call adapter.adapt() — catch AdapterError as error.
      4. Convert the canonical PluginResult to a dict.
      5. Diff against fixture.expected_canonical.
    """
    from datetime import datetime, timezone

    # Fixed timestamp for deterministic comparison
    fixed_ts = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    context = AdapterContext(
        plugin_id=fixture.plugin_id,
        plugin_version="1.0.0",
        plugin_instance="compliance_check",
        investigation_id="00000000-0000-0000-0000-000000000000",
        execution_id="00000000-0000-0000-0000-000000000000",
        request_id="00000000-0000-0000-0000-000000000000",
        target=fixture.input_target,
        target_type="domain",  # Fixtures should ideally include this; default for now
        executed_at=fixed_ts,
    )

    # Build a minimal legacy result object that quacks like plugins.base.PluginResult
    legacy = _LegacyResultStub(
        plugin_name=fixture.plugin_id,
        success=fixture.legacy_result.get("success", True),
        data=fixture.legacy_result.get("data", {}),
        error=fixture.legacy_result.get("error"),
    )

    try:
        canonical = adapter.adapt(legacy, context)
    except AdapterError as e:
        return FixtureCheckResult(fixture=fixture, passed=False, error=str(e))
    except Exception as e:
        return FixtureCheckResult(
            fixture=fixture, passed=False,
            error=f"Unexpected {type(e).__name__}: {e}",
        )

    # Convert to dict for diffing
    actual_dict = canonical.model_dump(mode="json")

    diffs = diff_canonical_results(
        fixture.expected_canonical,
        actual_dict,
    )

    return FixtureCheckResult(
        fixture=fixture,
        passed=len(diffs) == 0,
        diffs=diffs,
    )


def compliance_check_plugin(
    plugin_id: str,
    fixtures_dir: str | Path,
) -> list[FixtureCheckResult]:
    """
    Check all fixtures for a specific plugin.

    If no adapter is registered for plugin_id, returns empty list
    (compliance is N/A, not failed).
    """
    if not registry.is_registered(plugin_id):
        return []

    adapter = registry.get(plugin_id)
    all_fixtures = load_fixtures_dir(fixtures_dir)
    plugin_fixtures = [f for f in all_fixtures if f.plugin_id == plugin_id]

    return [compliance_check_fixture(adapter, f) for f in plugin_fixtures]


def compliance_check_all(
    fixtures_dir: str | Path,
) -> ComplianceReport:
    """
    Check every registered adapter against every fixture in fixtures_dir.

    Fixtures for plugins that have no registered adapter are SKIPPED
    (not failed) — this is intentional, since not every plugin needs
    canonical ingestion yet.
    """
    report = ComplianceReport()
    all_fixtures = load_fixtures_dir(fixtures_dir)

    for fixture in all_fixtures:
        if not registry.is_registered(fixture.plugin_id):
            logger.debug(
                "Skipping fixture %s/%s — no adapter registered",
                fixture.plugin_id, fixture.fixture_name,
            )
            continue

        adapter = registry.get(fixture.plugin_id)
        result = compliance_check_fixture(adapter, fixture)
        report.results.append(result)
        report.total += 1
        if result.error:
            report.errors += 1
        elif result.passed:
            report.passed += 1
        else:
            report.failed += 1

    return report


# ─── Helper: legacy result stub ───────────────────────────────────────

class _LegacyResultStub:
    """Minimal object that quacks like plugins.base.PluginResult."""
    def __init__(self, plugin_name: str, success: bool, data: dict, error: Optional[str]):
        self.plugin_name = plugin_name
        self.success = success
        self.data = data
        self.error = error


__all__ = [
    "ComplianceReport",
    "compliance_check_fixture",
    "compliance_check_plugin",
    "compliance_check_all",
]
