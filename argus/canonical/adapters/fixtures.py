"""
Golden fixtures — known-good plugin outputs used to detect regressions.

A fixture is a JSON file that contains:
  - plugin_id: which plugin this fixture is for
  - fixture_name: human-readable name (e.g. "example_com_basic")
  - input: the target that was passed to the plugin
  - legacy_result: the plugins.base.PluginResult dataclass as a dict
  - expected_canonical: the expected canonical.schemas.PluginResult after adaptation
  - schema_version: fixture format version (currently 1)

The compliance checker loads a fixture, runs the adapter, and diffs
the actual canonical result against expected_canonical. Any field-level
difference is a regression.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("argus.adapters.fixtures")


FIXTURE_SCHEMA_VERSION = 1


@dataclass
class GoldenFixture:
    """In-memory representation of a golden fixture."""
    plugin_id: str
    fixture_name: str
    input_target: str
    legacy_result: dict[str, Any]
    expected_canonical: dict[str, Any]
    schema_version: int = FIXTURE_SCHEMA_VERSION
    source_file: Optional[str] = None  # Path to the JSON file (for error messages)

    def __repr__(self) -> str:
        return (
            f"<GoldenFixture plugin_id={self.plugin_id!r} "
            f"name={self.fixture_name!r}>"
        )


@dataclass
class FixtureDiff:
    """A single field-level diff between actual and expected."""
    path: str
    expected: Any
    actual: Any

    def __repr__(self) -> str:
        return f"<FixtureDiff path={self.path!r} expected={self.expected!r} actual={self.actual!r}>"


@dataclass
class FixtureCheckResult:
    """Result of checking an adapter against a fixture."""
    fixture: GoldenFixture
    passed: bool
    diffs: list[FixtureDiff] = field(default_factory=list)
    error: Optional[str] = None  # If the adapter raised

    @property
    def summary(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.passed:
            return "PASS"
        return f"FAIL ({len(self.diffs)} diffs)"


def load_fixture(path: str | Path) -> GoldenFixture:
    """
    Load a single golden fixture from a JSON file.

    Raises ValueError if the file is malformed or missing required fields.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Fixture file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    required = {"plugin_id", "fixture_name", "input", "legacy_result", "expected_canonical"}
    missing = required - set(data.keys())
    if missing:
        raise ValueError(f"Fixture {path} missing required fields: {missing}")

    return GoldenFixture(
        plugin_id=data["plugin_id"],
        fixture_name=data["fixture_name"],
        input_target=data["input"],
        legacy_result=data["legacy_result"],
        expected_canonical=data["expected_canonical"],
        schema_version=data.get("schema_version", FIXTURE_SCHEMA_VERSION),
        source_file=str(path),
    )


def load_fixtures_dir(directory: str | Path) -> list[GoldenFixture]:
    """
    Load all .json fixtures from a directory.

    Non-JSON files are skipped. Malformed fixtures raise ValueError
    (fail-fast — don't silently skip broken fixtures).
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []

    fixtures: list[GoldenFixture] = []
    for path in sorted(directory.glob("*.json")):
        fixtures.append(load_fixture(path))
    return fixtures


def diff_canonical_results(
    expected: dict[str, Any],
    actual: dict[str, Any],
    *,
    ignore_fields: frozenset[str] = frozenset({
        # Fields that are expected to differ between fixture and live run
        "request_id", "execution_id", "executed_at", "investigation_id",
    }),
) -> list[FixtureDiff]:
    """
    Deep-compare two canonical PluginResult dicts, returning a list of
    field-level diffs.

    Args:
        expected: the expected_canonical from the fixture
        actual: the actual canonical result from the adapter
        ignore_fields: top-level fields to skip (timestamps, UUIDs that
            vary per run)
    """
    diffs: list[FixtureDiff] = []
    _diff_recursive(expected, actual, "", diffs, ignore_fields, top_level=True)
    return diffs


def _diff_recursive(
    expected: Any,
    actual: Any,
    path: str,
    diffs: list[FixtureDiff],
    ignore_fields: frozenset[str],
    *,
    top_level: bool = False,
) -> None:
    """Recursive comparison helper."""
    # Type mismatch
    if type(expected) is not type(actual):
        diffs.append(FixtureDiff(path or "<root>", expected, actual))
        return

    # Dict comparison
    if isinstance(expected, dict):
        all_keys = set(expected.keys()) | set(actual.keys())
        for key in sorted(all_keys):
            if top_level and key in ignore_fields:
                continue
            child_path = f"{path}.{key}" if path else key
            if key not in expected:
                diffs.append(FixtureDiff(child_path, "<missing>", actual[key]))
            elif key not in actual:
                diffs.append(FixtureDiff(child_path, expected[key], "<missing>"))
            else:
                _diff_recursive(
                    expected[key], actual[key], child_path, diffs, ignore_fields,
                    top_level=False,
                )
        return

    # List comparison
    if isinstance(expected, list):
        if len(expected) != len(actual):
            diffs.append(FixtureDiff(path or "<root>", expected, actual))
            return
        for i, (e, a) in enumerate(zip(expected, actual)):
            _diff_recursive(e, a, f"{path}[{i}]", diffs, ignore_fields, top_level=False)
        return

    # Scalar comparison
    if expected != actual:
        diffs.append(FixtureDiff(path or "<root>", expected, actual))


__all__ = [
    "GoldenFixture", "FixtureDiff", "FixtureCheckResult",
    "FIXTURE_SCHEMA_VERSION",
    "load_fixture", "load_fixtures_dir", "diff_canonical_results",
]
