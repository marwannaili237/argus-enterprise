"""
Migration tests for migration 0002 (plugin_adapter_framework).

Verifies:
  - upgrade() creates the three new tables with correct schema
  - downgrade() drops them cleanly
  - The migration is additive (no existing tables touched)
  - Indexes and unique constraints are created correctly

Uses an in-memory SQLite DB and runs the migration via Alembic's
MigrationContext + Operations (the proper way to test migrations
without the alembic CLI).
"""
import os
import sys
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from alembic.migration import MigrationContext
from alembic.operations import Operations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))


def _load_migration_module():
    """Load the migration module by file path (not import path)."""
    migration_path = Path(__file__).parent.parent / "argus" / "migrations" / "versions" / "20250102_0002_plugin_adapter_framework.py"
    spec = importlib.util.spec_from_file_location("migration_0002", migration_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def migration_module():
    return _load_migration_module()


@pytest.fixture
def sqlite_engine_with_op(migration_module):
    """
    Fresh SQLite engine with an Alembic Operations context set up.

    Each test gets a fresh engine. The migration's upgrade()/downgrade()
    functions use the module-level `op` proxy, which we bind to the
    Operations instance via Operations._install_proxy (Alembic's
    internal API for the op proxy).
    """
    engine = create_engine("sqlite:///:memory:", echo=False)
    conn = engine.connect()
    ctx = MigrationContext.configure(conn)
    op_proxy = Operations(ctx)
    Operations._install_proxy(op_proxy)
    try:
        yield engine, op_proxy, conn
    finally:
        # _remove_proxy is an instance method on the proxy class
        try:
            op_proxy._remove_proxy()
        except Exception:
            pass
        conn.close()
        engine.dispose()


def _get_tables(engine) -> list[str]:
    return inspect(engine).get_table_names()


def _get_indexes(engine, table: str) -> list[str]:
    return [i["name"] for i in inspect(engine).get_indexes(table)]


def _get_columns(engine, table: str) -> list[str]:
    return [c["name"] for c in inspect(engine).get_columns(table)]


class TestMigrationUpgrade:
    def test_creates_identity_events_table(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        assert "identity_events" in _get_tables(engine)

    def test_creates_plugin_health_table(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        assert "plugin_health" in _get_tables(engine)

    def test_creates_adapter_fixtures_table(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        assert "adapter_fixtures" in _get_tables(engine)

    def test_identity_events_columns(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        cols = _get_columns(engine, "identity_events")
        expected = {"id", "identity_id", "action", "investigation_id", "details", "timestamp"}
        assert expected.issubset(set(cols))

    def test_plugin_health_columns(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        cols = _get_columns(engine, "plugin_health")
        expected = {
            "id", "plugin_id", "status", "structural_failure_count",
            "transient_failure_count", "total_runs", "successful_runs",
            "quarantined_at", "last_failure_at", "last_failure_kind",
            "last_failure_message", "updated_at",
        }
        assert expected.issubset(set(cols))

    def test_adapter_fixtures_columns(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        cols = _get_columns(engine, "adapter_fixtures")
        expected = {
            "id", "plugin_id", "fixture_name", "fixture_file",
            "last_checked_at", "last_result", "last_diff_summary", "created_at",
        }
        assert expected.issubset(set(cols))

    def test_identity_events_indexes(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        indexes = _get_indexes(engine, "identity_events")
        assert "ix_identity_event_identity" in indexes
        assert "ix_identity_event_investigation" in indexes
        assert "ix_identity_event_action" in indexes

    def test_plugin_health_unique_constraint(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        # The unique constraint on plugin_id should be enforced
        conn.execute(text(
            "INSERT INTO plugin_health (id, plugin_id, status) VALUES ('a', 'plugin_x', 'active')"
        ))
        conn.commit()
        with pytest.raises(Exception):
            conn.execute(text(
                "INSERT INTO plugin_health (id, plugin_id, status) VALUES ('b', 'plugin_x', 'active')"
            ))
            conn.commit()

    def test_adapter_fixtures_unique_constraint(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        conn.execute(text(
            "INSERT INTO adapter_fixtures (id, plugin_id, fixture_name, fixture_file) "
            "VALUES ('a', 'plugin_x', 'basic', '/path/to/fixture.json')"
        ))
        conn.commit()
        with pytest.raises(Exception):
            conn.execute(text(
                "INSERT INTO adapter_fixtures (id, plugin_id, fixture_name, fixture_file) "
                "VALUES ('b', 'plugin_x', 'basic', '/other/path.json')"
            ))
            conn.commit()

    def test_adapter_fixtures_index(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        indexes = _get_indexes(engine, "adapter_fixtures")
        assert "ix_adapter_fixture_plugin" in indexes


class TestMigrationDowngrade:
    def test_drops_all_three_tables(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        assert "identity_events" in _get_tables(engine)
        assert "plugin_health" in _get_tables(engine)
        assert "adapter_fixtures" in _get_tables(engine)

        migration_module.downgrade()
        conn.commit()
        tables = _get_tables(engine)
        assert "identity_events" not in tables
        assert "plugin_health" not in tables
        assert "adapter_fixtures" not in tables

    def test_downgrade_is_idempotent_safe_after_upgrade(self, sqlite_engine_with_op, migration_module):
        """upgrade → downgrade → upgrade should work cleanly."""
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        migration_module.downgrade()
        conn.commit()
        migration_module.upgrade()
        conn.commit()
        tables = _get_tables(engine)
        assert "identity_events" in tables
        assert "plugin_health" in tables
        assert "adapter_fixtures" in tables


class TestMigrationIsAdditive:
    def test_does_not_create_canonical_tables(self, sqlite_engine_with_op, migration_module):
        """Migration 0002 must NOT create the tables from 0001 (additive only)."""
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        tables = _get_tables(engine)
        for t in ["canonical_entities", "identities", "raw_evidence", "observations"]:
            assert t not in tables

    def test_only_three_new_tables(self, sqlite_engine_with_op, migration_module):
        engine, op, conn = sqlite_engine_with_op
        migration_module.upgrade()
        conn.commit()
        tables = set(_get_tables(engine))
        tables.discard("sqlite_sequence")
        assert tables == {"identity_events", "plugin_health", "adapter_fixtures"}


class TestMigrationMetadata:
    def test_revision_string(self, migration_module):
        assert migration_module.revision == "0002_plugin_adapter_framework"

    def test_down_revision_chains_to_0001(self, migration_module):
        assert migration_module.down_revision == "0001_canonical_entity_layer"

    def test_upgrade_callable(self, migration_module):
        assert callable(migration_module.upgrade)

    def test_downgrade_callable(self, migration_module):
        assert callable(migration_module.downgrade)
