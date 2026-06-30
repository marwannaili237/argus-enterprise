"""Migration 0002 — plugin health, adapter fixtures, identity events.

Adds three new tables:
  - identity_events: audit trail for identity operations
  - plugin_health: persisted plugin health records
  - adapter_fixtures: golden fixture registry

This migration is ADDITIVE only. No existing tables are modified.
Downgrade drops the three new tables.
"""
from alembic import op
import sqlalchemy as sa
import uuid


revision = "0002_plugin_adapter_framework"
down_revision = "0001_canonical_entity_layer"
branch_labels = None
depends_on = None


def _uuid_default():
    return str(uuid.uuid4())


def upgrade() -> None:
    # ─── identity_events ─────────────────────────────────────────────
    op.create_table(
        "identity_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("identity_id", sa.String(36),
                  sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_identity_event_identity", "identity_events", ["identity_id"])
    op.create_index("ix_identity_event_investigation", "identity_events", ["investigation_id"])
    op.create_index("ix_identity_event_action", "identity_events", ["action"])

    # ─── plugin_health ───────────────────────────────────────────────
    op.create_table(
        "plugin_health",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plugin_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("structural_failure_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("transient_failure_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_runs", sa.Integer, nullable=False, server_default="0"),
        sa.Column("successful_runs", sa.Integer, nullable=False, server_default="0"),
        sa.Column("quarantined_at", sa.DateTime, nullable=True),
        sa.Column("last_failure_at", sa.DateTime, nullable=True),
        sa.Column("last_failure_kind", sa.String(16), nullable=True),
        sa.Column("last_failure_message", sa.Text, nullable=True),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("plugin_id", name="uq_plugin_health_plugin_id"),
    )

    # ─── adapter_fixtures ────────────────────────────────────────────
    op.create_table(
        "adapter_fixtures",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("plugin_id", sa.String(64), nullable=False),
        sa.Column("fixture_name", sa.String(128), nullable=False),
        sa.Column("fixture_file", sa.String(512), nullable=False),
        sa.Column("last_checked_at", sa.DateTime, nullable=True),
        sa.Column("last_result", sa.String(16), nullable=True),
        sa.Column("last_diff_summary", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("plugin_id", "fixture_name", name="uq_adapter_fixture_plugin_name"),
    )
    op.create_index("ix_adapter_fixture_plugin", "adapter_fixtures", ["plugin_id"])


def downgrade() -> None:
    op.drop_table("adapter_fixtures")
    op.drop_table("plugin_health")
    op.drop_table("identity_events")
