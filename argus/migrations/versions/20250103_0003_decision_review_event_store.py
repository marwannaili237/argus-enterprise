"""Migration 0003 — Event Store, Review Queue, Merge Records.

Adds three new tables:
  - decision_events: append-only audit trail for decisions
  - review_queue: pending decisions awaiting human approval
  - identity_merge_records: merge provenance for split operations

This migration is ADDITIVE only. No existing tables are modified.
"""
from alembic import op
import sqlalchemy as sa
import uuid


revision = "0003_decision_review_event_store"
down_revision = "0002_plugin_adapter_framework"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ─── decision_events ─────────────────────────────────────────────
    op.create_table(
        "decision_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("decision_id", sa.String(36), nullable=False),
        sa.Column("identity_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("rule_version", sa.String(32), nullable=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("timestamp", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("payload", sa.JSON, nullable=True),
        sa.Column("config_snapshot", sa.JSON, nullable=True),
    )
    op.create_index("ix_decision_event_decision", "decision_events", ["decision_id"])
    op.create_index("ix_decision_event_identity", "decision_events", ["identity_id"])
    op.create_index("ix_decision_event_action", "decision_events", ["action"])
    op.create_index("ix_decision_event_timestamp", "decision_events", ["timestamp"])

    # ─── review_queue ────────────────────────────────────────────────
    op.create_table(
        "review_queue",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("decision_id", sa.String(36), nullable=False, unique=True),
        sa.Column("candidate_identity_id", sa.String(36), nullable=False),
        sa.Column("target_identity_id", sa.String(36), nullable=True),
        sa.Column("score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("reasoning", sa.JSON, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("proposed_by_rule", sa.String(64), nullable=False),
        sa.Column("proposed_by_rule_version", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("reviewed_at", sa.DateTime, nullable=True),
        sa.Column("reviewed_by", sa.String(128), nullable=True),
        sa.Column("review_notes", sa.Text, nullable=True),
    )
    op.create_index("ix_review_queue_status", "review_queue", ["status"])
    op.create_index("ix_review_queue_target", "review_queue", ["target_identity_id"])
    op.create_index("ix_review_queue_candidate", "review_queue", ["candidate_identity_id"])

    # ─── identity_merge_records ──────────────────────────────────────
    op.create_table(
        "identity_merge_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_identity_id", sa.String(36),
                  sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_identity_id", sa.String(36),
                  sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decision_id", sa.String(36), nullable=True),
        sa.Column("moved_entities", sa.JSON, nullable=True),
        sa.Column("merged_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("reverted_at", sa.DateTime, nullable=True),
        sa.Column("reverted_by", sa.String(128), nullable=True),
    )
    op.create_index("ix_merge_record_source", "identity_merge_records", ["source_identity_id"])
    op.create_index("ix_merge_record_target", "identity_merge_records", ["target_identity_id"])


def downgrade() -> None:
    op.drop_table("identity_merge_records")
    op.drop_table("review_queue")
    op.drop_table("decision_events")
