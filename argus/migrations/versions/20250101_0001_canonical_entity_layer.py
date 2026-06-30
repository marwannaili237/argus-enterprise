"""Canonical entity layer migration.

Creates the cross-investigation canonical entity data model:
  - canonical_entities
  - identities
  - identity_entities
  - raw_evidence
  - observations
  - entity_observations
  - relationships
  - relationship_provenance
  - entity_investigation_links

This migration is additive — it does not touch any existing tables.
"""
from alembic import op
import sqlalchemy as sa
import uuid


# Revision identifiers
revision = "0001_canonical_entity_layer"
down_revision = None
branch_labels = None
depends_on = None


def _uuid_pk() -> sa.Column:
    """UUID PK stored as String(36) for SQLite portability."""
    return sa.Column(sa.String(36), primary_key=True,
                     default=lambda: str(uuid.uuid4()))


def upgrade() -> None:
    # ─── canonical_entities ──────────────────────────────────────────
    op.create_table(
        "canonical_entities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("normalized_value", sa.String(512), nullable=False),
        sa.Column("raw_value", sa.String(512), nullable=False),
        sa.Column("first_seen", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("last_seen", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("investigation_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("source_count", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("type", "normalized_value", name="uq_canonical_type_norm"),
    )
    op.create_index("ix_canonical_type", "canonical_entities", ["type"])
    op.create_index("ix_canonical_last_seen", "canonical_entities", ["last_seen"])

    # ─── identities ──────────────────────────────────────────────────
    op.create_table(
        "identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("label", sa.String(256), nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="tentative"),
        sa.Column("merged_into", sa.String(36),
                  sa.ForeignKey("identities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_identity_status", "identities", ["status"])

    # ─── identity_entities (M2M) ─────────────────────────────────────
    op.create_table(
        "identity_entities",
        sa.Column("identity_id", sa.String(36),
                  sa.ForeignKey("identities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", sa.String(36),
                  sa.ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("signal_weight", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("added_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.PrimaryKeyConstraint("identity_id", "entity_id"),
    )

    # ─── raw_evidence ────────────────────────────────────────────────
    op.create_table(
        "raw_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("plugin_id", sa.String(64), nullable=False),
        sa.Column("plugin_version", sa.String(32), nullable=False, server_default="0.0.0"),
        sa.Column("execution_id", sa.String(36), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("collected_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("raw_response", sa.JSON, nullable=False),
        sa.Column("source_url", sa.String(2048), nullable=True),
        sa.Column("source_reliability", sa.Float, nullable=True),
    )
    op.create_index("ix_raw_evidence_investigation", "raw_evidence", ["investigation_id"])
    op.create_index("ix_raw_evidence_plugin", "raw_evidence", ["plugin_id"])
    op.create_index("ix_raw_evidence_execution", "raw_evidence", ["execution_id"])

    # ─── observations ────────────────────────────────────────────────
    op.create_table(
        "observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(36),
                  sa.ForeignKey("raw_evidence.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observation_type", sa.String(64), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("context", sa.Text, nullable=True),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("extracted_at", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_observation_evidence", "observations", ["evidence_id"])
    op.create_index("ix_observation_type", "observations", ["observation_type"])

    # ─── entity_observations (M2M) ───────────────────────────────────
    op.create_table(
        "entity_observations",
        sa.Column("entity_id", sa.String(36),
                  sa.ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observation_id", sa.String(36),
                  sa.ForeignKey("observations.id", ondelete="CASCADE"), nullable=False),
        sa.PrimaryKeyConstraint("entity_id", "observation_id"),
    )

    # ─── relationships ───────────────────────────────────────────────
    op.create_table(
        "relationships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_entity_id", sa.String(36),
                  sa.ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_entity_id", sa.String(36),
                  sa.ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship_type", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("first_seen", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
        sa.Column("last_seen", sa.DateTime, nullable=False, server_default=sa.func.current_timestamp()),
    )
    op.create_index("ix_rel_source", "relationships", ["source_entity_id"])
    op.create_index("ix_rel_target", "relationships", ["target_entity_id"])
    op.create_index("ix_rel_type", "relationships", ["relationship_type"])

    # ─── relationship_provenance (M2M) ───────────────────────────────
    op.create_table(
        "relationship_provenance",
        sa.Column("relationship_id", sa.String(36),
                  sa.ForeignKey("relationships.id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_id", sa.String(36),
                  sa.ForeignKey("raw_evidence.id", ondelete="CASCADE"), nullable=False),
        sa.Column("observation_id", sa.String(36),
                  sa.ForeignKey("observations.id", ondelete="SET NULL"), nullable=True),
        sa.PrimaryKeyConstraint("relationship_id", "evidence_id"),
    )

    # ─── entity_investigation_links (M2M) ────────────────────────────
    op.create_table(
        "entity_investigation_links",
        sa.Column("entity_id", sa.String(36),
                  sa.ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint("entity_id", "investigation_id"),
    )
    op.create_index("ix_eil_investigation", "entity_investigation_links", ["investigation_id"])


def downgrade() -> None:
    op.drop_table("entity_investigation_links")
    op.drop_table("relationship_provenance")
    op.drop_table("relationships")
    op.drop_table("entity_observations")
    op.drop_table("observations")
    op.drop_table("raw_evidence")
    op.drop_table("identity_entities")
    op.drop_table("identities")
    op.drop_table("canonical_entities")
