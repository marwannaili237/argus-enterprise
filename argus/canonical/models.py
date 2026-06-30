"""
Canonical entity data model for Argus.

This module defines the cross-investigation, normalized data layer that
sits alongside (not replaces) the existing per-investigation Evidence
table. The goal is to provide:

  - A single canonical record per real-world entity (email, domain, IP, ...)
  - Identity records that group multiple entities into "same actor" clusters
  - Full provenance: every observation links back to the raw evidence + plugin
    that produced it, and every relationship records which evidence supports it

Design notes
------------
* All primary keys are UUIDs (stored as strings for SQLite portability).
* SQLAlchemy 2.0 async style with Mapped[] / mapped_column().
* Uses the same DeclarativeBase as existing models (database.Base) so all
  tables live in one metadata and a single create_all() call works.
* No back_populates on cross-package relationships to avoid circular imports.
* __repr__ on every model for debugging.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import uuid

from sqlalchemy import (
    String, Text, Float, Integer, DateTime, ForeignKey, JSON,
    UniqueConstraint, PrimaryKeyConstraint, Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

# Reuse the existing declarative base so all tables share metadata.
# Importing here would create a circular import (database.py imports
# models.py). Instead, models register themselves lazily at import time
# of database.init_db(). See canonical/__init__.py for the wiring.
from database import Base


def _utcnow() -> datetime:
    """Return tz-naive UTC datetime (matches existing convention)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _uuid_str() -> str:
    """Generate a new UUID4 as a string (SQLite-friendly PK)."""
    return str(uuid.uuid4())


# ─── Allowed entity types ──────────────────────────────────────────────
# Single source of truth — kept here so models + validator agree without
# an extra import cycle.
ALLOWED_ENTITY_TYPES = frozenset({
    "email", "username", "phone", "domain", "ip", "ipv4", "ipv6",
    "url", "wallet", "btc", "eth", "hash", "md5", "sha1", "sha256",
    "cve", "asn", "mac", "iban", "vat", "user_agent", "certificate",
    "person", "company", "image",
})


# ─── Identity status enum ──────────────────────────────────────────────
IDENTITY_STATUSES = frozenset({"tentative", "confirmed", "disputed", "merged"})


# ─── Relationship types enum ───────────────────────────────────────────
# Open set — these are the well-known ones; plugins may introduce more.
ALLOWED_RELATIONSHIP_TYPES = frozenset({
    "owns", "uses", "same_person", "hosted_on", "resolves_to",
    "registered_by", "links_to", "mentions", "verified_by",
    "compromised_in", "found_alongside", "rotates_to", "redirects_to",
    "same_as", "member_of", "employed_at", "located_in",
})


# =====================================================================
# Core canonical entity
# =====================================================================

class CanonicalEntity(Base):
    """
    A single canonical record per real-world entity.

    The (type, normalized_value) pair is unique — no matter how many
    investigations touch the same email/domain/IP, there's exactly one
    CanonicalEntity row for it.
    """
    __tablename__ = "canonical_entities"
    __table_args__ = (
        UniqueConstraint("type", "normalized_value", name="uq_canonical_type_norm"),
        Index("ix_canonical_type", "type"),
        Index("ix_canonical_last_seen", "last_seen"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_value: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)
    investigation_count: Mapped[int] = mapped_column(Integer, default=1)
    source_count: Mapped[int] = mapped_column(Integer, default=1)

    # Relationships (no back_populates to avoid circular refs across packages)
    identity_links: Mapped[list["IdentityEntity"]] = relationship(
        "IdentityEntity", back_populates="entity", cascade="all, delete-orphan"
    )
    observation_links: Mapped[list["EntityObservation"]] = relationship(
        "EntityObservation", back_populates="entity", cascade="all, delete-orphan"
    )
    investigation_links: Mapped[list["EntityInvestigationLink"]] = relationship(
        "EntityInvestigationLink", back_populates="entity", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<CanonicalEntity id={self.id!r} type={self.type!r} "
            f"normalized_value={self.normalized_value!r}>"
        )


# =====================================================================
# Identity — groups multiple entities into a real-world actor
# =====================================================================

class Identity(Base):
    """
    A real-world actor (person, organization, threat group) that one or
    more canonical entities belong to.

    Identities have a lifecycle: tentative → confirmed | disputed → merged.
    When two identities are determined to be the same actor, one is
    marked `merged` and `merged_into` points to the surviving identity.
    """
    __tablename__ = "identities"
    __table_args__ = (
        Index("ix_identity_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    label: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="tentative")
    merged_into: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    entities: Mapped[list["IdentityEntity"]] = relationship(
        "IdentityEntity", back_populates="identity", cascade="all, delete-orphan",
        foreign_keys="IdentityEntity.identity_id",
    )
    merged_into_rel: Mapped[Optional["Identity"]] = relationship(
        "Identity", remote_side="Identity.id", foreign_keys=[merged_into]
    )

    def __repr__(self) -> str:
        return (
            f"<Identity id={self.id!r} label={self.label!r} "
            f"status={self.status!r} confidence={self.confidence}>"
        )


class IdentityEntity(Base):
    """
    Many-to-many between Identity and CanonicalEntity.

    `signal_weight` is how much this entity contributes to the identity's
    overall confidence (e.g. an email address is a strong signal, a
    username on a forum is a weak signal).
    """
    __tablename__ = "identity_entities"
    __table_args__ = (
        PrimaryKeyConstraint("identity_id", "entity_id"),
    )

    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False
    )
    signal_weight: Mapped[float] = mapped_column(Float, default=0.5)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    identity: Mapped["Identity"] = relationship(
        "Identity", back_populates="entities", foreign_keys=[identity_id]
    )
    entity: Mapped["CanonicalEntity"] = relationship(
        "CanonicalEntity", back_populates="identity_links", foreign_keys=[entity_id]
    )

    def __repr__(self) -> str:
        return (
            f"<IdentityEntity identity_id={self.identity_id!r} "
            f"entity_id={self.entity_id!r} weight={self.signal_weight}>"
        )


# =====================================================================
# Raw evidence — immutable record of a plugin's source response
# =====================================================================

class RawEvidence(Base):
    """
    Immutable record of what a plugin actually fetched/computed.

    One RawEvidence row per plugin execution per investigation. The
    `raw_response` JSON column is NEVER mutated — it is the cryptographic
    ground truth for chain-of-custody.
    """
    __tablename__ = "raw_evidence"
    __table_args__ = (
        Index("ix_raw_evidence_investigation", "investigation_id"),
        Index("ix_raw_evidence_plugin", "plugin_id"),
        Index("ix_raw_evidence_execution", "execution_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    investigation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    plugin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(32), default="0.0.0")
    execution_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    raw_response: Mapped[dict] = mapped_column(JSON, nullable=False)
    source_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    source_reliability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    observations: Mapped[list["Observation"]] = relationship(
        "Observation", back_populates="evidence", cascade="all, delete-orphan"
    )
    relationship_provenance: Mapped[list["RelationshipProvenance"]] = relationship(
        "RelationshipProvenance", back_populates="evidence", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<RawEvidence id={self.id!r} plugin_id={self.plugin_id!r} "
            f"investigation_id={self.investigation_id!r} collected_at={self.collected_at}>"
        )


# =====================================================================
# Observations — atomic facts extracted from raw evidence
# =====================================================================

class Observation(Base):
    """
    A single atomic observation extracted from a piece of raw evidence
    (e.g. "an email was found", "a subdomain was enumerated").

    Observations are the bridge between raw evidence and canonical
    entities: an observation extracts a value, that value is normalized
    and upserted into canonical_entities, and the link is recorded in
    entity_observations.
    """
    __tablename__ = "observations"
    __table_args__ = (
        Index("ix_observation_evidence", "evidence_id"),
        Index("ix_observation_type", "observation_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("raw_evidence.id", ondelete="CASCADE"), nullable=False
    )
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    extracted_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    evidence: Mapped["RawEvidence"] = relationship("RawEvidence", back_populates="observations")
    entity_links: Mapped[list["EntityObservation"]] = relationship(
        "EntityObservation", back_populates="observation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Observation id={self.id!r} type={self.observation_type!r} "
            f"value={self.value!r} confidence={self.confidence}>"
        )


class EntityObservation(Base):
    """Many-to-many between CanonicalEntity and Observation."""
    __tablename__ = "entity_observations"
    __table_args__ = (
        PrimaryKeyConstraint("entity_id", "observation_id"),
    )

    entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("observations.id", ondelete="CASCADE"), nullable=False
    )

    entity: Mapped["CanonicalEntity"] = relationship(
        "CanonicalEntity", back_populates="observation_links", foreign_keys=[entity_id]
    )
    observation: Mapped["Observation"] = relationship(
        "Observation", back_populates="entity_links", foreign_keys=[observation_id]
    )

    def __repr__(self) -> str:
        return (
            f"<EntityObservation entity_id={self.entity_id!r} "
            f"observation_id={self.observation_id!r}>"
        )


# =====================================================================
# Relationships — edges between canonical entities
# =====================================================================

class Relationship(Base):
    """
    A directed edge between two canonical entities.

    e.g. (entity:domain "example.com") --[resolves_to]--> (entity:ip "1.2.3.4")

    A relationship has a confidence score and first/last seen timestamps.
    Multiple pieces of evidence can support the same relationship (see
    RelationshipProvenance).
    """
    __tablename__ = "relationships"
    __table_args__ = (
        Index("ix_rel_source", "source_entity_id"),
        Index("ix_rel_target", "target_entity_id"),
        Index("ix_rel_type", "relationship_type"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    source_entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False
    )
    target_entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    provenance: Mapped[list["RelationshipProvenance"]] = relationship(
        "RelationshipProvenance", back_populates="relationship_rel", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Relationship id={self.id!r} {self.source_entity_id} "
            f"--[{self.relationship_type}]--> {self.target_entity_id} "
            f"conf={self.confidence}>"
        )


class RelationshipProvenance(Base):
    """
    Provenance link: which evidence (and optionally which observation)
    supports a given relationship.
    """
    __tablename__ = "relationship_provenance"
    __table_args__ = (
        PrimaryKeyConstraint("relationship_id", "evidence_id"),
    )

    relationship_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("relationships.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("raw_evidence.id", ondelete="CASCADE"), nullable=False
    )
    observation_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("observations.id", ondelete="SET NULL"), nullable=True
    )

    relationship_rel: Mapped["Relationship"] = relationship(
        "Relationship", back_populates="provenance", foreign_keys=[relationship_id]
    )
    evidence: Mapped["RawEvidence"] = relationship(
        "RawEvidence", back_populates="relationship_provenance", foreign_keys=[evidence_id]
    )

    def __repr__(self) -> str:
        return (
            f"<RelationshipProvenance relationship_id={self.relationship_id!r} "
            f"evidence_id={self.evidence_id!r} observation_id={self.observation_id!r}>"
        )


# =====================================================================
# Entity ↔ Investigation cross-link
# =====================================================================

class EntityInvestigationLink(Base):
    """
    Records that a canonical entity appeared in a specific investigation.

    This is the "shared investigations" index — given an entity, we can
    find every investigation that touched it, which is the basis for
    cross-investigation correlation.
    """
    __tablename__ = "entity_investigation_links"
    __table_args__ = (
        PrimaryKeyConstraint("entity_id", "investigation_id"),
        Index("ix_eil_investigation", "investigation_id"),
    )

    entity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("canonical_entities.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[str] = mapped_column(String(36), nullable=False)

    entity: Mapped["CanonicalEntity"] = relationship(
        "CanonicalEntity", back_populates="investigation_links", foreign_keys=[entity_id]
    )

    def __repr__(self) -> str:
        return (
            f"<EntityInvestigationLink entity_id={self.entity_id!r} "
            f"investigation_id={self.investigation_id!r}>"
        )


# =====================================================================
# Identity events — audit trail for identity operations
# =====================================================================

class IdentityEvent(Base):
    """
    Audit-trail event for identity operations.

    Every identity creation, promotion, dispute, and merge emits an event.
    Events are append-only — never updated or deleted. Used for:
      - Audit: who/what/when for every identity change
      - Replay: rebuild identity state from events (future)
      - Rollback: reverse a specific operation (future)

    NOTE: This table is added in migration 0002. Code that references
    it must be resilient to the table not existing yet (pre-migration
    environments).
    """
    __tablename__ = "identity_events"
    __table_args__ = (
        Index("ix_identity_event_identity", "identity_id"),
        Index("ix_identity_event_investigation", "investigation_id"),
        Index("ix_identity_event_action", "action"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # created|promoted|disputed|merged
    investigation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:
        return (
            f"<IdentityEvent id={self.id!r} identity_id={self.identity_id!r} "
            f"action={self.action!r} investigation_id={self.investigation_id!r}>"
        )


# =====================================================================
# Plugin health — persisted health records (migration 0002)
# =====================================================================

class PluginHealthRecord(Base):
    """
    Persisted plugin health record.

    NOTE: This mirrors the in-memory PluginHealthTracker in
    canonical/adapters/health.py. The in-memory tracker is the live
    source of truth during a process run; this table provides
    cross-restart visibility and is populated by a periodic flush
    job (not yet implemented). For now, the in-memory tracker is
    authoritative and this table is informational.
    """
    __tablename__ = "plugin_health"
    __table_args__ = (
        UniqueConstraint("plugin_id", name="uq_plugin_health_plugin_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    plugin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|quarantined
    structural_failure_count: Mapped[int] = mapped_column(Integer, default=0)
    transient_failure_count: Mapped[int] = mapped_column(Integer, default=0)
    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    successful_runs: Mapped[int] = mapped_column(Integer, default=0)
    quarantined_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_failure_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_failure_kind: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # transient|structural
    last_failure_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    def __repr__(self) -> str:
        return (
            f"<PluginHealthRecord plugin_id={self.plugin_id!r} "
            f"status={self.status!r} structural={self.structural_failure_count}>"
        )


# =====================================================================
# Adapter fixtures — golden fixture registry (migration 0002)
# =====================================================================

class AdapterFixtureRecord(Base):
    """
    Persisted record of a golden fixture (compliance test case).

    This is metadata only — the actual fixture JSON lives on disk.
    The table tracks which fixtures have been run, when, and whether
    they passed (for dashboard display).
    """
    __tablename__ = "adapter_fixtures"
    __table_args__ = (
        UniqueConstraint("plugin_id", "fixture_name", name="uq_adapter_fixture_plugin_name"),
        Index("ix_adapter_fixture_plugin", "plugin_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    plugin_id: Mapped[str] = mapped_column(String(64), nullable=False)
    fixture_name: Mapped[str] = mapped_column(String(128), nullable=False)
    fixture_file: Mapped[str] = mapped_column(String(512), nullable=False)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_result: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # pass|fail|error
    last_diff_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self) -> str:
        return (
            f"<AdapterFixtureRecord plugin_id={self.plugin_id!r} "
            f"name={self.fixture_name!r} last_result={self.last_result!r}>"
        )


# =====================================================================
# Event Store — decision_events + identity_events (audit trail)
# =====================================================================

class DecisionEvent(Base):
    """
    Append-only event log for every decision in the system.

    Every state change (Requested, Evaluated, Approved, Rejected,
    Executed, Reverted) is an event. Events are NEVER updated or
    deleted — they are the cryptographic ground truth for replay.

    Lifecycle of a decision:
      Requested → Evaluated → Approved/Rejected → Executed/Reverted
    """
    __tablename__ = "decision_events"
    __table_args__ = (
        Index("ix_decision_event_decision", "decision_id"),
        Index("ix_decision_event_identity", "identity_id"),
        Index("ix_decision_event_action", "action"),
        Index("ix_decision_event_timestamp", "timestamp"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    decision_id: Mapped[str] = mapped_column(String(36), nullable=False)
    identity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    # action values: requested|evaluated|approved|rejected|executed|reverted
    rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    rule_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)  # user_id, "system", "rule:<rule_id>"
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)

    def __repr__(self) -> str:
        return (
            f"<DecisionEvent id={self.id!r} decision_id={self.decision_id!r} "
            f"action={self.action!r} actor={self.actor!r}>"
        )


# =====================================================================
# Review Queue — pending decisions awaiting human approval
# =====================================================================

class ReviewQueueItem(Base):
    """
    A proposed decision awaiting human review.

    Created by the Decision Engine when a rule proposes QUEUE_FOR_REVIEW.
    Resolved by a human via POST /api/v1/review-queue/{id}/approve or /reject.

    Status lifecycle:
      pending → approved → executed
      pending → rejected
    """
    __tablename__ = "review_queue"
    __table_args__ = (
        Index("ix_review_queue_status", "status"),
        Index("ix_review_queue_target", "target_identity_id"),
        Index("ix_review_queue_candidate", "candidate_identity_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    decision_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    candidate_identity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_identity_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    # target is None for PROMOTE_TO_GLOBAL decisions (no existing global identity)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    reasoning: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # status values: pending|approved|rejected|executed
    proposed_by_rule: Mapped[str] = mapped_column(String(64), nullable=False)
    proposed_by_rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ReviewQueueItem id={self.id!r} decision_id={self.decision_id!r} "
            f"status={self.status!r} score={self.score}>"
        )


# =====================================================================
# Identity merge provenance — tracks merge history for split operations
# =====================================================================

class IdentityMergeRecord(Base):
    """
    Records a merge operation so it can be reversed (split_identity).

    When identity B is merged into identity A:
      - A IdentityMergeRecord is created with source=B, target=A
      - All IdentityEntity rows from B are reparented to A
      - The original signal_weights are recorded so split can restore them

    To reverse (split_identity):
      - Read the IdentityMergeRecord
      - Reparent the entities back to B
      - Restore original signal_weights
      - Mark B as active (status=confirmed or tentative based on confidence)
      - Emit IdentityEvent("split")
    """
    __tablename__ = "identity_merge_records"
    __table_args__ = (
        Index("ix_merge_record_source", "source_identity_id"),
        Index("ix_merge_record_target", "target_identity_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    source_identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    target_identity_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identities.id", ondelete="CASCADE"), nullable=False
    )
    decision_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    # The entity_ids that were moved from source to target, with their
    # original signal_weights (for restoration during split)
    moved_entities: Mapped[dict] = mapped_column(JSON, default=dict)
    # {entity_id: original_signal_weight, ...}
    merged_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    reverted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    reverted_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<IdentityMergeRecord source={self.source_identity_id!r} "
            f"target={self.target_identity_id!r} reverted={self.reverted_at is not None}>"
        )


# ─── Export list for convenience ──────────────────────────────────────
__all__ = [
    "CanonicalEntity",
    "Identity",
    "IdentityEntity",
    "RawEvidence",
    "Observation",
    "EntityObservation",
    "Relationship",
    "RelationshipProvenance",
    "EntityInvestigationLink",
    "IdentityEvent",
    "PluginHealthRecord",
    "AdapterFixtureRecord",
    "DecisionEvent",
    "ReviewQueueItem",
    "IdentityMergeRecord",
    "ALLOWED_ENTITY_TYPES",
    "ALLOWED_RELATIONSHIP_TYPES",
    "IDENTITY_STATUSES",
]
