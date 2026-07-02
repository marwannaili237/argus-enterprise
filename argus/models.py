from sqlalchemy import String, Integer, Text, Boolean, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import mapped_column, Mapped, relationship
from datetime import datetime, timezone
from database import Base


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    telegram_id: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=True)
    full_name: Mapped[str] = mapped_column(String(128), nullable=True)
    email_address: Mapped[str] = mapped_column(String(256), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    investigations: Mapped[list["Investigation"]] = relationship(back_populates="user")
    monitors: Mapped[list["Monitor"]] = relationship(back_populates="user")


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_user_id", "user_id"),
        Index("ix_investigations_status", "status"),
        Index("ix_investigations_created_at", "created_at"),
        Index("ix_investigations_user_status", "user_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    telegram_chat_id: Mapped[int] = mapped_column(Integer, nullable=True)
    telegram_message_id: Mapped[int] = mapped_column(Integer, nullable=True)

    user: Mapped["User"] = relationship(back_populates="investigations")
    evidence: Mapped[list["Evidence"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    notes: Mapped[list["InvestigationNote"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_investigation_id", "investigation_id"),
        Index("ix_evidence_plugin_name", "plugin_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=False)
    plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    data: Mapped[dict] = mapped_column(JSON, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    investigation: Mapped["Investigation"] = relationship(back_populates="evidence")


class Monitor(Base):
    __tablename__ = "monitors"
    __table_args__ = (
        Index("ix_monitors_user_id", "user_id"),
        Index("ix_monitors_active", "active"),
        Index("ix_monitors_next_check", "next_check"),
        Index("ix_monitors_user_active", "user_id", "active"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    telegram_chat_id: Mapped[int] = mapped_column(Integer, nullable=False)
    schedule: Mapped[str] = mapped_column(String(16), default="daily")   # hourly | daily | weekly
    interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_checked: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_check: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    last_investigation_id: Mapped[int] = mapped_column(Integer, nullable=True)
    change_count: Mapped[int] = mapped_column(Integer, default=0)
    webhook_url: Mapped[str] = mapped_column(String(512), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped["User"] = relationship(back_populates="monitors")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    investigation: Mapped["Investigation"] = relationship(back_populates="notes")


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    events: Mapped[dict] = mapped_column(JSON, nullable=False)  # list of event names
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ─── Monster Mode: Case Files, Tags, Watchlists, IOC DB ────────────────


class Case(Base):
    """A case file groups multiple investigations, like Maltego CaseFile."""
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open | closed | archived
    tlp: Mapped[str] = mapped_column(String(8), default="AMBER")  # TLP:RED|AMBER|AMBER+STRICT|GREEN|WHITE
    priority: Mapped[str] = mapped_column(String(16), default="medium")  # low|medium|high|critical
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    user: Mapped["User"] = relationship()
    investigations: Mapped[list["CaseInvestigation"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    notes: Mapped[list["CaseNote"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class CaseInvestigation(Base):
    """Many-to-many: investigations attached to a case."""
    __tablename__ = "case_investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id"), nullable=False)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    added_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    case: Mapped["Case"] = relationship(back_populates="investigations")


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    case: Mapped["Case"] = relationship(back_populates="notes")


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    color: Mapped[str] = mapped_column(String(16), default="#e94560")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TagAssociation(Base):
    """Polymorphic tag associations: tag any entity (investigation, case, IOC)."""
    __tablename__ = "tag_associations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tag_id: Mapped[int] = mapped_column(Integer, ForeignKey("tags.id"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # investigation|case|ioc|evidence
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Watchlist(Base):
    """A named list of IOCs to monitor across all investigations."""
    __tablename__ = "watchlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    ioc_type: Mapped[str] = mapped_column(String(32), default="any")  # ip|domain|url|email|hash|any
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    entries: Mapped[list["IOCEntry"]] = relationship(back_populates="watchlist", cascade="all, delete-orphan")


class IOCEntry(Base):
    """Individual IOC entry on a watchlist or extracted from an investigation."""
    __tablename__ = "ioc_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    watchlist_id: Mapped[int] = mapped_column(Integer, ForeignKey("watchlists.id"), nullable=True)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ip|domain|url|email|hash|user|asn|btc|eth
    source: Mapped[str] = mapped_column(String(64), default="manual")  # manual|plugin_name
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    notes: Mapped[str] = mapped_column(Text, nullable=True)
    tlp: Mapped[str] = mapped_column(String(8), default="AMBER")
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100 (Admiralty code credibility)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    watchlist: Mapped["Watchlist"] = relationship(back_populates="entries")


class ChainOfCustody(Base):
    """Immutable evidence provenance log (RFC 3161 timestamp + SHA-256)."""
    __tablename__ = "chain_of_custody"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=False)
    evidence_id: Mapped[int] = mapped_column(Integer, ForeignKey("evidence.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # collected|exported|viewed|verified
    actor: Mapped[str] = mapped_column(String(128), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rfc3161_token: Mapped[str] = mapped_column(Text, nullable=True)  # base64 TSA response
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)


class EnrichedEntity(Base):
    """Auto-extracted entities from investigation evidence (NER output)."""
    __tablename__ = "enriched_entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(Integer, ForeignKey("investigations.id"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ip|domain|email|url|hash|cve|asn|btc|user
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    source_plugin: Mapped[str] = mapped_column(String(64), nullable=True)
    context: Mapped[str] = mapped_column(Text, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)