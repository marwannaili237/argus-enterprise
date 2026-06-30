"""
Pydantic schemas for the canonical data layer.

These schemas define the contract that plugins (or any data producer)
must satisfy to write into the canonical store. They are intentionally
strict — every field has a clear purpose and the validator (see
validator.py) enforces semantic constraints beyond just types.

Note: this PluginResult is distinct from the legacy dataclass
plugins.base.PluginResult. The legacy one stays for backward
compatibility; new code should use this Pydantic version.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict, field_validator


# ─── Enums ────────────────────────────────────────────────────────────

class EntityType(str, Enum):
    """Allowed entity types. Mirror of canonical.models.ALLOWED_ENTITY_TYPES."""
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"
    WALLET = "wallet"
    BTC = "btc"
    ETH = "eth"
    HASH = "hash"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    ASN = "asn"
    MAC = "mac"
    IBAN = "iban"
    VAT = "vat"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    PERSON = "person"
    COMPANY = "company"
    IMAGE = "image"


class IdentityStatus(str, Enum):
    TENTATIVE = "tentative"
    CONFIRMED = "confirmed"
    DISPUTED = "disputed"
    MERGED = "merged"


# ─── Sub-schemas ──────────────────────────────────────────────────────

class ExtractedEntity(BaseModel):
    """
    An entity extracted by a plugin.

    `raw_value` is exactly what the plugin saw. `normalized_value` is
    optional here — if absent, the CanonicalEntityService will compute
    it via Normalizer. `confidence` is the plugin's confidence that
    this extraction is correct (0.0-1.0).
    """
    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., description="Entity type, see EntityType enum")
    raw_value: str = Field(..., min_length=1, max_length=512)
    normalized_value: Optional[str] = Field(
        None, description="Pre-normalized value; if absent, service will normalize"
    )
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    context: Optional[str] = Field(None, max_length=2000)

    @field_validator("type")
    @classmethod
    def _validate_type(cls, v: str) -> str:
        # Allow any string — the validator (validator.py) checks against
        # the canonical allowed set. This keeps the schema permissive
        # while validation is strict.
        return v.strip().lower()


class ExtractedRelationship(BaseModel):
    """
    A directed relationship between two entities.

    Either `target_entity` (inline) or `target_entity_id` (reference to
    an entity already in the same PluginResult.entities list) must be
    provided. The service resolves the reference after upserting.
    """
    model_config = ConfigDict(extra="forbid")

    source_entity_type: str = Field(..., min_length=1)
    source_entity_value: str = Field(..., min_length=1)
    target_entity_type: str = Field(..., min_length=1)
    target_entity_value: str = Field(..., min_length=1)
    relationship_type: str = Field(..., min_length=1, max_length=64)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    observed_at: Optional[datetime] = None


class Observation(BaseModel):
    """
    An atomic observation extracted from raw evidence.

    e.g. "email admin@example.com was found in field 'contact_email'".
    """
    model_config = ConfigDict(extra="forbid")

    observation_type: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)
    context: Optional[str] = Field(None, max_length=2000)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    # Optional: link this observation to one of the entities in the same result
    linked_entity_type: Optional[str] = None
    linked_entity_value: Optional[str] = None


class Evidence(BaseModel):
    """
    A piece of evidence (e.g. a URL, a screenshot hash, a file).
    Distinct from RawEvidence (the SQLAlchemy model) — this is the
    Pydantic input that gets persisted as a RawEvidence row.
    """
    model_config = ConfigDict(extra="forbid")

    source_url: Optional[str] = Field(None, max_length=2048)
    source_reliability: Optional[float] = Field(None, ge=0.0, le=1.0)
    # The immutable raw response from the source
    raw: dict = Field(default_factory=dict)
    # Post-normalization copy (may differ from raw after the service
    # normalizes entity values, strips PII, etc.)
    normalized: dict = Field(default_factory=dict)


class PluginMetrics(BaseModel):
    """Runtime metrics for a plugin execution."""
    model_config = ConfigDict(extra="forbid")

    duration_ms: int = Field(0, ge=0)
    network_bytes: int = Field(0, ge=0)
    cache_hit: bool = False
    retries: int = Field(0, ge=0)


# ─── Top-level contract ───────────────────────────────────────────────

class PluginResult(BaseModel):
    """
    The canonical output contract of every Argus plugin.

    A plugin run produces exactly one PluginResult. The validator
    (validator.py) checks structural integrity, the canonical entity
    service (services/canonical_entity.py) upserts entities, and the
    provenance service (services/provenance.py) records the evidence
    chain.

    All UUID fields accept either a pre-generated UUID string or None
    (in which case the service generates one).
    """
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(1, ge=1)
    plugin_id: str = Field(..., min_length=1, max_length=64)
    plugin_version: str = Field("0.0.0", max_length=32)
    plugin_instance: str = Field("default", max_length=64)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    execution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = Field(..., min_length=1, max_length=512)
    target_type: str = Field(..., min_length=1, max_length=32)
    executed_at: datetime
    investigation_id: str = Field(..., min_length=1, max_length=36)
    confidence: float = Field(0.5, ge=0.0, le=1.0)

    entities: list[ExtractedEntity] = Field(default_factory=list)
    relationships: list[ExtractedRelationship] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    metrics: PluginMetrics = Field(default_factory=PluginMetrics)

    # Immutable original source response (single evidence dict for
    # backward simplicity; the `evidence` list above is for multi-source).
    raw: dict = Field(default_factory=dict)
    normalized: dict = Field(default_factory=dict)

    @field_validator("target_type")
    @classmethod
    def _validate_target_type(cls, v: str) -> str:
        return v.strip().lower()


# ─── Validation result ────────────────────────────────────────────────

class ValidationError(BaseModel):
    """A single validation error."""
    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Dot-separated path to the offending field")
    message: str
    code: str = Field(..., description="Machine-readable error code, e.g. 'invalid_type'")
    severity: str = Field("error", pattern=r"^(error|warning)$")


class ValidationResult(BaseModel):
    """Result of validating a PluginResult."""
    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    errors: list[ValidationError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    sanitized_result: Optional[PluginResult] = None


# ─── Provenance chain (output of ProvenanceService.get_full_provenance) ──

class ProvenanceChain(BaseModel):
    """
    Full provenance chain for a relationship: the relationship itself,
    all supporting evidence, all supporting observations, the plugins
    that produced them, and the time range over which they were collected.
    """
    model_config = ConfigDict(extra="forbid")

    relationship_id: str
    relationship_type: str
    source_entity_id: str
    target_entity_id: str
    confidence: float
    supporting_evidence: list[dict] = Field(default_factory=list)
    supporting_observations: list[dict] = Field(default_factory=list)
    plugins: list[str] = Field(default_factory=list)
    collected_at_range: Optional[tuple[datetime, datetime]] = None


__all__ = [
    "EntityType",
    "IdentityStatus",
    "ExtractedEntity",
    "ExtractedRelationship",
    "Observation",
    "Evidence",
    "PluginMetrics",
    "PluginResult",
    "ValidationError",
    "ValidationResult",
    "ProvenanceChain",
]
