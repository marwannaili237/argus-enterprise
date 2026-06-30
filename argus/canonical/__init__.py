"""
Canonical data layer for Argus.

This package provides:
  - models: SQLAlchemy 2.0 async models for canonical entities, identities,
    raw evidence, observations, relationships, and provenance
  - schemas: Pydantic schemas (PluginResult contract)
  - normalizer: entity value normalization (email, domain, phone, ...)
  - validator: PluginResult structural + semantic validation
  - services: CanonicalEntityService and ProvenanceService

All new code — does not touch existing investigation or plugin runner code.
"""
from canonical import models, schemas, normalizer, validator
from canonical.services.canonical_entity import CanonicalEntityService
from canonical.services.provenance import ProvenanceService

__all__ = [
    "models",
    "schemas",
    "normalizer",
    "validator",
    "CanonicalEntityService",
    "ProvenanceService",
]
