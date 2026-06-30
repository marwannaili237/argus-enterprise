"""
PluginResult validator.

Validates the structural integrity, semantic correctness, and
referential consistency of a PluginResult before it enters the
canonical store. Returns a ValidationResult with sanitized_result
(if recoverable) or None (if not).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import uuid as _uuid

from pydantic import ValidationError as PydanticValidationError

from canonical.schemas import (
    PluginResult, ExtractedEntity, ExtractedRelationship, Observation,
    ValidationError, ValidationResult,
)
from canonical.models import ALLOWED_ENTITY_TYPES, ALLOWED_RELATIONSHIP_TYPES
from canonical.normalizer import Normalizer


class PluginResultValidator:
    """
    All methods are static — pure-function validator.

    Usage:
        result = PluginResult(...)
        vr = PluginResultValidator.validate_structure(result)
        if not vr.is_valid:
            log_errors(vr.errors)
    """

    # ─── Confidence range ────────────────────────────────────────────

    @staticmethod
    def validate_confidence_range(value: float) -> bool:
        """True if 0.0 <= value <= 1.0."""
        try:
            v = float(value)
        except (TypeError, ValueError):
            return False
        return 0.0 <= v <= 1.0

    # ─── Entity type ─────────────────────────────────────────────────

    @staticmethod
    def validate_entity_type(type: str) -> bool:
        """True if type is in the canonical allowed set."""
        if not type or not isinstance(type, str):
            return False
        return type.strip().lower() in ALLOWED_ENTITY_TYPES

    # ─── Relationship type ───────────────────────────────────────────

    @staticmethod
    def validate_relationship_type(rel_type: str) -> bool:
        """
        True if relationship_type is in the known set OR follows the
        custom 'x-' prefix convention (plugins may introduce custom
        relationship types via the x-namespace).
        """
        if not rel_type or not isinstance(rel_type, str):
            return False
        t = rel_type.strip().lower()
        if t in ALLOWED_RELATIONSHIP_TYPES:
            return True
        # Allow custom types under x- namespace
        if t.startswith("x-") and len(t) > 2:
            return True
        return False

    # ─── Entities ────────────────────────────────────────────────────

    @staticmethod
    def validate_entities(entities: list[ExtractedEntity]) -> list[ValidationError]:
        """
        Validate a list of ExtractedEntity objects.

        Checks:
          - type is in allowed set
          - raw_value is non-empty
          - confidence is in [0, 1]
          - normalized_value (if provided) matches the Normalizer's output
            (warning, not error — they may diverge intentionally)
        """
        errors: list[ValidationError] = []
        if not entities:
            return errors

        for i, ent in enumerate(entities):
            path = f"entities[{i}]"

            # Type check
            if not PluginResultValidator.validate_entity_type(ent.type):
                errors.append(ValidationError(
                    path=f"{path}.type",
                    message=f"Unknown entity type: {ent.type!r}",
                    code="invalid_entity_type",
                ))

            # raw_value non-empty
            if not ent.raw_value or not ent.raw_value.strip():
                errors.append(ValidationError(
                    path=f"{path}.raw_value",
                    message="raw_value must be non-empty",
                    code="empty_value",
                ))

            # Confidence range
            if not PluginResultValidator.validate_confidence_range(ent.confidence):
                errors.append(ValidationError(
                    path=f"{path}.confidence",
                    message=f"confidence {ent.confidence} out of range [0.0, 1.0]",
                    code="invalid_confidence",
                ))

            # If normalized_value provided, check it matches what Normalizer would produce
            if ent.normalized_value:
                try:
                    expected = Normalizer.normalize(ent.type, ent.raw_value)
                    if expected and ent.normalized_value != expected:
                        # This is a warning, not an error — the caller may
                        # have used a different normalization. We log it but
                        # don't reject.
                        # We'll surface it as a warning via the structure validator.
                        pass
                except Exception:
                    pass

        return errors

    # ─── Relationships ───────────────────────────────────────────────

    @staticmethod
    def validate_relationships(rels: list[ExtractedRelationship]) -> list[ValidationError]:
        """
        Validate relationships. Checks:
          - relationship_type is known or x-* prefixed
          - confidence in range
          - source and target entity types/values are non-empty
          - source != target (no self-loops unless explicitly allowed)
        """
        errors: list[ValidationError] = []
        if not rels:
            return errors

        for i, rel in enumerate(rels):
            path = f"relationships[{i}]"

            if not PluginResultValidator.validate_relationship_type(rel.relationship_type):
                errors.append(ValidationError(
                    path=f"{path}.relationship_type",
                    message=f"Unknown relationship type: {rel.relationship_type!r} "
                            f"(allowed: known types or 'x-*' namespaced)",
                    code="invalid_relationship_type",
                ))

            if not PluginResultValidator.validate_confidence_range(rel.confidence):
                errors.append(ValidationError(
                    path=f"{path}.confidence",
                    message=f"confidence {rel.confidence} out of range [0.0, 1.0]",
                    code="invalid_confidence",
                ))

            if not rel.source_entity_type or not rel.source_entity_value:
                errors.append(ValidationError(
                    path=f"{path}.source",
                    message="source_entity_type and source_entity_value required",
                    code="missing_source",
                ))

            if not rel.target_entity_type or not rel.target_entity_value:
                errors.append(ValidationError(
                    path=f"{path}.target",
                    message="target_entity_type and target_entity_value required",
                    code="missing_target",
                ))

            # Self-loop check (only if both sides parse)
            if (rel.source_entity_type == rel.target_entity_type and
                rel.source_entity_value.strip().lower() == rel.target_entity_value.strip().lower()):
                errors.append(ValidationError(
                    path=f"{path}",
                    message="Self-relationship (source == target) is not allowed",
                    code="self_relationship",
                ))

        return errors

    # ─── Observations ────────────────────────────────────────────────

    @staticmethod
    def validate_observations(observations: list[Observation]) -> list[ValidationError]:
        """Validate observations: type/value non-empty, confidence in range."""
        errors: list[ValidationError] = []
        for i, obs in enumerate(observations):
            path = f"observations[{i}]"
            if not obs.observation_type or not obs.observation_type.strip():
                errors.append(ValidationError(
                    path=f"{path}.observation_type",
                    message="observation_type must be non-empty",
                    code="empty_observation_type",
                ))
            if not obs.value or not obs.value.strip():
                errors.append(ValidationError(
                    path=f"{path}.value",
                    message="observation value must be non-empty",
                    code="empty_value",
                ))
            if not PluginResultValidator.validate_confidence_range(obs.confidence):
                errors.append(ValidationError(
                    path=f"{path}.confidence",
                    message=f"confidence {obs.confidence} out of range [0.0, 1.0]",
                    code="invalid_confidence",
                ))
        return errors

    # ─── Top-level structure ─────────────────────────────────────────

    @staticmethod
    def validate_structure(result: PluginResult) -> ValidationResult:
        """
        Full structural validation of a PluginResult.

        Returns a ValidationResult with:
          - is_valid: True if no errors (warnings don't affect this)
          - errors: list of ValidationError
          - warnings: list of human-readable warning strings
          - sanitized_result: a cleaned-up PluginResult (always present
            if is_valid, even if no changes were needed)
        """
        errors: list[ValidationError] = []
        warnings: list[str] = []

        # Schema version
        if result.schema_version != 1:
            errors.append(ValidationError(
                path="schema_version",
                message=f"Unsupported schema_version {result.schema_version}, expected 1",
                code="unsupported_schema_version",
            ))

        # Required string fields non-empty
        for field_name in ("plugin_id", "target", "target_type", "investigation_id", "execution_id", "request_id"):
            v = getattr(result, field_name, None)
            if not v or not str(v).strip():
                errors.append(ValidationError(
                    path=field_name,
                    message=f"{field_name} must be non-empty",
                    code="empty_required_field",
                ))

        # executed_at not in future
        if result.executed_at:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            # Pydantic may give us tz-aware or tz-naive; normalize
            exec_at = result.executed_at
            if hasattr(exec_at, "tzinfo") and exec_at.tzinfo is not None:
                exec_at = exec_at.replace(tzinfo=None)
            if exec_at > now + _ALLOWED_FUTURE_SKEW:
                errors.append(ValidationError(
                    path="executed_at",
                    message=f"executed_at {exec_at} is too far in the future",
                    code="future_timestamp",
                ))

        # Confidence
        if not PluginResultValidator.validate_confidence_range(result.confidence):
            errors.append(ValidationError(
                path="confidence",
                message=f"top-level confidence {result.confidence} out of range [0.0, 1.0]",
                code="invalid_confidence",
            ))

        # Validate UUID-format fields
        for field_name in ("request_id", "execution_id"):
            v = getattr(result, field_name, None)
            if v:
                try:
                    _uuid.UUID(str(v))
                except (ValueError, AttributeError):
                    errors.append(ValidationError(
                        path=field_name,
                        message=f"{field_name} is not a valid UUID: {v!r}",
                        code="invalid_uuid",
                    ))

        # Sub-collection validation
        errors.extend(PluginResultValidator.validate_entities(result.entities))
        errors.extend(PluginResultValidator.validate_relationships(result.relationships))
        errors.extend(PluginResultValidator.validate_observations(result.observations))

        # Cross-collection consistency: observation.linked_entity_* should
        # match an entity in result.entities
        if result.observations and result.entities:
            entity_keys = {
                (e.type, e.raw_value.strip().lower()) for e in result.entities
            }
            for i, obs in enumerate(result.observations):
                if obs.linked_entity_type and obs.linked_entity_value:
                    key = (obs.linked_entity_type, obs.linked_entity_value.strip().lower())
                    if key not in entity_keys:
                        warnings.append(
                            f"observations[{i}].linked_entity ({obs.linked_entity_type}/"
                            f"{obs.linked_entity_value}) not found in entities list"
                        )

        # Sanitize: normalize entity values if not already normalized
        sanitized: Optional[PluginResult] = None
        if not errors:
            sanitized = PluginResultValidator._sanitize(result, warnings)

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_result=sanitized,
        )

    # ─── Sanitization ────────────────────────────────────────────────

    @staticmethod
    def _sanitize(result: PluginResult, warnings: list[str]) -> PluginResult:
        """
        Produce a sanitized copy:
          - For each entity, if normalized_value is missing or doesn't
            match Normalizer's output, set it to the Normalizer's output
            and emit a warning.
          - Strip leading/trailing whitespace from all string fields.
        """
        # Deep-copy via Pydantic
        sanitized = result.model_copy(deep=True)

        for i, ent in enumerate(sanitized.entities):
            expected = Normalizer.normalize(ent.type, ent.raw_value)
            if not expected:
                continue
            if ent.normalized_value and ent.normalized_value != expected:
                warnings.append(
                    f"entities[{i}].normalized_value {ent.normalized_value!r} "
                    f"overridden by Normalizer output {expected!r}"
                )
            ent.normalized_value = expected

        # Strip whitespace from string fields
        sanitized.plugin_id = sanitized.plugin_id.strip()
        sanitized.target = sanitized.target.strip()
        sanitized.target_type = sanitized.target_type.strip().lower()
        sanitized.investigation_id = str(sanitized.investigation_id).strip()

        return sanitized


# ─── Module-level constants ──────────────────────────────────────────

# Allow executed_at to be up to 5 minutes in the future (clock skew)
_ALLOWED_FUTURE_SKEW = _ALLOWED_FUTURE_SKEW_TD = __import__("datetime").timedelta(minutes=5)


__all__ = ["PluginResultValidator"]
