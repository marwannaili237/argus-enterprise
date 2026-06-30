"""
Unit tests for the PluginResultValidator.

Covers: confidence range, entity type, relationship type, structure,
sanitization, warnings, and edge cases (empty collections, future
timestamps, invalid UUIDs, self-relationships).
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.schemas import (
    PluginResult, ExtractedEntity, ExtractedRelationship,
    Observation as ObservationSchema, PluginMetrics, Evidence,
)
from canonical.validator import PluginResultValidator


class TestValidateConfidenceRange:
    def test_zero_is_valid(self):
        assert PluginResultValidator.validate_confidence_range(0.0) is True

    def test_one_is_valid(self):
        assert PluginResultValidator.validate_confidence_range(1.0) is True

    def test_half_is_valid(self):
        assert PluginResultValidator.validate_confidence_range(0.5) is True

    def test_negative_is_invalid(self):
        assert PluginResultValidator.validate_confidence_range(-0.1) is False

    def test_above_one_is_invalid(self):
        assert PluginResultValidator.validate_confidence_range(1.1) is False

    def test_non_numeric_is_invalid(self):
        assert PluginResultValidator.validate_confidence_range("high") is False
        assert PluginResultValidator.validate_confidence_range(None) is False


class TestValidateEntityType:
    def test_known_types(self):
        for t in ("email", "domain", "ip", "username", "phone", "url", "btc", "cve"):
            assert PluginResultValidator.validate_entity_type(t) is True, f"{t} should be valid"

    def test_unknown_type(self):
        assert PluginResultValidator.validate_entity_type("foo") is False

    def test_case_insensitive(self):
        assert PluginResultValidator.validate_entity_type("EMAIL") is True
        assert PluginResultValidator.validate_entity_type("Email") is True

    def test_empty(self):
        assert PluginResultValidator.validate_entity_type("") is False
        assert PluginResultValidator.validate_entity_type(None) is False


class TestValidateRelationshipType:
    def test_known_types(self):
        for t in ("owns", "uses", "same_person", "hosted_on", "resolves_to"):
            assert PluginResultValidator.validate_relationship_type(t) is True

    def test_custom_x_namespaced(self):
        assert PluginResultValidator.validate_relationship_type("x-custom-rel") is True
        assert PluginResultValidator.validate_relationship_type("x-found-with") is True

    def test_unknown_type_rejected(self):
        assert PluginResultValidator.validate_relationship_type("random_relation") is False

    def test_empty(self):
        assert PluginResultValidator.validate_relationship_type("") is False
        assert PluginResultValidator.validate_relationship_type(None) is False

    def test_x_alone_rejected(self):
        # "x-" alone (no name) should be rejected
        assert PluginResultValidator.validate_relationship_type("x-") is False


class TestValidateEntities:
    def test_valid_entities(self):
        entities = [
            ExtractedEntity(type="email", raw_value="user@example.com", confidence=0.9),
            ExtractedEntity(type="domain", raw_value="example.com", confidence=0.8),
        ]
        errors = PluginResultValidator.validate_entities(entities)
        assert errors == []

    def test_unknown_entity_type(self):
        entities = [ExtractedEntity(type="foo", raw_value="bar", confidence=0.5)]
        errors = PluginResultValidator.validate_entities(entities)
        assert len(errors) == 1
        assert errors[0].code == "invalid_entity_type"

    def test_empty_raw_value(self):
        # Use model_construct to bypass Pydantic validation so we can test
        # the validator's handling of empty raw_value
        ent = ExtractedEntity.model_construct(type="email", raw_value="", confidence=0.5)
        errors = PluginResultValidator.validate_entities([ent])
        assert len(errors) == 1
        assert errors[0].code == "empty_value"

    def test_whitespace_only_raw_value(self):
        entities = [ExtractedEntity(type="email", raw_value="   ", confidence=0.5)]
        errors = PluginResultValidator.validate_entities(entities)
        assert any(e.code == "empty_value" for e in errors)

    def test_invalid_confidence(self):
        # Use model_construct to bypass Pydantic's [0,1] range check
        ent = ExtractedEntity.model_construct(type="email", raw_value="x@y.z", confidence=1.5)
        errors = PluginResultValidator.validate_entities([ent])
        assert any(e.code == "invalid_confidence" for e in errors)

    def test_empty_list_is_valid(self):
        assert PluginResultValidator.validate_entities([]) == []


class TestValidateRelationships:
    def test_valid_relationship(self):
        rels = [
            ExtractedRelationship(
                source_entity_type="domain",
                source_entity_value="example.com",
                target_entity_type="ip",
                target_entity_value="1.2.3.4",
                relationship_type="resolves_to",
                confidence=0.8,
            ),
        ]
        errors = PluginResultValidator.validate_relationships(rels)
        assert errors == []

    def test_self_relationship_rejected(self):
        rels = [
            ExtractedRelationship(
                source_entity_type="domain",
                source_entity_value="example.com",
                target_entity_type="domain",
                target_entity_value="example.com",
                relationship_type="same_as",
                confidence=0.5,
            ),
        ]
        errors = PluginResultValidator.validate_relationships(rels)
        assert any(e.code == "self_relationship" for e in errors)

    def test_unknown_relationship_type_warns_but_custom_ok(self):
        rels = [
            ExtractedRelationship(
                source_entity_type="domain",
                source_entity_value="a.com",
                target_entity_type="ip",
                target_entity_value="1.2.3.4",
                relationship_type="random_thing",
                confidence=0.5,
            ),
        ]
        errors = PluginResultValidator.validate_relationships(rels)
        assert any(e.code == "invalid_relationship_type" for e in errors)

    def test_missing_source(self):
        # Use model_construct to bypass Pydantic's min_length=1 check
        rel = ExtractedRelationship.model_construct(
            source_entity_type="",
            source_entity_value="",
            target_entity_type="ip",
            target_entity_value="1.2.3.4",
            relationship_type="resolves_to",
            confidence=0.5,
        )
        errors = PluginResultValidator.validate_relationships([rel])
        assert any(e.code == "missing_source" for e in errors)


class TestValidateStructure:
    def _make_valid_result(self) -> PluginResult:
        return PluginResult(
            plugin_id="whois",
            plugin_version="1.0.0",
            target="example.com",
            target_type="domain",
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
            confidence=0.8,
            entities=[
                ExtractedEntity(type="domain", raw_value="example.com", confidence=0.9),
            ],
            relationships=[],
            observations=[],
            metrics=PluginMetrics(duration_ms=100),
            raw={"source": "test"},
            normalized={},
        )

    def test_valid_result_passes(self):
        result = self._make_valid_result()
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid
        assert vr.errors == []
        assert vr.sanitized_result is not None

    def test_unsupported_schema_version(self):
        result = self._make_valid_result()
        result.schema_version = 2
        vr = PluginResultValidator.validate_structure(result)
        assert not vr.is_valid
        assert any(e.code == "unsupported_schema_version" for e in vr.errors)

    def test_empty_plugin_id(self):
        result = self._make_valid_result()
        result.plugin_id = ""
        vr = PluginResultValidator.validate_structure(result)
        assert not vr.is_valid
        assert any(e.code == "empty_required_field" for e in vr.errors)

    def test_future_timestamp_rejected(self):
        result = self._make_valid_result()
        # 1 hour in the future
        result.executed_at = datetime.now(timezone.utc) + timedelta(hours=1)
        vr = PluginResultValidator.validate_structure(result)
        assert not vr.is_valid
        assert any(e.code == "future_timestamp" for e in vr.errors)

    def test_invalid_request_id_uuid(self):
        result = self._make_valid_result()
        result.request_id = "not-a-uuid"
        vr = PluginResultValidator.validate_structure(result)
        assert not vr.is_valid
        assert any(e.code == "invalid_uuid" for e in vr.errors)

    def test_invalid_confidence(self):
        result = self._make_valid_result()
        result.confidence = 1.5
        vr = PluginResultValidator.validate_structure(result)
        assert not vr.is_valid
        assert any(e.code == "invalid_confidence" for e in vr.errors)

    def test_sanitized_result_has_normalized_values(self):
        result = self._make_valid_result()
        # Don't set normalized_value on the entity — sanitizer should set it
        result.entities[0].normalized_value = None
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid
        assert vr.sanitized_result is not None
        assert vr.sanitized_result.entities[0].normalized_value == "example.com"

    def test_sanitizer_overrides_mismatched_normalized_value(self):
        result = self._make_valid_result()
        result.entities[0].normalized_value = "WRONG"
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid
        # Should have a warning about the override
        assert any("overridden" in w for w in vr.warnings)
        assert vr.sanitized_result.entities[0].normalized_value == "example.com"

    def test_observation_linked_entity_not_in_entities_warns(self):
        result = self._make_valid_result()
        result.observations = [
            ObservationSchema(
                observation_type="extracted_email",
                value="admin@example.com",
                confidence=0.7,
                linked_entity_type="email",
                linked_entity_value="admin@example.com",  # Not in entities list
            ),
        ]
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid  # warnings don't fail validation
        assert any("not found in entities list" in w for w in vr.warnings)

    def test_empty_collections_are_valid(self):
        result = self._make_valid_result()
        result.entities = []
        result.relationships = []
        result.observations = []
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid


class TestSanitizationSideEffects:
    def test_target_type_lowercased(self):
        result = PluginResult(
            plugin_id="whois",
            target="example.com",
            target_type="DOMAIN",  # uppercase
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
        )
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid
        assert vr.sanitized_result.target_type == "domain"

    def test_whitespace_stripped_from_strings(self):
        result = PluginResult(
            plugin_id="  whois  ",
            target="  example.com  ",
            target_type="domain",
            executed_at=datetime.now(timezone.utc),
            investigation_id=str(uuid.uuid4()),
        )
        vr = PluginResultValidator.validate_structure(result)
        assert vr.is_valid
        assert vr.sanitized_result.plugin_id == "whois"
        assert vr.sanitized_result.target == "example.com"
