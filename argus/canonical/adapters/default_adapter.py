"""
Default legacy adapter.

Translates the legacy `plugins.base.PluginResult` dataclass (5 fields)
into the canonical `canonical.schemas.PluginResult` Pydantic model
(18 fields).

This adapter is registered for the plugin_id "default_legacy" and is
NOT used as a fallback. Plugins that want canonical ingestion must
either:
  (a) explicitly use this adapter by registering it for their plugin_id, OR
  (b) have a custom adapter written for them.

The legacy PluginResult has no entities/relationships/observations —
just an opaque `data: dict`. This adapter uses intel.entity_extractor
to pull entities out of the data dict, and produces one Observation
per top-level key in the data dict (so that the raw evidence is
queryable by field name).
"""
from __future__ import annotations

import logging
from typing import Any

from canonical.adapters.base import BaseAdapter, AdapterContext, AdapterError
from canonical.adapters.registry import registry
from canonical.schemas import (
    PluginResult as CanonicalPluginResult,
    ExtractedEntity, ExtractedRelationship,
    Observation as ObservationSchema,
)

logger = logging.getLogger("argus.adapters.default")


class DefaultLegacyAdapter(BaseAdapter):
    """
    Adapter for legacy plugins.base.PluginResult.

    Translation rules:
      - legacy.plugin_name  → context.plugin_id (must match)
      - legacy.success      → if False, set errors=[legacy.error] and skip entity extraction
      - legacy.data         → raw dict; entities extracted via intel.entity_extractor
      - legacy.error        → appended to errors list
      - One Observation per top-level key in legacy.data
      - No relationships (legacy format has no relationship info)
    """

    plugin_id = "_default_legacy"  # Private namespace; not auto-applied

    def adapt(
        self,
        legacy_result: Any,
        context: AdapterContext,
    ) -> CanonicalPluginResult:
        """
        Translate legacy PluginResult → canonical PluginResult.

        Raises AdapterError if legacy_result doesn't have the expected
        dataclass shape.
        """
        # Validate shape
        if not hasattr(legacy_result, "plugin_name") or not hasattr(legacy_result, "data"):
            raise AdapterError(
                context.plugin_id,
                f"legacy_result is not a plugins.base.PluginResult (got {type(legacy_result).__name__})",
            )

        # Verify the plugin_name matches context (defensive)
        if legacy_result.plugin_name and legacy_result.plugin_name != context.plugin_id:
            logger.debug(
                "plugin_name mismatch in adapter: legacy=%s context=%s — using context",
                legacy_result.plugin_name, context.plugin_id,
            )

        legacy_data: dict = legacy_result.data or {}
        errors: list[str] = []
        if not legacy_result.success:
            if legacy_result.error:
                errors.append(str(legacy_result.error))
            else:
                errors.append("legacy plugin returned success=False with no error")

        # Extract entities from the data dict using the regex entity_extractor
        entities = self._extract_entities(legacy_data, context)

        # Build one Observation per top-level key in the data dict.
        # This makes every field of the raw response queryable.
        observations = self._build_observations(legacy_data, context)

        return CanonicalPluginResult(
            schema_version=1,
            plugin_id=context.plugin_id,
            plugin_version=context.plugin_version,
            plugin_instance=context.plugin_instance,
            request_id=context.request_id,
            execution_id=context.execution_id,
            target=context.target,
            target_type=context.target_type,
            executed_at=context.executed_at,
            investigation_id=context.investigation_id,
            confidence=0.5,  # Default; legacy has no confidence concept
            entities=entities,
            relationships=[],  # Legacy has no relationship info
            observations=observations,
            evidence=[],  # Adapters can add Evidence entries; default none
            errors=errors,
            references=[],  # Legacy has no references
            metrics=self.make_metrics(),
            raw=legacy_data,  # Immutable original
            normalized={},  # Post-normalization copy (filled by IngestionService)
        )

    def _extract_entities(
        self,
        data: dict,
        context: AdapterContext,
    ) -> list[ExtractedEntity]:
        """Use intel.entity_extractor to pull entities from the data dict."""
        try:
            from intel.entity_extractor import extract_entities
            raw_entities = extract_entities(
                context.target, context.target_type, {"_default": data}
            )
            return [
                ExtractedEntity(
                    type=e["type"],
                    raw_value=e["value"],
                    normalized_value=None,  # Normalizer will compute
                    confidence=0.6,  # Default extraction confidence
                    context=e.get("context", "")[:2000] if isinstance(e.get("context"), str) else None,
                )
                for e in raw_entities
                if e.get("value")
            ]
        except Exception as e:
            logger.debug("entity extraction failed for %s: %s", context.plugin_id, e)
            return []

    def _build_observations(
        self,
        data: dict,
        context: AdapterContext,
    ) -> list[ObservationSchema]:
        """One Observation per top-level key in the data dict."""
        observations: list[ObservationSchema] = []
        for key, value in data.items():
            # Skip nested objects (we only want scalar observations here)
            if isinstance(value, (dict, list)):
                continue
            observations.append(ObservationSchema(
                observation_type=f"field:{key}",
                value=str(value)[:512],
                context=key,
                confidence=0.5,
            ))
        return observations


__all__ = ["DefaultLegacyAdapter"]
