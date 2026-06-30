"""
Adapter base — the contract every adapter must implement.

An adapter translates the OUTPUT of a specific plugin (the legacy
`plugins.base.PluginResult` dataclass) into the canonical
`canonical.schemas.PluginResult` Pydantic model that the ingestion
pipeline consumes.

One adapter per plugin_id. No fallback. If no adapter is registered
for a plugin_id, ingestion is SKIPPED for that plugin (with a logged
warning) — never silently auto-translated.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

from canonical.schemas import (
    PluginResult as CanonicalPluginResult,
    ExtractedEntity, ExtractedRelationship,
    Observation as ObservationSchema,
    Evidence as EvidenceSchema,
    PluginMetrics,
)


@dataclass
class AdapterContext:
    """
    Context passed to every adapter.adapt() call.

    Provides the metadata the adapter needs to construct a valid
    canonical PluginResult, without the adapter having to know about
    the investigation model.
    """
    plugin_id: str
    plugin_version: str
    plugin_instance: str = "default"
    investigation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    target_type: str = ""
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseAdapter(ABC):
    """
    Abstract base for all plugin adapters.

    Subclasses MUST set `plugin_id` (the legacy plugin name, matching
    `BasePlugin.name`) and implement `adapt()`.

    The adapter must be DETERMINISTIC: given the same legacy result
    and context, it must produce the same canonical result. No random
    IDs (use the request_id/execution_id from context), no time-of-day
    logic, no environment-dependent branches.
    """

    #: The legacy plugin_id this adapter handles. Must match exactly
    #: one entry in the registry.
    plugin_id: str = ""

    @abstractmethod
    def adapt(
        self,
        legacy_result: Any,
        context: AdapterContext,
    ) -> CanonicalPluginResult:
        """
        Translate a legacy plugin result into a canonical PluginResult.

        Args:
            legacy_result: the output of BasePlugin.run() — typically
                the plugins.base.PluginResult dataclass
            context: AdapterContext with investigation/execution metadata

        Returns:
            A canonical.schemas.PluginResult. Will be validated by
            PluginResultValidator before ingestion.

        Raises:
            AdapterError: if the legacy result cannot be translated.
                This is a STRUCTURAL failure (will affect plugin health).
        """
        ...

    @staticmethod
    def make_evidence(
        raw: dict,
        source_url: Optional[str] = None,
        source_reliability: Optional[float] = None,
    ) -> EvidenceSchema:
        """Helper for adapters to build an Evidence schema."""
        return EvidenceSchema(
            source_url=source_url,
            source_reliability=source_reliability,
            raw=raw or {},
            normalized={},
        )

    @staticmethod
    def make_metrics(
        duration_ms: int = 0,
        network_bytes: int = 0,
        cache_hit: bool = False,
        retries: int = 0,
    ) -> PluginMetrics:
        """Helper for adapters to build PluginMetrics."""
        return PluginMetrics(
            duration_ms=duration_ms,
            network_bytes=network_bytes,
            cache_hit=cache_hit,
            retries=retries,
        )


class AdapterError(Exception):
    """Raised when an adapter cannot translate a legacy result. Structural failure."""

    def __init__(self, plugin_id: str, message: str, *, cause: Optional[Exception] = None):
        self.plugin_id = plugin_id
        self.cause = cause
        super().__init__(f"[adapter:{plugin_id}] {message}")


__all__ = ["BaseAdapter", "AdapterContext", "AdapterError"]
