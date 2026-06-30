"""
Plugin health tracker — classifies failures as transient or structural,
quarantines plugins after repeated structural failures.

Failure classification:
  TRANSIENT (does NOT affect health):
    - asyncio.TimeoutError
    - aiohttp.ClientResponseError with status 429, 500, 502, 503, 504
    - aiohttp.ClientConnectorError (connection reset, DNS failure)
    - ConnectionError, OSError (network down)

  STRUCTURAL (affects health):
    - AdapterError (adapter couldn't translate the result)
    - Pydantic ValidationError (schema mismatch)
    - FixtureCheckResult.failed (golden fixture regression)
    - KeyError/AttributeError on expected fields (mapping failure)

Quarantine:
  After QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD structural failures
  within QUARANTINE_WINDOW_HOURS, the plugin is quarantined. A
  quarantined plugin's results are NOT ingested (skipped with a log).

  Quarantine is per-plugin_id, per-instance (in-memory). Restart clears
  quarantine — a human should investigate before re-enabling.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional

from canonical import confidence as conf

logger = logging.getLogger("argus.adapters.health")


class FailureKind(str, Enum):
    TRANSIENT = "transient"
    STRUCTURAL = "structural"


class PluginStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"


@dataclass
class FailureEvent:
    """A single recorded failure."""
    plugin_id: str
    kind: FailureKind
    timestamp: datetime
    message: str
    cause_type: Optional[str] = None  # e.g. "asyncio.TimeoutError"


@dataclass
class PluginHealthRecord:
    """In-memory health record for one plugin."""
    plugin_id: str
    status: PluginStatus = PluginStatus.ACTIVE
    structural_failures: deque[FailureEvent] = field(default_factory=deque)
    transient_failures: deque[FailureEvent] = field(default_factory=deque)
    total_runs: int = 0
    successful_runs: int = 0
    quarantined_at: Optional[datetime] = None

    @property
    def success_rate(self) -> float:
        if self.total_runs == 0:
            return 0.0
        return self.successful_runs / self.total_runs

    def __repr__(self) -> str:
        return (
            f"<PluginHealthRecord plugin_id={self.plugin_id!r} "
            f"status={self.status.value} runs={self.total_runs} "
            f"structural={len(self.structural_failures)} "
            f"transient={len(self.transient_failures)}>"
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _quarantine_cutoff() -> datetime:
    return _utcnow() - timedelta(hours=conf.QUARANTINE_WINDOW_HOURS)


# ─── Exception classification ─────────────────────────────────────────

# Structural exception types (by class name — string match for cross-import safety)
_STRUCTURAL_EXCEPTION_TYPES: frozenset[str] = frozenset({
    "AdapterError",
    "ValidationError",  # Pydantic
    "KeyError",
    "AttributeError",
    "TypeError",
    "ValueError",  # When raised by validator/mapper
})

# Transient exception types
_TRANSIENT_EXCEPTION_TYPES: frozenset[str] = frozenset({
    "TimeoutError",
    "asyncio.TimeoutError",
    "ClientConnectorError",
    "ClientResponseError",
    "ClientError",
    "ConnectionError",
    "OSError",
    "ServerDisconnectedError",
})

# HTTP status codes that count as transient
_TRANSIENT_HTTP_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})


def classify_exception(exc: Exception) -> FailureKind:
    """
    Classify an exception as transient or structural.

    Deterministic: same exception class + same status code → same kind.
    """
    exc_type_name = type(exc).__name__

    # Check structural first (explicit)
    if exc_type_name in _STRUCTURAL_EXCEPTION_TYPES:
        return FailureKind.STRUCTURAL

    # Check transient
    if exc_type_name in _TRANSIENT_EXCEPTION_TYPES:
        return FailureKind.TRANSIENT

    # aiohttp ClientResponseError has a `status` attribute
    status = getattr(exc, "status", None) or getattr(exc, "code", None)
    if isinstance(status, int) and status in _TRANSIENT_HTTP_STATUSES:
        return FailureKind.TRANSIENT

    # Default: structural (safer to quarantine than to silently retry)
    # This is intentional — unknown failures should be investigated, not hidden.
    return FailureKind.STRUCTURAL


# ─── Health tracker ───────────────────────────────────────────────────

class PluginHealthTracker:
    """
    In-memory plugin health tracker.

    Not persisted — on restart, all plugins start fresh (active).
    A human should investigate quarantined plugins before re-enabling.
    """

    def __init__(self) -> None:
        self._records: dict[str, PluginHealthRecord] = {}

    def get_or_create(self, plugin_id: str) -> PluginHealthRecord:
        if plugin_id not in self._records:
            self._records[plugin_id] = PluginHealthRecord(plugin_id=plugin_id)
        return self._records[plugin_id]

    def record_success(self, plugin_id: str) -> None:
        rec = self.get_or_create(plugin_id)
        rec.total_runs += 1
        rec.successful_runs += 1

    def record_failure(
        self,
        plugin_id: str,
        exc: Exception,
        *,
        message: Optional[str] = None,
    ) -> FailureKind:
        """
        Record a failure. Returns the kind (transient/structural).

        If structural and the threshold is met within the window,
        the plugin is quarantined.
        """
        kind = classify_exception(exc)
        rec = self.get_or_create(plugin_id)
        rec.total_runs += 1

        event = FailureEvent(
            plugin_id=plugin_id,
            kind=kind,
            timestamp=_utcnow(),
            message=message or str(exc),
            cause_type=type(exc).__name__,
        )

        if kind == FailureKind.TRANSIENT:
            rec.transient_failures.append(event)
        else:
            rec.structural_failures.append(event)
            self._maybe_quarantine(rec)

        return kind

    def _maybe_quarantine(self, record: PluginHealthRecord) -> None:
        """Check if the plugin should be quarantined based on recent structural failures."""
        if record.status == PluginStatus.QUARANTINED:
            return

        cutoff = _quarantine_cutoff()
        # Drop old failures outside the window
        while record.structural_failures and record.structural_failures[0].timestamp < cutoff:
            record.structural_failures.popleft()

        if len(record.structural_failures) >= conf.QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD:
            record.status = PluginStatus.QUARANTINED
            record.quarantined_at = _utcnow()
            logger.warning(
                "Plugin %s QUARANTINED after %d structural failures in %d hours",
                record.plugin_id,
                len(record.structural_failures),
                conf.QUARANTINE_WINDOW_HOURS,
            )

    def is_quarantined(self, plugin_id: str) -> bool:
        return self.get_or_create(plugin_id).status == PluginStatus.QUARANTINED

    def status(self, plugin_id: str) -> PluginStatus:
        return self.get_or_create(plugin_id).status

    def reactivate(self, plugin_id: str) -> None:
        """
        Manually re-enable a quarantined plugin. Clears the failure history
        so the plugin starts fresh.
        """
        rec = self.get_or_create(plugin_id)
        rec.status = PluginStatus.ACTIVE
        rec.quarantined_at = None
        rec.structural_failures.clear()
        rec.transient_failures.clear()
        logger.info("Plugin %s reactivated (manual override)", plugin_id)

    def get_record(self, plugin_id: str) -> Optional[PluginHealthRecord]:
        return self._records.get(plugin_id)

    def all_records(self) -> dict[str, PluginHealthRecord]:
        return dict(self._records)

    def clear(self) -> None:
        """Test-only: clear all records."""
        self._records.clear()


# Module-level singleton
health_tracker: PluginHealthTracker = PluginHealthTracker()


__all__ = [
    "FailureKind", "PluginStatus", "FailureEvent", "PluginHealthRecord",
    "PluginHealthTracker", "health_tracker",
    "classify_exception",
]
