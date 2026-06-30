"""
Explicit adapter registry.

Rules (from architecture spec):
  - No fallback adapters. If a plugin_id has no registered adapter,
    ingestion is skipped for that plugin.
  - No auto-discovery. Adapters must be registered explicitly at
    startup via register().
  - One adapter per plugin_id. Re-registering overwrites (with a warning).
  - get() returns the adapter or raises — never returns None silently.

This is a module-level singleton. Registration happens at import time
of canonical.adapters.__init__ (which imports default_adapter, which
registers itself).
"""
from __future__ import annotations

import logging
from typing import Dict, Iterator, Optional

from canonical.adapters.base import BaseAdapter

logger = logging.getLogger("argus.adapters.registry")


class AdapterRegistry:
    """
    Singleton registry. Access via the module-level `registry` instance.

    Thread-safe for read operations (dict lookups). Registration should
    happen at import time, before any async work begins.
    """

    def __init__(self) -> None:
        self._adapters: Dict[str, BaseAdapter] = {}

    def register(self, adapter: BaseAdapter, *, overwrite: bool = False) -> None:
        """
        Register an adapter. The adapter's plugin_id must be non-empty
        and unique unless overwrite=True.
        """
        if not adapter.plugin_id:
            raise ValueError(f"Adapter {type(adapter).__name__} has empty plugin_id")
        if adapter.plugin_id in self._adapters:
            if not overwrite:
                existing = type(self._adapters[adapter.plugin_id]).__name__
                raise ValueError(
                    f"Adapter already registered for plugin_id={adapter.plugin_id!r} "
                    f"(existing={existing}, new={type(adapter).__name__}). "
                    f"Pass overwrite=True to replace."
                )
            logger.warning(
                "Overwriting adapter for plugin_id=%s (old=%s, new=%s)",
                adapter.plugin_id,
                type(self._adapters[adapter.plugin_id]).__name__,
                type(adapter).__name__,
            )
        self._adapters[adapter.plugin_id] = adapter
        logger.debug("Registered adapter for plugin_id=%s (%s)",
                     adapter.plugin_id, type(adapter).__name__)

    def get(self, plugin_id: str) -> BaseAdapter:
        """
        Return the adapter for plugin_id.

        Raises KeyError if none registered. Callers MUST handle this
        and skip ingestion for that plugin (do NOT fall back to a
        default adapter — that would violate the no-fallback rule).
        """
        if plugin_id not in self._adapters:
            raise KeyError(
                f"No adapter registered for plugin_id={plugin_id!r}. "
                f"Ingestion will be skipped for this plugin."
            )
        return self._adapters[plugin_id]

    def try_get(self, plugin_id: str) -> Optional[BaseAdapter]:
        """Return adapter or None. Use when skipping is acceptable."""
        return self._adapters.get(plugin_id)

    def is_registered(self, plugin_id: str) -> bool:
        return plugin_id in self._adapters

    def list_registered(self) -> list[str]:
        """Return sorted list of registered plugin_ids."""
        return sorted(self._adapters.keys())

    def clear(self) -> None:
        """Remove all registrations. Test-only."""
        self._adapters.clear()

    def __iter__(self) -> Iterator[tuple[str, BaseAdapter]]:
        return iter(self._adapters.items())

    def __len__(self) -> int:
        return len(self._adapters)


# Module-level singleton
registry: AdapterRegistry = AdapterRegistry()


__all__ = ["AdapterRegistry", "registry"]
