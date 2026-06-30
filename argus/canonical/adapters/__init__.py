"""
Canonical adapter framework.

Public API:
  - BaseAdapter, AdapterContext, AdapterError  (base.py)
  - AdapterRegistry, registry                  (registry.py)
  - DefaultLegacyAdapter                        (default_adapter.py)
  - GoldenFixture, load_fixture, ...           (fixtures.py)
  - ComplianceReport, compliance_check_all     (compliance.py)
  - PluginHealthTracker, health_tracker        (health.py)
  - register_default_adapters                  (this module)

Registration model:
  - Adapters are NOT auto-registered. Per the architecture spec,
    "no fallback adapters" — each plugin_id must have an explicit
    adapter registered at startup.
  - register_default_adapters() registers the DefaultLegacyAdapter
    for a curated list of plugin_ids that have opted into canonical
    ingestion. Call this once at app startup (after importing the
    adapter framework).
"""
from canonical.adapters.base import BaseAdapter, AdapterContext, AdapterError
from canonical.adapters.registry import AdapterRegistry, registry
from canonical.adapters.default_adapter import DefaultLegacyAdapter
from canonical.adapters.fixtures import (
    GoldenFixture, FixtureDiff, FixtureCheckResult,
    load_fixture, load_fixtures_dir, diff_canonical_results,
    FIXTURE_SCHEMA_VERSION,
)
from canonical.adapters.compliance import (
    ComplianceReport,
    compliance_check_fixture,
    compliance_check_plugin,
    compliance_check_all,
)
from canonical.adapters.health import (
    FailureKind, PluginStatus, FailureEvent, PluginHealthRecord,
    PluginHealthTracker, health_tracker,
    classify_exception,
)


# Plugins that have opted into canonical ingestion via the DefaultLegacyAdapter.
# Each entry is a legacy plugin_id whose output shape is compatible with the
# default adapter (opaque `data: dict` that entity_extractor can parse).
# New plugins with custom output shapes should write their own adapter and
# register it explicitly.
DEFAULT_ADAPTED_PLUGINS: frozenset[str] = frozenset({
    "whois", "dns", "certs", "ip_geo", "http", "shodan", "wayback",
    "bgp", "reputation", "subdomains", "passive_dns", "pastes",
    "github_osint", "email", "breach", "social_email", "username",
    "profile", "entity", "phone", "crypto_tracer",
})


def register_default_adapters(
    plugin_ids: frozenset[str] = DEFAULT_ADAPTED_PLUGINS,
    *,
    overwrite: bool = False,
) -> int:
    """
    Register the DefaultLegacyAdapter for each plugin_id in plugin_ids.

    Call this ONCE at app startup, after importing the adapter framework.
    Returns the number of adapters registered.

    This is explicit, not auto-discovery — the caller controls which
    plugins get canonical ingestion. Plugins not in the list are
    skipped (their results never enter the canonical store).
    """
    count = 0
    for plugin_id in plugin_ids:
        if registry.is_registered(plugin_id):
            continue
        adapter = DefaultLegacyAdapter()
        # Override the plugin_id on the instance (the class default is _default_legacy)
        adapter.plugin_id = plugin_id
        registry.register(adapter, overwrite=overwrite)
        count += 1
    return count


__all__ = [
    # base
    "BaseAdapter", "AdapterContext", "AdapterError",
    # registry
    "AdapterRegistry", "registry",
    # default adapter
    "DefaultLegacyAdapter", "DEFAULT_ADAPTED_PLUGINS", "register_default_adapters",
    # fixtures
    "GoldenFixture", "FixtureDiff", "FixtureCheckResult",
    "load_fixture", "load_fixtures_dir", "diff_canonical_results",
    "FIXTURE_SCHEMA_VERSION",
    # compliance
    "ComplianceReport",
    "compliance_check_fixture", "compliance_check_plugin", "compliance_check_all",
    # health
    "FailureKind", "PluginStatus", "FailureEvent", "PluginHealthRecord",
    "PluginHealthTracker", "health_tracker",
    "classify_exception",
]
