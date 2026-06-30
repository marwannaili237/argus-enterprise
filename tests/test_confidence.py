"""
Tests for canonical.confidence — centralized signal tiers and thresholds.

Verifies determinism, tier classification, weight lookup, and env-var override.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical import confidence
from canonical.confidence import (
    TIER_1_TYPES, TIER_2_TYPES, TIER_3_TYPES,
    TIER_1_WEIGHT, TIER_2_WEIGHT, TIER_3_WEIGHT,
    IDENTITY_PROMOTION_THRESHOLD, IDENTITY_DISPUTE_THRESHOLD,
    QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD, QUARANTINE_WINDOW_HOURS,
    INGESTION_MAX_ENTITIES_PER_CALL, INGESTION_MAX_OBSERVATIONS_PER_CALL,
    INGESTION_MAX_RELATIONSHIPS_PER_CALL,
    signal_weight_for_type, tier_for_type, EvidenceSource,
)


class TestSignalTiers:
    def test_tier1_contains_email(self):
        assert "email" in TIER_1_TYPES

    def test_tier1_contains_phone(self):
        assert "phone" in TIER_1_TYPES

    def test_tier1_contains_wallet_types(self):
        assert "btc" in TIER_1_TYPES
        assert "eth" in TIER_1_TYPES
        assert "wallet" in TIER_1_TYPES

    def test_tier1_contains_pgp(self):
        assert "pgp_fingerprint" in TIER_1_TYPES

    def test_tier2_contains_username(self):
        assert "username" in TIER_2_TYPES

    def test_tier2_contains_avatar_hash(self):
        assert "avatar_hash" in TIER_2_TYPES

    def test_tier3_contains_display_name(self):
        assert "display_name" in TIER_3_TYPES

    def test_tier3_contains_city_company(self):
        assert "city" in TIER_3_TYPES
        assert "company" in TIER_3_TYPES

    def test_no_overlap_between_tiers(self):
        assert TIER_1_TYPES.isdisjoint(TIER_2_TYPES)
        assert TIER_1_TYPES.isdisjoint(TIER_3_TYPES)
        assert TIER_2_TYPES.isdisjoint(TIER_3_TYPES)


class TestTierForType:
    @pytest.mark.parametrize("t", sorted(TIER_1_TYPES))
    def test_tier1_returns_1(self, t):
        assert tier_for_type(t) == 1

    @pytest.mark.parametrize("t", sorted(TIER_2_TYPES))
    def test_tier2_returns_2(self, t):
        assert tier_for_type(t) == 2

    @pytest.mark.parametrize("t", sorted(TIER_3_TYPES))
    def test_tier3_returns_3(self, t):
        assert tier_for_type(t) == 3

    def test_unknown_type_returns_3(self):
        assert tier_for_type("unknown_type") == 3

    def test_case_insensitive(self):
        assert tier_for_type("EMAIL") == 1
        assert tier_for_type("Email") == 1

    def test_empty_returns_3(self):
        assert tier_for_type("") == 3
        assert tier_for_type(None) == 3


class TestSignalWeightForType:
    def test_tier1_returns_tier1_weight(self):
        assert signal_weight_for_type("email") == TIER_1_WEIGHT

    def test_tier2_returns_tier2_weight(self):
        assert signal_weight_for_type("username") == TIER_2_WEIGHT

    def test_tier3_returns_tier3_weight(self):
        assert signal_weight_for_type("city") == TIER_3_WEIGHT

    def test_unknown_returns_tier3_weight(self):
        assert signal_weight_for_type("unknown") == TIER_3_WEIGHT

    def test_deterministic(self):
        """Same input always returns same output."""
        for t in ["email", "phone", "username", "city", "unknown"]:
            w1 = signal_weight_for_type(t)
            w2 = signal_weight_for_type(t)
            assert w1 == w2

    def test_weights_ordered_tier1_strongest(self):
        assert TIER_1_WEIGHT > TIER_2_WEIGHT > TIER_3_WEIGHT


class TestThresholds:
    def test_promotion_threshold_in_range(self):
        assert 0.0 < IDENTITY_PROMOTION_THRESHOLD <= 1.0

    def test_dispute_threshold_below_promotion(self):
        assert IDENTITY_DISPUTE_THRESHOLD < IDENTITY_PROMOTION_THRESHOLD

    def test_quarantine_threshold_positive(self):
        assert QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD > 0

    def test_quarantine_window_positive(self):
        assert QUARANTINE_WINDOW_HOURS > 0


class TestIngestionCaps:
    def test_entity_cap_positive(self):
        assert INGESTION_MAX_ENTITIES_PER_CALL > 0

    def test_observation_cap_positive(self):
        assert INGESTION_MAX_OBSERVATIONS_PER_CALL > 0

    def test_relationship_cap_positive(self):
        assert INGESTION_MAX_RELATIONSHIPS_PER_CALL > 0

    def test_observation_cap_larger_than_entity_cap(self):
        """Observations tend to be more numerous than entities."""
        assert INGESTION_MAX_OBSERVATIONS_PER_CALL >= INGESTION_MAX_ENTITIES_PER_CALL


class TestEvidenceSource:
    def test_equality_same_plugin_same_source(self):
        a = EvidenceSource(plugin_id="whois", source_url="https://rdap.org")
        b = EvidenceSource(plugin_id="whois", source_url="https://rdap.org")
        assert a == b
        assert hash(a) == hash(b)

    def test_inequality_different_plugin(self):
        a = EvidenceSource(plugin_id="whois", source_url="https://rdap.org")
        b = EvidenceSource(plugin_id="dns", source_url="https://rdap.org")
        assert a != b

    def test_inequality_different_source(self):
        a = EvidenceSource(plugin_id="whois", source_url="https://rdap.org")
        b = EvidenceSource(plugin_id="whois", source_url="https://other.com")
        assert a != b

    def test_none_source_normalizes_to_empty_string(self):
        a = EvidenceSource(plugin_id="whois", source_url=None)
        b = EvidenceSource(plugin_id="whois", source_url=None)
        assert a == b
        assert hash(a) == hash(b)

    def test_usable_in_set(self):
        s = {EvidenceSource("a", "x"), EvidenceSource("a", "x"), EvidenceSource("b", "x")}
        assert len(s) == 2


class TestEnvVarOverride:
    """Verify env vars override defaults at module load time."""

    def test_env_var_override_works(self, monkeypatch):
        # This test verifies the _env_float helper logic by re-importing
        # the module with a patched env var. We can't easily reload the
        # module (it's cached), so we test the helper directly.
        monkeypatch.setenv("ARGUS_TIER1_WEIGHT", "0.99")
        # Re-import to pick up the env var
        import importlib
        import canonical.confidence as conf
        importlib.reload(conf)
        try:
            assert conf.TIER_1_WEIGHT == 0.99
        finally:
            # Restore default
            monkeypatch.delenv("ARGUS_TIER1_WEIGHT")
            importlib.reload(conf)
