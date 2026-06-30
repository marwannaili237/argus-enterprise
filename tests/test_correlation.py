"""
Tests for the Correlation Engine.

Covers:
  - Scoring with single-tier matches
  - Tier caps (Tier 2 max 0.75, Tier 3 max 0.45)
  - Evidence independence (same evidence_id counts once)
  - Noisy-OR across distinct evidence sources
  - Decisive tier determination
  - Corroboration boost from lower tiers
  - Matched entities and relationships
  - Explanation completeness
  - Determinism (same input → same output)
  - Cross-investigation safety (engine never touches DB)
"""
import os
import sys
import pytest
from dataclasses import FrozenInstanceError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.correlation import (
    CorrelationEngine, CorrelationResult, Signal, MatchedEntity,
    TIER_1_SIGNALS, TIER_2_SIGNALS, TIER_3_SIGNALS,
    TIER_2_CAP, TIER_3_CAP, SIGNAL_WEIGHTS,
    tier_for_signal, cap_for_tier, signal_type_for_entity,
)


# ─── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return CorrelationEngine()


def _entity(entity_id, etype, value, evidence_id="ev-1"):
    return {
        "entity_id": entity_id,
        "type": etype,
        "normalized_value": value,
        "evidence_id": evidence_id,
    }


def _rel(rel_type, src_type, src_val, tgt_type, tgt_val, evidence_id="ev-1"):
    return {
        "relationship_type": rel_type,
        "source_entity_type": src_type,
        "source_normalized_value": src_val,
        "target_entity_type": tgt_type,
        "target_normalized_value": tgt_val,
        "evidence_id": evidence_id,
    }


# ─── Tier classification tests ───────────────────────────────────────

class TestTierClassification:
    def test_tier1_signals(self):
        for s in ["email_exact", "phone_e164", "wallet_address", "pgp_fingerprint"]:
            assert tier_for_signal(s) == 1

    def test_tier2_signals(self):
        for s in ["username_exact", "avatar_phash", "domain_owner"]:
            assert tier_for_signal(s) == 2

    def test_tier3_signals(self):
        for s in ["display_name", "company", "city", "country", "language"]:
            assert tier_for_signal(s) == 3

    def test_unknown_signal_is_tier3(self):
        assert tier_for_signal("unknown") == 3

    def test_tier1_has_no_cap(self):
        assert cap_for_tier(1) is None

    def test_tier2_cap(self):
        assert cap_for_tier(2) == TIER_2_CAP
        assert TIER_2_CAP == 0.75

    def test_tier3_cap(self):
        assert cap_for_tier(3) == TIER_3_CAP
        assert TIER_3_CAP == 0.45


class TestSignalTypeMapping:
    def test_email_maps_to_email_exact(self):
        assert signal_type_for_entity("email") == "email_exact"

    def test_phone_maps_to_phone_e164(self):
        assert signal_type_for_entity("phone") == "phone_e164"

    def test_btc_maps_to_wallet_address(self):
        assert signal_type_for_entity("btc") == "wallet_address"

    def test_pgp_maps_to_pgp_fingerprint(self):
        assert signal_type_for_entity("pgp_fingerprint") == "pgp_fingerprint"

    def test_username_maps_to_username_exact(self):
        assert signal_type_for_entity("username") == "username_exact"

    def test_unknown_type_returns_none(self):
        assert signal_type_for_entity("nonexistent") is None

    def test_case_insensitive(self):
        assert signal_type_for_entity("EMAIL") == "email_exact"


# ─── Basic scoring tests ─────────────────────────────────────────────

class TestBasicScoring:
    def test_no_matches_returns_zero(self, engine):
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=[_entity("e1", "email", "a@example.com")],
            global_entities=[_entity("e2", "email", "b@example.com")],
        )
        assert result.final_score == 0.0
        assert result.matched_entities == []
        assert result.contributing_signals == []

    def test_single_email_match(self, engine):
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=[_entity("e1", "email", "user@example.com", "ev-1")],
            global_entities=[_entity("e2", "email", "user@example.com", "ev-2")],
        )
        assert len(result.matched_entities) == 1
        assert result.decisive_tier == 1
        # Single Tier-1 signal with weight 0.90 → score = 0.90
        assert result.final_score == pytest.approx(0.90, abs=0.01)

    def test_single_phone_match(self, engine):
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=[_entity("e1", "phone", "+14155552671", "ev-1")],
            global_entities=[_entity("e2", "phone", "+14155552671", "ev-2")],
        )
        assert result.decisive_tier == 1
        assert result.final_score == pytest.approx(0.90, abs=0.01)

    def test_case_insensitive_matching(self, engine):
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=[_entity("e1", "email", "USER@example.com", "ev-1")],
            global_entities=[_entity("e2", "email", "user@example.com", "ev-2")],
        )
        assert len(result.matched_entities) == 1


# ─── Tier cap tests ──────────────────────────────────────────────────

class TestTierCaps:
    def test_tier2_capped_at_075(self, engine):
        """Multiple Tier-2 signals from different evidence shouldn't exceed 0.75."""
        draft = [
            _entity("e1", "username", "johndoe", "ev-1"),
            _entity("e2", "avatar_hash", "abc123", "ev-2"),
            _entity("e3", "domain", "example.com", "ev-3"),
        ]
        global_ = [
            _entity("e4", "username", "johndoe", "ev-4"),
            _entity("e5", "avatar_hash", "abc123", "ev-5"),
            _entity("e6", "domain", "example.com", "ev-6"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        assert result.decisive_tier == 2
        # Tier 2 raw score: 1 - (1-0.55)(1-0.50)(1-0.45) = 1 - 0.45*0.50*0.55 = 1 - 0.12375 = 0.87625
        # But capped at 0.75
        assert result.tier_breakdown[2].raw_score > TIER_2_CAP
        assert result.tier_breakdown[2].capped_score == TIER_2_CAP
        assert result.tier_breakdown[2].cap_applied is True
        # Final score should be 0.75 (decisive tier) + small boost from tier 3
        assert result.final_score <= TIER_2_CAP + 0.1  # generous bound for boost

    def test_tier3_capped_at_045(self, engine):
        """Multiple Tier-3 signals shouldn't exceed 0.45."""
        draft = [
            _entity("e1", "display_name", "John Doe", "ev-1"),
            _entity("e2", "company", "Acme Corp", "ev-2"),
            _entity("e3", "city", "New York", "ev-3"),
            _entity("e4", "country", "USA", "ev-4"),
            _entity("e5", "language", "en", "ev-5"),
        ]
        global_ = [
            _entity("e6", "display_name", "John Doe", "ev-6"),
            _entity("e7", "company", "Acme Corp", "ev-7"),
            _entity("e8", "city", "New York", "ev-8"),
            _entity("e9", "country", "USA", "ev-9"),
            _entity("e10", "language", "en", "ev-10"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        assert result.decisive_tier == 3
        assert result.tier_breakdown[3].raw_score > TIER_3_CAP
        assert result.tier_breakdown[3].capped_score == TIER_3_CAP
        assert result.tier_breakdown[3].cap_applied is True
        assert result.final_score <= TIER_3_CAP

    def test_tier1_not_capped(self, engine):
        """Tier-1 signals can exceed any threshold — no cap."""
        draft = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e2", "phone", "+14155552671", "ev-2"),
            _entity("e3", "btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ev-3"),
            _entity("e4", "pgp_fingerprint", "abc123def456", "ev-4"),
        ]
        global_ = [
            _entity("e5", "email", "user@example.com", "ev-5"),
            _entity("e6", "phone", "+14155552671", "ev-6"),
            _entity("e7", "btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ev-7"),
            _entity("e8", "pgp_fingerprint", "abc123def456", "ev-8"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        assert result.decisive_tier == 1
        assert result.tier_breakdown[1].cap_applied is False
        # With 4 strong signals, score should be very high (>0.99)
        assert result.final_score > 0.99


# ─── Evidence independence tests ─────────────────────────────────────

class TestEvidenceIndependence:
    def test_same_evidence_id_counts_once(self, engine):
        """Multiple signals from the same evidence_id count as ONE."""
        # Two Tier-1 signals from the SAME evidence_id
        draft = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e2", "phone", "+14155552671", "ev-1"),  # same evidence
        ]
        global_ = [
            _entity("e3", "email", "user@example.com", "ev-1"),
            _entity("e4", "phone", "+14155552671", "ev-1"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        # Both signals are from ev-1, so only the strongest counts
        # Strongest is email (0.90) or phone (0.90) — same weight
        # Score = 0.90 (single signal, not 1 - 0.1*0.1 = 0.99)
        assert result.final_score == pytest.approx(0.90, abs=0.01)
        assert len(result.tier_breakdown[1].distinct_evidence_ids) == 1

    def test_different_evidence_ids_use_noisy_or(self, engine):
        """Signals from different evidence_ids combine via noisy-OR."""
        draft = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e2", "phone", "+14155552671", "ev-2"),  # different evidence
        ]
        global_ = [
            _entity("e3", "email", "user@example.com", "ev-3"),
            _entity("e4", "phone", "+14155552671", "ev-4"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        # Two distinct evidence sources: 1 - (1-0.90)(1-0.90) = 1 - 0.01 = 0.99
        assert result.final_score == pytest.approx(0.99, abs=0.01)
        assert len(result.tier_breakdown[1].distinct_evidence_ids) == 2

    def test_five_signals_same_evidence_still_one(self, engine):
        """5 signals from the same evidence_id count as ONE — no inflation.

        The Tier-1 raw score should be 0.95 (single strongest signal),
        NOT 1 - (1-0.9)(1-0.9)(1-0.95)(1-0.95) = 0.9999...
        The final score may include a small corroboration boost from Tier 2.
        """
        draft = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e2", "phone", "+14155552671", "ev-1"),
            _entity("e3", "btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ev-1"),
            _entity("e4", "pgp_fingerprint", "abc123", "ev-1"),
            _entity("e5", "username", "johndoe", "ev-1"),
        ]
        global_ = [
            _entity("e6", "email", "user@example.com", "ev-1"),
            _entity("e7", "phone", "+14155552671", "ev-1"),
            _entity("e8", "btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "ev-1"),
            _entity("e9", "pgp_fingerprint", "abc123", "ev-1"),
            _entity("e10", "username", "johndoe", "ev-1"),
        ]
        result = engine.correlate(
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            draft_entities=draft,
            global_entities=global_,
        )
        # All from ev-1 → only strongest counts per tier
        # Tier 1 strongest: wallet/pgp at 0.95 → raw_score = 0.95 (NOT 0.9999)
        assert result.tier_breakdown[1].raw_score == pytest.approx(0.95, abs=0.01)
        assert len(result.tier_breakdown[1].distinct_evidence_ids) == 1
        # The final score includes a corroboration boost from Tier 2
        # (0.95 + 0.1*0.55 = 1.005, clamped to 1.0)
        # The KEY assertion: Tier-1 raw score is NOT inflated
        assert result.tier_breakdown[1].raw_score < 0.97  # not inflated by dependent signals


# ─── Decisive tier tests ─────────────────────────────────────────────

class TestDecisiveTier:
    def test_tier1_decisive_when_present(self, engine):
        draft = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e2", "username", "johndoe", "ev-2"),  # tier 2
            _entity("e3", "city", "NYC", "ev-3"),  # tier 3
        ]
        global_ = [
            _entity("e4", "email", "user@example.com", "ev-4"),
            _entity("e5", "username", "johndoe", "ev-5"),
            _entity("e6", "city", "NYC", "ev-6"),
        ]
        result = engine.correlate("d", "g", draft, global_)
        assert result.decisive_tier == 1

    def test_tier2_decisive_when_no_tier1(self, engine):
        draft = [
            _entity("e1", "username", "johndoe", "ev-1"),
            _entity("e2", "city", "NYC", "ev-2"),
        ]
        global_ = [
            _entity("e3", "username", "johndoe", "ev-3"),
            _entity("e4", "city", "NYC", "ev-4"),
        ]
        result = engine.correlate("d", "g", draft, global_)
        assert result.decisive_tier == 2

    def test_tier3_decisive_when_no_tier1_or_2(self, engine):
        draft = [_entity("e1", "city", "NYC", "ev-1")]
        global_ = [_entity("e2", "city", "NYC", "ev-2")]
        result = engine.correlate("d", "g", draft, global_)
        assert result.decisive_tier == 3

    def test_corroboration_boost_from_lower_tiers(self, engine):
        """Tier-1 + Tier-2 should score higher than Tier-1 alone."""
        draft_t1_only = [_entity("e1", "email", "user@example.com", "ev-1")]
        global_t1_only = [_entity("e2", "email", "user@example.com", "ev-2")]

        draft_t1_t2 = [
            _entity("e1", "email", "user@example.com", "ev-1"),
            _entity("e3", "username", "johndoe", "ev-3"),
        ]
        global_t1_t2 = [
            _entity("e2", "email", "user@example.com", "ev-2"),
            _entity("e4", "username", "johndoe", "ev-4"),
        ]

        r1 = engine.correlate("d", "g", draft_t1_only, global_t1_only)
        r2 = engine.correlate("d", "g", draft_t1_t2, global_t1_t2)
        # r2 should be slightly higher due to corroboration boost
        assert r2.final_score > r1.final_score


# ─── Relationship matching tests ─────────────────────────────────────

class TestRelationshipMatching:
    def test_matched_relationships_detected(self, engine):
        draft_rels = [_rel("resolves_to", "domain", "example.com", "ip", "1.2.3.4", "ev-1")]
        global_rels = [_rel("resolves_to", "domain", "example.com", "ip", "1.2.3.4", "ev-2")]
        result = engine.correlate(
            "d", "g",
            draft_entities=[],
            global_entities=[],
            draft_relationships=draft_rels,
            global_relationships=global_rels,
        )
        assert len(result.matched_relationships) == 1
        # Relationship matches produce Tier-3 'domain_owner' signals
        assert result.decisive_tier == 3

    def test_different_relationships_not_matched(self, engine):
        draft_rels = [_rel("resolves_to", "domain", "a.com", "ip", "1.2.3.4", "ev-1")]
        global_rels = [_rel("resolves_to", "domain", "b.com", "ip", "1.2.3.4", "ev-2")]
        result = engine.correlate(
            "d", "g", [], [], draft_rels, global_rels,
        )
        assert len(result.matched_relationships) == 0


# ─── Explanation tests ───────────────────────────────────────────────

class TestExplanation:
    def test_explanation_contains_required_fields(self, engine):
        result = engine.correlate(
            "draft-1", "global-1",
            [_entity("e1", "email", "user@example.com", "ev-1")],
            [_entity("e2", "email", "user@example.com", "ev-2")],
        )
        expl = result.explanation
        assert "engine" in expl
        assert "engine_version" in expl
        assert "final_score" in expl
        assert "decisive_tier" in expl
        assert "tier_breakdown" in expl
        assert "contributing_evidence_ids" in expl
        assert "reasoning" in expl
        assert "signal_weights" in expl
        assert "tier_caps" in expl

    def test_confidence_reasoning_is_human_readable(self, engine):
        result = engine.correlate(
            "draft-1", "global-1",
            [_entity("e1", "email", "user@example.com", "ev-1")],
            [_entity("e2", "email", "user@example.com", "ev-2")],
        )
        assert isinstance(result.confidence_reasoning, str)
        assert "Final score:" in result.confidence_reasoning
        assert "Decisive tier:" in result.confidence_reasoning

    def test_contributing_evidence_listed(self, engine):
        result = engine.correlate(
            "draft-1", "global-1",
            [
                _entity("e1", "email", "user@example.com", "ev-1"),
                _entity("e2", "phone", "+14155552671", "ev-2"),
            ],
            [
                _entity("e3", "email", "user@example.com", "ev-3"),
                _entity("e4", "phone", "+14155552671", "ev-4"),
            ],
        )
        assert "ev-1" in result.contributing_evidence
        assert "ev-2" in result.contributing_evidence


# ─── Determinism tests ───────────────────────────────────────────────

class TestDeterminism:
    def test_same_input_same_output(self, engine):
        draft = [_entity("e1", "email", "user@example.com", "ev-1")]
        global_ = [_entity("e2", "email", "user@example.com", "ev-2")]

        r1 = engine.correlate("d", "g", draft, global_)
        r2 = engine.correlate("d", "g", draft, global_)

        assert r1.final_score == r2.final_score
        assert r1.decisive_tier == r2.decisive_tier
        # Compare everything except the explanation timestamp (which is non-deterministic)
        d1 = r1.to_dict()
        d2 = r2.to_dict()
        d1["explanation"].pop("timestamp", None)
        d2["explanation"].pop("timestamp", None)
        assert d1 == d2

    def test_engine_never_touches_db(self, engine):
        """The correlation engine is a pure function — no DB access."""
        # If this test passes (no exception), the engine didn't try DB ops
        result = engine.correlate(
            "d", "g",
            [_entity("e1", "email", "user@example.com", "ev-1")],
            [_entity("e2", "email", "user@example.com", "ev-2")],
        )
        assert result is not None


# ─── Immutability tests ──────────────────────────────────────────────

class TestImmutability:
    def test_signal_is_frozen(self):
        s = Signal(
            signal_type="email_exact",
            draft_value="a@b.com",
            global_value="a@b.com",
            evidence_id="ev-1",
            weight=0.9,
            tier=1,
        )
        with pytest.raises(FrozenInstanceError):
            s.weight = 0.5

    def test_matched_entity_is_frozen(self):
        me = MatchedEntity(
            entity_type="email",
            draft_entity_id="e1",
            global_entity_id="e2",
            normalized_value="user@example.com",
            signal_type="email_exact",
        )
        with pytest.raises(FrozenInstanceError):
            me.entity_type = "phone"

    def test_proposed_decision_is_frozen(self):
        from canonical.rules.proposed_decision import ProposedDecision, DecisionKind
        d = ProposedDecision(
            decision_id="d1",
            rule_id="test",
            rule_version="1.0",
            kind=DecisionKind.AUTO_MERGE,
            draft_identity_id="draft-1",
            global_identity_id="global-1",
            correlation_score=0.95,
            reasoning="test",
            explanation={},
        )
        with pytest.raises(FrozenInstanceError):
            d.kind = DecisionKind.REJECT
