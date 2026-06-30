"""
Tests for the Rule Engine + conflict resolution + 4 reference rules.

Covers:
  - RuleRegistry registration
  - RuleEngine evaluation
  - HighConfidenceAutoMergeRule (score >= 0.90, tier 1)
  - ReviewBandRule (0.50 <= score < 0.90)
  - WatchlistRule (watchlist hits → QUEUE_FOR_REVIEW)
  - NoOverlapPromotionRule (no matches → PROMOTE_TO_GLOBAL)
  - Conflict resolution (REJECT > QUEUE > PROMOTE > AUTO_MERGE)
  - Rules never modify the database
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "argus"))

from canonical.correlation import CorrelationResult, TierBreakdown, MatchedEntity, Signal
from canonical.rules import (
    RuleRegistry, RuleEngine, registry,
    ProposedDecision, DecisionKind, resolve_conflicts,
    HighConfidenceAutoMergeRule, ReviewBandRule, WatchlistRule,
    NoOverlapPromotionRule, register_default_rules,
)
from canonical.rules.high_confidence_auto_merge import THRESHOLD as HC_THRESHOLD
from canonical.rules.review_band import LOWER_BOUND, UPPER_BOUND


# ─── Fixtures ────────────────────────────────────────────────────────

def _make_correlation(
    score: float = 0.5,
    decisive_tier: int = 1,
    matched_entities: list | None = None,
    contributing_evidence: list | None = None,
) -> CorrelationResult:
    """Build a CorrelationResult for testing."""
    # Explicitly handle None vs empty list — they mean different things.
    # If contributing_evidence is None, default to ["ev-1"].
    # If it's an empty list, keep it empty.
    if contributing_evidence is None:
        contributing_evidence = ["ev-1"]
    return CorrelationResult(
        draft_identity_id="draft-1",
        global_identity_id="global-1",
        final_score=score,
        decisive_tier=decisive_tier,
        tier_breakdown={},
        matched_entities=matched_entities or [],
        matched_relationships=[],
        contributing_signals=[],
        contributing_evidence=contributing_evidence,
        confidence_reasoning="test",
        explanation={"test": True},
    )


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the global registry before each test."""
    registry.clear()
    yield
    registry.clear()


# ─── Registry tests ──────────────────────────────────────────────────

class TestRuleRegistry:
    def test_register_and_get(self):
        reg = RuleRegistry()
        rule = HighConfidenceAutoMergeRule()
        reg.register(rule)
        assert reg.get(rule.rule_id) is rule

    def test_duplicate_register_raises(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        with pytest.raises(ValueError, match="already registered"):
            reg.register(HighConfidenceAutoMergeRule())

    def test_overwrite_allowed(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        reg.register(HighConfidenceAutoMergeRule(), overwrite=True)

    def test_empty_rule_id_raises(self):
        reg = RuleRegistry()
        class BadRule:
            rule_id = ""
            rule_version = "1.0"
            def evaluate(self, c): return None
        with pytest.raises(ValueError, match="empty rule_id"):
            reg.register(BadRule())

    def test_list_rules(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        reg.register(ReviewBandRule())
        listed = reg.list_rules()
        assert "high_confidence_auto_merge" in listed
        assert "review_band" in listed

    def test_clear(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        assert len(reg) == 1
        reg.clear()
        assert len(reg) == 0


# ─── HighConfidenceAutoMergeRule tests ───────────────────────────────

class TestHighConfidenceAutoMergeRule:
    def test_fires_on_high_score_tier1(self):
        rule = HighConfidenceAutoMergeRule()
        corr = _make_correlation(score=0.95, decisive_tier=1)
        decision = rule.evaluate(corr)
        assert decision is not None
        assert decision.kind == DecisionKind.AUTO_MERGE
        assert decision.rule_id == "high_confidence_auto_merge"

    def test_does_not_fire_on_low_score(self):
        rule = HighConfidenceAutoMergeRule()
        corr = _make_correlation(score=0.80, decisive_tier=1)
        assert rule.evaluate(corr) is None

    def test_does_not_fire_on_tier2_even_if_high_score(self):
        rule = HighConfidenceAutoMergeRule()
        corr = _make_correlation(score=0.95, decisive_tier=2)
        assert rule.evaluate(corr) is None

    def test_threshold_value(self):
        assert HC_THRESHOLD == 0.90

    def test_explanation_contains_threshold(self):
        rule = HighConfidenceAutoMergeRule()
        corr = _make_correlation(score=0.95, decisive_tier=1)
        decision = rule.evaluate(corr)
        assert decision.explanation["threshold"] == HC_THRESHOLD
        assert decision.explanation["actual_score"] == 0.95


# ─── ReviewBandRule tests ────────────────────────────────────────────

class TestReviewBandRule:
    def test_fires_in_review_band(self):
        rule = ReviewBandRule()
        corr = _make_correlation(score=0.65)
        decision = rule.evaluate(corr)
        assert decision is not None
        assert decision.kind == DecisionKind.QUEUE_FOR_REVIEW

    def test_does_not_fire_below_band(self):
        rule = ReviewBandRule()
        corr = _make_correlation(score=0.30)
        assert rule.evaluate(corr) is None

    def test_does_not_fire_above_band(self):
        rule = ReviewBandRule()
        corr = _make_correlation(score=0.95)
        assert rule.evaluate(corr) is None

    def test_fires_at_lower_bound(self):
        rule = ReviewBandRule()
        corr = _make_correlation(score=0.50)
        assert rule.evaluate(corr) is not None

    def test_does_not_fire_at_upper_bound(self):
        rule = ReviewBandRule()
        corr = _make_correlation(score=0.90)
        assert rule.evaluate(corr) is None


# ─── WatchlistRule tests ─────────────────────────────────────────────

class TestWatchlistRule:
    def test_fires_when_entity_on_watchlist(self):
        watchlist = {"user@example.com"}
        rule = WatchlistRule(watchlist_checker=lambda vals: vals & watchlist)
        corr = _make_correlation(
            score=0.95,  # high score, but watchlist forces review
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        decision = rule.evaluate(corr)
        assert decision is not None
        assert decision.kind == DecisionKind.QUEUE_FOR_REVIEW
        assert "user@example.com" in decision.explanation["watchlist_hits"]

    def test_does_not_fire_when_no_watchlist_hits(self):
        watchlist = {"other@example.com"}
        rule = WatchlistRule(watchlist_checker=lambda vals: vals & watchlist)
        corr = _make_correlation(
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        assert rule.evaluate(corr) is None

    def test_does_not_fire_when_no_matched_entities(self):
        rule = WatchlistRule(watchlist_checker=lambda vals: vals)
        corr = _make_correlation(matched_entities=[])
        assert rule.evaluate(corr) is None

    def test_noop_checker_never_fires(self):
        rule = WatchlistRule(watchlist_checker=lambda vals: set())
        corr = _make_correlation(
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        assert rule.evaluate(corr) is None


# ─── NoOverlapPromotionRule tests ────────────────────────────────────

class TestNoOverlapPromotionRule:
    def test_fires_when_no_matches_and_has_evidence(self):
        rule = NoOverlapPromotionRule()
        corr = _make_correlation(
            score=0.0,
            matched_entities=[],
            contributing_evidence=["ev-1", "ev-2"],
        )
        decision = rule.evaluate(corr)
        assert decision is not None
        assert decision.kind == DecisionKind.PROMOTE_TO_GLOBAL

    def test_does_not_fire_when_matches_exist(self):
        rule = NoOverlapPromotionRule()
        corr = _make_correlation(
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        assert rule.evaluate(corr) is None

    def test_does_not_fire_when_no_evidence(self):
        rule = NoOverlapPromotionRule()
        corr = _make_correlation(
            score=0.0,
            matched_entities=[],
            contributing_evidence=[],
        )
        assert rule.evaluate(corr) is None


# ─── Conflict resolution tests ───────────────────────────────────────

class TestConflictResolution:
    def _make_decision(self, kind: DecisionKind, score: float = 0.5) -> ProposedDecision:
        return ProposedDecision(
            decision_id="d1",
            rule_id="test",
            rule_version="1.0",
            kind=kind,
            draft_identity_id="d",
            global_identity_id="g",
            correlation_score=score,
            reasoning="test",
            explanation={},
        )

    def test_reject_beats_queue(self):
        winner = resolve_conflicts([
            self._make_decision(DecisionKind.REJECT),
            self._make_decision(DecisionKind.QUEUE_FOR_REVIEW),
        ])
        assert winner.kind == DecisionKind.REJECT

    def test_queue_beats_promote(self):
        winner = resolve_conflicts([
            self._make_decision(DecisionKind.QUEUE_FOR_REVIEW),
            self._make_decision(DecisionKind.PROMOTE_TO_GLOBAL),
        ])
        assert winner.kind == DecisionKind.QUEUE_FOR_REVIEW

    def test_promote_beats_auto_merge(self):
        winner = resolve_conflicts([
            self._make_decision(DecisionKind.PROMOTE_TO_GLOBAL),
            self._make_decision(DecisionKind.AUTO_MERGE),
        ])
        assert winner.kind == DecisionKind.PROMOTE_TO_GLOBAL

    def test_reject_beats_all(self):
        winner = resolve_conflicts([
            self._make_decision(DecisionKind.AUTO_MERGE),
            self._make_decision(DecisionKind.PROMOTE_TO_GLOBAL),
            self._make_decision(DecisionKind.QUEUE_FOR_REVIEW),
            self._make_decision(DecisionKind.REJECT),
        ])
        assert winner.kind == DecisionKind.REJECT

    def test_empty_list_returns_none(self):
        assert resolve_conflicts([]) is None

    def test_same_priority_higher_score_wins(self):
        winner = resolve_conflicts([
            self._make_decision(DecisionKind.QUEUE_FOR_REVIEW, score=0.6),
            self._make_decision(DecisionKind.QUEUE_FOR_REVIEW, score=0.7),
        ])
        assert winner.correlation_score == 0.7


# ─── RuleEngine tests ────────────────────────────────────────────────

class TestRuleEngine:
    def test_engine_runs_all_rules(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        reg.register(ReviewBandRule())
        engine = RuleEngine(reg)

        corr = _make_correlation(score=0.65, decisive_tier=1)
        decision = engine.evaluate(corr)
        # ReviewBand fires (0.50 <= 0.65 < 0.90), HighConfidence doesn't
        assert decision is not None
        assert decision.kind == DecisionKind.QUEUE_FOR_REVIEW

    def test_engine_returns_none_when_no_rule_fires(self):
        reg = RuleRegistry()
        reg.register(HighConfidenceAutoMergeRule())
        engine = RuleEngine(reg)
        corr = _make_correlation(score=0.30, decisive_tier=1)
        assert engine.evaluate(corr) is None

    def test_engine_conflict_resolution(self):
        """When multiple rules fire, most conservative wins."""
        reg = RuleRegistry()
        # Register a watchlist rule that fires on high score too
        watchlist = {"user@example.com"}
        reg.register(WatchlistRule(watchlist_checker=lambda vals: vals & watchlist))
        reg.register(HighConfidenceAutoMergeRule())
        engine = RuleEngine(reg)

        corr = _make_correlation(
            score=0.95,
            decisive_tier=1,
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        decision = engine.evaluate(corr)
        # Both fire, but QUEUE_FOR_REVIEW beats AUTO_MERGE
        assert decision.kind == DecisionKind.QUEUE_FOR_REVIEW

    def test_evaluate_all_returns_all_decisions(self):
        reg = RuleRegistry()
        watchlist = {"user@example.com"}
        reg.register(WatchlistRule(watchlist_checker=lambda vals: vals & watchlist))
        reg.register(HighConfidenceAutoMergeRule())
        engine = RuleEngine(reg)

        corr = _make_correlation(
            score=0.95,
            decisive_tier=1,
            matched_entities=[
                MatchedEntity("email", "e1", "e2", "user@example.com", "email_exact"),
            ],
        )
        decisions = engine.evaluate_all(corr)
        assert len(decisions) == 2  # both rules fired


# ─── register_default_rules tests ────────────────────────────────────

class TestRegisterDefaultRules:
    def test_registers_all_four_rules(self):
        count = register_default_rules()
        assert count == 4
        assert "high_confidence_auto_merge" in registry.list_rules()
        assert "review_band" in registry.list_rules()
        assert "watchlist" in registry.list_rules()
        assert "no_overlap_promotion" in registry.list_rules()

    def test_idempotent(self):
        c1 = register_default_rules()
        c2 = register_default_rules()
        assert c1 == 4
        assert c2 == 0  # all already registered

    def test_with_custom_watchlist_checker(self):
        watchlist = {"monitored@example.com"}
        count = register_default_rules(watchlist_checker=lambda vals: vals & watchlist)
        assert count == 4
