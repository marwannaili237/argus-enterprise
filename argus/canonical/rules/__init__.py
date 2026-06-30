"""
Canonical Rule Engine package.

Public API:
  - Rule (Protocol)
  - RuleRegistry, registry
  - RuleEngine
  - ProposedDecision, DecisionKind, resolve_conflicts
  - HighConfidenceAutoMergeRule
  - ReviewBandRule
  - WatchlistRule
  - NoOverlapPromotionRule
  - register_default_rules()
"""
from canonical.rules.engine import Rule, RuleRegistry, RuleEngine, registry
from canonical.rules.proposed_decision import (
    ProposedDecision, DecisionKind, DECISION_PRIORITY, resolve_conflicts,
)
from canonical.rules.high_confidence_auto_merge import HighConfidenceAutoMergeRule
from canonical.rules.review_band import ReviewBandRule
from canonical.rules.watchlist import WatchlistRule, WatchlistChecker
from canonical.rules.no_overlap_promotion import NoOverlapPromotionRule


def register_default_rules(
    watchlist_checker: WatchlistChecker | None = None,
    *,
    overwrite: bool = False,
) -> int:
    """
    Register the 4 reference rules. Call once at startup.

    Args:
        watchlist_checker: callable for the WatchlistRule. If None,
            the WatchlistRule is registered with a no-op checker
            (never fires). Replace it later via registry.register(..., overwrite=True).
        overwrite: if True, re-register rules that are already present.

    Returns the number of rules registered.
    """
    count = 0
    rules = [
        HighConfidenceAutoMergeRule(),
        ReviewBandRule(),
        NoOverlapPromotionRule(),
    ]
    # WatchlistRule needs a checker — default to no-op (returns empty set)
    checker: WatchlistChecker = watchlist_checker or (lambda values: set())
    rules.append(WatchlistRule(checker))

    for rule in rules:
        if registry._rules.get(rule.rule_id) and not overwrite:
            continue
        registry.register(rule, overwrite=overwrite)
        count += 1
    return count


__all__ = [
    "Rule", "RuleRegistry", "RuleEngine", "registry",
    "ProposedDecision", "DecisionKind", "DECISION_PRIORITY", "resolve_conflicts",
    "HighConfidenceAutoMergeRule",
    "ReviewBandRule",
    "WatchlistRule", "WatchlistChecker",
    "NoOverlapPromotionRule",
    "register_default_rules",
]
