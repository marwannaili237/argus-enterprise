"""
WatchlistRule — fires when the draft identity contains an entity that's
on a user's watchlist.

Action: QUEUE_FOR_REVIEW (always — watchlist hits never auto-merge)

This rule consults an injected watchlist check function. The function
is provided at construction time so the rule remains pure (no DB access).
"""
from __future__ import annotations

from typing import Callable, Optional, Set

from canonical.correlation import CorrelationResult
from canonical.rules.proposed_decision import ProposedDecision, DecisionKind


RULE_ID = "watchlist"
RULE_VERSION = "1.0.0"


# Type: takes a set of normalized entity values, returns the subset that's on the watchlist
WatchlistChecker = Callable[[Set[str]], Set[str]]


class WatchlistRule:
    """
    Fires when any matched entity's normalized_value is on the watchlist.

    The watchlist checker is injected at construction:
        rule = WatchlistRule(checker=lambda values: values & my_watchlist_set)

    This keeps the rule pure (no DB access, no side effects).
    """

    rule_id = RULE_ID
    rule_version = RULE_VERSION

    def __init__(self, watchlist_checker: WatchlistChecker):
        self._checker = watchlist_checker

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        # Collect all matched entity values
        values = {e.normalized_value for e in correlation.matched_entities}
        if not values:
            return None

        # Check which are on the watchlist
        watchlist_hits = self._checker(values)
        if not watchlist_hits:
            return None

        return ProposedDecision(
            decision_id=ProposedDecision.make_id(),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            kind=DecisionKind.QUEUE_FOR_REVIEW,
            draft_identity_id=correlation.draft_identity_id,
            global_identity_id=correlation.global_identity_id,
            correlation_score=correlation.final_score,
            reasoning=(
                f"Watchlist hit: {len(watchlist_hits)} matched entities are on "
                f"a user watchlist ({', '.join(sorted(watchlist_hits)[:5])}). "
                f"Queued for review regardless of score ({correlation.final_score:.4f})."
            ),
            explanation={
                "rule_id": self.rule_id,
                "rule_version": self.rule_version,
                "watchlist_hits": sorted(watchlist_hits),
                "actual_score": correlation.final_score,
                "correlation_explanation": correlation.explanation,
            },
        )


__all__ = ["WatchlistRule", "WatchlistChecker", "RULE_ID", "RULE_VERSION"]
