"""
ReviewBandRule — fires when correlation score is in the "review band"
(medium confidence, not high enough for auto-merge, not low enough to reject).

Threshold: 0.50 <= score < 0.90
Action: QUEUE_FOR_REVIEW

This is the safety net: when there's a reasonable match but not enough
confidence to auto-merge, send it to a human reviewer.
"""
from __future__ import annotations

from typing import Optional

from canonical.correlation import CorrelationResult
from canonical.rules.proposed_decision import ProposedDecision, DecisionKind


RULE_ID = "review_band"
RULE_VERSION = "1.0.0"
LOWER_BOUND = 0.50
UPPER_BOUND = 0.90


class ReviewBandRule:
    """Fires when 0.50 <= score < 0.90."""

    rule_id = RULE_ID
    rule_version = RULE_VERSION

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        if correlation.final_score < LOWER_BOUND:
            return None
        if correlation.final_score >= UPPER_BOUND:
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
                f"Review band: score {correlation.final_score:.4f} in "
                f"[{LOWER_BOUND}, {UPPER_BOUND}). Queued for human review. "
                f"Decisive tier: {correlation.decisive_tier}. "
                f"{len(correlation.contributing_evidence)} evidence sources."
            ),
            explanation={
                "rule_id": self.rule_id,
                "rule_version": self.rule_version,
                "lower_bound": LOWER_BOUND,
                "upper_bound": UPPER_BOUND,
                "actual_score": correlation.final_score,
                "decisive_tier": correlation.decisive_tier,
                "contributing_evidence_count": len(correlation.contributing_evidence),
                "correlation_explanation": correlation.explanation,
            },
        )


__all__ = ["ReviewBandRule", "RULE_ID", "RULE_VERSION", "LOWER_BOUND", "UPPER_BOUND"]
