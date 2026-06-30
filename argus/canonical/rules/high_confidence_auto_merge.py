"""
HighConfidenceAutoMergeRule — fires when correlation score is very high
AND decisive tier is 1 (strong identifier match).

Threshold: score >= 0.90 AND decisive_tier == 1
Action: AUTO_MERGE

This is the only rule that can trigger an automatic merge. It requires
a Tier-1 signal match (email, phone, wallet, PGP) at high confidence.
"""
from __future__ import annotations

from typing import Optional

from canonical.correlation import CorrelationResult
from canonical.rules.proposed_decision import ProposedDecision, DecisionKind


RULE_ID = "high_confidence_auto_merge"
RULE_VERSION = "1.0.0"
THRESHOLD = 0.90


class HighConfidenceAutoMergeRule:
    """Fires when score >= 0.90 and decisive tier is 1."""

    rule_id = RULE_ID
    rule_version = RULE_VERSION

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        if correlation.final_score < THRESHOLD:
            return None
        if correlation.decisive_tier != 1:
            return None

        # Build explanation
        tier1 = correlation.tier_breakdown.get(1)
        signal_types = [s.signal_type for s in tier1.signals] if tier1 else []

        return ProposedDecision(
            decision_id=ProposedDecision.make_id(),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            kind=DecisionKind.AUTO_MERGE,
            draft_identity_id=correlation.draft_identity_id,
            global_identity_id=correlation.global_identity_id,
            correlation_score=correlation.final_score,
            reasoning=(
                f"Auto-merge: score {correlation.final_score:.4f} >= {THRESHOLD} "
                f"with decisive Tier-1 signals ({', '.join(signal_types)}). "
                f"{len(correlation.contributing_evidence)} distinct evidence sources."
            ),
            explanation={
                "rule_id": self.rule_id,
                "rule_version": self.rule_version,
                "threshold": THRESHOLD,
                "actual_score": correlation.final_score,
                "decisive_tier": correlation.decisive_tier,
                "tier1_signal_types": signal_types,
                "contributing_evidence_count": len(correlation.contributing_evidence),
                "correlation_explanation": correlation.explanation,
            },
        )


__all__ = ["HighConfidenceAutoMergeRule", "RULE_ID", "RULE_VERSION", "THRESHOLD"]
