"""
NoOverlapPromotionRule — fires when a draft identity has no overlap with
any global identity (no matched entities) but has high internal confidence.

Action: PROMOTE_TO_GLOBAL

This is the "new identity" path: the draft identity doesn't match any
existing global identity, so we propose promoting it to a global identity
(so future investigations can match against it).

Note: This rule fires when there are ZERO matched entities. If there's
even one match, other rules handle it.
"""
from __future__ import annotations

from typing import Optional

from canonical.correlation import CorrelationResult
from canonical.rules.proposed_decision import ProposedDecision, DecisionKind


RULE_ID = "no_overlap_promotion"
RULE_VERSION = "1.0.0"


class NoOverlapPromotionRule:
    """
    Fires when there are zero matched entities (no overlap with global).

    This rule is typically evaluated against a "null" global identity
    (a placeholder indicating "no match found"). The correlation engine
    should be called with empty global_entities to produce a zero-match
    result, which this rule then acts on.
    """

    rule_id = RULE_ID
    rule_version = RULE_VERSION

    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]:
        # Only fires when there are NO matched entities
        if correlation.matched_entities:
            return None

        # Even with no matches, we need some contributing evidence
        # (otherwise there's nothing to promote)
        if not correlation.contributing_evidence:
            return None

        return ProposedDecision(
            decision_id=ProposedDecision.make_id(),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            kind=DecisionKind.PROMOTE_TO_GLOBAL,
            draft_identity_id=correlation.draft_identity_id,
            global_identity_id=correlation.global_identity_id,
            correlation_score=correlation.final_score,
            reasoning=(
                f"No overlap with global identity. Draft has "
                f"{len(correlation.contributing_evidence)} evidence sources. "
                f"Proposing promotion to global identity."
            ),
            explanation={
                "rule_id": self.rule_id,
                "rule_version": self.rule_version,
                "matched_entity_count": len(correlation.matched_entities),
                "contributing_evidence_count": len(correlation.contributing_evidence),
                "correlation_explanation": correlation.explanation,
            },
        )


__all__ = ["NoOverlapPromotionRule", "RULE_ID", "RULE_VERSION"]
