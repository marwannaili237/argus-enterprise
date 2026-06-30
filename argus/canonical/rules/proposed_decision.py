"""
ProposedDecision — the output of a Rule's evaluate() method.

A ProposedDecision is a recommendation, NOT an action. The Decision
Engine consumes ProposedDecisions and executes them (or queues them
for review).

Conflict resolution (when multiple rules fire):
  Priority (most conservative wins):
    REJECT         (highest — always wins)
    QUEUE_FOR_REVIEW
    PROMOTE_TO_GLOBAL
    AUTO_MERGE     (lowest — only if no higher-priority rule fires)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid


class DecisionKind(str, Enum):
    """What kind of action the rule proposes."""
    AUTO_MERGE = "auto_merge"
    PROMOTE_TO_GLOBAL = "promote_to_global"
    QUEUE_FOR_REVIEW = "queue_for_review"
    REJECT = "reject"


# Priority for conflict resolution: lower number = higher priority
# (most conservative wins)
DECISION_PRIORITY: dict[DecisionKind, int] = {
    DecisionKind.REJECT: 0,
    DecisionKind.QUEUE_FOR_REVIEW: 1,
    DecisionKind.PROMOTE_TO_GLOBAL: 2,
    DecisionKind.AUTO_MERGE: 3,
}


@dataclass(frozen=True)
class ProposedDecision:
    """
    A recommendation produced by a Rule.

    Immutable (frozen=True) so rules can't mutate each other's output.
    """
    decision_id: str
    rule_id: str
    rule_version: str
    kind: DecisionKind
    draft_identity_id: str
    global_identity_id: str
    correlation_score: float
    reasoning: str
    explanation: dict[str, Any]  # full explainability chain
    proposed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "kind": self.kind.value,
            "draft_identity_id": self.draft_identity_id,
            "global_identity_id": self.global_identity_id,
            "correlation_score": round(self.correlation_score, 6),
            "reasoning": self.reasoning,
            "explanation": self.explanation,
            "proposed_at": self.proposed_at.isoformat(),
        }

    @staticmethod
    def make_id() -> str:
        return str(uuid.uuid4())


def resolve_conflicts(decisions: list[ProposedDecision]) -> Optional[ProposedDecision]:
    """
    Given multiple ProposedDecisions from different rules, return the
    one that wins according to the priority order (most conservative wins).

    If multiple decisions have the same priority, the one with the higher
    correlation_score wins (stronger evidence preferred when equally conservative).

    Returns None if decisions is empty.
    """
    if not decisions:
        return None
    # Sort by (priority asc, score desc) — first element wins
    sorted_decisions = sorted(
        decisions,
        key=lambda d: (DECISION_PRIORITY[d.kind], -d.correlation_score),
    )
    return sorted_decisions[0]


__all__ = [
    "DecisionKind", "ProposedDecision", "DECISION_PRIORITY", "resolve_conflicts",
]
