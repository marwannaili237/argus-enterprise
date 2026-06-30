"""
Correlation Engine — compares a Draft Identity against a Global Identity.

CRITICAL RULES (architectural constraints):
  - NEVER writes to the database.
  - NEVER merges identities.
  - NEVER creates decisions.
  - ONLY computes evidence and returns a CorrelationResult.

The engine is a pure function: (draft_identity, global_identity, evidence) → CorrelationResult.
Same inputs always produce the same output. No randomness, no time-of-day logic.

Signal tiers (mirrors canonical.confidence but with correlation-specific caps):
  Tier 1: email_exact, phone_e164, wallet_address, pgp_fingerprint
          — may exceed threshold (no cap)
  Tier 2: username_exact, avatar_phash, domain_owner
          — max contribution = 0.75
  Tier 3: display_name, company, city, country, language
          — max contribution = 0.45

Evidence independence:
  Within each tier, group signals by evidence_id.
  Signals from the same evidence_id count ONCE.
  Noisy-OR is applied ONLY across DISTINCT evidence sources.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime, timezone


# ─── Signal type definitions ──────────────────────────────────────────

# Tier 1: strong identifiers (no cap)
TIER_1_SIGNALS: frozenset[str] = frozenset({
    "email_exact", "phone_e164", "wallet_address", "pgp_fingerprint",
})

# Tier 2: moderate signals (cap 0.75)
TIER_2_SIGNALS: frozenset[str] = frozenset({
    "username_exact", "avatar_phash", "domain_owner",
})

# Tier 3: weak signals (cap 0.45)
TIER_3_SIGNALS: frozenset[str] = frozenset({
    "display_name", "company", "city", "country", "language",
})

# Per-tier contribution caps (Tier 1 has no cap — None means uncapped)
TIER_2_CAP: float = 0.75
TIER_3_CAP: float = 0.45

# Per-signal base weights (the noisy-OR contribution per independent observation)
SIGNAL_WEIGHTS: dict[str, float] = {
    # Tier 1
    "email_exact": 0.90,
    "phone_e164": 0.90,
    "wallet_address": 0.95,
    "pgp_fingerprint": 0.95,
    # Tier 2
    "username_exact": 0.55,
    "avatar_phash": 0.50,
    "domain_owner": 0.45,
    # Tier 3
    "display_name": 0.20,
    "company": 0.18,
    "city": 0.15,
    "country": 0.12,
    "language": 0.10,
}


def tier_for_signal(signal_type: str) -> int:
    """Return 1, 2, or 3 for the signal's tier. Unknown → 3."""
    if signal_type in TIER_1_SIGNALS:
        return 1
    if signal_type in TIER_2_SIGNALS:
        return 2
    return 3


def cap_for_tier(tier: int) -> Optional[float]:
    """Return the contribution cap for a tier, or None for uncapped."""
    if tier == 1:
        return None
    if tier == 2:
        return TIER_2_CAP
    return TIER_3_CAP


# ─── Data structures ──────────────────────────────────────────────────

@dataclass(frozen=True)
class Signal:
    """
    A single matched signal between draft and global identity.

    `evidence_id` is the ID of the RawEvidence that produced this signal.
    Two signals with the same evidence_id are DEPENDENT and count once.
    """
    signal_type: str
    draft_value: str
    global_value: str
    evidence_id: str
    weight: float
    tier: int

    def __repr__(self) -> str:
        return (
            f"<Signal type={self.signal_type!r} tier={self.tier} "
            f"weight={self.weight} evidence={self.evidence_id[:8]}...>"
        )


@dataclass(frozen=True)
class MatchedEntity:
    """An entity that exists in both draft and global identities."""
    entity_type: str
    draft_entity_id: str
    global_entity_id: str
    normalized_value: str
    signal_type: str

    def __repr__(self) -> str:
        return f"<MatchedEntity type={self.entity_type!r} value={self.normalized_value!r}>"


@dataclass(frozen=True)
class MatchedRelationship:
    """A relationship that exists in both draft and global identity contexts."""
    relationship_type: str
    source_entity_type: str
    source_normalized_value: str
    target_entity_type: str
    target_normalized_value: str
    evidence_id: str

    def __repr__(self) -> str:
        return f"<MatchedRelationship {self.source_normalized_value}-[{self.relationship_type}]->{self.target_normalized_value}>"


@dataclass
class TierBreakdown:
    """Per-tier scoring breakdown for explainability."""
    tier: int
    signals: list[Signal] = field(default_factory=list)
    distinct_evidence_ids: set[str] = field(default_factory=set)
    raw_score: float = 0.0
    capped_score: float = 0.0
    cap_applied: bool = False

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "signal_count": len(self.signals),
            "distinct_evidence_count": len(self.distinct_evidence_ids),
            "raw_score": round(self.raw_score, 6),
            "capped_score": round(self.capped_score, 6),
            "cap_applied": self.cap_applied,
            "signals": [
                {
                    "signal_type": s.signal_type,
                    "draft_value": s.draft_value,
                    "global_value": s.global_value,
                    "evidence_id": s.evidence_id,
                    "weight": s.weight,
                    "tier": s.tier,
                }
                for s in self.signals
            ],
        }


@dataclass
class CorrelationResult:
    """
    The output of the Correlation Engine.

    This is a pure data object — it carries the evidence but does NOT
    prescribe any action. The Rule Engine consumes this and produces
    ProposedDecisions.
    """
    draft_identity_id: str
    global_identity_id: str
    final_score: float
    decisive_tier: int  # the tier that determined the final score
    tier_breakdown: dict[int, TierBreakdown]  # tier → breakdown
    matched_entities: list[MatchedEntity]
    matched_relationships: list[MatchedRelationship]
    contributing_signals: list[Signal]
    contributing_evidence: list[str]  # evidence_ids
    confidence_reasoning: str  # human-readable
    explanation: dict[str, Any]  # full machine-readable explanation

    def to_dict(self) -> dict:
        return {
            "draft_identity_id": self.draft_identity_id,
            "global_identity_id": self.global_identity_id,
            "final_score": round(self.final_score, 6),
            "decisive_tier": self.decisive_tier,
            "tier_breakdown": {str(k): v.to_dict() for k, v in self.tier_breakdown.items()},
            "matched_entities": [
                {
                    "entity_type": e.entity_type,
                    "draft_entity_id": e.draft_entity_id,
                    "global_entity_id": e.global_entity_id,
                    "normalized_value": e.normalized_value,
                    "signal_type": e.signal_type,
                }
                for e in self.matched_entities
            ],
            "matched_relationships": [
                {
                    "relationship_type": r.relationship_type,
                    "source_entity_type": r.source_entity_type,
                    "source_normalized_value": r.source_normalized_value,
                    "target_entity_type": r.target_entity_type,
                    "target_normalized_value": r.target_normalized_value,
                    "evidence_id": r.evidence_id,
                }
                for r in self.matched_relationships
            ],
            "contributing_signals": [
                {
                    "signal_type": s.signal_type,
                    "evidence_id": s.evidence_id,
                    "weight": s.weight,
                    "tier": s.tier,
                }
                for s in self.contributing_signals
            ],
            "contributing_evidence": list(self.contributing_evidence),
            "confidence_reasoning": self.confidence_reasoning,
            "explanation": self.explanation,
        }


# ─── Signal type mapping ──────────────────────────────────────────────

# Maps entity types to the signal type they produce when matched.
# This is how we translate "both identities have the same email" into
# "email_exact signal".
ENTITY_TYPE_TO_SIGNAL: dict[str, str] = {
    "email": "email_exact",
    "phone": "phone_e164",
    "btc": "wallet_address",
    "eth": "wallet_address",
    "wallet": "wallet_address",
    "pgp_fingerprint": "pgp_fingerprint",
    "username": "username_exact",
    "avatar_hash": "avatar_phash",
    "domain": "domain_owner",
    "display_name": "display_name",
    "company": "company",
    "city": "city",
    "country": "country",
    "language": "language",
}


def signal_type_for_entity(entity_type: str) -> Optional[str]:
    """Return the signal type for an entity type, or None if no mapping."""
    return ENTITY_TYPE_TO_SIGNAL.get(entity_type.strip().lower())


# ─── Correlation Engine ───────────────────────────────────────────────

class CorrelationEngine:
    """
    Pure-function correlation engine.

    Usage:
        engine = CorrelationEngine()
        result = engine.correlate(
            draft_identity_id="...",
            global_identity_id="...",
            draft_entities=[...],
            global_entities=[...],
            draft_relationships=[...],
            global_relationships=[...],
        )
    """

    def correlate(
        self,
        draft_identity_id: str,
        global_identity_id: str,
        draft_entities: list[dict],
        global_entities: list[dict],
        draft_relationships: list[dict] | None = None,
        global_relationships: list[dict] | None = None,
    ) -> CorrelationResult:
        """
        Compute correlation between a draft identity and a global identity.

        Args:
            draft_entities: list of {entity_id, type, normalized_value, evidence_id}
            global_entities: list of {entity_id, type, normalized_value, evidence_id}
            draft_relationships: list of {relationship_type, source_type, source_value, target_type, target_value, evidence_id}
            global_relationships: same shape as draft_relationships

        Returns:
            CorrelationResult with full explanation.

        This method is a pure function. It does not read from or write to
        the database. All inputs are passed explicitly.
        """
        draft_relationships = draft_relationships or []
        global_relationships = global_relationships or []

        # 1. Find matched entities (entities in both draft and global with same type + normalized_value)
        matched_entities, signals_from_entities = self._match_entities(
            draft_entities, global_entities,
        )

        # 2. Find matched relationships
        matched_relationships, signals_from_relationships = self._match_relationships(
            draft_relationships, global_relationships,
        )

        # 3. Combine all signals
        all_signals = signals_from_entities + signals_from_relationships

        # 4. Compute per-tier scores with evidence independence
        tier_breakdown = self._compute_tier_scores(all_signals)

        # 5. Combine tiers into final score
        final_score, decisive_tier = self._combine_tiers(tier_breakdown)

        # 6. Build explanation
        contributing_evidence = sorted({s.evidence_id for s in all_signals})
        contributing_signals = all_signals

        reasoning = self._build_reasoning(
            tier_breakdown, final_score, decisive_tier, len(contributing_evidence),
        )
        explanation = self._build_explanation(
            draft_identity_id, global_identity_id,
            tier_breakdown, final_score, decisive_tier,
            matched_entities, matched_relationships,
            contributing_signals, contributing_evidence,
            reasoning,
        )

        return CorrelationResult(
            draft_identity_id=draft_identity_id,
            global_identity_id=global_identity_id,
            final_score=final_score,
            decisive_tier=decisive_tier,
            tier_breakdown=tier_breakdown,
            matched_entities=matched_entities,
            matched_relationships=matched_relationships,
            contributing_signals=contributing_signals,
            contributing_evidence=contributing_evidence,
            confidence_reasoning=reasoning,
            explanation=explanation,
        )

    # ─── Entity matching ─────────────────────────────────────────────

    def _match_entities(
        self,
        draft_entities: list[dict],
        global_entities: list[dict],
    ) -> tuple[list[MatchedEntity], list[Signal]]:
        """
        Find entities that appear in both draft and global with the same
        (type, normalized_value). Each match produces a Signal.
        """
        # Index global entities by (type, normalized_value)
        global_index: dict[tuple[str, str], dict] = {}
        for ge in global_entities:
            key = (ge["type"].strip().lower(), ge["normalized_value"].strip().lower())
            global_index[key] = ge

        matched: list[MatchedEntity] = []
        signals: list[Signal] = []

        for de in draft_entities:
            key = (de["type"].strip().lower(), de["normalized_value"].strip().lower())
            ge = global_index.get(key)
            if not ge:
                continue

            signal_type = signal_type_for_entity(de["type"])
            if not signal_type:
                continue

            tier = tier_for_signal(signal_type)
            weight = SIGNAL_WEIGHTS.get(signal_type, 0.1)

            matched.append(MatchedEntity(
                entity_type=de["type"],
                draft_entity_id=de["entity_id"],
                global_entity_id=ge["entity_id"],
                normalized_value=de["normalized_value"],
                signal_type=signal_type,
            ))

            signals.append(Signal(
                signal_type=signal_type,
                draft_value=de["normalized_value"],
                global_value=ge["normalized_value"],
                evidence_id=de.get("evidence_id", "unknown"),
                weight=weight,
                tier=tier,
            ))

        return matched, signals

    # ─── Relationship matching ───────────────────────────────────────

    def _match_relationships(
        self,
        draft_relationships: list[dict],
        global_relationships: list[dict],
    ) -> tuple[list[MatchedRelationship], list[Signal]]:
        """
        Find relationships that appear in both draft and global.

        A relationship match produces a Tier-3 'domain_owner' signal
        (relationships are corroborating evidence, not strong signals).
        """
        global_index: dict[tuple, dict] = {}
        for gr in global_relationships:
            key = self._rel_key(gr)
            global_index[key] = gr

        matched: list[MatchedRelationship] = []
        signals: list[Signal] = []

        for dr in draft_relationships:
            key = self._rel_key(dr)
            gr = global_index.get(key)
            if not gr:
                continue

            matched.append(MatchedRelationship(
                relationship_type=dr["relationship_type"],
                source_entity_type=dr["source_entity_type"],
                source_normalized_value=dr["source_normalized_value"],
                target_entity_type=dr["target_entity_type"],
                target_normalized_value=dr["target_normalized_value"],
                evidence_id=dr.get("evidence_id", "unknown"),
            ))

            # Relationship matches contribute as Tier-3 'domain_owner' signals
            # (corroborating evidence, weak on their own)
            signals.append(Signal(
                signal_type="domain_owner",
                draft_value=f"{dr['source_normalized_value']}->{dr['target_normalized_value']}",
                global_value=f"{gr['source_normalized_value']}->{gr['target_normalized_value']}",
                evidence_id=dr.get("evidence_id", "unknown"),
                weight=SIGNAL_WEIGHTS["domain_owner"],
                tier=3,
            ))

        return matched, signals

    def _rel_key(self, rel: dict) -> tuple:
        """Build a hashable key for a relationship."""
        return (
            rel["relationship_type"].strip().lower(),
            rel["source_entity_type"].strip().lower(),
            rel["source_normalized_value"].strip().lower(),
            rel["target_entity_type"].strip().lower(),
            rel["target_normalized_value"].strip().lower(),
        )

    # ─── Tier scoring with evidence independence ─────────────────────

    def _compute_tier_scores(self, signals: list[Signal]) -> dict[int, TierBreakdown]:
        """
        For each tier:
          1. Group signals by evidence_id.
          2. Within each evidence_id group, keep only the strongest signal
             (they're dependent — count once).
          3. Apply noisy-OR across the distinct evidence sources.
          4. Apply the tier cap.
        """
        # Group signals by tier
        by_tier: dict[int, list[Signal]] = {1: [], 2: [], 3: []}
        for s in signals:
            if s.tier not in by_tier:
                by_tier[s.tier] = []
            by_tier[s.tier].append(s)

        breakdowns: dict[int, TierBreakdown] = {}
        for tier, tier_signals in by_tier.items():
            if not tier_signals:
                breakdowns[tier] = TierBreakdown(tier=tier)
                continue

            # Group by evidence_id — dependent signals count once
            by_evidence: dict[str, list[Signal]] = {}
            for s in tier_signals:
                by_evidence.setdefault(s.evidence_id, []).append(s)

            # Within each evidence group, keep the strongest signal
            distinct_signals: list[Signal] = []
            for ev_id, group in by_evidence.items():
                strongest = max(group, key=lambda s: s.weight)
                distinct_signals.append(strongest)

            # Noisy-OR across distinct evidence sources
            prob_none = 1.0
            for s in distinct_signals:
                w = max(0.0, min(1.0, s.weight))
                prob_none *= (1.0 - w)
            raw_score = 1.0 - prob_none

            # Apply tier cap
            cap = cap_for_tier(tier)
            capped_score = raw_score
            cap_applied = False
            if cap is not None and raw_score > cap:
                capped_score = cap
                cap_applied = True

            breakdowns[tier] = TierBreakdown(
                tier=tier,
                signals=tier_signals,  # all signals, not just distinct
                distinct_evidence_ids={s.evidence_id for s in distinct_signals},
                raw_score=raw_score,
                capped_score=capped_score,
                cap_applied=cap_applied,
            )

        return breakdowns

    # ─── Tier combination ────────────────────────────────────────────

    def _combine_tiers(
        self, tier_breakdown: dict[int, TierBreakdown],
    ) -> tuple[float, int]:
        """
        Combine per-tier scores into a final score.

        Algorithm:
          - The decisive tier is the LOWEST tier number (strongest) that
            has any signals. If Tier 1 has signals, Tier 1 is decisive.
          - The final score is the decisive tier's capped score, PLUS
            a small boost from lower tiers (corroboration).
          - The boost is 10% of each lower tier's capped score, summed.
          - Final score is clamped to [0.0, 1.0].

        This ensures Tier 1 can exceed the threshold on its own, while
        Tier 2 and Tier 3 can only contribute corroboration.
        """
        # Find decisive tier (lowest tier number with signals)
        decisive_tier = 3  # default to weakest
        for tier in sorted(tier_breakdown.keys()):
            if tier_breakdown[tier].signals:
                decisive_tier = tier
                break

        decisive_score = tier_breakdown[decisive_tier].capped_score

        # Corroboration boost from weaker tiers
        boost = 0.0
        for tier, tb in tier_breakdown.items():
            if tier <= decisive_tier:
                continue
            if tb.signals:
                boost += 0.1 * tb.capped_score

        final_score = max(0.0, min(1.0, decisive_score + boost))
        return final_score, decisive_tier

    # ─── Explanation builders ────────────────────────────────────────

    def _build_reasoning(
        self,
        tier_breakdown: dict[int, TierBreakdown],
        final_score: float,
        decisive_tier: int,
        evidence_count: int,
    ) -> str:
        """Build a human-readable reasoning string."""
        parts: list[str] = []
        parts.append(f"Final score: {final_score:.4f}")
        parts.append(f"Decisive tier: {decisive_tier}")
        parts.append(f"Distinct evidence sources: {evidence_count}")

        for tier in sorted(tier_breakdown.keys()):
            tb = tier_breakdown[tier]
            if not tb.signals:
                continue
            cap_note = f" (capped at {tb.capped_score:.4f})" if tb.cap_applied else ""
            parts.append(
                f"Tier {tier}: {len(tb.signals)} signals across "
                f"{len(tb.distinct_evidence_ids)} distinct evidence → "
                f"raw {tb.raw_score:.4f}{cap_note}"
            )

        return "; ".join(parts)

    def _build_explanation(
        self,
        draft_identity_id: str,
        global_identity_id: str,
        tier_breakdown: dict[int, TierBreakdown],
        final_score: float,
        decisive_tier: int,
        matched_entities: list[MatchedEntity],
        matched_relationships: list[MatchedRelationship],
        contributing_signals: list[Signal],
        contributing_evidence: list[str],
        reasoning: str,
    ) -> dict[str, Any]:
        """Build the full machine-readable explanation."""
        return {
            "engine": "CorrelationEngine",
            "engine_version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "draft_identity_id": draft_identity_id,
            "global_identity_id": global_identity_id,
            "final_score": round(final_score, 6),
            "decisive_tier": decisive_tier,
            "tier_breakdown": {str(k): v.to_dict() for k, v in tier_breakdown.items()},
            "matched_entity_count": len(matched_entities),
            "matched_relationship_count": len(matched_relationships),
            "contributing_signal_count": len(contributing_signals),
            "contributing_evidence_ids": contributing_evidence,
            "reasoning": reasoning,
            "signal_weights": dict(SIGNAL_WEIGHTS),
            "tier_caps": {
                "tier_1": None,
                "tier_2": TIER_2_CAP,
                "tier_3": TIER_3_CAP,
            },
        }


__all__ = [
    "CorrelationEngine", "CorrelationResult", "Signal", "MatchedEntity",
    "MatchedRelationship", "TierBreakdown",
    "TIER_1_SIGNALS", "TIER_2_SIGNALS", "TIER_3_SIGNALS",
    "TIER_2_CAP", "TIER_3_CAP", "SIGNAL_WEIGHTS",
    "tier_for_signal", "cap_for_tier", "signal_type_for_entity",
    "ENTITY_TYPE_TO_SIGNAL",
]
