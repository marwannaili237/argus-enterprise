"""
Centralized confidence configuration for Argus.

Single source of truth for:
  - Signal tier classification (which entity types are strong vs weak signals)
  - Default signal weights per tier
  - Identity promotion thresholds
  - Quarantine thresholds

Design rules:
  - No magic numbers inline anywhere else in the codebase.
  - All thresholds live here as named constants.
  - Tiers are configurable via env vars (override at runtime) but default
    to deterministic values.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


# ─── Signal tiers ─────────────────────────────────────────────────────
# Tier 1: Strong identifiers. A single match is highly indicative of
#         same-identity (but never conclusive alone).
# Tier 2: Moderate signals. Useful corroborating evidence.
# Tier 3: Weak signals. Alone, almost never sufficient. Useful only
#         to break ties between already-strong candidates.
#
# Weights are the noisy-OR contribution per independent observation.
# They are NOT additive — see IdentityResolutionService for the math.

TIER_1_TYPES: frozenset[str] = frozenset({
    "email", "phone", "btc", "eth", "wallet",
    # PGP fingerprint is a strong biometric-equivalent
    "pgp_fingerprint",
})

TIER_2_TYPES: frozenset[str] = frozenset({
    "username", "avatar_hash",
})

TIER_3_TYPES: frozenset[str] = frozenset({
    "display_name", "city", "company", "domain",
})

# Default weights per tier. These are the contribution to the noisy-OR
# formula PER INDEPENDENT OBSERVATION (not per source — see evidence
# independence rules in IdentityResolutionService).
TIER_1_WEIGHT: float = 0.85
TIER_2_WEIGHT: float = 0.50
TIER_3_WEIGHT: float = 0.20

# Override via env vars (parsed at module import — settings pattern)
def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


TIER_1_WEIGHT = _env_float("ARGUS_TIER1_WEIGHT", TIER_1_WEIGHT)
TIER_2_WEIGHT = _env_float("ARGUS_TIER2_WEIGHT", TIER_2_WEIGHT)
TIER_3_WEIGHT = _env_float("ARGUS_TIER3_WEIGHT", TIER_3_WEIGHT)


# ─── Identity status thresholds ───────────────────────────────────────
# An identity auto-promotes from tentative → confirmed when its
# confidence reaches this value. Investigators can also manually promote.
IDENTITY_PROMOTION_THRESHOLD: float = _env_float("ARGUS_IDENTITY_PROMOTION_THRESHOLD", 0.85)

# Below this, identity stays tentative.
# Below DISPUTE_THRESHOLD (manually set), identity is disputed.
IDENTITY_DISPUTE_THRESHOLD: float = _env_float("ARGUS_IDENTITY_DISPUTE_THRESHOLD", 0.30)


# ─── Quarantine thresholds ────────────────────────────────────────────
# A plugin is quarantined after this many STRUCTURAL failures within
# the quarantine window. Transient failures never trigger quarantine.
QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD: int = int(
    os.getenv("ARGUS_QUARANTINE_THRESHOLD", "3")
)
QUARANTINE_WINDOW_HOURS: int = int(
    os.getenv("ARGUS_QUARANTINE_WINDOW_HOURS", "24")
)


# ─── Ingestion transaction bounds ─────────────────────────────────────
# Maximum entities/observations/relationships per single ingestion call.
# Prevents a runaway plugin from blowing up the transaction.
INGESTION_MAX_ENTITIES_PER_CALL: int = int(
    os.getenv("ARGUS_INGESTION_MAX_ENTITIES", "500")
)
INGESTION_MAX_OBSERVATIONS_PER_CALL: int = int(
    os.getenv("ARGUS_INGESTION_MAX_OBSERVATIONS", "1000")
)
INGESTION_MAX_RELATIONSHIPS_PER_CALL: int = int(
    os.getenv("ARGUS_INGESTION_MAX_RELATIONSHIPS", "200")
)


# ─── Signal weight lookup ─────────────────────────────────────────────

def signal_weight_for_type(entity_type: str) -> float:
    """
    Return the default signal weight for an entity type.

    Deterministic: same input → same output, always.
    Unknown types default to TIER_3 (weak) — better to under-claim
    than over-claim.
    """
    t = (entity_type or "").strip().lower()
    if t in TIER_1_TYPES:
        return TIER_1_WEIGHT
    if t in TIER_2_TYPES:
        return TIER_2_WEIGHT
    if t in TIER_3_TYPES:
        return TIER_3_WEIGHT
    return TIER_3_WEIGHT


def tier_for_type(entity_type: str) -> int:
    """Return 1, 2, or 3 for the tier. Unknown → 3."""
    t = (entity_type or "").strip().lower()
    if t in TIER_1_TYPES:
        return 1
    if t in TIER_2_TYPES:
        return 2
    return 3


# ─── Evidence independence rules ──────────────────────────────────────
# Two observations are INDEPENDENT if they come from different (plugin, source)
# pairs. Two observations from the same plugin execution on the same source
# are DEPENDENT — they count as one signal, not two.
#
# This is enforced in IdentityResolutionService.compute_confidence by
# grouping observations by (plugin_id, source_url) before applying noisy-OR.

@dataclass(frozen=True)
class EvidenceSource:
    """A (plugin_id, source_url) pair — the unit of evidence independence."""
    plugin_id: str
    source_url: str | None = None

    def __hash__(self) -> int:
        return hash((self.plugin_id, self.source_url or ""))


__all__ = [
    "TIER_1_TYPES", "TIER_2_TYPES", "TIER_3_TYPES",
    "TIER_1_WEIGHT", "TIER_2_WEIGHT", "TIER_3_WEIGHT",
    "IDENTITY_PROMOTION_THRESHOLD", "IDENTITY_DISPUTE_THRESHOLD",
    "QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD", "QUARANTINE_WINDOW_HOURS",
    "INGESTION_MAX_ENTITIES_PER_CALL",
    "INGESTION_MAX_OBSERVATIONS_PER_CALL",
    "INGESTION_MAX_RELATIONSHIPS_PER_CALL",
    "signal_weight_for_type", "tier_for_type",
    "EvidenceSource",
]
