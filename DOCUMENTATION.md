# Argus Enterprise — Technical Documentation

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Canonical Entity Layer](#3-canonical-entity-layer)
4. [Pipeline Stages](#4-pipeline-stages)
5. [Correlation Engine](#5-correlation-engine)
6. [Rule Engine](#6-rule-engine)
7. [Decision Engine](#7-decision-engine)
8. [Review Queue](#8-review-queue)
9. [Event Store & Replay](#9-event-store--replay)
10. [Identity Resolution](#10-identity-resolution)
11. [Plugin Adapter Framework](#11-plugin-adapter-framework)
12. [Confidence & Signal Tiers](#12-confidence--signal-tiers)
13. [Provenance](#13-provenance)
14. [Split Identity](#14-split-identity)
15. [Explainability](#15-explainability)
16. [Database Schema](#16-database-schema)
17. [API Reference](#17-api-reference)
18. [Testing](#18-testing)
19. [Deployment](#19-deployment)
20. [Security](#20-security)

---

## 1. Introduction

Argus Enterprise is an extension of the Argus OSINT platform that adds enterprise-grade identity resolution, correlation, and decision-making capabilities. The system is designed around four absolute principles:

- **Deterministic**: Every conclusion is explainable, every score is reproducible
- **Auditable**: Every state change is an event; nothing happens without provenance
- **Reversible**: Every decision can be reverted; replay rebuilds state from events
- **Safe**: Cross-investigation identity merges are forbidden by design

### Design Philosophy

- Never introduce unnecessary complexity
- Prefer deterministic algorithms
- Every conclusion must be explainable
- Every score must be reproducible
- Every relationship must have provenance
- Every decision must be reversible
- No hidden magic, no duplicated logic, no breaking changes
- Everything must be testable, everything must be async

---

## 2. System Architecture

### Component Responsibilities

| Component | Responsibility | Cannot Do |
|---|---|---|
| Plugin Runner | Runs plugins | Write to canonical store |
| Adapter | Translates legacy output | Modify DB |
| Validator | Validates structure | Compute confidence |
| Normalizer | Normalizes values | Modify DB |
| Canonical Service | Stores entities | Compute correlation |
| Identity Resolution | Clusters within one investigation | Cross-investigation merges |
| Correlation Engine | Computes evidence (pure function) | Write to DB, merge identities, create decisions |
| Rule Engine | Evaluates policies | Modify DB |
| Decision Engine | Executes approved actions | Compute confidence/similarity/thresholds |
| Review Queue | Handles investigator approval | Execute merges directly |
| Event Store | Audit trail + replay | Modify current state tables directly |

### Pipeline Flow

```
Plugin → Adapter → Validator → Normalizer → Canonical Store
  → Identity Resolution (within investigation only)
  → Correlation Engine (pure function, no DB)
  → Rule Engine (4 rules, conflict resolution)
  → Review Queue (human approval)
  → Decision Engine (idempotent execution)
  → Event Store (append-only, replayable)
```

---

## 3. Canonical Entity Layer

### Overview

The canonical entity layer provides a cross-investigation, normalized data model. It sits alongside (not replaces) the existing per-investigation Evidence table.

### Models

#### CanonicalEntity
```python
class CanonicalEntity(Base):
    __tablename__ = "canonical_entities"
    id: Mapped[str]           # UUID PK
    type: Mapped[str]         # email, username, phone, domain, ip, wallet...
    normalized_value: Mapped[str]  # normalized form
    raw_value: Mapped[str]    # original value as seen by plugin
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    investigation_count: Mapped[int]  # how many investigations touched this
    source_count: Mapped[int]         # how many sources provided this
    # UNIQUE(type, normalized_value)
```

#### Identity
```python
class Identity(Base):
    __tablename__ = "identities"
    id: Mapped[str]           # UUID PK
    label: Mapped[Optional[str]]  # human-assigned name
    confidence: Mapped[float]     # 0.0 - 1.0
    status: Mapped[str]           # tentative | confirmed | disputed | merged
    merged_into: Mapped[Optional[str]]  # FK self, for merge tracking
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
```

#### RawEvidence
```python
class RawEvidence(Base):
    __tablename__ = "raw_evidence"
    id: Mapped[str]               # UUID PK
    investigation_id: Mapped[str]
    plugin_id: Mapped[str]
    plugin_version: Mapped[str]
    execution_id: Mapped[str]
    target: Mapped[str]
    collected_at: Mapped[datetime]
    raw_response: Mapped[dict]    # JSON, immutable
    source_url: Mapped[Optional[str]]
    source_reliability: Mapped[Optional[float]]
```

### Full Model List

| Model | Table | Purpose |
|---|---|---|
| `CanonicalEntity` | `canonical_entities` | One row per real-world entity |
| `Identity` | `identities` | Real-world actor grouping |
| `IdentityEntity` | `identity_entities` | M2M Identity ↔ CanonicalEntity with signal_weight |
| `RawEvidence` | `raw_evidence` | Immutable plugin output |
| `Observation` | `observations` | Atomic facts from evidence |
| `EntityObservation` | `entity_observations` | M2M Entity ↔ Observation |
| `Relationship` | `relationships` | Directed edges between entities |
| `RelationshipProvenance` | `relationship_provenance` | Evidence supporting a relationship |
| `EntityInvestigationLink` | `entity_investigation_links` | M2M Entity ↔ Investigation |
| `IdentityEvent` | `identity_events` | Audit trail for identity ops |
| `PluginHealthRecord` | `plugin_health` | Persisted plugin health |
| `AdapterFixtureRecord` | `adapter_fixtures` | Golden fixture registry |
| `DecisionEvent` | `decision_events` | Decision audit trail |
| `ReviewQueueItem` | `review_queue` | Pending human review |
| `IdentityMergeRecord` | `identity_merge_records` | Merge provenance for split |

---

## 4. Pipeline Stages

### Stage 1: Plugin Execution
Plugins run via the concurrent plugin runner (semaphore-bounded, default 5 parallel). Each plugin produces a legacy `PluginResult` dataclass.

### Stage 2: Adapter Translation
The adapter for the plugin's `plugin_id` translates the legacy result into a canonical `PluginResult` (Pydantic v2). If no adapter is registered, ingestion is skipped.

### Stage 3: Validation
`PluginResultValidator` checks:
- Schema version
- Required fields non-empty
- Confidence in [0.0, 1.0]
- Entity types in allowed set
- Relationship types in allowed set (or `x-*` namespaced)
- No self-relationships
- UUID format on request_id/execution_id
- executed_at not too far in the future

### Stage 4: Normalization
`Normalizer` applies type-specific normalization:
- Email: lowercase, strip, remove `mailto:`
- Domain: lowercase, strip `www.`, punycode IDN
- Phone: E.164 via libphonenumber
- Username: lowercase, strip `@`
- Hash: uppercase hex, strip prefixes
- IP: compress IPv6, strip brackets/ports
- URL: lowercase scheme+host, strip default ports
- And 7 more types

### Stage 5: Canonical Store
`IngestionService` persists (in a single transaction):
- `RawEvidence` (immutable)
- `Observation` rows (one per observation)
- `CanonicalEntity` upserts (normalize + INSERT ON CONFLICT)
- `EntityInvestigationLink` (M2M)
- `EntityObservation` (M2M)
- `Relationship` upserts
- `RelationshipProvenance` (evidence → relationship)

### Stage 6: Identity Resolution
`IdentityResolutionService` clusters entities within ONE investigation using union-find. Confidence computed via noisy-OR over independent evidence sources.

### Stage 7: Correlation
`CorrelationEngine` compares a draft identity against a global identity. Pure function — no DB access.

### Stage 8: Rule Evaluation
`RuleEngine` runs all registered rules against the `CorrelationResult`. Conflict resolution: most conservative wins.

### Stage 9: Review Queue (if needed)
If a rule proposes `QUEUE_FOR_REVIEW`, a `ReviewQueueItem` is created. A human approves or rejects via the API.

### Stage 10: Decision Execution
`DecisionEngine` executes the approved decision (merge, promote, or reject). Emits `DecisionEvent` for every state change.

### Stage 11: Event Store
All events are append-only. The `ReplayEngine` can rebuild state from events.

---

## 5. Correlation Engine

### File
`argus/canonical/correlation.py`

### Properties
- **Pure function**: no DB access, no side effects
- **Deterministic**: same input → same output
- **Never merges identities**: only computes evidence
- **Never creates decisions**: only returns `CorrelationResult`

### Signal Tiers

| Tier | Signals | Cap | Base Weight |
|---|---|---|---|
| 1 | email_exact, phone_e164, wallet_address, pgp_fingerprint | None | 0.90-0.95 |
| 2 | username_exact, avatar_phash, domain_owner | 0.75 | 0.45-0.55 |
| 3 | display_name, company, city, country, language | 0.45 | 0.10-0.20 |

### Evidence Independence

Within each tier:
1. Group signals by `evidence_id`
2. Signals from the same `evidence_id` are **dependent** — only the strongest counts
3. Apply noisy-OR across distinct `evidence_id` groups

### Scoring Algorithm

```
For each tier:
  1. Group signals by evidence_id
  2. Keep strongest per group (dependent signals count once)
  3. noisy-OR across distinct groups: 1 - product(1 - w_i)
  4. Apply tier cap (Tier 2: 0.75, Tier 3: 0.45, Tier 1: uncapped)

Combine tiers:
  - Decisive tier = lowest tier number with signals
  - Final score = decisive_tier.capped_score + 0.1 * sum(lower_tier.capped_scores)
  - Clamp to [0.0, 1.0]
```

### Output

```python
@dataclass
class CorrelationResult:
    final_score: float
    decisive_tier: int
    tier_breakdown: dict[int, TierBreakdown]
    matched_entities: list[MatchedEntity]
    matched_relationships: list[MatchedRelationship]
    contributing_signals: list[Signal]
    contributing_evidence: list[str]
    confidence_reasoning: str
    explanation: dict[str, Any]
```

---

## 6. Rule Engine

### Files
- `argus/canonical/rules/engine.py` — Rule protocol, RuleRegistry, RuleEngine
- `argus/canonical/rules/proposed_decision.py` — ProposedDecision, DecisionKind, resolve_conflicts
- `argus/canonical/rules/high_confidence_auto_merge.py`
- `argus/canonical/rules/review_band.py`
- `argus/canonical/rules/watchlist.py`
- `argus/canonical/rules/no_overlap_promotion.py`

### Rule Protocol

```python
@runtime_checkable
class Rule(Protocol):
    rule_id: str
    rule_version: str
    def evaluate(self, correlation: CorrelationResult) -> Optional[ProposedDecision]: ...
```

### Reference Rules

| Rule | Condition | Action | Threshold |
|---|---|---|---|
| HighConfidenceAutoMergeRule | score ≥ 0.90 AND tier == 1 | AUTO_MERGE | 0.90 |
| ReviewBandRule | 0.50 ≤ score < 0.90 | QUEUE_FOR_REVIEW | [0.50, 0.90) |
| WatchlistRule | Any matched entity on watchlist | QUEUE_FOR_REVIEW | Always |
| NoOverlapPromotionRule | No matches + has evidence | PROMOTE_TO_GLOBAL | — |

### Conflict Resolution

Priority (most conservative wins):
```
REJECT (0) > QUEUE_FOR_REVIEW (1) > PROMOTE_TO_GLOBAL (2) > AUTO_MERGE (3)
```

If same priority, higher correlation score wins.

---

## 7. Decision Engine

### File
`argus/canonical/decision_engine.py`

### Responsibilities (ONLY these)
1. **Idempotency**: re-processing same decision_id is no-op
2. **Event creation**: every state change emits DecisionEvent
3. **Dispatch**: routes to executor based on DecisionKind
4. **Merge execution**: calls IdentityResolutionService.merge_identities
5. **Split execution**: reverses merge via IdentityMergeRecord
6. **Watchlist notification**: notifies watchers

### NEVER does
- Compute confidence
- Compute similarity
- Compute thresholds

### Decision Kinds

| Kind | Action |
|---|---|
| AUTO_MERGE | Execute merge immediately |
| PROMOTE_TO_GLOBAL | Promote draft to confirmed status |
| QUEUE_FOR_REVIEW | Create ReviewQueueItem for human |
| REJECT | Record rejection (no state change) |

### Idempotency

The engine checks for existing `DecisionEvent` rows with the same `decision_id`. If found, the decision is skipped (status="skipped").

---

## 8. Review Queue

### File
`argus/api/routes/review_queue.py`

### CRITICAL RULE
Both Telegram and Dashboard call the **exact same API endpoints**. No Telegram-specific logic exists. Business logic lives only in the Decision Engine.

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/review-queue` | List (paginated, filterable) |
| GET | `/api/v1/review-queue/{id}` | Get single item |
| POST | `/api/v1/review-queue/{id}/approve` | Approve → executes merge |
| POST | `/api/v1/review-queue/{id}/reject` | Reject → no merge |
| GET | `/api/v1/review-queue/{id}/events` | Decision audit trail |

### Status Lifecycle
```
pending → approved → executed
pending → rejected
```

---

## 9. Event Store & Replay

### Event Tables

#### decision_events
Actions: `requested`, `evaluated`, `approved`, `rejected`, `executed`, `reverted`

#### identity_events
Actions: `created`, `promoted`, `disputed`, `merged`, `split`

### Event Fields
Every event stores:
- `rule_id`, `rule_version` — which rule triggered it
- `actor` — user_id, "system", or "rule:<rule_id>"
- `timestamp`
- `payload` — event-specific data (JSON)
- `config_snapshot` — configuration at event time (JSON)

### Replay Engine

**File:** `argus/canonical/replay.py`

#### Algorithm
1. Snapshot current identity state (ids, status, confidence, merged_into)
2. Delete derived state (identities, identity_entities, merge_records)
3. Load all events sorted by timestamp
4. Apply each event:
   - `created` → create identity + restore entity links
   - `promoted` → set status to confirmed
   - `merged` → reparent entities, mark source as merged, create merge record
   - `split` → reverse merge, reactivate source
5. Recompute confidences
6. Compare snapshots (tolerance: 0.001 for float confidence)

#### Verification
```python
engine = ReplayEngine(db)
result = await engine.replay(verify=True)
assert result.verification_passed
```

---

## 10. Identity Resolution

### File
`argus/canonical/services/identity.py`

### CRITICAL RULE
**Identity resolution happens WITHIN one investigation only. Cross-investigation identity merges are FORBIDDEN.**

### Algorithm
1. Load all canonical entities linked to the investigation
2. Group into identity candidates using union-find:
   - Two entities merge if they were co-observed in the same evidence source
   - AND at least one is a Tier-1 entity
3. For each candidate, find-or-create an Identity
4. Compute confidence using noisy-OR over independent evidence sources
5. Auto-promote to `confirmed` at confidence ≥ 0.85

### Confidence Computation

```
For each entity in the identity:
  - Count distinct (plugin_id, source_url) pairs
  - Tier 1: base weight, no inflation
  - Tier 2/3: logarithmic boost for multiple independent sources

Combine across entities:
  confidence = 1 - product(1 - w_i)
```

### Evidence Independence
Two observations are independent iff they come from different `(plugin_id, source_url)` pairs. Observations from the same plugin execution count as ONE signal.

---

## 11. Plugin Adapter Framework

### Directory
`argus/canonical/adapters/`

### Components

| Component | File | Purpose |
|---|---|---|
| BaseAdapter | `base.py` | ABC for all adapters |
| AdapterContext | `base.py` | Metadata for adapt() calls |
| AdapterRegistry | `registry.py` | Explicit registry, no fallback |
| DefaultLegacyAdapter | `default_adapter.py` | Legacy → canonical translator |
| GoldenFixture | `fixtures.py` | Known-good plugin output |
| compliance_check_all | `compliance.py` | Run adapters against fixtures |
| PluginHealthTracker | `health.py` | Transient/structural classification |

### Registration Model
- Adapters are NOT auto-registered
- `register_default_adapters()` registers DefaultLegacyAdapter for 21 legacy plugins
- No fallback — if no adapter, ingestion is skipped

### Plugin Health

| Failure Type | Examples | Affects Health? |
|---|---|---|
| Transient | Timeout, 429, 5xx, connection reset | No |
| Structural | Schema failure, adapter failure, fixture regression | Yes |

Quarantine after 3 structural failures in 24 hours.

---

## 12. Confidence & Signal Tiers

### File
`argus/canonical/confidence.py`

### Tier 1 (Strong)
Types: `email`, `phone`, `btc`, `eth`, `wallet`, `pgp_fingerprint`
Weight: 0.85 (per independent observation)

### Tier 2 (Moderate)
Types: `username`, `avatar_hash`
Weight: 0.50

### Tier 3 (Weak)
Types: `display_name`, `city`, `company`, `domain`
Weight: 0.20

### All Thresholds (env-configurable)

| Threshold | Default | Env Var |
|---|---|---|
| Tier 1 weight | 0.85 | `ARGUS_TIER1_WEIGHT` |
| Tier 2 weight | 0.50 | `ARGUS_TIER2_WEIGHT` |
| Tier 3 weight | 0.20 | `ARGUS_TIER3_WEIGHT` |
| Identity promotion | 0.85 | `ARGUS_IDENTITY_PROMOTION_THRESHOLD` |
| Identity dispute | 0.30 | `ARGUS_IDENTITY_DISPUTE_THRESHOLD` |
| Quarantine failures | 3 | `ARGUS_QUARANTINE_THRESHOLD` |
| Quarantine window | 24h | `ARGUS_QUARANTINE_WINDOW_HOURS` |
| Max entities/ingestion | 500 | `ARGUS_INGESTION_MAX_ENTITIES` |
| Max observations/ingestion | 1000 | `ARGUS_INGESTION_MAX_OBSERVATIONS` |
| Max relationships/ingestion | 200 | `ARGUS_INGESTION_MAX_RELATIONSHIPS` |

---

## 13. Provenance

### Chain
```
Relationship
  ↓ RelationshipProvenance
RawEvidence (immutable JSON)
  ↓
Observation (atomic fact)
  ↓
Plugin (plugin_id, plugin_version, execution_id)
  ↓
Source (source_url, source_reliability)
```

**Nothing enters the graph without provenance.**

### ProvenanceService Methods
- `record_evidence(plugin_result)` → RawEvidence
- `record_observation(evidence_id, obs)` → Observation
- `link_observation_to_entity(obs_id, entity_id)`
- `link_evidence_to_relationship(evidence_id, relationship_id, obs_id)`
- `get_evidence_chain(entity_id)` → list[RawEvidence]
- `get_full_provenance(relationship_id)` → ProvenanceChain

---

## 14. Split Identity

### Method
```python
DecisionEngine.split_identity(merge_record_id, actor, reason)
```

### Process
1. Read `IdentityMergeRecord` (contains `moved_entities` with original signal_weights)
2. Reparent entities back to source identity
3. Restore original `signal_weight` values
4. Reactivate source identity (status = `tentative`)
5. Recompute confidence
6. Mark merge record as `reverted`
7. Emit `IdentityEvent("split")`
8. Emit `DecisionEvent("reverted")`

### Constraints
- Cannot split an already-reverted merge
- Cannot split if source identity was deleted

---

## 15. Explainability

Every `ProposedDecision` includes:

| Field | Content |
|---|---|
| `rule_id` | Which rule fired |
| `rule_version` | Rule version |
| `kind` | AUTO_MERGE / QUEUE_FOR_REVIEW / PROMOTE_TO_GLOBAL / REJECT |
| `correlation_score` | Final score from Correlation Engine |
| `reasoning` | Human-readable explanation |
| `explanation` | Full machine-readable chain |

### Explanation Structure
```json
{
  "rule_id": "high_confidence_auto_merge",
  "rule_version": "1.0.0",
  "threshold": 0.90,
  "actual_score": 0.99,
  "decisive_tier": 1,
  "tier1_signal_types": ["email_exact"],
  "contributing_evidence_count": 2,
  "correlation_explanation": {
    "final_score": 0.99,
    "tier_breakdown": { ... },
    "signal_weights": { ... },
    "tier_caps": { "tier_1": null, "tier_2": 0.75, "tier_3": 0.45 }
  }
}
```

**Nothing merges without an explainable chain.**

---

## 16. Database Schema

### Migrations

| Migration | Description |
|---|---|
| 0001 | Canonical entity layer (9 tables) |
| 0002 | Plugin adapter framework (3 tables: identity_events, plugin_health, adapter_fixtures) |
| 0003 | Decision/review/event store (3 tables: decision_events, review_queue, identity_merge_records) |

### Total: 15 canonical tables + 16 legacy tables = 31 tables

### Key Constraints
- UUID PKs (String(36) for SQLite/PostgreSQL portability)
- UNIQUE on `(type, normalized_value)` for canonical_entities
- UNIQUE on `decision_id` for review_queue
- CASCADE on all FKs from parent tables
- Indexes on all query-critical columns

---

## 17. API Reference

### Total: 57 endpoints

See [README.md](README.md#api-reference) for full list.

### Authentication
All endpoints (except `/api/health`, `/api/ready`, `/api/v1/users/auth/telegram`) require JWT Bearer token.

JWT can be passed via:
- `Authorization: Bearer <token>` header
- `?token=<token>` query parameter (for export downloads)

---

## 18. Testing

### Run Tests
```bash
PYTHONPATH=argus python3.13 -m pytest tests/ -v
```

### Test Count: 501 (all passing, zero regressions)

| Category | Count |
|---|---|
| Correlation engine | 38 |
| Rule engine | 36 |
| Decision engine + replay + split | 20 |
| Adapters + compliance + health | 48 |
| Ingestion pipeline | 19 |
| Identity resolution | 12 |
| Migration 0002 | 18 |
| Confidence config | 36 |
| Validator | 37 |
| Normalizer | 94 |
| Canonical entity service | 34 |
| SSRF protection | 11 |
| ATT&CK Navigator | 12 |
| Plugin dependencies | 14 |
| New endpoints | 10 |
| Legacy API + classifier + models | 39 |
| **Total** | **501** |

---

## 19. Deployment

### Supported Platforms
- Local (laptop/desktop)
- Termux (Android)
- Railway (free tier)
- Render (free tier)
- Fly.io
- Heroku
- Docker (standard + slim)

### See [README.md](README.md#deployment) for platform-specific instructions.

---

## 20. Security

### SSRF Protection
All URL-fetching plugins use `intel.ssrf.is_safe_url()` to block:
- AWS metadata (169.254.169.254)
- GCP metadata (metadata.google.internal)
- Private IPs (10.x, 172.16-31.x, 192.168.x)
- Loopback (127.x, ::1)
- Link-local (169.254.x)

### Auth
- JWT-based, Telegram ID → JWT
- First user becomes admin
- Dev-mode warning (no Telegram signature verification in dev)
- Rate limiting on all write endpoints

### Secrets
- `.env` file for all secrets
- `SESSION_SECRET` must be set in production
- No secrets in code or logs

---

*Documentation version: 1.0.0*
*Last updated: 2025-01-03*
