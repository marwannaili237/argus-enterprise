<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-0.138-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0-ff69b4?logo=sqlalchemy&logoColor=white" alt="SQLAlchemy 2.0">
  <img src="https://img.shields.io/badge/aiogram-3-26A5E4?logo=telegram&logoColor=white" alt="aiogram 3">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Plugins-130%2B-orange" alt="130+ Plugins">
  <img src="https://img.shields.io/badge/Target%20Types-18-blueviolet" alt="18 Target Types">
  <img src="https://img.shields.io/badge/Tests-501-brightgreen" alt="501 Tests">
  <img src="https://img.shields.io/badge/100%25-Free-success" alt="100% Free">
</p>

<h1 align="center">🦅 Argus Enterprise</h1>

<p align="center">
  <strong>Enterprise-grade OSINT Investigation Platform with Canonical Entity Layer, Correlation Engine, Rule Engine, Review Queue, Decision Engine, and Event Store</strong>
</p>

<p align="center">
  Argus Enterprise extends the original Argus OSINT platform with a deterministic, explainable, fully-audited identity resolution and correlation pipeline. Every decision traces back through rules, evidence, observations, and plugins to the original source. Nothing merges without an explainable chain.
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline](#pipeline)
- [Canonical Entity Layer](#canonical-entity-layer)
- [Correlation Engine](#correlation-engine)
- [Rule Engine](#rule-engine)
- [Review Queue](#review-queue)
- [Decision Engine](#decision-engine)
- [Event Store & Replay](#event-store--replay)
- [Identity Resolution](#identity-resolution)
- [Plugin Adapter Framework](#plugin-adapter-framework)
- [Confidence & Signal Tiers](#confidence--signal-tiers)
- [Provenance Chain](#provenance-chain)
- [Split Identity](#split-identity)
- [Explainability](#explainability)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Configuration](#configuration)
- [License](#license)

---

## Overview

Argus Enterprise is a modular OSINT investigation platform built with:

- **FastAPI** (async)
- **SQLAlchemy 2.x async** (SQLite for dev, PostgreSQL for production)
- **Pydantic v2**
- **Alembic** migrations
- **pytest** (501 tests, zero regressions)
- **Deterministic architecture** (no AI orchestration, no hidden magic)
- **Plugin-based investigation engine** (130+ plugins, 18 target types)

### Enterprise Extensions

The Enterprise layer adds:

1. **Canonical Entity Layer** — cross-investigation, normalized entity store with UUID PKs
2. **Correlation Engine** — pure-function scoring with tier caps and evidence independence
3. **Rule Engine** — 4 reference rules with conflict resolution (most conservative wins)
4. **Review Queue** — human approval workflow (Telegram + Dashboard call same API)
5. **Decision Engine** — idempotent execution, event creation, merge/split operations
6. **Event Store** — append-only audit trail with replay support
7. **Identity Resolution** — investigation-scoped, never cross-investigation merges
8. **Plugin Adapter Framework** — explicit registry, no fallback, golden fixtures, health tracking

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ARGUS ENTERPRISE                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────┐   ┌──────────┐   ┌───────────┐   ┌────────────┐      │
│  │ Plugin  │──▶│ Adapter  │──▶│ Validator │──▶│ Normalizer │      │
│  └─────────┘   └──────────┘   └───────────┘   └────────────┘      │
│                                                      │              │
│                                                      ▼              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Canonical Store                          │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │   │
│  │  │ RawEvidence│─▶│Observations│─▶│  CanonicalEntities │   │   │
│  │  └────────────┘  └────────────┘  └────────────────────┘   │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │   │
│  │  │Relationship│─▶│ Provenance │  │    Identities      │   │   │
│  │  └────────────┘  └────────────┘  └────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                      │                              │              │
│                      ▼                              ▼              │
│  ┌──────────────────────────┐    ┌─────────────────────────────┐  │
│  │  Identity Resolution     │    │   Correlation Engine        │  │
│  │  (within investigation)  │    │   (pure function, no DB)    │  │
│  └──────────────────────────┘    └─────────────────────────────┘  │
│                                          │                         │
│                                          ▼                         │
│                          ┌───────────────────────────┐            │
│                          │      Rule Engine          │            │
│                          │  (4 rules, conflict res)  │            │
│                          └───────────────────────────┘            │
│                                          │                         │
│                              ┌───────────┴───────────┐            │
│                              ▼                       ▼            │
│               ┌──────────────────────┐  ┌──────────────────────┐  │
│               │    Review Queue      │  │   Decision Engine    │  │
│               │ (human approval)     │  │ (idempotent execute) │  │
│               └──────────────────────┘  └──────────────────────┘  │
│                              │                       │            │
│                              └───────────┬───────────┘            │
│                                          ▼                        │
│                          ┌───────────────────────────┐            │
│               ┌──────────│      Event Store          │──────────┐ │
│               │          │  (append-only, replay)    │          │ │
│               │          └───────────────────────────┘          │ │
│               ▼                                                ▼ │ │
│    ┌─────────────────┐                              ┌──────────────┐│
│    │  decision_events│                              │identity_events│ │
│    └─────────────────┘                              └──────────────┘│
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline

The full data pipeline is deterministic and explainable at every step:

```
Plugin
  → Adapter (translates legacy output to canonical PluginResult)
  → Validator (structural + semantic validation)
  → Normalizer (email, domain, phone, username, hash, IP, URL, wallet, CVE, ASN, MAC, IBAN, VAT)
  → Canonical Store (RawEvidence → Observations → CanonicalEntities → Relationships)
  → Identity Resolution (within investigation only — NEVER cross-investigation)
  → Correlation Engine (pure function — computes evidence, never writes to DB)
  → Rule Engine (4 rules, conflict resolution — most conservative wins)
  → Review Queue (human approval — Telegram + Dashboard call same API)
  → Decision Engine (idempotent execution, event creation, merge/split)
  → Event Store (append-only audit trail, replay support)
```

**Each layer has one responsibility only. No layer bypasses another.**

---

## Canonical Entity Layer

### Models (15 tables, 3 migrations)

| Table | Purpose |
|---|---|
| `canonical_entities` | One row per real-world entity (email, domain, IP, etc.) — UUID PK, unique on (type, normalized_value) |
| `identities` | Real-world actor grouping (person, org, threat group) — status: tentative → confirmed → disputed → merged |
| `identity_entities` | M2M between Identity and CanonicalEntity with signal_weight |
| `raw_evidence` | Immutable record of what a plugin actually fetched — JSON `raw_response` never mutated |
| `observations` | Atomic facts extracted from raw evidence (e.g. "email found in field X") |
| `entity_observations` | M2M between CanonicalEntity and Observation |
| `relationships` | Directed edges between canonical entities (resolves_to, registered_by, same_person, etc.) |
| `relationship_provenance` | Which evidence (and optionally which observation) supports a relationship |
| `entity_investigation_links` | M2M between CanonicalEntity and Investigation — the cross-investigation correlation index |
| `identity_events` | Audit trail for identity operations (created, promoted, disputed, merged, split) |
| `plugin_health` | Persisted plugin health records (active, quarantined) |
| `adapter_fixtures` | Golden fixture registry for compliance checking |
| `decision_events` | Append-only event log for decisions (requested, evaluated, approved, rejected, executed, reverted) |
| `review_queue` | Pending decisions awaiting human approval |
| `identity_merge_records` | Merge provenance for split operations |

### Key Properties

- **UUID PKs** (stored as String(36) for SQLite/PostgreSQL portability)
- **Normalized values** — every entity has both `raw_value` and `normalized_value`
- **Unique constraint** on `(type, normalized_value)` — no duplicate entities
- **Referential integrity** — all FKs enforced with `ON DELETE CASCADE` or `SET NULL`
- **Indexes** on all query-critical columns (type, last_seen, investigation_id, etc.)

---

## Correlation Engine

**File:** `argus/canonical/correlation.py`

The Correlation Engine is a **pure function** — it never reads from or writes to the database. It takes a draft identity and a global identity (with their entities and relationships) and returns a `CorrelationResult`.

### Signal Tiers

| Tier | Signals | Cap | Description |
|---|---|---|---|
| **Tier 1** | `email_exact`, `phone_e164`, `wallet_address`, `pgp_fingerprint` | None (uncapped) | Strong identifiers — a single match is highly indicative |
| **Tier 2** | `username_exact`, `avatar_phash`, `domain_owner` | 0.75 | Moderate signals — corroborating evidence |
| **Tier 3** | `display_name`, `company`, `city`, `country`, `language` | 0.45 | Weak signals — alone, almost never sufficient |

### Evidence Independence

**Within each tier:**
1. Group signals by `evidence_id`
2. Signals from the same `evidence_id` are **dependent** — only the strongest counts
3. Apply **noisy-OR** across distinct `evidence_id` groups only

This prevents confidence inflation when 5 observations of the same email all come from one plugin execution.

### Output: `CorrelationResult`

```python
@dataclass
class CorrelationResult:
    draft_identity_id: str
    global_identity_id: str
    final_score: float
    decisive_tier: int
    tier_breakdown: dict[int, TierBreakdown]
    matched_entities: list[MatchedEntity]
    matched_relationships: list[MatchedRelationship]
    contributing_signals: list[Signal]
    contributing_evidence: list[str]
    confidence_reasoning: str  # human-readable
    explanation: dict[str, Any]  # full machine-readable
```

---

## Rule Engine

**Directory:** `argus/canonical/rules/`

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
| `HighConfidenceAutoMergeRule` | score ≥ 0.90 AND decisive_tier == 1 | `AUTO_MERGE` | 0.90 |
| `ReviewBandRule` | 0.50 ≤ score < 0.90 | `QUEUE_FOR_REVIEW` | [0.50, 0.90) |
| `WatchlistRule` | Any matched entity on watchlist | `QUEUE_FOR_REVIEW` | Always review |
| `NoOverlapPromotionRule` | No matched entities + has evidence | `PROMOTE_TO_GLOBAL` | — |

### Conflict Resolution

When multiple rules fire, **most conservative wins**:

```
REJECT (priority 0)
  > QUEUE_FOR_REVIEW (priority 1)
    > PROMOTE_TO_GLOBAL (priority 2)
      > AUTO_MERGE (priority 3)
```

If same priority, higher correlation score wins.

---

## Review Queue

**API:** `argus/api/routes/review_queue.py`

Both Telegram and Dashboard call the **exact same endpoints**. No Telegram-specific logic exists.

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/review-queue` | List pending items (paginated, filterable by status) |
| GET | `/api/v1/review-queue/{id}` | Get single review item |
| POST | `/api/v1/review-queue/{id}/approve` | Approve — executes the merge |
| POST | `/api/v1/review-queue/{id}/reject` | Reject — no merge |
| GET | `/api/v1/review-queue/{id}/events` | Full decision event audit trail |

### Status Lifecycle

```
pending → approved → executed
pending → rejected
```

---

## Decision Engine

**File:** `argus/canonical/decision_engine.py`

### Responsibilities (ONLY these)

1. **Idempotency** — re-processing the same `decision_id` is a no-op
2. **Event creation** — every state change emits a `DecisionEvent`
3. **Dispatch** — routes decisions to executors based on `DecisionKind`
4. **Merge execution** — calls `IdentityResolutionService.merge_identities`
5. **Split execution** — reverses a merge via `IdentityMergeRecord`
6. **Watchlist notification** — notifies watchers when a watched entity is involved

### What it NEVER does

- Computes confidence
- Computes similarity
- Computes thresholds
- Executes actions inline (everything is a queued task)

---

## Event Store & Replay

### Event Tables

| Table | Events |
|---|---|
| `decision_events` | requested, evaluated, approved, rejected, executed, reverted |
| `identity_events` | created, promoted, disputed, merged, split |

### Event Fields

Every event stores:
- `rule_id`, `rule_version` — which rule triggered it
- `actor` — user_id, "system", or "rule:<rule_id>"
- `timestamp`
- `payload` — event-specific data
- `config_snapshot` — configuration at the time of the event

### Replay

**File:** `argus/canonical/replay.py`

The Replay Engine can:
1. Delete all derived state (identities, identity_entities, merge_records)
2. Replay every event in timestamp order
3. Verify that the rebuilt state matches the pre-replay state

```python
engine = ReplayEngine(db)
result = await engine.replay(verify=True)
assert result.verification_passed
```

---

## Identity Resolution

**File:** `argus/canonical/services/identity.py`

### CRITICAL RULE

**Identity resolution happens WITHIN one investigation only. Cross-investigation identity merges are FORBIDDEN.**

The `IdentityResolutionService`:
- Groups entities into identity candidates using deterministic union-find
- Computes confidence using noisy-OR over **independent** evidence sources
- Auto-promotes from `tentative` → `confirmed` at confidence ≥ 0.85
- Emits `IdentityEvent` for every operation (audit trail)
- Refuses cross-investigation merges (raises `IdentityResolutionError`)

### Confidence Computation

```
For each entity in the identity:
  - Count distinct (plugin_id, source_url) pairs that observed it
  - Tier 1: single match is enough — no inflation
  - Tier 2/3: multiple independent sources increase weight logarithmically

Combine across entities using noisy-OR:
  confidence = 1 - product(1 - w_i) for each entity i
```

---

## Plugin Adapter Framework

**Directory:** `argus/canonical/adapters/`

### Components

| Component | Purpose |
|---|---|
| `BaseAdapter` | ABC for all adapters — one per plugin_id |
| `AdapterContext` | Metadata passed to every `adapt()` call |
| `AdapterRegistry` | Explicit registry — no auto-discovery, no fallback |
| `DefaultLegacyAdapter` | Translates `plugins.base.PluginResult` → canonical `PluginResult` |
| `GoldenFixture` | Known-good plugin output for regression detection |
| `compliance_check_all` | Runs all adapters against their golden fixtures |
| `PluginHealthTracker` | Classifies failures as transient/structural, quarantines after threshold |

### Rules

- Plugins **never** write directly into canonical storage
- Plugins only emit `PluginResult`
- Canonical ingestion performs: validation → normalization → deduplication → entity creation → relationship creation → identity updates
- No fallback adapters — if no adapter is registered, ingestion is skipped

### Plugin Health

| Failure Type | Examples | Affects Health? |
|---|---|---|
| **Transient** | Timeout, 429, 5xx, connection reset | No |
| **Structural** | Schema validation failure, adapter failure, mapping failure, fixture regression | Yes |

After `QUARANTINE_STRUCTURAL_FAILURE_THRESHOLD` (default 3) structural failures within `QUARANTINE_WINDOW_HOURS` (default 24h), the plugin is quarantined.

---

## Confidence & Signal Tiers

**File:** `argus/canonical/confidence.py`

Single source of truth for all thresholds — no magic numbers inline anywhere else.

### Tier 1 (Strong)
`email`, `phone`, `btc`, `eth`, `wallet`, `pgp_fingerprint`
Weight: 0.85 (per independent observation)

### Tier 2 (Moderate)
`username`, `avatar_hash`
Weight: 0.50

### Tier 3 (Weak)
`display_name`, `city`, `company`, `domain`
Weight: 0.20

### Thresholds

| Threshold | Default | Env Var |
|---|---|---|
| Identity promotion | 0.85 | `ARGUS_IDENTITY_PROMOTION_THRESHOLD` |
| Identity dispute | 0.30 | `ARGUS_IDENTITY_DISPUTE_THRESHOLD` |
| Quarantine failures | 3 | `ARGUS_QUARANTINE_THRESHOLD` |
| Quarantine window | 24 hours | `ARGUS_QUARANTINE_WINDOW_HOURS` |
| Max entities per ingestion | 500 | `ARGUS_INGESTION_MAX_ENTITIES` |
| Max observations per ingestion | 1000 | `ARGUS_INGESTION_MAX_OBSERVATIONS` |
| Max relationships per ingestion | 200 | `ARGUS_INGESTION_MAX_RELATIONSHIPS` |

---

## Provenance Chain

Every relationship traces back to the original source:

```
Relationship
  ↓
RelationshipProvenance
  ↓
RawEvidence (immutable JSON)
  ↓
Observation (atomic fact)
  ↓
Plugin (plugin_id, plugin_version, execution_id)
  ↓
Source (source_url, source_reliability)
```

**Nothing enters the graph without provenance.**

---

## Split Identity

**Method:** `DecisionEngine.split_identity(merge_record_id, actor, reason)`

Completely reverses a merge operation:
1. Reads the `IdentityMergeRecord`
2. Reparents entities back to the source identity
3. Restores original `signal_weight` values
4. Reactivates the source identity (status = `tentative`)
5. Recomputes confidence
6. Emits `IdentityEvent("split")` and `DecisionEvent("reverted")`

---

## Explainability

Every decision includes:

```json
{
  "rule_id": "high_confidence_auto_merge",
  "rule_version": "1.0.0",
  "kind": "auto_merge",
  "correlation_score": 0.99,
  "reasoning": "Auto-merge: score 0.99 >= 0.90 with Tier-1 signals (email_exact). 2 distinct evidence sources.",
  "explanation": {
    "threshold": 0.90,
    "actual_score": 0.99,
    "decisive_tier": 1,
    "tier1_signal_types": ["email_exact"],
    "contributing_evidence_count": 2,
    "correlation_explanation": {
      "final_score": 0.99,
      "tier_breakdown": {
        "1": {
          "signals": [...],
          "distinct_evidence_count": 2,
          "raw_score": 0.99,
          "capped_score": 0.99
        }
      },
      "signal_weights": {...},
      "tier_caps": {"tier_1": null, "tier_2": 0.75, "tier_3": 0.45}
    }
  }
}
```

**Nothing merges without an explainable chain.**

---

## Quick Start

### Prerequisites

- Python 3.11+
- A Telegram bot token (from [@BotFather](https://t.me/botfather))

### Install

```bash
git clone https://github.com/marwannaili237/argus-enterprise.git
cd argus-enterprise
pip install -e ".[dev]"
cd argus
cp .env.example .env
# Edit .env — set TELEGRAM_BOT_TOKEN
python main.py
```

### Run Tests

```bash
PYTHONPATH=argus python3.13 -m pytest tests/ -v
# 501 passed
```

---

## Deployment

### Termux (Android)

```bash
pkg update && pkg install -y python git
git clone https://github.com/marwannaili237/argus-enterprise.git
cd argus-enterprise
bash termux_setup.sh
cd argus && python main.py
```

### Railway

```bash
# railway.toml is included — Railway auto-detects it
# Set env vars: TELEGRAM_BOT_TOKEN, SESSION_SECRET
```

### Render

```bash
# render.yaml is included — Render reads it automatically
# Set TELEGRAM_BOT_TOKEN in dashboard
```

### Docker

```bash
cp argus/.env.example argus/.env
docker compose up -d --build
# Or use the slim image:
docker build -f Dockerfile.slim -t argus-enterprise .
docker run -p 8000:8000 --env-file argus/.env argus-enterprise
```

---

## API Reference

### Core
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/ready` | Readiness check |
| GET | `/api/metrics` | Prometheus metrics |
| GET | `/docs` | Swagger API docs |

### Auth
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/users/auth/telegram` | Register/login via Telegram ID → JWT |
| GET | `/api/v1/users/me` | Current user profile |

### Investigations
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/investigations` | Start (optional `template` field) |
| POST | `/api/v1/investigations/bulk` | Bulk create (up to 50 targets) |
| GET | `/api/v1/investigations` | List (paginated, filterable, sortable) |
| GET | `/api/v1/investigations/{id}` | Get + evidence |
| GET | `/api/v1/investigations/{id1}/compare/{id2}` | Compare two |
| POST | `/api/v1/investigations/{id}/analyze` | AI report |

### Canonical / Enterprise
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/search?q=` | Global full-text search |
| GET | `/api/v1/exports/{id}/stix` | STIX 2.1 export |
| GET | `/api/v1/exports/{id}/misp` | MISP export |
| GET | `/api/v1/exports/{id}/attack-navigator` | MITRE ATT&CK Navigator |
| GET | `/api/v1/exports/{id}/risk-matrix` | Risk matrix |
| POST | `/api/v1/exports/{id}/verify-integrity` | Evidence integrity check |
| GET | `/api/v1/graph/{id}` | D3 graph + analytics |
| GET | `/api/v1/graph/{id}/timeline` | Timeline events |

### Review Queue (Enterprise)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/review-queue` | List pending items |
| GET | `/api/v1/review-queue/{id}` | Get single item |
| POST | `/api/v1/review-queue/{id}/approve` | Approve (executes merge) |
| POST | `/api/v1/review-queue/{id}/reject` | Reject (no merge) |
| GET | `/api/v1/review-queue/{id}/events` | Decision audit trail |

### Cases, Tags, Watchlists, Monitors, Snapshots
See `/docs` for full reference (57 endpoints total).

---

## Testing

```bash
PYTHONPATH=argus python3.13 -m pytest tests/ -v
```

### Test Coverage

| Test File | Tests | Coverage |
|---|---|---|
| `test_correlation.py` | 38 | Tier caps, evidence independence, determinism |
| `test_rules.py` | 36 | 4 rules, conflict resolution, registry |
| `test_decision_engine.py` | 20 | Idempotency, review queue, split, replay |
| `test_adapters.py` | 48 | Registry, default adapter, fixtures, compliance, health |
| `test_ingestion.py` | 19 | Validation, caps, idempotency, transaction rollback |
| `test_identity_resolution.py` | 12 | Cross-investigation refusal, evidence independence |
| `test_migration_0002.py` | 18 | Upgrade, downgrade, additive-only |
| `test_confidence.py` | 36 | Tiers, weights, thresholds, env overrides |
| `test_validator.py` | 37 | Structure, entities, relationships, sanitization |
| `test_normalizer.py` | 94 | All normalize_* methods + edge cases |
| `test_canonical_entity_service.py` | 34 | Upsert, link, identity clustering |
| `test_ssrf.py` | 11 | SSRF guard for all blocked ranges |
| `test_attack_navigator.py` | 12 | ATT&CK mapping, Navigator layer, risk matrix |
| `test_plugin_deps.py` | 14 | Follow-up generation, topological sort |
| `test_new_endpoints.py` | 10 | All new endpoints registered |
| `test_api.py` | 4 | Health, ready, router registration |
| `test_classifier.py` | 32 | Target classification, plugin registry |
| `test_models.py` | 3 | SQLAlchemy model creation |
| **Total** | **501** | **All passing, zero regressions** |

---

## Configuration

All config via environment variables or `argus/.env` file. See `argus/.env.example`.

### Required
| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | From [@BotFather](https://t.me/botfather) |

### Enterprise (Optional)
| Variable | Default | Description |
|---|---|---|
| `ARGUS_TIER1_WEIGHT` | 0.85 | Tier 1 signal weight |
| `ARGUS_TIER2_WEIGHT` | 0.50 | Tier 2 signal weight |
| `ARGUS_TIER3_WEIGHT` | 0.20 | Tier 3 signal weight |
| `ARGUS_IDENTITY_PROMOTION_THRESHOLD` | 0.85 | Auto-promote to confirmed |
| `ARGUS_QUARANTINE_THRESHOLD` | 3 | Structural failures before quarantine |
| `ARGUS_QUARANTINE_WINDOW_HOURS` | 24 | Quarantine window |
| `ARGUS_INGESTION_MAX_ENTITIES` | 500 | Max entities per ingestion call |
| `MAX_CONCURRENT_PLUGINS` | 5 | Plugin parallelism |

---

## License

MIT License — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built for hackers, journalists, researchers, and the curious. 🦅</strong>
</p>
