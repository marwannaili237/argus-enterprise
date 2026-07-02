<p align="center">
  <img src="https://img.shields.io/badge/Production-Ready-success?style=for-the-badge&logo=checkmarx" alt="Production Ready">
  <img src="https://img.shields.io/badge/Security-Hardened-blue?style=for-the-badge&logo=googlesheets" alt="Security Hardened">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-0.138-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Tests-501-brightgreen" alt="501 Tests">
</p>

<h1 align="center">🦅 Argus Enterprise</h1>

<p align="center">
  <strong>Enterprise-grade OSINT Investigation Platform with Canonical Entity Layer, Correlation Engine, Rule Engine, and Production-Ready Security.</strong>
</p>

---

## 🚀 Production Status Update (July 2026)

Argus Enterprise has undergone a comprehensive **Production Fix Pass** and **Architecture Audit**. The platform is now fully stabilized, security-hardened, and ready for deployment.

### 🛡️ Security & Reliability Enhancements
- **Secure Telegram Authentication:** Replaced insecure "dev-mode" auth with HMAC-SHA256 verification for Telegram Web Apps.
- **SSRF Protection:** Implemented robust URL validation and network blocking to prevent Server-Side Request Forgery in webhooks and plugins.
- **Token Leakage Fixes:** Secured RSS feeds by moving JWT authentication from query parameters to Authorization headers.
- **Database Optimization:** Migrated to a production-ready connection pooling strategy with enhanced error handling.
- **AI Token Saving:** Added `AI_ANALYSIS_MODE` to control LLM usage (Disabled, Ollama-local, Gemini-cloud, or Auto-fallback).

### 📂 Audit & Roadmap Documentation
Detailed reports from the production audit are available in the `docs/audit/` directory:
- [Production Fix Pass Report](docs/audit/production_fix_pass_report.md) — Summary of all critical bug fixes.
- [Architecture Roadmap](docs/audit/architecture_roadmap.md) — Prioritized plan for future scaling (PostgreSQL, Task Queues, etc.).
- [Stack Evaluation](docs/audit/stack_evaluation.md) — Technical analysis of the current architecture.

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
- **SQLAlchemy 2.x async** (Production-ready connection pooling)
- **Pydantic v2**
- **Alembic** migrations
- **pytest** (501 tests, zero regressions)
- **Deterministic architecture** (Explainable identity resolution)
- **Plugin-based investigation engine** (130+ plugins, 18 target types)

### Enterprise Extensions

The Enterprise layer adds:

1. **Canonical Entity Layer** — cross-investigation, normalized entity store with UUID PKs.
2. **Correlation Engine** — pure-function scoring with tier caps and evidence independence.
3. **Rule Engine** — deterministic rule evaluation with conflict resolution.
4. **Review Queue** — human approval workflow (Telegram + Dashboard).
5. **Decision Engine** — idempotent execution and event creation.
6. **Event Store** — append-only audit trail with replay support.

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

## Quick Start

### 1. Environment Setup
Copy the example environment file and fill in your secrets:
```bash
cp .env.example .env
```

### 2. Install Dependencies
```bash
pip install -e ".[dev]"
```

### 3. Run Migrations
```bash
alembic upgrade head
```

### 4. Start the Platform
```bash
python argus/main.py
```

---

## Deployment

Argus Enterprise is optimized for containerized deployment. See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions on:
- **Docker Compose** (Production-ready setup)
- **Railway/Render** (Cloud deployment)
- **Termux** (Mobile/Android setup)

---

## Testing

The platform maintains a high quality bar with over 500 automated tests.
```bash
pytest
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
