# Argus Enterprise: Current Stack Evaluation

## 1. Core Frameworks & Libraries

| Component | Current Implementation | Evaluation | Recommendation |
| :--- | :--- | :--- | :--- |
| **API Framework** | FastAPI | Excellent choice for async performance and type safety. | **Remain & Optimize** |
| **Bot Framework** | aiogram 3.x | Industry standard for async Telegram bots. | **Remain** |
| **ORM** | SQLAlchemy 2.0 (Async) | Powerful and standard, but complex for simple OSINT data. | **Remain** |
| **Database** | SQLite (aiosqlite) | Good for dev, but limited for concurrent production OSINT data. | **Upgrade to PostgreSQL** |
| **AI SDK** | google-genai / google-generativeai | Using two different Gemini SDKs is redundant. | **Unify to google-genai** |
| **Configuration** | Pydantic Settings | Standard and robust. | **Remain** |
| **Authentication** | Custom JWT (python-jose) | Basic, lacks advanced features like refresh tokens or OIDC. | **Consider Authlib/FastAPI-Users** |

## 2. Infrastructure & Orchestration

| Component | Current Implementation | Evaluation | Recommendation |
| :--- | :--- | :--- | :--- |
| **Task Queue** | In-process `asyncio.gather` | Risks memory bloat and job loss on crash. | **Replace with Celery/TaskIQ** |
| **Scheduling** | Custom polling loop in `monitor_scheduler.py` | Inefficient, lacks distributed locking. | **Replace with APScheduler/Celery Beat** |
| **Caching** | In-memory thread-local SQLite | Ephemeral, not shared across workers. | **Replace with Redis** |
| **Logging** | Custom JSON Formatter | Good, but lacks tracing integration. | **Integrate OpenTelemetry** |
| **Monitoring** | Manual Prometheus endpoint | Minimal, process-local counters only. | **Use Prometheus Client SDK** |

## 3. Architectural Decisions

*   **Monolithic Process:** API, Bot, and Scheduler all run in a single process (or parallel threads). This is a single point of failure and hard to scale.
*   **Homegrown Change Detection:** Fingerprinting and diffing logic is manual and hardcoded per plugin.
*   **Tight Coupling:** `monitor_scheduler.py` is tightly coupled with `plugins.runner.py`.
*   **Data Layer:** The "Canonical" layer is a good start for data normalization but could be more event-driven.
