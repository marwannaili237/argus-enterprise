# Argus Enterprise: Architecture & Ecosystem Improvement Roadmap

## 1. Core Technology Stack Upgrade

| Component | Current State | Target State | Justification |
| :--- | :--- | :--- | :--- |
| **Database** | SQLite (aiosqlite) | **PostgreSQL** (asyncpg) | Essential for high concurrency, reliable JSON indexing, and cross-process data consistency in production. |
| **Task Queue** | `asyncio.gather` | **TaskIQ** or **Celery** | Decouples investigation execution from the API/Bot process. Prevents job loss on restarts and enables horizontal scaling of workers. |
| **Caching/Broker** | SQLite (In-memory) | **Redis** | Provides a shared, high-performance cache for AI responses and a reliable broker for the task queue. |
| **AI Orchestration** | Redundant SDKs | **Unified Google GenAI** | Streamlines the codebase by removing `google-generativeai` in favor of the modern `google-genai` SDK. |

## 2. Infrastructure & Deployment Refactoring

*   **Process Decomposition:** Split the monolithic `main.py` into separate services: `api`, `bot`, and `worker`. This allows independent scaling and failure isolation.
*   **Centralized Scheduling:** Replace the custom polling loop in `monitor_scheduler.py` with a robust scheduler like **APScheduler** or **Celery Beat** to ensure reliable monitor execution and prevent duplicate jobs.
*   **Infrastructure as Code:** Enhance the Docker Compose setup to include health-dependent restarts and proper networking between services.

## 3. Data & Canonical Layer Improvements

*   **Event-Driven Ingestion:** Transition the canonical ingestion pipeline to be event-driven. When a plugin finishes, it emits a message that the ingestion service consumes asynchronously.
*   **Typed Plugin Contracts:** Move away from generic `dict` outputs for plugins to structured **Pydantic models**. This improves data quality and makes the canonical adapters easier to maintain.
*   **Enhanced Entity Extraction:** Integrate a more robust entity extraction service (e.g., using spaCy or a dedicated LLM-based extractor) to improve the quality of the canonical data layer.

## 4. Observability & Reliability

*   **Prometheus Integration:** Replace the manual metrics endpoint with the official `prometheus_client` SDK for standardized monitoring.
*   **OpenTelemetry Tracing:** Implement distributed tracing across the API, Bot, and Worker to simplify debugging of complex investigation pipelines.
*   **Sentry/Error Reporting:** Integrate Sentry for real-time error tracking and alerting in production.

## 5. Security Hardening

*   **Vault Integration:** For enterprise-grade deployments, support fetching secrets from a vault (e.g., HashiCorp Vault) instead of relying solely on environment variables.
*   **API Rate Limiting:** Implement per-user rate limiting at the API level to prevent abuse and ensure fair resource allocation.
