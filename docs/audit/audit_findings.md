# Argus Enterprise - Comprehensive Audit Findings

## 1. Authentication & Security
- **Broken Authentication:** `api/routes/users.py` allows JWT issuance for any `telegram_id` without proof of ownership.
- **Privilege Escalation:** First registered user automatically becomes `admin`.
- **Insecure RSS Auth:** `api/routes/rss.py` uses JWT in query parameters (`key`), leading to token leakage.
- **Missing Token Revocation:** No refresh token or revocation mechanism found.
- **Hardcoded Secrets:** `config.py` uses `secrets.token_hex(32)` as fallback, but lacks persistent secret management for production.
- **SSRF Vulnerabilities:**
  - `api/routes/webhooks.py`: No URL validation for webhooks.
  - `notifiers/webhook.py`: Outbound webhooks are sent without SSRF protection.
  - `plugins/http_plugin.py`: Uses `intel.ssrf.is_safe_url`, but redirects are only checked for the final URL, potentially missing intermediate hops.

## 2. API & Database
- **Response Inconsistency:** Bot handlers expect different keys than API returns (e.g., `investigations` vs `created`).
- **N+1 Queries:** Potential issues in `list_investigations` and `get_investigation` where related evidence is fetched.
- **Migration Integrity:** `alembic` was missing from dependencies (fixed in previous pass, but needs verification on clean DB).
- **SQLite Defaults:** Dockerfile defaults to SQLite in-container, which is not production-ready for multi-user scenarios.

## 3. AI Pipeline
- **Token Inefficiency:** Auto-analysis was running on every investigation (fixed with `AI_ANALYSIS_MODE`, but needs further refinement for caching).
- **No Response Caching:** Duplicate investigations on the same target will re-run AI analysis.

## 4. Telegram Bot
- **Synchronization Issues:** Bot handlers for bulk and history were broken due to API contract mismatches (fixed in previous pass).
- **Localhost Coupling:** Bot uses `localhost` for API calls, which fails in containerized environments.

## 5. DevOps & Performance
- **Docker Build Order:** `Dockerfile` copies `pyproject.toml` and installs before copying source code, but `pip install .` requires the source tree for some build backends.
- **Missing CI/CD Gaps:** CI only runs lint and basic tests; lacks migration tests, coverage reports, and security scans.
- **Performance:** No database indexes on some foreign keys or frequently queried columns like `user_id`.

## 6. Documentation
- **Stale Content:** `start.py` and `help` menu still mention Gemini as the only AI option.
- **Missing Guides:** Lacks a proper production deployment guide for PostgreSQL.
