# Production Deployment Guide — Argus Enterprise

This guide covers the recommended steps to deploy Argus Enterprise in a production environment.

## 🚀 Quick Start (Docker Compose)

The easiest way to deploy is using Docker Compose.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/marwannaili237/argus-enterprise.git
    cd argus-enterprise
    ```

2.  **Create a `.env` file:**
    ```bash
    cp argus/.env.example .env
    ```
    Edit `.env` and provide your secrets:
    - `SESSION_SECRET`: Generate with `python -c 'import secrets; print(secrets.token_hex(32))'`
    - `TELEGRAM_BOT_TOKEN`: Your bot token from @BotFather
    - `GEMINI_API_KEY`: Your Google Gemini API key

3.  **Deploy with Docker Compose:**
    ```bash
    docker-compose up -d
    ```

## 🔒 Security Hardening

### 1. Reverse Proxy (Nginx)
Always run Argus behind a reverse proxy like Nginx with SSL/TLS.

Example Nginx config:
```nginx
server {
    listen 443 ssl;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

### 2. Secrets Management
In production, do not store secrets in `.env` files. Use your hosting provider's secret management (e.g., AWS Secrets Manager, GitHub Secrets, or Docker Secrets).

### 3. Database
While SQLite is fine for small deployments, for high-traffic production use, switch to PostgreSQL by updating `ARGUS_DB_URL`:
`postgresql+asyncpg://user:password@db_host:5432/argus_db`

## 🤖 AI Token Optimization

Argus is designed to be token-efficient. You can control AI usage via the `AI_ANALYSIS_MODE` setting:

- `disabled`: No AI analysis (saves all tokens).
- `ollama`: Uses local Ollama (zero cost).
- `gemini`: Uses Google Gemini (high quality).
- `auto` (Default): Tries local Ollama first, falls back to Gemini if Ollama is unavailable.

## 📊 Monitoring & Logging

- **Logs:** Argus produces structured JSON logs in `argus.log`.
- **Health Checks:** The API provides a health check endpoint at `/api/health`.
- **Metrics:** Basic execution metrics are available at `/api/metrics` (Admin only).

## 🛠️ Maintenance

### Database Migrations
Argus uses Alembic for database migrations. To apply migrations:
```bash
docker-compose exec argus alembic upgrade head
```

### Updating
```bash
git pull
docker-compose up -d --build
```
