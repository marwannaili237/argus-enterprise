FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application code
COPY argus/ ./argus/

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash argus
USER argus

# Database and data volume
VOLUME ["/app/data"]

ENV ARGUS_DB_URL=sqlite+aiosqlite:////app/data/argus.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

# Run the full platform (API + Telegram bot + monitor scheduler)
WORKDIR /app/argus
CMD ["python", "main.py"]