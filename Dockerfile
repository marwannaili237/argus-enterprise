# Use Python 3.12 slim image for a smaller footprint
FROM python:3.12-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first to leverage Docker cache
COPY pyproject.toml .
COPY argus/requirements.txt ./argus/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r argus/requirements.txt && \
    pip install --no-cache-dir -e .

# Final stage
FROM python:3.12-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m argus && \
    chown -R argus:argus /app
USER argus

# Database and data volume
VOLUME ["/app/data"]
ENV ARGUS_DB_URL=sqlite+aiosqlite:////app/data/argus.db
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start script
CMD ["python", "argus/main.py"]
