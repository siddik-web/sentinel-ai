# Multi-stage Dockerfile for Sentinel AI
FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

# Production Runtime Image
FROM python:3.11-slim AS runner

RUN useradd --system --create-home --uid 10001 sentinel \
    && mkdir -p /app/data \
    && chown -R sentinel:sentinel /app

COPY --from=builder /install /usr/local

WORKDIR /app
USER sentinel

EXPOSE 8000
VOLUME ["/app/data"]

ENV PYTHONUNBUFFERED=1 \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8000 \
    SENTINEL_DB_PATH=/app/data/sentinel_ai.db

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["sentinel-ai", "serve"]
