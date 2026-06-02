# ═══════════════════════════════════════════════════════════════════
# XSS Scout — Production Dockerfile
# Multi-stage: deps → playwright browsers → final app
# Works on Railway, Render, Fly.io, any Docker host
# ═══════════════════════════════════════════════════════════════════

# ── Stage 1: Python dependencies ──────────────────────────────────
FROM python:3.12-slim AS deps

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

# ── Stage 2: Playwright + Chromium ────────────────────────────────
FROM python:3.12-slim AS browsers

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Chromium runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libx11-6 libxext6 libxrender1 libxi6 libxtst6 \
    fonts-liberation libdbus-1-3 libglib2.0-0 \
    libnspr4 libnss3 libxcb1 libxss1 xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /install /usr/local
RUN playwright install chromium --with-deps

# ── Stage 3: Final image ──────────────────────────────────────────
FROM python:3.12-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    WORKERS=1 \
    LOG_LEVEL=info \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    SCAN_WORKERS=20 \
    SCAN_EVIDENCE_DIR=/app/evidence \
    SCAN_REPORTS_DIR=/app/reports

# Chromium runtime deps (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libx11-6 libxext6 libxrender1 libxi6 libxtst6 \
    fonts-liberation libdbus-1-3 libglib2.0-0 \
    libnspr4 libnss3 libxcb1 libxss1 xvfb \
    && rm -rf /var/lib/apt/lists/*

# Python packages from stage 1
COPY --from=deps /install /usr/local

# Playwright browsers from stage 2
COPY --from=browsers /ms-playwright /ms-playwright

# Non-root user
RUN useradd -m -u 1001 -s /bin/bash xscout

WORKDIR /app

# ── Copy application files ────────────────────────────────────────
# Everything is in the repo root — no nested paths
COPY --chown=xscout:xscout api/           ./api/
COPY --chown=xscout:xscout xscanner/      ./xscanner/
COPY --chown=xscout:xscout static/        ./static/
COPY --chown=xscout:xscout templates/     ./templates/
COPY --chown=xscout:xscout requirements.txt ./

# Runtime directories
RUN mkdir -p /app/evidence /app/reports /app/data /app/uploads \
    && chown -R xscout:xscout /app

USER xscout

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')"

EXPOSE ${PORT}

CMD ["sh", "-c", \
    "uvicorn api.main:app \
        --host ${HOST} \
        --port ${PORT} \
        --workers ${WORKERS} \
        --log-level ${LOG_LEVEL} \
        --proxy-headers \
        --forwarded-allow-ips='*'"]
