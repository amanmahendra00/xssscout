# ═══════════════════════════════════════════════════════════════════
# XSS Scout — Production Dockerfile
# Multi-stage: deps → playwright browsers → app
# Compatible with Render, Railway, Fly.io, any Docker host
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

# ── Stage 2: Playwright browser install ───────────────────────────
FROM python:3.12-slim AS browsers

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps for Chromium headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates \
    # Chromium runtime deps
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 libx11-6 libxext6 \
    libxrender1 libxi6 libxtst6 fonts-liberation libdbus-1-3 \
    libglib2.0-0 libnspr4 libnss3 libxcb1 libxss1 \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /install /usr/local

RUN playwright install chromium --with-deps

# ── Stage 3: Final image ──────────────────────────────────────────
FROM python:3.12-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # App config
    PORT=8000 \
    HOST=0.0.0.0 \
    WORKERS=1 \
    LOG_LEVEL=info \
    # Playwright
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    # Scanner defaults
    SCAN_WORKERS=20 \
    SCAN_EVIDENCE_DIR=/app/evidence \
    SCAN_REPORTS_DIR=/app/reports

# System runtime deps only (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 libx11-6 libxext6 \
    libxrender1 libxi6 libxtst6 fonts-liberation libdbus-1-3 \
    libglib2.0-0 libnspr4 libnss3 libxcb1 libxss1 \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages
COPY --from=deps /install /usr/local

# Copy Playwright browsers
COPY --from=browsers /ms-playwright /ms-playwright

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash xscout

# App directory
WORKDIR /app

# Copy application code
COPY --chown=xscout:xscout . /app
COPY --chown=xscout:xscout \
    xss-scout-fixed/src/xscanner /app/xscanner

# Create runtime directories
RUN mkdir -p /app/evidence /app/reports /app/data /app/uploads \
    && chown -R xscout:xscout /app

USER xscout

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
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
