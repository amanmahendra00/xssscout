# ═══════════════════════════════════════════════════════════════════
# XSS Scout — Production Dockerfile
# Fixed: Playwright browser path now matches actual install location
# ═══════════════════════════════════════════════════════════════════

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    WORKERS=1 \
    LOG_LEVEL=info \
    SCAN_WORKERS=20 \
    SCAN_EVIDENCE_DIR=/app/evidence \
    SCAN_REPORTS_DIR=/app/reports \
    # Tell Playwright where to find browsers
    PLAYWRIGHT_BROWSERS_PATH=/app/ms-playwright

# ── System deps for Chromium ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libx11-6 libxext6 libxrender1 libxi6 libxtst6 \
    fonts-liberation libdbus-1-3 libglib2.0-0 \
    libnspr4 libxcb1 libxss1 xvfb \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    --root-user-action=ignore

# ── Playwright: install chromium into known path ──────────────────
RUN playwright install chromium

# ── Non-root user ─────────────────────────────────────────────────
RUN useradd -m -u 1001 -s /bin/bash xscout \
    && chown -R xscout:xscout /app

# ── Application code ──────────────────────────────────────────────
COPY --chown=xscout:xscout api/           ./api/
COPY --chown=xscout:xscout xscanner/      ./xscanner/
COPY --chown=xscout:xscout static/        ./static/
COPY --chown=xscout:xscout templates/     ./templates/

# ── Runtime directories ───────────────────────────────────────────
RUN mkdir -p /app/evidence /app/reports /app/data /app/uploads \
    && chown -R xscout:xscout /app

USER xscout

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

EXPOSE ${PORT}

CMD ["sh", "-c", \
    "uvicorn api.main:app \
        --host ${HOST} \
        --port ${PORT} \
        --workers ${WORKERS} \
        --log-level ${LOG_LEVEL} \
        --proxy-headers \
        --forwarded-allow-ips='*'"]
