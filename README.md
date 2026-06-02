# XSS Scout — Intelligent XSS Discovery & Verification Framework

A production-ready full-stack XSS research platform with a live web UI, WebSocket log streaming, real browser verification via Playwright, and one-click deployment to Render or Railway.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Browser (any)                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  XSS Scout UI  (17 panels, live WebSocket)   │   │
│  └──────────────┬───────────────────────────────┘   │
└─────────────────┼───────────────────────────────────┘
                  │ REST + WebSocket
┌─────────────────▼───────────────────────────────────┐
│  FastAPI server  (api/main.py)                      │
│  ├── POST /api/scan/start                           │
│  ├── POST /api/scan/stop                            │
│  ├── GET  /api/scan/state                           │
│  ├── GET  /api/scan/findings                        │
│  ├── GET  /api/scan/logs                            │
│  ├── POST /api/upload/urls                          │
│  ├── GET  /api/report/{scan_id}/{fmt}               │
│  └── WS   /ws/live  ← real-time findings + logs    │
│                                                     │
│  ScanManager (api/scan_manager.py)                  │
│  └── xscanner engine (xscanner/)                   │
│      ├── reflection.py    §5                        │
│      ├── js_dom.py        §6                        │
│      ├── payloads.py      §8                        │
│      ├── csp.py           §9                        │
│      ├── waf.py           §10                       │
│      ├── verifier.py      §11  (Playwright)         │
│      ├── session.py       §15  (SQLite)             │
│      └── reporter.py      §16                       │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start — Local

```bash
# 1. Clone and enter directory
git clone https://github.com/yourorg/xss-scout.git
cd xss-scout

# 2. Create virtualenv
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browsers (for browser verification)
playwright install chromium

# 5. Run
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# 6. Open browser
open http://localhost:8000
```

---

## Quick Start — Docker

```bash
# Build and run (SQLite only — simplest)
docker compose up --build

# With PostgreSQL + Redis
docker compose --profile full up --build

# Open browser
open http://localhost:8000
```

---

## Deploy to Render.com

1. Push this repo to GitHub.
2. Go to [render.com](https://render.com) → **New** → **Blueprint**.
3. Connect your GitHub repo.
4. Render detects `render.yaml` automatically.
5. Click **Apply** — deployment takes ~3 minutes.
6. Visit the generated `.onrender.com` URL.

**Important:** Select the **Standard** plan (minimum) — the free tier has insufficient RAM for Playwright/Chromium. If you don't need browser verification, the free tier works fine — just leave "Browser Verify" unchecked in the UI.

### Render environment variables

Set these in the Render dashboard → Environment:

| Variable | Value |
|----------|-------|
| `SCAN_WORKERS` | `20` |
| `LOG_LEVEL` | `info` |

---

## Deploy to Railway.app

1. Push this repo to GitHub.
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**.
3. Railway detects `railway.json` + `Dockerfile` automatically.
4. Add environment variables from `.env.example` in the Railway dashboard.
5. Click **Deploy** — live in ~4 minutes.

### Add PostgreSQL on Railway

In Railway dashboard → **New** → **Database** → **PostgreSQL**.  
Railway auto-injects `DATABASE_URL` into your service.

### Add Redis on Railway

**New** → **Database** → **Redis**. Auto-injects `REDIS_URL`.

---

## UI Panel Map

| Panel | Spec Section | Description |
|-------|-------------|-------------|
| Configuration | §1 §2 §14 §18 | Scan setup, workers, auth, modules |
| URL Processing | §1 §2 §3 | Sources, streaming, dedup, priority |
| Crawler Engine | §4 | SPA detection, endpoint extraction |
| Payload Engine | §8 | Adaptive mutation, evasion layers |
| Reflection & Context | §5 | 8-context analysis, encoding state |
| DOM / AST / Taint | §6 | Taint flows, sinks, sources, parsers |
| Context Verification | §7 | Pre-exploit escape analysis |
| CSP Analysis | §9 | Policy parse, weaknesses, bypasses |
| WAF Detection | §10 | Fingerprint, differential, evasion |
| Historical | §13 | Wayback/Gau/OTX archived endpoints |
| FP Elimination | §12 | Classification, suppression logic |
| Findings | §12 §16 | All findings with detail + evidence |
| Browser Verify | §11 | Playwright evidence, screenshots |
| Performance | §14 §17 | Throughput chart, worker stats |
| Live Logs | §18 | Real-time structured log stream |
| Storage | §15 | SQLite tables, session progress |
| Plugins / CLI | §18 | Plugin list, full CLI reference |
| Report Export | §16 | JSON / Markdown / HTML download |

---

## WebSocket Protocol

Connect to `ws://host/ws/live`. Messages:

```jsonc
// On connect — full state snapshot
{ "type": "snapshot", "data": { "status", "stats", "findings", "logs" } }

// Live finding
{ "type": "finding", "data": { "id", "url", "param", "type", "severity", "evidence" } }

// Stats update (every scan tick)
{ "type": "stats", "data": { "scanned", "total", "confirmed", "potential", ... } }

// Log line
{ "type": "log", "data": { "ts", "level", "logger", "msg" } }

// Scan status change
{ "type": "status", "data": { "status": "running|done|idle|error" } }

// Keepalive
{ "type": "ping" }
```

---

## REST API

```
POST /api/scan/start       Start a scan (ScanRequest body)
POST /api/scan/stop        Stop running scan
GET  /api/scan/state       Full state (status, stats, findings, logs)
GET  /api/scan/findings    All findings as JSON array
GET  /api/scan/logs        All log lines

POST /api/upload/urls      Upload URL list file (multipart)

GET  /api/report/{id}/json       Download JSON report
GET  /api/report/{id}/markdown   Download Markdown report
GET  /api/report/{id}/html       Download HTML report

GET  /api/evidence/{id}/{file}   Download evidence file (screenshot, DOM)
GET  /health                     Health check
```

---

## Project Structure

```
xss-scout/
├── api/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, all routes, WebSocket
│   ├── models.py            # Pydantic request/response models
│   └── scan_manager.py      # Scan lifecycle, WS broadcast, log bridge
├── xscanner/                # Scanner engine (from xscanner-fixed/)
│   ├── analysis/
│   │   ├── csp.py           §9
│   │   ├── js_dom.py        §6
│   │   ├── payloads.py      §8
│   │   ├── reflection.py    §5
│   │   ├── sourcemap.py     §4
│   │   └── waf.py           §10
│   ├── browser/
│   │   └── verifier.py      §11
│   ├── crawl/
│   │   ├── normalize.py     §3
│   │   ├── spa.py           §4
│   │   └── url_stream.py    §2
│   ├── distributed/
│   │   └── redis_queue.py   §14
│   ├── engine/
│   │   └── scanner.py       core
│   ├── plugins/
│   │   └── base.py          §18
│   ├── reporting/
│   │   └── reporter.py      §16
│   ├── storage/
│   │   └── session.py       §15
│   ├── config.py
│   ├── logging.py
│   └── models.py
├── static/
│   ├── css/app.css          Full design system
│   └── js/app.js            All 17 panels + WebSocket + API
├── templates/
│   └── index.html           App shell
├── evidence/                Screenshots, DOM snapshots (gitignored)
├── reports/                 Generated reports (gitignored)
├── Dockerfile               Multi-stage production build
├── docker-compose.yml       Local dev + optional PG/Redis
├── render.yaml              Render.com blueprint
├── railway.json             Railway.app config
├── Procfile                 Heroku/Render non-Docker
├── requirements.txt
└── .env.example
```

---

## License

For authorized security research and penetration testing only. Always obtain written permission before scanning any target.
