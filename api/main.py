from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from api.models import ScanRequest, ScanState, ScanStatus
from api.scan_manager import scan_manager

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent.parent

app = FastAPI(
    title="XSS Scout",
    description="Intelligent XSS Discovery & Verification Framework",
    version="2.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ── HTML entry point ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html_file = BASE_DIR / "templates" / "index.html"
    return HTMLResponse(content=html_file.read_text(encoding="utf-8"))


# ── Scan control ──────────────────────────────────────────────────────────────

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    try:
        scan_id = await scan_manager.start_scan(req)
        return {"ok": True, "scan_id": scan_id}
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan/stop")
async def stop_scan():
    await scan_manager.stop_scan()
    return {"ok": True}


@app.get("/api/scan/state")
async def get_state() -> ScanState:
    return scan_manager.state


@app.get("/api/scan/logs")
async def get_logs():
    return {"logs": scan_manager.get_logs()}


@app.get("/api/scan/findings")
async def get_findings():
    return {"findings": [f.model_dump() for f in scan_manager.state.findings]}


# ── URL file upload ───────────────────────────────────────────────────────────

@app.post("/api/upload/urls")
async def upload_urls(file: UploadFile):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
    valid = [l for l in lines if l.startswith("http://") or l.startswith("https://")]
    return {
        "ok": True,
        "total_lines": len(lines),
        "valid_urls": len(valid),
        "text": text[:500_000],  # cap at 500KB for the UI
    }


# ── Report download ───────────────────────────────────────────────────────────

@app.get("/api/report/{scan_id}/{fmt}")
async def download_report(scan_id: str, fmt: str):
    p = scan_manager.get_report_path(scan_id, fmt)
    if p is None:
        raise HTTPException(status_code=404, detail="Report not found")
    media = {
        "json": "application/json",
        "markdown": "text/markdown",
        "html": "text/html",
    }.get(fmt, "text/plain")
    return FileResponse(str(p), media_type=media, filename=p.name)


# ── Evidence files ────────────────────────────────────────────────────────────

@app.get("/api/evidence/{scan_id}/{filename}")
async def get_evidence(scan_id: str, filename: str):
    p = BASE_DIR / "evidence" / scan_id / filename
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    # Security: ensure path stays within evidence dir
    try:
        p.resolve().relative_to((BASE_DIR / "evidence").resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")
    return FileResponse(str(p))


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "scan_status": scan_manager.state.status.value,
        "version": "2.1.0",
    }


# ── WebSocket live feed ───────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    q = scan_manager.subscribe()

    # Send current state snapshot immediately on connect
    try:
        await websocket.send_json({
            "type": "snapshot",
            "data": {
                "status":   scan_manager.state.status.value,
                "scan_id":  scan_manager.state.scan_id,
                "stats":    scan_manager.state.stats.model_dump(),
                "findings": [f.model_dump() for f in scan_manager.state.findings[-50:]],
                "logs":     scan_manager.get_logs()[-100:],
            },
        })
    except Exception:
        scan_manager.unsubscribe(q)
        return

    # Relay queued messages to the WebSocket client
    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=20.0)
                await websocket.send_json(msg)
            except asyncio.TimeoutError:
                # Keepalive ping
                await websocket.send_json({"type": "ping"})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        scan_manager.unsubscribe(q)
