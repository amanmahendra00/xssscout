from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from api.models import FindingOut, ScanRequest, ScanState, ScanStats, ScanStatus

logger = logging.getLogger(__name__)

MAX_LOG_LINES = 2000


class ScanManager:
    """
    Singleton — owns the current scan lifecycle.
    Bridges xscanner engine findings/logs → WebSocket subscribers.
    """

    def __init__(self) -> None:
        self._state = ScanState()
        self._log_buffer: deque[dict] = deque(maxlen=MAX_LOG_LINES)
        self._ws_subscribers: list[asyncio.Queue] = []
        self._scan_task: asyncio.Task | None = None
        self._start_time: float = 0.0
        self._finding_seq = 0
        self._lock = asyncio.Lock()

    # ── WebSocket pub/sub ─────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._ws_subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._ws_subscribers.remove(q)
        except ValueError:
            pass

    def _broadcast(self, msg: dict) -> None:
        dead = []
        for q in self._ws_subscribers:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    # ── Log ingestion ─────────────────────────────────────────────

    def push_log(self, level: str, name: str, message: str) -> None:
        ts = time.strftime("%H:%M:%S")
        entry = {"ts": ts, "level": level, "logger": name, "msg": message}
        self._log_buffer.append(entry)
        self._broadcast({"type": "log", "data": entry})

    # ── Finding ingestion ─────────────────────────────────────────

    def _push_finding(self, raw: Any) -> FindingOut:
        self._finding_seq += 1
        ev = raw.evidence if hasattr(raw, "evidence") else {}
        fo = FindingOut(
            id=self._finding_seq,
            url=raw.url,
            param=raw.param,
            type=raw.type.value if hasattr(raw.type, "value") else str(raw.type),
            severity=raw.severity,
            evidence=ev,
        )
        self._state.findings.append(fo)
        self._update_stats(fo)
        self._broadcast({"type": "finding", "data": fo.model_dump()})
        return fo

    def _update_stats(self, fo: FindingOut) -> None:
        s = self._state.stats
        if fo.type in ("verified_reflected_xss", "verified_execution", "potential_stored_input"):
            s.confirmed += 1
        elif fo.type == "reflection":
            s.potential += 1
        elif fo.type == "dom_sink":
            s.dom_sinks += 1
        elif fo.type == "waf_signal":
            s.waf_hits += 1
        elif fo.type == "csp_weakness":
            s.csp_issues += 1

    def _tick_stats(self, scanned: int, total: int) -> None:
        s = self._state.stats
        s.scanned = scanned
        s.total = total
        elapsed = time.monotonic() - self._start_time
        s.elapsed_s = round(elapsed, 1)
        s.urls_per_min = round((scanned / elapsed) * 60, 1) if elapsed > 0 else 0.0
        self._broadcast({"type": "stats", "data": s.model_dump()})

    # ── Scan lifecycle ────────────────────────────────────────────

    @property
    def state(self) -> ScanState:
        return self._state

    @property
    def is_running(self) -> bool:
        return self._state.status == ScanStatus.RUNNING

    async def start_scan(self, req: ScanRequest) -> str:
        async with self._lock:
            if self.is_running:
                raise RuntimeError("A scan is already running")

            scan_id = uuid.uuid4().hex[:12]
            self._state = ScanState(
                status=ScanStatus.RUNNING,
                scan_id=scan_id,
            )
            self._log_buffer.clear()
            self._finding_seq = 0
            self._start_time = time.monotonic()

            self._broadcast({"type": "status", "data": {"status": "running", "scan_id": scan_id}})
            self._scan_task = asyncio.create_task(self._run(req, scan_id))
            return scan_id

    async def stop_scan(self) -> None:
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
        self._state.status = ScanStatus.IDLE
        self._broadcast({"type": "status", "data": {"status": "idle"}})

    async def _run(self, req: ScanRequest, scan_id: str) -> None:
        import tempfile

        try:
            # Build URL list
            url_lines: list[str] = []
            if req.target_url.strip():
                url_lines.extend(req.target_url.strip().splitlines())
            if req.url_list_text.strip():
                url_lines.extend(req.url_list_text.strip().splitlines())

            seen: set[str] = set()
            unique: list[str] = []
            for u in url_lines:
                u = u.strip()
                if u and u not in seen and (u.startswith("http://") or u.startswith("https://")):
                    seen.add(u)
                    unique.append(u)

            if not unique:
                raise ValueError("No valid URLs provided (must start with http:// or https://)")

            self._state.stats.total = len(unique)
            self._broadcast({"type": "stats", "data": self._state.stats.model_dump()})
            self.push_log("INFO", "scanner", f"Starting scan — {len(unique)} URLs")

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, dir="/tmp"
            ) as f:
                f.write("\n".join(unique))
                tmp_path = Path(f.name)

            # Import scanner engine (xscanner/ is in PYTHONPATH)
            from xscanner.config import ScanConfig
            from xscanner.engine.scanner import Scanner

            db_path = f"/tmp/scan_{scan_id}.db"
            config = ScanConfig(
                workers=min(req.workers, 50),
                chunk_size=req.chunk_size,
                timeout_seconds=req.timeout,
                verify_browser=req.verify_browser,
                verify_budget=req.verify_budget,
                spa_crawl=req.spa_crawl,
                auth_header=req.auth_header or None,
                auth_cookie=req.auth_cookie or None,
                storage_backend=req.storage_backend,
                resume=req.resume,
                evidence_dir=f"/app/evidence/{scan_id}",
            )

            scanner = Scanner(config=config, db_path=db_path)

            # Intercept _record to push findings live
            original_record = scanner._record

            async def _intercepting_record(finding):
                await original_record(finding)
                self._push_finding(finding)
                self._tick_stats(scanner._scanned, len(unique))

            scanner._record = _intercepting_record

            # Bridge Python logging → WS
            bridge = _LogBridge(self)
            logging.getLogger().addHandler(bridge)

            try:
                findings = await scanner.run(tmp_path)
            finally:
                logging.getLogger().removeHandler(bridge)
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass

            self._tick_stats(scanner._scanned, len(unique))
            self._state.status = ScanStatus.DONE

            # Write reports
            reports_dir = Path(f"/app/reports/{scan_id}")
            reports_dir.mkdir(parents=True, exist_ok=True)
            from xscanner.reporting.reporter import (
                write_categorized, write_html, write_json, write_markdown,
            )
            write_json(findings, reports_dir / "findings.json")
            write_markdown(findings, reports_dir / "findings.md")
            write_html(findings, reports_dir / "findings.html")
            write_categorized(findings, reports_dir)

            self._broadcast({"type": "status", "data": {"status": "done", "scan_id": scan_id}})
            self.push_log("OK", "scanner",
                          f"Scan complete — {len(findings)} findings | "
                          f"{self._state.stats.confirmed} confirmed | "
                          f"{self._state.stats.potential} potential")

        except asyncio.CancelledError:
            self._state.status = ScanStatus.IDLE
            self.push_log("WARN", "scanner", "Scan cancelled by user")
            raise
        except Exception as exc:
            logger.exception("Scan failed: %s", exc)
            self._state.status = ScanStatus.ERROR
            self._state.error = str(exc)
            self.push_log("ERROR", "scanner", f"Scan failed: {exc}")
            self._broadcast({"type": "status", "data": {"status": "error", "error": str(exc)}})

    def get_logs(self) -> list[dict]:
        return list(self._log_buffer)

    def get_report_path(self, scan_id: str, fmt: str) -> Path | None:
        ext_map = {"json": "findings.json", "markdown": "findings.md", "html": "findings.html"}
        ext = ext_map.get(fmt)
        if not ext:
            return None
        p = Path(f"/app/reports/{scan_id}/{ext}")
        return p if p.exists() else None


class _LogBridge(logging.Handler):
    """Forwards Python log records into ScanManager.push_log()."""

    def __init__(self, mgr: ScanManager) -> None:
        super().__init__()
        self._mgr = mgr

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level_map = {
                "DEBUG": "DEBUG", "INFO": "INFO",
                "WARNING": "WARN", "ERROR": "ERROR", "CRITICAL": "ERROR",
            }
            lv = level_map.get(record.levelname, "INFO")
            self._mgr.push_log(lv, record.name, record.getMessage())
        except Exception:
            pass


# Global singleton
scan_manager = ScanManager()
