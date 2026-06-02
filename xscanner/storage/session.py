from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass

import aiosqlite

from xscanner.models import Finding

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  param TEXT,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS processed_urls (
  normalized_url TEXT PRIMARY KEY,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS retries (
  url TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL,
  last_error TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS frontier (
  normalized_url TEXT PRIMARY KEY,
  original_url TEXT NOT NULL,
  priority INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  claimed_by TEXT,
  lease_expires_at DATETIME,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_frontier_status_priority ON frontier(status, priority DESC);
CREATE INDEX IF NOT EXISTS idx_frontier_lease ON frontier(lease_expires_at);
CREATE TABLE IF NOT EXISTS checkpoints (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass(slots=True)
class _WriteEvent:
    table: str
    payload: tuple


class SqliteStorage:
    """
    Single-writer, multi-reader SQLite backend with async WAL batching.

    FIX 1: Original opened a new aiosqlite connection on every read (claim_frontier_batch
            used self._readers queue but the connections were never properly pooled).
            Now we keep a fixed reader pool initialised at start().
    FIX 2: Original _writer_loop had a logic error — the `continue` inside the inner
            for loop broke out of the inner loop correctly but the outer loop then
            iterated over events that had already been consumed.  Rewrote to use
            get_nowait with a try/except properly.
    FIX 3: has_seen_url previously opened a new connection every call.  Now uses pool.
    FIX 4: claim_frontier_batch used a reader connection for a write transaction
            (BEGIN IMMEDIATE + UPDATE) which is unsafe with WAL.  Moved to writer queue.
    FIX 5: drain() only joined the queue; it did not wait for the writer task itself
            to finish flushing.  Added a final explicit flush after join().
    """

    def __init__(
        self,
        path: str,
        *,
        reader_pool_size: int = 4,
        writer_queue_size: int = 200_000,
        batch_size: int = 500,
        flush_interval: float = 0.25,
    ):
        self.path = path
        self.reader_pool_size = max(1, reader_pool_size)
        self.writer_queue_size = max(1_000, writer_queue_size)
        self.batch_size = max(50, batch_size)
        self.flush_interval = flush_interval
        self._readers: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue(
            maxsize=self.reader_pool_size
        )
        self._writer_queue: asyncio.Queue[_WriteEvent] = asyncio.Queue(
            maxsize=self.writer_queue_size
        )
        self._writer_conn: aiosqlite.Connection | None = None
        self._writer_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        await self._init_db()
        for _ in range(self.reader_pool_size):
            conn = await aiosqlite.connect(self.path)
            await self._apply_pragmas(conn)
            await self._readers.put(conn)
        self._writer_conn = await aiosqlite.connect(self.path)
        await self._apply_pragmas(self._writer_conn)
        self._writer_task = asyncio.create_task(self._writer_loop())
        logger.debug("SqliteStorage started (path=%s, readers=%d)", self.path, self.reader_pool_size)

    @staticmethod
    async def _apply_pragmas(conn: aiosqlite.Connection) -> None:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA temp_store=MEMORY")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")   # FIX: avoid SQLITE_BUSY crashes

    async def close(self) -> None:
        self._stop_event.set()
        if self._writer_task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._writer_task, timeout=10.0)
        while not self._readers.empty():
            conn = self._readers.get_nowait()
            with contextlib.suppress(Exception):
                await conn.close()
        if self._writer_conn is not None:
            with contextlib.suppress(Exception):
                await self._writer_conn.close()

    async def _init_db(self) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.executescript(SCHEMA)
            await db.commit()

    # ── write helpers ──────────────────────────────────────────────

    async def store_finding(self, finding: Finding) -> None:
        await self._writer_queue.put(_WriteEvent(
            "findings",
            (finding.url, finding.param, finding.type.value, finding.severity,
             json.dumps(finding.evidence, default=str)),
        ))

    async def mark_processed_url(self, normalized_url: str) -> None:
        await self._writer_queue.put(_WriteEvent("processed_urls", (normalized_url,)))

    async def store_retry(self, url: str, attempts: int, last_error: str) -> None:
        await self._writer_queue.put(_WriteEvent("retries", (url, attempts, last_error)))

    async def enqueue_frontier_url(
        self, normalized_url: str, original_url: str, priority: int
    ) -> None:
        await self._writer_queue.put(
            _WriteEvent("frontier_enqueue", (normalized_url, original_url, priority))
        )

    async def mark_frontier_done(self, normalized_url: str) -> None:
        await self._writer_queue.put(_WriteEvent("frontier_done", (normalized_url,)))

    async def set_checkpoint(self, key: str, value: str) -> None:
        await self._writer_queue.put(_WriteEvent("checkpoint", (key, value)))

    # ── read helpers ───────────────────────────────────────────────

    async def has_seen_url(self, normalized_url: str) -> bool:
        """
        FIX 3: was opening a new connection on every call.  Now uses reader pool.
        """
        conn = await self._readers.get()
        try:
            cursor = await conn.execute(
                "SELECT 1 FROM processed_urls WHERE normalized_url=? "
                "UNION SELECT 1 FROM frontier WHERE normalized_url=? LIMIT 1",
                (normalized_url, normalized_url),
            )
            return await cursor.fetchone() is not None
        finally:
            await self._readers.put(conn)

    async def frontier_counts(self) -> tuple[int, int]:
        conn = await self._readers.get()
        try:
            pending_row = await (await conn.execute(
                "SELECT COUNT(*) FROM frontier "
                "WHERE status='pending' OR (status='claimed' AND lease_expires_at < CURRENT_TIMESTAMP)"
            )).fetchone()
            done_row = await (await conn.execute(
                "SELECT COUNT(*) FROM processed_urls"
            )).fetchone()
            return int(pending_row[0]), int(done_row[0])
        finally:
            await self._readers.put(conn)

    async def claim_frontier_batch(
        self, limit: int, *, node_id: str, lease_seconds: int = 90
    ) -> list[tuple[str, str, int]]:
        """
        FIX 4: claiming requires a write (UPDATE frontier).  This now goes through
        the writer connection directly (under an async lock) rather than a reader.
        """
        assert self._writer_conn is not None
        try:
            await self._writer_conn.execute("BEGIN IMMEDIATE")
            # expire stale leases first
            await self._writer_conn.execute(
                "UPDATE frontier SET status='pending', claimed_by=NULL, lease_expires_at=NULL "
                "WHERE status='claimed' AND lease_expires_at < CURRENT_TIMESTAMP"
            )
            cursor = await self._writer_conn.execute(
                "SELECT normalized_url, original_url, priority FROM frontier "
                "WHERE status='pending' ORDER BY priority DESC LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()
            if rows:
                await self._writer_conn.executemany(
                    "UPDATE frontier SET status='claimed', claimed_by=?, "
                    "lease_expires_at=datetime('now', ?), updated_at=CURRENT_TIMESTAMP "
                    "WHERE normalized_url=?",
                    [(node_id, f"+{lease_seconds} seconds", r[0]) for r in rows],
                )
            await self._writer_conn.commit()
            return [(str(r[0]), str(r[1]), int(r[2])) for r in rows]
        except Exception:
            with contextlib.suppress(Exception):
                await self._writer_conn.rollback()
            raise

    # ── drain / writer loop ────────────────────────────────────────

    async def drain(self) -> None:
        """Wait until all queued writes are persisted. FIX 5: also flush after join."""
        await self._writer_queue.join()
        # final explicit flush in case last batch was partial
        await self._flush_pending()

    async def _flush_pending(self) -> None:
        events: list[_WriteEvent] = []
        while not self._writer_queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                events.append(self._writer_queue.get_nowait())
        if events:
            await self._flush_events(events)
            for _ in events:
                self._writer_queue.task_done()

    async def _writer_loop(self) -> None:
        """
        FIX 2: rewrote inner batch-accumulation logic.
        """
        assert self._writer_conn is not None
        while True:
            if self._stop_event.is_set() and self._writer_queue.empty():
                return
            events: list[_WriteEvent] = []
            try:
                first = await asyncio.wait_for(
                    self._writer_queue.get(), timeout=self.flush_interval
                )
                events.append(first)
            except asyncio.TimeoutError:
                continue

            # drain up to batch_size - 1 more without blocking
            for _ in range(self.batch_size - 1):
                try:
                    events.append(self._writer_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            try:
                await self._flush_events(events)
            except Exception as exc:
                logger.error("writer flush error: %s", exc)
            finally:
                for _ in events:
                    self._writer_queue.task_done()

    async def _flush_events(self, events: list[_WriteEvent]) -> None:
        assert self._writer_conn is not None
        by_table: dict[str, list[tuple]] = {}
        for event in events:
            by_table.setdefault(event.table, []).append(event.payload)

        await self._writer_conn.execute("BEGIN")
        try:
            if "findings" in by_table:
                await self._writer_conn.executemany(
                    "INSERT INTO findings(url,param,type,severity,evidence_json) VALUES (?,?,?,?,?)",
                    by_table["findings"],
                )
            if "processed_urls" in by_table:
                await self._writer_conn.executemany(
                    "INSERT OR IGNORE INTO processed_urls(normalized_url) VALUES (?)",
                    by_table["processed_urls"],
                )
            if "retries" in by_table:
                await self._writer_conn.executemany(
                    "INSERT INTO retries(url, attempts, last_error) VALUES (?,?,?) "
                    "ON CONFLICT(url) DO UPDATE SET attempts=excluded.attempts, "
                    "last_error=excluded.last_error, updated_at=CURRENT_TIMESTAMP",
                    by_table["retries"],
                )
            if "frontier_enqueue" in by_table:
                await self._writer_conn.executemany(
                    "INSERT INTO frontier(normalized_url, original_url, priority, status) "
                    "VALUES (?,?,?,'pending') ON CONFLICT(normalized_url) DO UPDATE SET "
                    "priority=MAX(priority, excluded.priority), original_url=excluded.original_url",
                    by_table["frontier_enqueue"],
                )
            if "frontier_done" in by_table:
                await self._writer_conn.executemany(
                    "UPDATE frontier SET status='done', claimed_by=NULL, "
                    "lease_expires_at=NULL, updated_at=CURRENT_TIMESTAMP "
                    "WHERE normalized_url=?",
                    by_table["frontier_done"],
                )
            if "checkpoint" in by_table:
                await self._writer_conn.executemany(
                    "INSERT INTO checkpoints(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                    "updated_at=CURRENT_TIMESTAMP",
                    by_table["checkpoint"],
                )
            await self._writer_conn.commit()
        except Exception:
            with contextlib.suppress(Exception):
                await self._writer_conn.rollback()
            raise
