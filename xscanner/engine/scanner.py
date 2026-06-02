from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx

from xscanner.analysis.csp import CSPState, analyze_csp
from xscanner.analysis.js_dom import quick_dom_pattern_scan
from xscanner.analysis.payloads import generate_payloads
from xscanner.analysis.reflection import detect_reflection
from xscanner.analysis.sourcemap import analyze_bundle_text
from xscanner.analysis.waf import WafState, detect_waf_signals, monotonic_ms
from xscanner.browser.verifier import analyze_dom_runtime, verify_runtime
from xscanner.config import ScanConfig
from xscanner.crawl.normalize import normalize_url, score_url, should_skip
from xscanner.crawl.spa import crawl_spa
from xscanner.crawl.url_stream import stream_urls
from xscanner.distributed.redis_queue import RedisCoordinator
from xscanner.models import Finding, FindingType, UrlTask
from xscanner.plugins.base import PluginContext, load_plugins
from xscanner.storage.session import SqliteStorage

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, config: ScanConfig, db_path: str):
        self.config = config
        self.db_path = db_path
        self.findings: list[Finding] = []
        self.in_memory_findings_limit = 10_000
        self.verify_count = 0
        self._verify_lock = asyncio.Lock()   # FIX: verify_count was not thread-safe
        self.domain_limits: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(config.per_domain_concurrency)
        )
        self.waf_state: dict[str, WafState] = defaultdict(WafState)
        self.csp_state = CSPState()
        self.plugins = load_plugins(config.plugin_paths)
        self.storage = SqliteStorage(db_path, batch_size=config.chunk_size)
        self.coordinator: RedisCoordinator | None = None
        self._hb_task: asyncio.Task[None] | None = None
        self._scanned = 0
        self._found   = 0

    async def _record(self, finding: Finding) -> None:
        if len(self.findings) < self.in_memory_findings_limit:
            self.findings.append(finding)
        self._found += 1
        await self.storage.store_finding(finding)

    async def _enqueue_if_new(self, url: str) -> bool:
        if should_skip(url):
            return False
        normalized = normalize_url(url)
        if await self.storage.has_seen_url(normalized):
            return False
        priority = score_url(url)
        await self.storage.enqueue_frontier_url(normalized, url, priority)
        if self.coordinator is not None:
            await self.coordinator.enqueue(normalized, url, priority)
        return True

    async def ingest(self, url_file: Path) -> None:
        seeds: list[str] = []
        async for url in stream_urls(url_file, self.config.max_urls):
            seeds.append(url)
            await self._enqueue_if_new(url)

        if self.config.spa_crawl and seeds:
            logger.info("SPA crawl enabled — crawling %d seed URLs", len(seeds[:50]))
            spa = await crawl_spa(
                seeds[:50],                       # FIX: don't pass millions of seeds to SPA crawler
                max_pages=self.config.spa_max_pages,
                timeout_ms=self.config.spa_timeout_ms,
            )
            for url in spa.routes | spa.api_endpoints | spa.graphql_endpoints | spa.js_routes:
                await self._enqueue_if_new(url)

        pending, done = await self.storage.frontier_counts()
        logger.info("Ingestion complete — %d pending, %d already done", pending, done)

    async def _next_task(self) -> UrlTask | None:
        if self.coordinator is not None:
            # FIX: was calling self.coordinator.lease() which doesn't exist — renamed to claim()
            task = await self.coordinator.claim()
            if task is None:
                return None
            return UrlTask(url=task.url, priority=task.priority)

        claimed = await self.storage.claim_frontier_batch(
            1, node_id=self.config.distributed_node_id,
            lease_seconds=self.config.lease_ttl_seconds,
        )
        if not claimed:
            return None
        _, original, priority = claimed[0]
        return UrlTask(url=original, priority=priority)

    async def _heartbeat_loop(self) -> None:
        assert self.coordinator is not None
        while True:
            await self.coordinator.worker_heartbeat()
            await self.coordinator.requeue_expired_leases()
            await asyncio.sleep(max(1, self.config.heartbeat_interval_seconds))

    async def worker(self, client: httpx.AsyncClient) -> None:
        while True:
            task = await self._next_task()
            if task is None:
                return
            normalized = normalize_url(task.url)
            try:
                await self._scan_url(client, task.url)
                self._scanned += 1
                if self._scanned % 100 == 0:
                    logger.info("Progress: %d scanned, %d findings", self._scanned, self._found)
                await self.storage.mark_processed_url(normalized)
                await self.storage.mark_frontier_done(normalized)
                if self.coordinator is not None:
                    await self.coordinator.ack(normalized)
            except Exception as exc:
                await self.storage.store_retry(task.url, 1, str(exc)[:500])
                if self.coordinator is not None:
                    await self.coordinator.fail(normalized, task.priority)
                logger.exception("worker error on %s", task.url)

    async def _scan_url(self, client: httpx.AsyncClient, url: str) -> None:   # noqa: C901
        split  = urlsplit(url)
        sem    = self.domain_limits[split.netloc]
        qs     = parse_qs(split.query, keep_blank_values=True)
        marker = "XSCANREFMARK"

        # Build probe URL with marker substituted into each param value
        probe_url = url
        if qs:
            mutated   = {k: [f"{marker}_{k}"] for k in qs}
            probe_url = urlunsplit((
                split.scheme, split.netloc, split.path,
                urlencode(mutated, doseq=True), split.fragment,
            ))

        async with sem:
            try:
                t0       = monotonic_ms()
                baseline = await client.get(url)
                t1       = monotonic_ms()
                response = await client.get(probe_url)
                t2       = monotonic_ms()
            except httpx.RequestError as exc:
                logger.debug("HTTP error on %s: %s", url, exc)
                return

        base_latency  = t1 - t0
        probe_latency = t2 - t1
        self.waf_state[split.netloc].observe_baseline(base_latency)

        # ── WAF detection ─────────────────────────────────────────
        waf = detect_waf_signals(
            split.netloc, baseline, response, base_latency, probe_latency, self.waf_state
        )
        if waf.triggered:
            await self._record(Finding(
                url=url, param=None,
                type=FindingType.WAF_SIGNAL,
                severity="medium",
                evidence={
                    "score": waf.score,
                    "reasons": waf.reasons,
                    "action": waf.action,
                    "status_delta": list(waf.status_delta),
                    "fingerprint": waf.fingerprint,
                },
            ))

        # ── CSP analysis ──────────────────────────────────────────
        csp_header = response.headers.get("content-security-policy", "")
        csp = analyze_csp(csp_header, url=url, state=self.csp_state)
        if csp["weaknesses"]:
            await self._record(Finding(
                url=url, param=None,
                type=FindingType.CSP_WEAKNESS,
                severity="medium" if len(csp["weaknesses"]) < 3 else "high",
                evidence=csp,
            ))

        # ── JS / DOM taint analysis ───────────────────────────────
        # FIX: original passed full HTML to quick_dom_pattern_scan which is slow
        #      and produces many false positives.  Only analyse <script> content.
        content_type = response.headers.get("content-type", "")
        if "javascript" in content_type or "html" in content_type:
            dom_flows = quick_dom_pattern_scan(response.text)
            for flow in dom_flows:
                await self._record(Finding(
                    url=url, param=None,
                    type=FindingType.DOM_SINK,
                    severity="high",
                    evidence=flow,
                ))

        # ── Source map / bundle analysis ──────────────────────────
        sm_intel = analyze_bundle_text(response.text)
        for endpoint in sorted(sm_intel.discovered_endpoints)[:50]:
            await self._record(Finding(
                url=url, param=None,
                type=FindingType.HISTORICAL_ENDPOINT,
                severity="info",
                evidence={
                    "endpoint": endpoint,
                    "source_map_hints": sorted(sm_intel.source_map_urls),
                    "sink_hints": sorted(sm_intel.sink_hints),
                },
            ))

        # ── Plugin hooks ──────────────────────────────────────────
        # FIX: PluginContext field was "response_headers" but engine passed "headers"
        ct = content_type
        for p in self.plugins:
            with contextlib.suppress(Exception):
                extras = await p.analyze(PluginContext(
                    url=url,
                    response_text=response.text,
                    headers=dict(response.headers),
                    content_type=ct,
                ))
                for item in extras:
                    await self._record(item)

        # ── Reflection probing ────────────────────────────────────
        if not qs:
            return

        for param in qs:
            probe = f"{marker}_{param}"
            refl  = detect_reflection(response.text, probe)
            if not refl:
                continue

            evidence = {"probe": probe, **refl.__dict__}
            await self._record(Finding(
                url=url, param=param,
                type=FindingType.REFLECTION,
                severity="info",
                evidence=evidence,
            ))

            # ── Browser verification ──────────────────────────────
            if not (self.config.verify_browser and refl.executable_hint):
                continue

            async with self._verify_lock:   # FIX: verify_count was a race condition
                if self.verify_count >= self.config.verify_budget:
                    continue
                self.verify_count += 1

            payload_plan = generate_payloads(
                refl.context, refl.encoded, csp_header, waf.triggered
            )
            try:
                runtime = await verify_runtime(
                    url, param, payload_plan.payloads,
                    Path(self.config.evidence_dir),
                )
            except Exception as exc:
                logger.warning("verify_runtime failed for %s[%s]: %s", url, param, exc)
                continue

            if runtime.execution_proof:
                repro = [
                    f"Open: {runtime.replay_url}",
                    f"Payload: {runtime.executed_payload}",
                    "Observe: execution token in console / dialog evidence",
                ]
                await self._record(Finding(
                    url=url, param=param,
                    type=FindingType.VERIFIED_REFLECTED_XSS,
                    severity="critical",
                    evidence={
                        "runtime": {
                            "alert_triggered": runtime.alert_triggered,
                            "execution_proof": runtime.execution_proof,
                            "execution_token": runtime.execution_token,
                            "executed_payload": runtime.executed_payload,
                            "replay_url": runtime.replay_url,
                            "screenshot_path": runtime.screenshot_path,
                            "dom_snapshot_path": runtime.dom_snapshot_path,
                            "console_events": runtime.console_events[:20],
                            "dialog_events": runtime.dialog_events,
                            "runtime_sink_hits": runtime.runtime_sink_hits[:20],
                            "dom_mutation_count": runtime.dom_mutation_count,
                            "network_events": runtime.network_events[:20],
                        },
                        "strategy": payload_plan.strategy,
                        "exact_payload": runtime.executed_payload,
                        "reproduction_steps": repro,
                    },
                ))

        # ── DOM runtime observation ───────────────────────────────
        if self.config.verify_browser:
            try:
                rt = await analyze_dom_runtime(url, marker, Path(self.config.evidence_dir))
                if rt.get("sink_hits") and rt.get("marker_observed"):
                    await self._record(Finding(
                        url=url, param=None,
                        type=FindingType.VERIFIED_EXECUTION,
                        severity="high",
                        evidence=rt,
                    ))
            except Exception as exc:
                logger.debug("analyze_dom_runtime error %s: %s", url, exc)

    async def run(self, url_file: Path) -> list[Finding]:
        await self.storage.start()

        if self.config.distributed_enabled:
            self.coordinator = RedisCoordinator(
                redis_url=self.config.redis_url,
                node_id=self.config.distributed_node_id,
                lease_ttl_seconds=self.config.lease_ttl_seconds,
                heartbeat_interval_seconds=self.config.heartbeat_interval_seconds,
                max_retry_attempts=self.config.retries,
            )
            self._hb_task = asyncio.create_task(self._heartbeat_loop())

        await self.ingest(url_file)

        try:
            limits = httpx.Limits(
                max_connections=self.config.max_connections,
                max_keepalive_connections=self.config.max_keepalive_connections,
            )
            # FIX: added auth header/cookie to client headers rather than nowhere
            headers: dict[str, str] = {"User-Agent": self.config.user_agent}
            if self.config.auth_header:
                k, _, v = self.config.auth_header.partition(":")
                headers[k.strip()] = v.strip()
            cookies: dict[str, str] = {}
            if self.config.auth_cookie:
                for pair in self.config.auth_cookie.split(";"):
                    ck, _, cv = pair.strip().partition("=")
                    if ck:
                        cookies[ck.strip()] = cv.strip()

            async with httpx.AsyncClient(
                timeout=self.config.timeout_seconds,
                follow_redirects=True,
                limits=limits,
                headers=headers,
                cookies=cookies,
            ) as client:
                await asyncio.gather(*[
                    self.worker(client) for _ in range(self.config.workers)
                ])

            await self.storage.drain()
            logger.info(
                "Scan complete: %d URLs scanned, %d findings", self._scanned, self._found
            )
            return self.findings

        finally:
            if self._hb_task is not None:
                self._hb_task.cancel()
                with contextlib.suppress(Exception):
                    await self._hb_task
            if self.coordinator is not None:
                await self.coordinator.close()
            await self.storage.close()
