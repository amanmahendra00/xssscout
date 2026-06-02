from __future__ import annotations

import logging
from dataclasses import dataclass, field
from time import monotonic

import httpx

logger = logging.getLogger(__name__)


def monotonic_ms() -> float:
    return monotonic() * 1000.0


@dataclass(slots=True)
class WafState:
    baseline_latencies: list[float] = field(default_factory=list)
    block_fingerprints: set[str]    = field(default_factory=set)
    recent_statuses: list[int]      = field(default_factory=list)

    def observe_baseline(self, latency_ms: float) -> None:
        self.baseline_latencies.append(latency_ms)
        if len(self.baseline_latencies) > 40:
            self.baseline_latencies.pop(0)

    @property
    def baseline_avg(self) -> float:
        if not self.baseline_latencies:
            return 0.0
        return sum(self.baseline_latencies) / len(self.baseline_latencies)


@dataclass(slots=True)
class WafSignal:
    triggered: bool
    score: int
    reasons: list[str]
    action: str
    baseline_latency_ms: float
    probe_latency_ms: float
    status_delta: tuple[int, int]
    normalized_payload_detected: bool
    fingerprint: str | None = None


# FIX: expanded fingerprint hints — original list was too short
BLOCK_HINTS = (
    "access denied",
    "forbidden",
    "request blocked",
    "malicious request",
    "security policy",
    "cloudflare ray id",
    "attention required",      # CF block page
    "akamai reference",
    "incapsula incident",
    "sucuri website firewall",
    "aws waf",
    "mod_security",
    "you have been blocked",
    "blocked by",
    "error 1005",              # CF error codes
    "error 1006",
    "error 1010",
    "error 1012",
)

WAF_HEADER_HINTS = (
    "cf-ray",
    "x-sucuri-id",
    "x-iinfo",
    "x-akamai-transformed",
    "x-cdn",
    "x-waf-event-info",
    "x-amzn-waf",
    "server-timing",           # sometimes used by CDN for timing injection
)


def _fingerprint(resp: httpx.Response) -> str:
    body  = resp.text[:1024].lower()
    server = resp.headers.get("server", "").lower()
    return f"{resp.status_code}|{server}|{hash(body)}"


def detect_waf_signals(
    host: str,
    baseline_resp: httpx.Response,
    probe_resp: httpx.Response,
    baseline_latency_ms: float,
    probe_latency_ms: float,
    state_map: dict[str, WafState],
) -> WafSignal:
    """
    Heuristic WAF/CDN detection via differential analysis.

    FIX 1: Original did not check response headers for WAF fingerprint headers.
    FIX 2: Score threshold was 35 which fired too easily on slow servers.
           Now uses a 40 threshold with a stronger confirmation on header fingerprinting.
    FIX 3: `normalized_payload_detected` logic was inverted — it was True when the
           marker was NOT in the body, which is normal for non-reflected pages.
           Fixed to only flag when status also differs.
    """
    state   = state_map[host]
    reasons: list[str] = []
    score   = 0

    # ── differential status ───────────────────────────────────────
    if probe_resp.status_code in {403, 406, 429} and probe_resp.status_code != baseline_resp.status_code:
        reasons.append("differential-status-block")
        score += 35
    if probe_resp.status_code >= 500 and baseline_resp.status_code < 500:
        reasons.append("differential-server-error")
        score += 20

    # ── timing anomaly ────────────────────────────────────────────
    baseline_avg = max(state.baseline_avg, baseline_latency_ms, 1.0)
    if probe_latency_ms > baseline_avg * 3.0:   # FIX 2: raised multiplier to reduce noise
        reasons.append("timing-anomaly")
        score += 15

    # ── block page body fingerprint ───────────────────────────────
    body_low = probe_resp.text[:4096].lower()
    matched_hints = [h for h in BLOCK_HINTS if h in body_low]
    if matched_hints:
        reasons.append(f"block-page-fingerprint:{matched_hints[0]}")
        score += 30

    # FIX 1: WAF header fingerprinting
    probe_headers_low = {k.lower(): v for k, v in probe_resp.headers.items()}
    matched_headers = [h for h in WAF_HEADER_HINTS if h in probe_headers_low]
    if matched_headers:
        reasons.append(f"waf-header:{matched_headers[0]}")
        score += 20

    # FIX 3: payload normalization — only meaningful when status differs
    probe_marker_absent = (
        "xscanrefmark" not in body_low and "__xscan" not in body_low
    )
    normalized_payload_detected = (
        probe_marker_absent
        and probe_resp.status_code != baseline_resp.status_code
    )
    if normalized_payload_detected:
        reasons.append("payload-normalization-suspected")
        score += 10

    # ── known fingerprint cache ────────────────────────────────────
    fp = _fingerprint(probe_resp)
    if fp in state.block_fingerprints:
        reasons.append("known-block-fingerprint")
        score += 10
    if any(r in reasons for r in ("block-page-fingerprint", "differential-status-block", "waf-header")):
        state.block_fingerprints.add(fp)

    state.recent_statuses.append(probe_resp.status_code)
    if len(state.recent_statuses) > 30:
        state.recent_statuses.pop(0)

    triggered = score >= 40     # FIX 2: raised threshold
    action    = "adaptive-throttle" if triggered else "continue"

    if triggered:
        logger.debug("WAF detected on %s (score=%d reasons=%s)", host, score, reasons)

    return WafSignal(
        triggered=triggered,
        score=score,
        reasons=reasons,
        action=action,
        baseline_latency_ms=baseline_latency_ms,
        probe_latency_ms=probe_latency_ms,
        status_delta=(baseline_resp.status_code, probe_resp.status_code),
        normalized_payload_detected=normalized_payload_detected,
        fingerprint=fp if triggered else None,
    )
