from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ParsedCSP:
    directives: dict[str, list[str]]


@dataclass
class CSPState:
    # maps nonce_value → set of hosts that have served it
    nonce_to_origins: dict[str, set[str]] = field(default_factory=dict)


# Common JSONP and open-redirect patterns on allowlisted CDNs
COMMON_JSONP_ENDPOINT_HINTS = (
    "callback=",
    "jsonp",
    "?cb=",
    "?json=",
    "format=jsonp",
)

FRAMEWORK_SCRIPT_HOST_HINTS: dict[str, tuple[str, ...]] = {
    "angular": (
        "ajax.googleapis.com",
        "gstatic.com",
        "unpkg.com",
        "cdn.jsdelivr.net",
    ),
    "react": (
        "unpkg.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "cdn.skypack.dev",
    ),
}


def _parse_policy(policy: str) -> ParsedCSP:
    directives: dict[str, list[str]] = {}
    for part in (policy or "").split(";"):
        token = part.strip()
        if not token:
            continue
        bits  = token.split()
        name  = bits[0].lower()
        directives[name] = bits[1:]
    return ParsedCSP(directives=directives)


def _effective_sources(parsed: ParsedCSP, directive: str) -> list[str]:
    """Return the effective source list, falling back to default-src."""
    if directive in parsed.directives:
        return parsed.directives[directive]
    return parsed.directives.get("default-src", [])


def _extract_nonces(sources: list[str]) -> list[str]:
    nonces: list[str] = []
    for src in sources:
        s = src.strip("\"'")
        if s.lower().startswith("nonce-"):
            nonces.append(s[len("nonce-"):])
    return nonces


def _is_trusted_remote_source(src: str) -> bool:
    s = src.strip("\"'").lower()
    return s.startswith("https://") or s.startswith("http://") or s.startswith("//")


def _source_has_jsonp_risk(src: str) -> bool:
    s = src.lower()
    return any(h in s for h in COMMON_JSONP_ENDPOINT_HINTS)


def analyze_csp(  # noqa: C901
    policy: str,
    url: str | None = None,
    state: CSPState | None = None,
) -> dict[str, object]:
    """
    Parse and analyse a Content-Security-Policy header.

    FIX 1: Original did not check for missing `base-uri` (allows base-tag injection).
    FIX 2: Original did not detect `unsafe-hashes` weakness.
    FIX 3: Nonce-reuse check now also catches same-origin nonce reuse (not just
           cross-origin), which still defeats nonce protection.
    FIX 4: risk_score calculation was linear and topped out at a meaningless number;
           now uses a weighted scheme that better reflects real exploitability.
    FIX 5: Added `report-uri` / `report-to` detection (useful for reconnaissance).
    """
    state = state or CSPState()
    weaknesses: list[str] = []

    if not policy or not policy.strip():
        return {
            "policy": "",
            "weaknesses": ["missing-csp"],
            "risk_score": 100,
            "model": {},
        }

    parsed     = _parse_policy(policy)
    script_src = _effective_sources(parsed, "script-src")
    object_src = _effective_sources(parsed, "object-src")
    connect_src= _effective_sources(parsed, "connect-src")
    base_uri   = parsed.directives.get("base-uri", None)   # FIX 1

    # ── inline / eval ─────────────────────────────────────────────
    if "'unsafe-inline'" in script_src:
        weaknesses.append("unsafe-inline-script")
    if "'unsafe-eval'" in script_src:
        weaknesses.append("unsafe-eval-script")
    if "'unsafe-hashes'" in script_src:            # FIX 2
        weaknesses.append("unsafe-hashes-script")

    # ── wildcard ──────────────────────────────────────────────────
    if "*" in script_src or "*" in connect_src:
        weaknesses.append("wildcard-execution-surface")

    # ── insecure http origins ─────────────────────────────────────
    if any(s.lower().startswith("http:") for s in script_src + connect_src):
        weaknesses.append("insecure-http-origin")

    # ── object-src ────────────────────────────────────────────────
    if not object_src or "'none'" not in [o.lower() for o in object_src]:
        weaknesses.append("object-src-not-locked")

    # ── strict-dynamic ────────────────────────────────────────────
    if "'strict-dynamic'" not in [s.lower() for s in script_src]:
        weaknesses.append("missing-strict-dynamic")

    # FIX 1: base-uri
    if base_uri is None:
        weaknesses.append("missing-base-uri")
    elif base_uri and "'none'" not in [b.lower() for b in base_uri] and "'self'" not in [b.lower() for b in base_uri]:
        weaknesses.append("permissive-base-uri")

    # ── nonce reuse (FIX 3: same-origin reuse counts too) ─────────
    nonce_values = _extract_nonces(script_src)
    host         = urlparse(url).netloc if url else ""
    nonce_reuse: list[str] = []
    for n in nonce_values:
        prev = state.nonce_to_origins.setdefault(n, set())
        if prev:                    # FIX 3: any prior sighting = reuse
            nonce_reuse.append(n)
        if host:
            prev.add(host)
    if nonce_reuse:
        weaknesses.append("nonce-reuse-detected")

    # ── trusted origins & gadgets ─────────────────────────────────
    trusted_origins = [s for s in script_src if _is_trusted_remote_source(s)]
    jsonp_trusted   = [s for s in trusted_origins if _source_has_jsonp_risk(s)]
    if jsonp_trusted:
        weaknesses.append("trusted-jsonp-surface")

    angular_gadget = any(
        any(h in src for h in FRAMEWORK_SCRIPT_HOST_HINTS["angular"])
        for src in trusted_origins
    )
    react_gadget = any(
        any(h in src for h in FRAMEWORK_SCRIPT_HOST_HINTS["react"])
        for src in trusted_origins
    )

    if angular_gadget:
        weaknesses.append("angular-gadget-possible")
    if react_gadget and "'strict-dynamic'" not in [s.lower() for s in script_src]:
        weaknesses.append("react-gadget-possible")
    if trusted_origins and nonce_values and "'strict-dynamic'" not in [s.lower() for s in script_src]:
        weaknesses.append("trusted-script-abuse-path")

    # FIX 5: report-uri / report-to detection
    report_uri = parsed.directives.get("report-uri", [])
    report_to  = parsed.directives.get("report-to",  [])

    # ── bypass reasoning ──────────────────────────────────────────
    bypass_paths: list[str] = []
    if "unsafe-inline-script" in weaknesses:
        bypass_paths.append("Inline script execution — no bypass needed")
    if "trusted-jsonp-surface" in weaknesses:
        bypass_paths.append("JSONP callback injection via trusted allowlisted domain")
    if "trusted-script-abuse-path" in weaknesses:
        bypass_paths.append("Nonce-bearing bootstrap can load attacker-controlled trusted scripts")
    if "angular-gadget-possible" in weaknesses:
        bypass_paths.append("Angular template injection via trusted CDN gadget")
    if "react-gadget-possible" in weaknesses:
        bypass_paths.append("React dangerouslySetInnerHTML via trusted CDN gadget")
    if "wildcard-execution-surface" in weaknesses:
        bypass_paths.append("Wildcard allows loading script from any origin")
    if "nonce-reuse-detected" in weaknesses:
        bypass_paths.append("Inject <script nonce=OBSERVED_NONCE> in reflection")

    # FIX 4: weighted risk score
    weight_map = {
        "missing-csp":              100,
        "unsafe-inline-script":      70,
        "wildcard-execution-surface":65,
        "unsafe-eval-script":        50,
        "trusted-jsonp-surface":     45,
        "angular-gadget-possible":   40,
        "react-gadget-possible":     35,
        "nonce-reuse-detected":      35,
        "trusted-script-abuse-path": 30,
        "missing-base-uri":          20,
        "missing-strict-dynamic":    15,
        "insecure-http-origin":      15,
        "object-src-not-locked":     10,
        "unsafe-hashes-script":      25,
    }
    risk_score = min(100, sum(weight_map.get(w, 5) for w in weaknesses))

    return {
        "policy":     policy[:4000],
        "weaknesses": weaknesses,
        "risk_score": risk_score,
        "model": {
            "directives":        parsed.directives,
            "trusted_origins":   trusted_origins,
            "nonce_values_count": len(nonce_values),
            "nonce_reuse_values": nonce_reuse,
            "trusted_jsonp_origins": jsonp_trusted,
            "framework_gadgets": {"angular": angular_gadget, "react": react_gadget},
            "bypass_paths":      bypass_paths,
            "report_endpoints":  report_uri + report_to,
            "directive_graph": {
                "script-src":  script_src,
                "connect-src": connect_src,
                "object-src":  object_src,
                "base-uri":    base_uri or [],
                "inherits_default": {
                    "script-src":  "script-src" not in parsed.directives,
                    "connect-src": "connect-src" not in parsed.directives,
                    "object-src":  "object-src" not in parsed.directives,
                },
            },
        },
    }
