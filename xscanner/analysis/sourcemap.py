from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SourceMapIntel:
    source_map_urls: set[str]        = field(default_factory=set)
    discovered_endpoints: set[str]   = field(default_factory=set)
    discovered_routes: set[str]      = field(default_factory=set)
    sink_hints: set[str]             = field(default_factory=set)


# FIX: original regex only matched /api and /graphql paths — too narrow.
#      New pattern covers more common API path structures.
_ENDPOINT_RE = re.compile(
    r"""(?:"|')("""
    r"""(?:https?:)?//[^"' ]{4,}/(?:api|graphql|v\d+|rest|rpc|gql)[^"']*"""
    r"""|/[a-zA-Z0-9_\-/]*(?:api|graphql|auth|admin|oauth|rpc|gql)[^"']{0,80}"""
    r""")(?:"|')""",
    re.VERBOSE,
)

_ROUTE_RE = re.compile(
    r"""(?:"|')(/(?:[a-zA-Z0-9_\-.:@]+/?){1,8})(?:"|')"""
)

_SINK_RE = re.compile(
    # FIX: added document.writeln, srcdoc, location.href assignment
    r"\b(innerHTML|outerHTML|insertAdjacentHTML"
    r"|document\.write(?:ln)?|eval|Function"
    r"|setTimeout|setInterval|srcdoc)\b"
)

# common path segments that are noise (don't discover as API endpoints)
_NOISE_SEGMENTS = {
    "/static/", "/assets/", "/images/", "/fonts/", "/css/", "/js/",
    ".png", ".jpg", ".svg", ".woff", ".css",
}


def _is_noise_route(route: str) -> bool:
    low = route.lower()
    return any(seg in low for seg in _NOISE_SEGMENTS) or len(route) < 3


def find_source_map_urls(js_text: str) -> set[str]:
    urls: set[str] = set()
    # sourceMappingURL can be anywhere in the last 10 lines or in X-SourceMap header hints
    for line in js_text.splitlines()[-10:]:
        if "sourceMappingURL=" in line:
            raw = line.split("sourceMappingURL=", 1)[1].strip()
            # strip trailing */ or similar
            raw = re.split(r"[\s*/]", raw)[0]
            if raw:
                urls.add(raw)
    return urls


def analyze_bundle_text(js_text: str) -> SourceMapIntel:
    intel = SourceMapIntel()
    intel.source_map_urls    = find_source_map_urls(js_text)
    intel.discovered_endpoints = {
        m.group(1) for m in _ENDPOINT_RE.finditer(js_text)
    }
    intel.discovered_routes  = {
        m.group(1) for m in _ROUTE_RE.finditer(js_text)
        if not _is_noise_route(m.group(1)) and m.group(1).count("/") <= 8
    }
    intel.sink_hints         = {m.group(1) for m in _SINK_RE.finditer(js_text)}
    return intel


def analyze_source_map_json(raw_map: str) -> SourceMapIntel:
    """
    Parse a .map file and extract endpoint/sink intelligence from source paths and names.

    FIX: original silently returned empty intel on JSON parse error without logging.
    """
    intel = SourceMapIntel()
    try:
        obj = json.loads(raw_map)
    except Exception as exc:
        logger.debug("analyze_source_map_json: JSON parse failed: %s", exc)
        return intel

    srcs  = obj.get("sources", [])
    names = obj.get("names",   [])
    combined = "\n".join([
        *(s for s in srcs  if isinstance(s, str)),
        *(n for n in names if isinstance(n, str)),
    ])
    mined = analyze_bundle_text(combined)
    intel.source_map_urls      |= mined.source_map_urls
    intel.discovered_endpoints |= mined.discovered_endpoints
    intel.discovered_routes    |= mined.discovered_routes
    intel.sink_hints           |= mined.sink_hints
    return intel
