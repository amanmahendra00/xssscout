from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Attribute names that are genuinely non-executable even when reflected
# ---------------------------------------------------------------------------
_INERT_ATTRS = {
    "title", "alt", "placeholder", "value", "aria-label",
    "aria-describedby", "aria-description", "data", "id", "class",
    "name", "for", "tabindex", "role", "lang", "dir",
}

# Patterns indicating the runtime has escaped or encoded the reflection
_ESCAPE_RE = re.compile(
    r"(\\u[0-9a-fA-F]{2,4}"
    r"|\\x[0-9a-fA-F]{2}"
    r"|&(?:quot|apos|#x27|#39|lt|gt|amp);"
    r"|\\[\"'])",
)

# CSS / SVG contexts
_CSS_CONTEXT_RE  = re.compile(r"<style[^>]*>[\s\S]*?MARKER[\s\S]*?</style>", re.IGNORECASE)
_SVG_CONTEXT_RE  = re.compile(r"<svg[^>]*>[\s\S]*?MARKER[\s\S]*?</svg>",   re.IGNORECASE)
_URL_CONTEXT_RE  = re.compile(r'(?:href|src|action|data|formaction)\s*=\s*["\'][^"\']*MARKER')
_JSON_CONTEXT_RE = re.compile(r'[{,]\s*"[^"]*"\s*:\s*(?:"[^"]*MARKER[^"]*"|\bMARKER\b)')


@dataclass(slots=True)
class ReflectionResult:
    context: str                    # html_text | attribute | script | css | svg | url | json | unknown
    encoded: bool                   # marker only found after HTML-entity decode
    escaped: bool                   # JS-level escaping detected near marker
    raw_hit: bool
    executable_hint: bool           # True only when reflection is realistically exploitable
    classification: str             # potentially-executable | sanitized-reflection | dead-reflection
    suppressed: bool
    suppression_reasons: list[str]


def _has_escaping_near_marker(body: str, marker: str) -> bool:
    idx = body.find(marker)
    if idx < 0:
        return False
    start = max(0, idx - 20)
    window = body[start: idx + len(marker) + 20]
    return bool(_ESCAPE_RE.search(window))


def detect_reflection(body: str, marker: str) -> ReflectionResult | None:   # noqa: C901
    """
    Detect how and where *marker* is reflected in *body*.

    FIX 1: Original missed CSS, SVG, and URL contexts entirely.
    FIX 2: Original dead_reflection logic was wrong — a reflection in html_text IS
            a potential XSS if there is no escaping (e.g. innerHTML assignment).
    FIX 3: Original encoded check used `marker in decoded` but not `marker not in body`
            which could produce a false encoded=True when both contain the marker.
    FIX 4: executable_hint now requires context to be one of the genuinely dangerous
            contexts rather than any non-dead context.
    """
    decoded = unescape(body)
    raw_hit = marker in body or marker in decoded
    if not raw_hit:
        return None

    # ---- context detection (ordered most-specific → least) ----
    soup = BeautifulSoup(body, "lxml")

    in_script = any(
        marker in (script.string or "")
        for script in soup.find_all("script")
    )

    # attribute context
    attr_hits: list[tuple[str, str]] = []
    for tag in soup.find_all():
        for k, v in tag.attrs.items():
            rendered = " ".join(v) if isinstance(v, list) else str(v)
            if marker in rendered:
                attr_hits.append((str(k).lower(), rendered))
    in_attr = bool(attr_hits)

    # specialised contexts via regex (replace MARKER placeholder)
    _b = body.replace(marker, "MARKER")
    in_css  = bool(_CSS_CONTEXT_RE.search(_b))
    in_svg  = bool(_SVG_CONTEXT_RE.search(_b))
    in_url  = bool(_URL_CONTEXT_RE.search(_b))
    in_json = bool(_JSON_CONTEXT_RE.search(_b))
    in_text = marker in soup.get_text(" ", strip=False)

    # priority order
    if in_script:
        context = "script"
    elif in_css:
        context = "css"
    elif in_svg:
        context = "svg"
    elif in_url:
        context = "url"
    elif in_json:
        context = "json"
    elif in_attr:
        context = "attribute"
    elif in_text:
        context = "html_text"
    else:
        context = "unknown"

    # FIX 3: encoded = marker only appears after decode, not in raw body
    encoded = (marker not in body) and (marker in decoded)
    escaped = _has_escaping_near_marker(body, marker)

    # attribute sub-classification
    inert_attr      = in_attr and all(a in _INERT_ATTRS for a, _ in attr_hits)
    event_handler   = any(a.startswith("on") for a, _ in attr_hits)

    suppression_reasons: list[str] = []
    if encoded:
        suppression_reasons.append("encoded_reflection")
    if escaped:
        suppression_reasons.append("escaped_reflection")
    if in_attr and inert_attr and not event_handler:
        suppression_reasons.append("non_exploitable_sink")
    if context in {"unknown", "json"} and not in_script and not event_handler:
        suppression_reasons.append("dead_reflection")
    if in_css:
        suppression_reasons.append("css_context_low_risk")

    suppressed = bool(suppression_reasons)

    # FIX 4: only flag executable_hint for genuinely dangerous contexts
    dangerous_context = context in {"script", "svg", "html_text", "url", "attribute"}
    executable_hint = (
        dangerous_context
        and not encoded
        and not escaped
        and not (in_attr and inert_attr and not event_handler)
    )

    if executable_hint:
        classification = "potentially-executable"
    elif encoded or escaped:
        classification = "sanitized-reflection"
    else:
        classification = "dead-reflection"

    return ReflectionResult(
        context=context,
        encoded=encoded,
        escaped=escaped,
        raw_hit=raw_hit,
        executable_hint=executable_hint,
        classification=classification,
        suppressed=suppressed,
        suppression_reasons=suppression_reasons,
    )
