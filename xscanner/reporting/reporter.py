from __future__ import annotations

import json
import logging
from pathlib import Path

from jinja2 import Environment, select_autoescape

from xscanner.models import Finding, FindingType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(findings: list[Finding], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    # FIX: __dict__ on a dataclass with slots does not work — use dataclasses.asdict
    import dataclasses
    serialisable = []
    for f in findings:
        d = dataclasses.asdict(f)
        d["type"] = f.type.value       # enum → string
        serialisable.append(d)
    out.write_text(json.dumps(serialisable, indent=2, default=str), encoding="utf-8")
    logger.info("Wrote JSON report → %s (%d findings)", out, len(findings))


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def write_markdown(findings: list[Finding], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# XScanner Findings", ""]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 9), f.url))

    for item in sorted_findings:
        lines.append(f"## [{item.severity.upper()}] {item.type.value}")
        lines.append(f"- **URL:** `{item.url}`")
        lines.append(f"- **Param:** `{item.param}`")

        ev = item.evidence

        if ev.get("exact_payload"):
            lines.append(f"- **Payload:** `{ev['exact_payload']}`")

        # Runtime evidence block
        rt = ev.get("runtime", {})
        if rt.get("screenshot_path"):
            lines.append(f"- **Screenshot:** `{rt['screenshot_path']}`")
        if rt.get("dom_snapshot_path"):
            lines.append(f"- **DOM snapshot:** `{rt['dom_snapshot_path']}`")
        if rt.get("replay_url"):
            lines.append(f"- **Replay URL:** `{rt['replay_url']}`")

        if ev.get("reproduction_steps"):
            lines.append("- **Reproduction:**")
            lines.extend(f"  {i+1}. {step}" for i, step in enumerate(ev["reproduction_steps"]))

        if ev.get("weaknesses"):
            lines.append(f"- **CSP weaknesses:** {', '.join(ev['weaknesses'])}")
        if ev.get("bypass_paths"):
            lines.append(f"- **Bypass paths:** {', '.join(ev.get('model', {}).get('bypass_paths', []))}")

        if ev.get("reasons"):
            lines.append(f"- **WAF signals:** {', '.join(ev['reasons'])}")

        lines.append("")

    out.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Wrote Markdown report → %s", out)


# ---------------------------------------------------------------------------
# HTML  (FIX: original was a barebones unstyled template)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>XScanner Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'JetBrains Mono',monospace,sans-serif;background:#080a0d;color:#e8f0ff;font-size:13px;padding:24px}
  h1{font-size:22px;margin-bottom:20px;color:#00e5ff;letter-spacing:.5px}
  h2{font-size:13px;font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:.1em}
  .finding{background:#111620;border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:16px;margin-bottom:12px;position:relative}
  .finding::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:8px 0 0 8px}
  .sev-critical::before{background:#ff3b4e}
  .sev-high::before{background:#ff7043}
  .sev-medium::before{background:#ffab00}
  .sev-info::before{background:#448aff}
  .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;margin-right:6px}
  .badge-critical{background:rgba(255,59,78,.2);color:#ff3b4e}
  .badge-high{background:rgba(255,112,67,.18);color:#ff7043}
  .badge-medium{background:rgba(255,171,0,.15);color:#ffab00}
  .badge-info{background:rgba(68,138,255,.15);color:#448aff}
  .row{display:flex;gap:8px;margin:5px 0;align-items:baseline}
  .key{color:#4a6080;min-width:120px;font-size:10px;text-transform:uppercase;letter-spacing:.06em}
  .val{color:#8fa4c8;word-break:break-all}
  code{background:#161d2a;padding:2px 6px;border-radius:3px;color:#00e5ff;font-size:11px}
  pre{background:#0c0f14;border:1px solid rgba(255,255,255,.06);border-radius:4px;padding:10px;overflow-x:auto;font-size:10px;color:#a8b8d0;margin-top:6px}
  .summary{background:#0c0f14;border:1px solid rgba(0,229,255,.15);border-radius:8px;padding:16px;margin-bottom:20px;display:flex;gap:24px;flex-wrap:wrap}
  .summary-stat .label{font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:.1em}
  .summary-stat .val{font-size:24px;font-weight:700;margin-top:4px}
</style>
</head>
<body>
<h1>XScanner Security Report</h1>
<div class="summary">
  {% for sev, cnt in severity_counts.items() %}
  <div class="summary-stat">
    <div class="label">{{ sev }}</div>
    <div class="val" style="color:{{ sev_colors[sev] }}">{{ cnt }}</div>
  </div>
  {% endfor %}
</div>
{% for f in findings %}
<div class="finding sev-{{ f.severity }}">
  <h2>
    <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
    {{ f.type.value }}
  </h2>
  <div class="row"><span class="key">URL</span><span class="val"><code>{{ f.url }}</code></span></div>
  {% if f.param %}<div class="row"><span class="key">Parameter</span><span class="val"><code>{{ f.param }}</code></span></div>{% endif %}
  {% set ev = f.evidence %}
  {% if ev.get('exact_payload') %}
  <div class="row"><span class="key">Payload</span><span class="val"><code>{{ ev.exact_payload | e }}</code></span></div>
  {% endif %}
  {% set rt = ev.get('runtime', {}) %}
  {% if rt.get('replay_url') %}
  <div class="row"><span class="key">Replay URL</span><span class="val"><code>{{ rt.replay_url | e }}</code></span></div>
  {% endif %}
  {% if rt.get('screenshot_path') %}
  <div class="row"><span class="key">Screenshot</span><span class="val">{{ rt.screenshot_path }}</span></div>
  {% endif %}
  {% if ev.get('reproduction_steps') %}
  <div class="row"><span class="key">Repro</span><div>{% for step in ev.reproduction_steps %}<div class="val">{{ loop.index }}. {{ step }}</div>{% endfor %}</div></div>
  {% endif %}
  {% if ev.get('weaknesses') %}
  <div class="row"><span class="key">CSP Issues</span><span class="val">{{ ev.weaknesses | join(', ') }}</span></div>
  {% endif %}
  {% if ev.get('reasons') %}
  <div class="row"><span class="key">WAF Signals</span><span class="val">{{ ev.reasons | join(', ') }}</span></div>
  {% endif %}
  <details style="margin-top:8px">
    <summary style="cursor:pointer;color:#4a6080;font-size:10px">Raw evidence</summary>
    <pre>{{ ev | tojson(indent=2) }}</pre>
  </details>
</div>
{% endfor %}
</body></html>"""


def write_html(findings: list[Finding], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)

    sev_order  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_colors = {"critical": "#ff3b4e", "high": "#ff7043", "medium": "#ffab00", "low": "#00e676", "info": "#448aff"}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 9), f.url))

    severity_counts: dict[str, int] = {}
    for f in sorted_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    env = Environment(autoescape=select_autoescape(["html"]))
    env.filters["tojson"] = lambda v, indent=None: json.dumps(v, indent=indent, default=str)
    tpl = env.from_string(_HTML_TEMPLATE)

    out.write_text(
        tpl.render(
            findings=sorted_findings,
            severity_counts=severity_counts,
            sev_colors=sev_colors,
        ),
        encoding="utf-8",
    )
    logger.info("Wrote HTML report → %s", out)


# ---------------------------------------------------------------------------
# Categorised output files  (§16)
# FIX: original did not include stored XSS type in confirmed bucket
# ---------------------------------------------------------------------------

def write_categorized(findings: list[Finding], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    confirmed_types = {
        FindingType.VERIFIED_EXECUTION.value,
        FindingType.VERIFIED_REFLECTED_XSS.value,
        FindingType.POTENTIAL_STORED_INPUT.value,   # FIX: was omitted
    }

    buckets: dict[str, list[Finding]] = {
        "confirmed_xss.txt":  [f for f in findings if f.type.value in confirmed_types],
        "potential_xss.txt":  [f for f in findings if f.type.value == FindingType.REFLECTION.value],
        "dom_xss.txt":        [f for f in findings if f.type.value == FindingType.DOM_SINK.value],
        "csp_bypass.txt":     [f for f in findings if f.type.value == FindingType.CSP_WEAKNESS.value],
        "waf_detected.txt":   [f for f in findings if f.type.value == FindingType.WAF_SIGNAL.value],
    }

    for name, items in buckets.items():
        lines = sorted({f.url for f in items})
        (output_dir / name).write_text("\n".join(lines), encoding="utf-8")
        logger.info("Wrote %s → %d URLs", name, len(lines))
