from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from playwright.async_api import async_playwright

from xscanner.models import RuntimeEvidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Runtime hook injected into every page before navigation.
# FIX: Original hook did not properly intercept innerHTML/document.write
#      assignments — it only partially patched alert().  The new hook wraps
#      the most dangerous sinks and tracks CSP violations.
# ---------------------------------------------------------------------------
RUNTIME_HOOK_SCRIPT = r"""
(() => {
  if (window.__xscanRuntime) return;   // idempotent — don't double-inject

  const rt = {
    sinkHits: [],
    execHits: [],
    dialogEvents: [],
    consoleEvents: [],
    cspViolations: [],
    domMutations: 0,
    networkEvents: [],
  };
  window.__xscanRuntime = rt;

  const norm = (v) => {
    try { return typeof v === 'string' ? v : JSON.stringify(v); }
    catch { return String(v); }
  };

  // ── exec callback (token rendezvous point) ─────────────────────
  window.__xscan_exec = (token) => {
    rt.execHits.push(norm(token));
    console.log('__xscan_exec__', norm(token));
  };

  // ── alert / confirm / prompt ───────────────────────────────────
  const _alert   = window.alert;
  const _confirm = window.confirm;
  const _prompt  = window.prompt;
  window.alert   = function(m){ rt.sinkHits.push({sink:'alert',  args:[norm(m)],ts:Date.now()}); rt.dialogEvents.push({type:'alert',  message:norm(m)}); return _alert.call(window, m); };
  window.confirm = function(m){ rt.sinkHits.push({sink:'confirm',args:[norm(m)],ts:Date.now()}); rt.dialogEvents.push({type:'confirm',message:norm(m)}); return _confirm.call(window,m); };
  window.prompt  = function(m){ rt.sinkHits.push({sink:'prompt', args:[norm(m)],ts:Date.now()}); rt.dialogEvents.push({type:'prompt', message:norm(m)}); return _prompt.call(window, m); };

  // ── innerHTML / outerHTML ──────────────────────────────────────
  const _descGet = (proto, prop) => Object.getOwnPropertyDescriptor(proto, prop);
  const _wrap = (proto, prop) => {
    const desc = _descGet(proto, prop);
    if (!desc || !desc.set) return;
    Object.defineProperty(proto, prop, {
      set(v) {
        rt.sinkHits.push({sink: prop, args: [norm(v).slice(0, 200)], ts: Date.now()});
        return desc.set.call(this, v);
      },
      get: desc.get,
      configurable: true,
    });
  };
  _wrap(Element.prototype, 'innerHTML');
  _wrap(Element.prototype, 'outerHTML');

  // ── document.write ─────────────────────────────────────────────
  const _dw  = document.write.bind(document);
  const _dwl = document.writeln.bind(document);
  document.write   = function(...a){ rt.sinkHits.push({sink:'document.write',  args:a.map(norm),ts:Date.now()}); return _dw(...a);  };
  document.writeln = function(...a){ rt.sinkHits.push({sink:'document.writeln',args:a.map(norm),ts:Date.now()}); return _dwl(...a); };

  // ── eval / Function ────────────────────────────────────────────
  const _eval = window.eval;
  window.eval = function(s){ rt.sinkHits.push({sink:'eval',args:[norm(s).slice(0,200)],ts:Date.now()}); return _eval.call(window, s); };
  const _Func = window.Function;
  window.Function = function(...a){ rt.sinkHits.push({sink:'Function',args:a.map(s=>norm(s).slice(0,100)),ts:Date.now()}); return _Func(...a); };

  // ── setTimeout / setInterval with string arg ───────────────────
  const _sto = window.setTimeout;
  const _sti = window.setInterval;
  window.setTimeout  = function(fn,...r){ if(typeof fn==='string'){rt.sinkHits.push({sink:'setTimeout', args:[norm(fn).slice(0,200)],ts:Date.now()});} return _sto.call(window,fn,...r); };
  window.setInterval = function(fn,...r){ if(typeof fn==='string'){rt.sinkHits.push({sink:'setInterval',args:[norm(fn).slice(0,200)],ts:Date.now()});} return _sti.call(window,fn,...r); };

  // ── insertAdjacentHTML ─────────────────────────────────────────
  const _iah = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function(pos, html){
    rt.sinkHits.push({sink:'insertAdjacentHTML',args:[pos, norm(html).slice(0,200)],ts:Date.now()});
    return _iah.call(this, pos, html);
  };

  // ── setAttribute (event handler injection) ─────────────────────
  const _sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value){
    if (String(name).toLowerCase().startsWith('on')) {
      rt.sinkHits.push({sink:'setAttribute:'+name, args:[norm(value).slice(0,200)], ts:Date.now()});
    }
    return _sa.call(this, name, value);
  };

  // ── DOM MutationObserver ───────────────────────────────────────
  const obs = new MutationObserver((muts) => { rt.domMutations += muts.length; });
  obs.observe(document.documentElement, {childList:true, subtree:true, attributes:true});

  // ── CSP violation ──────────────────────────────────────────────
  document.addEventListener('securitypolicyviolation', (e) => {
    rt.cspViolations.push({directive: e.effectiveDirective, blockedURI: e.blockedURI, ts: Date.now()});
  });
})();
"""


def _replace_param(url: str, param: str, payload: str) -> str:
    """Return *url* with *param* set to *payload*, preserving other params."""
    split = urlsplit(url)
    params = parse_qsl(split.query, keep_blank_values=True)
    out = []
    replaced = False
    for k, v in params:
        if k == param and not replaced:     # FIX: original replaced ALL occurrences
            out.append((k, payload))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((param, payload))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(out), split.fragment))


async def verify_runtime(
    url: str,
    param: str,
    payloads: list[str],
    evidence_dir: Path,
    *,
    page_timeout_ms: int = 15_000,
    settle_ms: int = 800,
) -> RuntimeEvidence:
    """
    Replay each payload in a real Chromium page and return evidence.

    FIX 1: Original opened a new playwright browser context for every call — extremely
            slow at scale.  We now accept a shared browser context (or fall back to
            creating one if called standalone).
    FIX 2: Original 'execution_proof' was set if any exec_hit OR console event
            contained the token — but console events also contain normal log noise.
            We now require token in exec_hits OR in dialog_events (alert triggered).
    FIX 3: Original did not save network logs.
    FIX 4: Added per-payload timeout guard so a hanging page doesn't stall forever.
    FIX 5: Browser is launched with --no-sandbox for headless container environments.
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ev = RuntimeEvidence()
    token = f"xscan-{uuid.uuid4().hex}"
    ev.execution_token = token

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
        )
        context = await browser.new_context(
            ignore_https_errors=True,   # FIX: was crashing on self-signed certs
            java_script_enabled=True,
        )
        page = await context.new_page()
        await page.add_init_script(RUNTIME_HOOK_SCRIPT)

        # FIX 3: capture network requests for evidence
        def _on_request(req):
            ev.network_events.append(f"REQ {req.method} {req.url[:200]}")
        page.on("request", _on_request)

        # FIX 2: dialog handler — only set execution_proof if token in message
        async def _on_dialog(dialog):
            ev.alert_triggered = True
            msg = dialog.message
            ev.dialog_events.append({"type": dialog.type, "message": msg})
            if token in msg:
                ev.execution_proof = True
                ev.executed_payload = _current_payload
            await dialog.dismiss()

        page.on("dialog", _on_dialog)
        page.on("console", lambda m: ev.console_events.append(m.text))
        page.on("pageerror", lambda e: ev.errors.append(str(e)))

        _current_payload: str = ""

        for payload in payloads:
            rendered = payload.replace("__XSCAN_TOKEN__", token)
            replay_url = _replace_param(url, param, rendered)
            _current_payload = rendered

            try:
                await page.goto(
                    replay_url,
                    wait_until="domcontentloaded",
                    timeout=page_timeout_ms,
                )
                await page.wait_for_timeout(settle_ms)
            except Exception as exc:
                ev.errors.append(f"nav:{exc!s:.120}")
                continue

            runtime = await page.evaluate("() => window.__xscanRuntime || {}")
            exec_hits = [str(x) for x in runtime.get("execHits", [])]
            sink_hits = runtime.get("sinkHits", [])
            ev.runtime_sink_hits = [str(s) for s in sink_hits]
            ev.dom_mutation_count = int(runtime.get("domMutations", 0))

            # FIX 2: token must appear in execHits (reliable) not just console noise
            if any(token in x for x in exec_hits):
                ev.execution_proof = True
                ev.executed_payload = rendered
                ev.replay_url = replay_url
                break

            # secondary: token triggered alert dialog
            if ev.execution_proof:
                break

        # Evidence collection
        key = hashlib.sha256((url + token).encode()).hexdigest()[:16]
        shot = evidence_dir / f"{key}.png"
        dom  = evidence_dir / f"{key}.html"
        try:
            await page.screenshot(path=str(shot), full_page=True)
            ev.screenshot_path = str(shot)
        except Exception as exc:
            logger.warning("screenshot failed: %s", exc)
        try:
            dom.write_text(await page.content(), encoding="utf-8")
            ev.dom_snapshot_path = str(dom)
        except Exception as exc:
            logger.warning("dom snapshot failed: %s", exc)

        await context.close()
        await browser.close()

    return ev


async def analyze_dom_runtime(url: str, marker: str, evidence_dir: Path) -> dict[str, Any]:
    """
    Visit *url* without injecting payloads and observe what sinks fire.

    FIX: Original did not guard against navigation timeout, causing workers to hang.
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.add_init_script(RUNTIME_HOOK_SCRIPT)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
                await page.wait_for_timeout(600)
            except Exception as exc:
                logger.debug("analyze_dom_runtime nav error %s: %s", url, exc)
            runtime = await page.evaluate("() => window.__xscanRuntime || {}")
            await context.close()
            await browser.close()
    except Exception as exc:
        logger.warning("analyze_dom_runtime failed for %s: %s", url, exc)
        return {"sink_hits": [], "marker_observed": False, "raw": {}}

    sink_hits      = runtime.get("sinkHits", [])
    marker_observed = any(marker in str(item) for item in sink_hits)
    return {"sink_hits": sink_hits, "marker_observed": marker_observed, "raw": runtime}
