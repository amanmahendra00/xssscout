/* ═══════════════════════════════════════════════════════════════════
   XSS Scout — Frontend Application
   Wires all 17 UI panels to live WebSocket + REST API
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

// ── STATE ─────────────────────────────────────────────────────────────────────
const STATE = {
  status:      'idle',
  scan_id:     '',
  stats:       { scanned:0, total:0, confirmed:0, potential:0, dom_sinks:0, waf_hits:0, csp_issues:0, elapsed_s:0, urls_per_min:0 },
  findings:    [],
  logs:        [],
  ws:          null,
  currentPanel:'config',
  selectedFinding: null,
  throughputHistory: new Array(20).fill(0),
  prevScanned: 0,
};

// ── PANEL METADATA ─────────────────────────────────────────────────────────────
const PANELS = {
  config:      { title:'Configuration — §1 §2 §14 §18',              meta:'python scanner.py --workers 20 --browser chromium' },
  urls:        { title:'URL Processing — §1 §2 §3',                   meta:'python scanner.py -l urls.txt' },
  crawl:       { title:'Crawler Engine — §4',                          meta:'SPA · WebSocket · Source maps' },
  payload:     { title:'Payload Mutation Engine — §8',                 meta:'Adaptive — no static lists' },
  reflect:     { title:'Reflection & Context Analysis — §5',           meta:'8 contexts per parameter' },
  dom:         { title:'DOM / AST / Taint Tracking — §6',              meta:'Tree-sitter · Babel · esprima' },
  ctxverify:   { title:'Context Verification — §7',                    meta:'Pre-exploitation analysis' },
  csp:         { title:'CSP Analysis & Bypass Research — §9',          meta:'CSP header audit' },
  waf:         { title:'WAF Detection & Adaptive Evasion — §10',       meta:'Fingerprint · evade' },
  hist:        { title:'Historical Endpoint Analysis — §13',            meta:'Wayback · Gau · Katana · OTX' },
  fp:          { title:'False Positive Elimination — §12',             meta:'Never report without runtime proof' },
  findings:    { title:'Findings — §12 §16',                           meta:'confirmed · potential · DOM' },
  browser:     { title:'Browser Verification Engine — §11',            meta:'Chromium via Playwright' },
  performance: { title:'Performance — §14 §17',                        meta:'URLs/min · workers' },
  logs:        { title:'Live Logs — §18',                              meta:'Structured log stream' },
  storage:     { title:'Storage Backend — §15',                        meta:'SQLite · session persistence' },
  plugins:     { title:'Plugin Architecture & CLI — §18',              meta:'Extensible · config-based' },
  report:      { title:'Report Export — §16',                          meta:'JSON · Markdown · HTML' },
};

// ── HELPERS ──────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const sevClass = (s) => ({ critical:'ri-critical', high:'ri-high', medium:'ri-medium' }[s] || 'ri-medium');
const badgeClass = (s) => `badge-${s}`;

function toast(msg, type='blue', duration=3000) {
  const c = $('toast-container');
  const d = document.createElement('div');
  d.className = `toast toast-${type}`;
  d.innerHTML = `<i class="fa fa-${type==='green'?'check-circle':type==='red'?'exclamation-circle':'info-circle'}"></i><span>${esc(msg)}</span>`;
  c.appendChild(d);
  setTimeout(() => d.remove(), duration);
}

function toggleTag(el) {
  const on = el.classList.contains('tag-on');
  el.classList.toggle('tag-on', !on);
  el.classList.toggle('tag-off', on);
  el.textContent = (on ? '+ ' : '✓ ') + el.textContent.replace(/^[✓+] /, '');
}

function fmtTime(s) {
  if (s < 60) return `${s}s`;
  return `${Math.floor(s/60)}m ${s%60}s`;
}

// ── WEBSOCKET ─────────────────────────────────────────────────────────────────
const WS = {
  connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
    STATE.ws = ws;

    ws.onopen = () => {
      $('ws-dot').className = 'ws-indicator connected';
    };

    ws.onclose = () => {
      $('ws-dot').className = 'ws-indicator disconnected';
      setTimeout(() => WS.connect(), 3000);
    };

    ws.onerror = () => {
      $('ws-dot').className = 'ws-indicator disconnected';
    };

    ws.onmessage = (e) => {
      try { WS.handle(JSON.parse(e.data)); } catch {}
    };
  },

  handle(msg) {
    const { type, data } = msg;
    if (type === 'ping') return;

    if (type === 'snapshot') {
      STATE.status   = data.status;
      STATE.scan_id  = data.scan_id;
      STATE.stats    = { ...STATE.stats, ...data.stats };
      STATE.findings = data.findings || [];
      STATE.logs     = data.logs || [];
      UI.syncAll();
      return;
    }

    if (type === 'status') {
      STATE.status  = data.status;
      STATE.scan_id = data.scan_id || STATE.scan_id;
      if (data.error) toast(data.error, 'red', 6000);
      UI.syncStatus();
      return;
    }

    if (type === 'stats') {
      // Track throughput history
      const delta = (data.scanned || 0) - STATE.prevScanned;
      STATE.prevScanned = data.scanned || 0;
      STATE.throughputHistory.push(delta);
      STATE.throughputHistory.shift();
      STATE.stats = { ...STATE.stats, ...data };
      UI.syncStats();
      return;
    }

    if (type === 'finding') {
      STATE.findings.push(data);
      UI.syncBadges();
      UI.syncStats();
      // Live-append to findings panel if visible
      if (STATE.currentPanel === 'findings') {
        UI.appendFindingRow(data);
      }
      // Auto-navigate to findings on first confirmed XSS
      if (data.type === 'verified_reflected_xss' && STATE.stats.confirmed === 1) {
        toast(`Confirmed XSS: ${data.url}`, 'red', 8000);
      }
      return;
    }

    if (type === 'log') {
      STATE.logs.push(data);
      if (STATE.logs.length > 2000) STATE.logs.shift();
      if (STATE.currentPanel === 'logs') {
        UI.appendLogLine(data);
      }
      return;
    }
  },
};

// ── UI CONTROLLER ─────────────────────────────────────────────────────────────
const UI = {

  init() {
    // Build all panel HTML into hidden divs
    Object.keys(PANELS).forEach(id => {
      const div = document.createElement('div');
      div.className = 'panel';
      div.id = `panel-${id}`;
      $('content').appendChild(div);
    });

    // Nav item clicks
    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.dataset.panel;
        if (id) UI.goTo(id, el);
      });
    });

    // Render initial panel
    UI.goTo('config');
    WS.connect();

    // Poll state every 5s as fallback
    setInterval(() => API.fetchState(), 5000);
  },

  goTo(panelId, navEl) {
    STATE.currentPanel = panelId;

    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const target = navEl || document.querySelector(`[data-panel="${panelId}"]`);
    if (target) target.classList.add('active');

    // Update topbar
    const meta = PANELS[panelId] || {};
    $('topbar-title').textContent = meta.title || panelId;
    $('topbar-meta').textContent  = meta.meta  || '';

    // Show panel
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const panel = $(`panel-${panelId}`);
    if (!panel) return;
    panel.classList.add('active');

    // Render panel content if empty
    if (!panel.dataset.rendered) {
      panel.innerHTML = RENDERERS[panelId] ? RENDERERS[panelId]() : '<div class="empty-state"><i class="fa fa-wrench"></i><p>Panel coming soon</p></div>';
      panel.dataset.rendered = '1';
    }

    // Post-render hooks
    if (panelId === 'logs')        UI.renderLogs();
    if (panelId === 'findings')    UI.renderFindings();
    if (panelId === 'performance') UI.renderThroughput();
    if (panelId === 'storage')     UI.renderStorage();
    if (panelId === 'report')      UI.renderReport();
  },

  // ── sync helpers ─────────────────────────────────────────────────

  syncAll() {
    UI.syncStatus();
    UI.syncStats();
    UI.syncBadges();
  },

  syncStatus() {
    const st = STATE.status;
    const dot = $('sf-dot');
    const lbl = $('sf-label');
    const btnStart = $('btn-start');
    const btnStop  = $('btn-stop');

    if (dot)   dot.className = `sf-dot ${st}`;
    if (lbl)   lbl.textContent = st.charAt(0).toUpperCase() + st.slice(1);

    if (btnStart) btnStart.style.display = st === 'running' ? 'none' : '';
    if (btnStop)  btnStop.style.display  = st === 'running' ? ''     : 'none';
  },

  syncStats() {
    const s = STATE.stats;
    const pct = s.total > 0 ? Math.round((s.scanned / s.total) * 100) : 0;

    const fill = $('sf-fill');
    const pctEl = $('sf-pct');
    const sub   = $('sf-sub');
    if (fill)  fill.style.width = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';
    if (sub)   sub.textContent = `${s.scanned} / ${s.total} URLs · ${s.confirmed} findings`;

    // Sync stat cards on findings and performance panels
    ['confirmed','potential','dom_sinks','scanned','waf_hits','csp_issues'].forEach(k => {
      const el = $(`sv-${k}`);
      if (el) el.textContent = (s[k] ?? 0).toLocaleString();
    });

    // Elapsed / rate on performance panel
    const elEl = $('sv-elapsed');
    const rateEl = $('sv-rate');
    if (elEl)  elEl.textContent = fmtTime(Math.round(s.elapsed_s));
    if (rateEl) rateEl.textContent = (s.urls_per_min || 0).toLocaleString();
  },

  syncBadges() {
    const s = STATE.stats;
    const map = {
      'badge-findings': s.confirmed + s.potential,
      'badge-reflect':  s.potential,
      'badge-dom':      s.dom_sinks,
      'badge-csp':      s.csp_issues,
      'badge-waf':      s.waf_hits,
      'badge-hist':     STATE.findings.filter(f => f.type === 'historical_endpoint').length,
    };
    Object.entries(map).forEach(([id, v]) => {
      const el = $(id);
      if (el) el.textContent = v;
    });
  },

  // ── findings ─────────────────────────────────────────────────────

  renderFindings() {
    const list = $('findings-list');
    if (!list) return;
    list.innerHTML = '';
    STATE.findings.forEach(f => UI.appendFindingRow(f, false));
  },

  appendFindingRow(f, scroll=true) {
    const list = $('findings-list');
    if (!list) return;
    const sev = f.severity || 'medium';
    const div = document.createElement('div');
    div.className = `result-item ${sevClass(sev)}`;
    div.dataset.id = f.id;
    div.innerHTML = `
      <div class="ri-top">
        <span class="badge badge-${sev}">${sev.toUpperCase()}</span>
        <span style="font-weight:700;font-size:12px;margin-left:4px">${esc(f.param || '—')}</span>
        <span style="margin-left:8px;font-size:11px;color:var(--t2)">${esc(f.type)}</span>
        <span style="margin-left:auto;font-size:10px;color:var(--t3);font-family:var(--mono)">${esc((f.evidence?.sink||'').split('(')[0].trim())}</span>
      </div>
      <div class="ri-url">${esc(f.url)}</div>
      <div class="ri-meta"><span>${esc(f.evidence?.context||f.evidence?.probe||'')}</span></div>`;
    div.addEventListener('click', () => UI.showFinding(f));
    list.appendChild(div);
    if (scroll) list.lastElementChild?.scrollIntoView({ behavior:'smooth', block:'nearest' });
  },

  showFinding(f) {
    STATE.selectedFinding = f;
    document.querySelectorAll('.result-item').forEach(x => x.classList.remove('selected'));
    const el = document.querySelector(`[data-id="${f.id}"]`);
    if (el) el.classList.add('selected');

    const det = $('finding-detail');
    if (!det) return;
    det.style.display = 'block';

    const rt = f.evidence?.runtime || {};
    $('det-title').textContent  = `${f.type.toUpperCase()} — ${(f.severity||'').toUpperCase()} — ${f.url}`;
    $('det-url').textContent    = f.url;
    $('det-param').textContent  = f.param || '—';
    $('det-type').textContent   = f.type;
    $('det-ctx').textContent    = f.evidence?.context || f.evidence?.probe || '—';
    $('det-sink').textContent   = f.evidence?.sink || rt.executed_payload?.slice(0,60) || '—';
    $('det-ver').textContent    = rt.execution_proof ? '✓ YES — alert() fired (Chromium/Playwright)' : 'Not verified';
    $('det-waf').textContent    = f.evidence?.reasons?.join(', ') || '—';
    $('det-csp').textContent    = f.evidence?.weaknesses?.join(', ') || '—';
    $('det-risk').textContent   = f.evidence?.risk || '—';
    $('det-payload').textContent  = rt.executed_payload || f.evidence?.exact_payload || '—';
    $('det-repro').textContent    = (f.evidence?.reproduction_steps || []).join('\n') || '—';

    // Evidence tiles
    const evGrid = $('det-evidence-grid');
    if (evGrid) {
      evGrid.innerHTML = '';
      if (rt.screenshot_path) evGrid.innerHTML += `<div class="ev-item"><div class="ev-icon ev-screenshot"><i class="fa fa-image"></i></div><div><div class="ev-label">Screenshot</div><div class="ev-sub">${esc(rt.screenshot_path)}</div></div></div>`;
      if (rt.dom_snapshot_path) evGrid.innerHTML += `<div class="ev-item"><div class="ev-icon ev-dom"><i class="fa fa-code"></i></div><div><div class="ev-label">DOM Snapshot</div><div class="ev-sub">${esc(rt.dom_snapshot_path)}</div></div></div>`;
      if (rt.console_events?.length) evGrid.innerHTML += `<div class="ev-item"><div class="ev-icon ev-console"><i class="fa fa-terminal"></i></div><div><div class="ev-label">Console Log</div><div class="ev-sub" style="color:var(--low)">alert() fired · token confirmed</div></div></div>`;
      if (rt.network_events?.length) evGrid.innerHTML += `<div class="ev-item"><div class="ev-icon ev-network"><i class="fa fa-network-wired"></i></div><div><div class="ev-label">Network HAR</div><div class="ev-sub">${rt.network_events.length} requests captured</div></div></div>`;
    }
  },

  // ── logs ─────────────────────────────────────────────────────────

  renderLogs() {
    const el = $('log-area');
    if (!el) return;
    el.innerHTML = '';
    STATE.logs.slice(-200).forEach(l => UI.appendLogLine(l, false));
    el.scrollTop = el.scrollHeight;
  },

  appendLogLine(log, scroll=true) {
    const el = $('log-area');
    if (!el) return;
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML = `<span class="log-ts">${esc(log.ts)}</span><span class="log-lv ${log.level}">${esc(log.level)}</span><span class="log-msg">${esc(log.msg)}</span>`;
    el.appendChild(div);
    if (scroll) el.scrollTop = el.scrollHeight;
    // Cap DOM to 500 lines
    while (el.children.length > 500) el.removeChild(el.firstChild);
  },

  // ── performance ───────────────────────────────────────────────────

  renderThroughput() {
    const wrap = $('throughput-bars');
    if (!wrap) return;
    const max = Math.max(...STATE.throughputHistory, 1);
    wrap.innerHTML = STATE.throughputHistory.map(v =>
      `<div class="mini-bar" style="height:${Math.round((v/max)*100)}%;background:linear-gradient(to top,var(--cyan2),var(--cyan));opacity:${0.4 + (v/max)*0.6}"></div>`
    ).join('');
  },

  // ── storage ───────────────────────────────────────────────────────

  renderStorage() {
    const pct = STATE.stats.total > 0 ? Math.round((STATE.stats.scanned / STATE.stats.total) * 100) : 0;
    const el = $('storage-progress-bar');
    if (el) el.style.width = pct + '%';
    const lbl = $('storage-progress-label');
    if (lbl) lbl.textContent = `${STATE.stats.scanned} / ${STATE.stats.total} URLs — ${pct}%`;
  },

  // ── report ────────────────────────────────────────────────────────

  renderReport() {
    const idEl = $('current-scan-id');
    if (idEl) idEl.textContent = STATE.scan_id || '—';
  },

  // ── scan control ──────────────────────────────────────────────────

  async toggleScan() {
    if (STATE.status === 'running') {
      await API.stopScan();
    } else {
      await API.startScan();
    }
  },

  importClick() {
    $('file-input').click();
  },

  async handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch('/api/upload/urls', { method:'POST', body:fd });
      const data = await res.json();
      if (data.ok) {
        const ta = $('url-list-textarea');
        if (ta) ta.value = data.text;
        toast(`Loaded ${data.valid_urls} URLs from ${file.name}`, 'green');
        // Navigate to config to show the loaded URLs
        UI.goTo('config');
      }
    } catch (err) {
      toast('Upload failed: ' + err.message, 'red');
    }
    e.target.value = '';
  },

  buildScanRequest() {
    const workers  = parseInt($('cfg-workers')?.value || '20');
    const timeout  = parseFloat($('cfg-timeout')?.value || '15');
    const target   = $('cfg-target')?.value?.trim() || '';
    const urlText  = $('url-list-textarea')?.value?.trim() || '';
    const verifyBr = $('cfg-verify-browser')?.checked || false;
    const budget   = parseInt($('cfg-verify-budget')?.value || '50');
    const spaCrawl = $('cfg-spa-crawl')?.checked || false;
    const authHdr  = $('cfg-auth-header')?.value?.trim() || '';
    const authCk   = $('cfg-auth-cookie')?.value?.trim() || '';
    const chunk    = parseInt($('cfg-chunk')?.value || '500');
    const storage  = $('cfg-storage')?.value || 'sqlite';
    const resume   = $('cfg-resume')?.checked || false;

    const moduleTags = document.querySelectorAll('#module-tags .tag-on');
    const modules = Array.from(moduleTags).map(t =>
      t.textContent.replace('✓ ','').trim().toLowerCase().replace(/[^a-z_]/g,'_')
    );

    return { target_url:target, url_list_text:urlText, workers, timeout, verify_browser:verifyBr,
             verify_budget:budget, spa_crawl:spaCrawl, auth_header:authHdr, auth_cookie:authCk,
             chunk_size:chunk, storage_backend:storage, resume, modules };
  },

};

// ── API ───────────────────────────────────────────────────────────────────────
const API = {

  async startScan() {
    const req = UI.buildScanRequest();
    if (!req.target_url && !req.url_list_text) {
      toast('Please enter a target URL or URL list', 'red');
      UI.goTo('config');
      return;
    }
    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify(req),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Start failed');
      STATE.scan_id = data.scan_id;
      STATE.findings = [];
      STATE.logs = [];
      // Reset finding panels
      ['findings-list', 'log-area'].forEach(id => { const el=$(id); if(el) el.innerHTML=''; });
      // Re-render findings panel if open
      if (STATE.currentPanel === 'findings') UI.renderFindings();
      toast(`Scan started — ${data.scan_id}`, 'green');
    } catch (err) {
      toast(err.message, 'red');
    }
  },

  async stopScan() {
    try {
      await fetch('/api/scan/stop', { method:'POST' });
      toast('Scan stopped', 'blue');
    } catch (err) {
      toast('Stop failed: ' + err.message, 'red');
    }
  },

  async fetchState() {
    try {
      const res = await fetch('/api/scan/state');
      const data = await res.json();
      STATE.status  = data.status;
      STATE.scan_id = data.scan_id;
      STATE.stats   = { ...STATE.stats, ...data.stats };
      UI.syncAll();
    } catch {}
  },

  async downloadReport(fmt) {
    const id = STATE.scan_id;
    if (!id) { toast('No scan completed yet', 'red'); return; }
    window.open(`/api/report/${id}/${fmt}`, '_blank');
  },
};

// ── PANEL RENDERERS ───────────────────────────────────────────────────────────
const RENDERERS = {

  // ── CONFIG §1 §2 §14 §18 ─────────────────────────────────────────
  config: () => `
<div class="notif notif-blue"><i class="fa fa-circle-info"></i> Configure all options then click <strong>Start Scan</strong>. WebSocket live-streams results. Use <code>--resume</code> to continue a saved session.</div>
<div class="g2">
  <div class="field g-full">
    <label>Target URL / URL list file (§1)</label>
    <input id="cfg-target" type="text" placeholder="https://target.com  OR paste URLs below"/>
  </div>
  <div class="field g-full">
    <label>URL List — paste or upload (§1 §2)</label>
    <textarea id="url-list-textarea" style="min-height:90px" placeholder="https://target.com/search?q=&#10;https://target.com/profile?id=1&#10;https://target.com/redirect?url=…&#10;&#10;Supports millions of URLs — streamed, not loaded into memory."></textarea>
  </div>
  <div class="field">
    <label>Workers / concurrency (§14)</label>
    <input id="cfg-workers" type="number" value="20" min="1" max="100"/>
  </div>
  <div class="field">
    <label>Request timeout (s)</label>
    <input id="cfg-timeout" type="number" value="15" min="1"/>
  </div>
  <div class="field">
    <label>Browser engine (§11)</label>
    <select id="cfg-browser">
      <option value="chromium">Chromium (Playwright)</option>
      <option value="firefox">Firefox (Playwright)</option>
      <option value="">Disabled — HTTP only</option>
    </select>
  </div>
  <div class="field">
    <label>Storage backend (§15)</label>
    <select id="cfg-storage">
      <option value="sqlite">SQLite (local)</option>
      <option value="postgres">PostgreSQL</option>
      <option value="redis">Redis</option>
    </select>
  </div>
  <div class="field">
    <label>Cookie / session token (§18)</label>
    <input id="cfg-auth-cookie" type="text" placeholder="session=abc123; token=xyz"/>
  </div>
  <div class="field">
    <label>Custom auth header (§18)</label>
    <input id="cfg-auth-header" type="text" placeholder="Authorization: Bearer eyJ…"/>
  </div>
  <div class="field">
    <label>Stream chunk size (§2)</label>
    <input id="cfg-chunk" type="number" value="500"/>
  </div>
  <div class="field">
    <label>Verify budget — max browser calls (§11)</label>
    <input id="cfg-verify-budget" type="number" value="50"/>
  </div>
</div>
<div class="sl">Options</div>
<div class="g3" style="margin-bottom:12px">
  <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--t1)">
    <input id="cfg-verify-browser" type="checkbox" style="width:auto"/>
    <span>Browser verify (§11)</span>
  </label>
  <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--t1)">
    <input id="cfg-spa-crawl" type="checkbox" style="width:auto"/>
    <span>SPA crawl (§4)</span>
  </label>
  <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--t1)">
    <input id="cfg-resume" type="checkbox" style="width:auto"/>
    <span>Resume session (§2)</span>
  </label>
</div>
<div class="sl">Scan Modules</div>
<div class="tags" id="module-tags">
  ${['✓ Reflected XSS','✓ Stored XSS','✓ DOM XSS','✓ postMessage','✓ CSP Analysis',
     '✓ WAF Detection','✓ AST / Taint','✓ Browser Verify','✓ FP Elimination',
     '+ SPA Crawl','+ Source Maps','+ WebSocket','+ Historical','+ Prototype Pollution','+ CSTI Detection'].map((t,i) =>
    `<span class="tag ${i<9?'tag-on':'tag-off'}" onclick="toggleTag(this)">${t}</span>`
  ).join('')}
</div>
<div class="sl">CLI Equivalent (§18)</div>
<div class="code-block">python scanner.py -l urls.txt --workers 20 --browser chromium \\
  --storage sqlite --verify-budget 50 --evidence-dir ./evidence</div>`,

  // ── URL PROCESSING §1 §2 §3 ──────────────────────────────────────
  urls: () => `
<div class="stat-row">
  <div class="stat-card sc-cyan"><div class="stat-label">URLs Queued</div><div class="stat-val cyan" id="sv-scanned">0</div><div class="stat-sub">of <span id="sv-total">0</span> total</div></div>
  <div class="stat-card sc-green"><div class="stat-label">After Dedup §3</div><div class="stat-val green">—</div><div class="stat-sub">param-order normalised</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">High Priority §3</div><div class="stat-val amber">—</div><div class="stat-sub">parameterised endpoints</div></div>
  <div class="stat-card"><div class="stat-label">Auto-Ignored §3</div><div class="stat-val muted">—</div><div class="stat-sub">static assets</div></div>
</div>
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">URL Sources — §1</span></div>
    <table class="tbl">
      <tr><th>Source</th><th>Description</th></tr>
      <tr><td class="mono">-l / --list FILE</td><td class="t2">Local file — millions of URLs, streamed</td></tr>
      <tr><td class="mono">Wayback Machine</td><td class="t2">Historical archived endpoints</td></tr>
      <tr><td class="mono">Gau</td><td class="t2">Get All URLs from AlienVault + Wayback</td></tr>
      <tr><td class="mono">Katana</td><td class="t2">Active crawl + JS analysis</td></tr>
      <tr><td class="mono">Common Crawl</td><td class="t2">Petabyte web archive</td></tr>
      <tr><td class="mono">AlienVault OTX</td><td class="t2">Threat intelligence URLs</td></tr>
      <tr><td class="mono">Stdin pipe</td><td class="t2">cat urls.txt | python scanner.py</td></tr>
    </table>
  </div>
  <div>
    <div class="card card-amber">
      <div class="card-header"><span class="card-title">Streaming & Memory Safety — §2</span></div>
      <div class="pills">
        <span class="pill pill-on">✓ Stream-only — no full load</span>
        <span class="pill pill-on">✓ Async queue</span>
        <span class="pill pill-on">✓ Resumable scan</span>
        <span class="pill pill-on">✓ Chunk processing</span>
      </div>
      <div class="code-block" style="margin-top:10px">python scanner.py --resume session.db</div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">Normalisation — §3</span></div>
      <div style="font-size:10px;color:var(--t2);margin-bottom:8px">Treated as identical:</div>
      <div style="display:flex;gap:10px;align-items:center;font-family:var(--mono);font-size:11px;margin-bottom:10px">
        <span style="color:var(--cyan)">?id=1&amp;cat=2</span>
        <span style="color:var(--t3);font-size:16px">≡</span>
        <span style="color:var(--cyan)">?cat=2&amp;id=1</span>
      </div>
      <div class="pills">
        <span class="pill pill-on">param-order norm</span><span class="pill pill-on">fragment strip</span>
        <span class="pill pill-on">case normalise</span><span class="pill pill-on">trailing slash</span>
        <span class="pill pill-on">default port strip</span><span class="pill pill-on">scheme norm</span>
      </div>
    </div>
  </div>
</div>
<div class="card">
  <div class="card-header"><span class="card-title">Priority Scoring — §3</span></div>
  <div class="g2">
    <div>
      <div style="font-size:9px;color:var(--crit);font-weight:700;margin-bottom:6px;font-family:var(--head);text-transform:uppercase">High priority</div>
      <div class="pills">
        ${['query params (?=)','search=/q=','redirect=/url=','callback=','jsonp=','JSON APIs','legacy endpoints','dynamic rendering'].map(p=>`<span class="pill pill-red">${p}</span>`).join('')}
      </div>
    </div>
    <div>
      <div style="font-size:9px;color:var(--t3);font-weight:700;margin-bottom:6px;font-family:var(--head);text-transform:uppercase">Auto-ignored</div>
      <div class="pills">
        ${['.png .jpg .gif .webp','.woff .ttf .eot','.mp4 .webm','.css (static)','.ico .pdf .zip'].map(p=>`<span class="pill">${p}</span>`).join('')}
      </div>
    </div>
  </div>
</div>`,

  // ── CRAWLER §4 ────────────────────────────────────────────────────
  crawl: () => `
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">SPA Framework Detection — §4</span></div>
    <table class="tbl">
      <tr><th>Framework</th><th>Detection Signal</th></tr>
      <tr><td class="mono">React</td><td class="t2">__reactFiber / react-dom marker</td></tr>
      <tr><td class="mono">Vue.js</td><td class="t2">__vue_app__ / data-v-* attrs</td></tr>
      <tr><td class="mono">Angular</td><td class="t2">ng-version / angular.json</td></tr>
      <tr><td class="mono">Next.js</td><td class="t2">__NEXT_DATA__ global</td></tr>
      <tr><td class="mono">Nuxt</td><td class="t2">__NUXT__ global</td></tr>
      <tr><td class="mono">Svelte</td><td class="t2">svelte- CSS class prefix</td></tr>
      <tr><td class="mono">SPA routing</td><td class="t2">pushState intercept + hash router</td></tr>
      <tr><td class="mono">Shadow DOM</td><td class="t2">attachShadow() call detection</td></tr>
      <tr><td class="mono">Lazy-loaded</td><td class="t2">dynamic import() + chunk files</td></tr>
    </table>
  </div>
  <div>
    <div class="card card-amber">
      <div class="card-header"><span class="card-title">Static Sources — §4</span></div>
      <div class="pills">
        <span class="pill pill-on">HTML href/action/src</span><span class="pill pill-on">JS files</span>
        <span class="pill pill-on">Source maps (.map)</span><span class="pill pill-on">OpenAPI schemas</span>
      </div>
    </div>
    <div class="card card-purple">
      <div class="card-header"><span class="card-title">Runtime Sources — §4</span></div>
      <div class="pills">
        <span class="pill pill-warn">Fetch / XHR</span><span class="pill pill-warn">WebSocket msgs</span>
        <span class="pill pill-warn">Lazy routes</span><span class="pill pill-warn">postMessage</span>
        <span class="pill pill-warn">dynamic import()</span><span class="pill pill-warn">Shadow DOM</span>
      </div>
    </div>
  </div>
</div>`,

  // ── PAYLOAD ENGINE §8 ─────────────────────────────────────────────
  payload: () => `
<div class="notif notif-blue"><i class="fa fa-robot"></i> Adaptive engine — payloads generated dynamically from context. No static wordlists. (§8)</div>
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">Generation Inputs — §8</span></div>
    <div class="pills">
      <span class="pill pill-on">reflection context</span><span class="pill pill-on">escaping behaviour</span>
      <span class="pill pill-on">framework detected</span><span class="pill pill-on">browser parse rules</span>
      <span class="pill pill-on">CSP restrictions</span><span class="pill pill-on">WAF fingerprint</span>
    </div>
  </div>
  <div class="card card-red">
    <div class="card-header"><span class="card-title">Payload Types — §8</span></div>
    <div class="pills">
      <span class="pill pill-red">polyglots</span><span class="pill pill-red">SVG payloads</span>
      <span class="pill pill-red">event handlers</span><span class="pill pill-red">script breakouts</span>
      <span class="pill pill-red">attr injections</span><span class="pill pill-red">template injection</span>
      <span class="pill pill-red">mutation-based</span><span class="pill pill-red">DOM clobbering</span>
      <span class="pill pill-red">prototype pollution</span><span class="pill pill-red">CSTI gadgets</span>
    </div>
  </div>
</div>
<div class="card card-amber">
  <div class="card-header"><span class="card-title">Evasion Layers — §8 §10</span></div>
  <div class="pills">
    <span class="pill pill-warn">URL/HTML/JS encoding</span><span class="pill pill-warn">unicode obfuscation (ı ＜)</span>
    <span class="pill pill-warn">case mutation</span><span class="pill pill-warn">parser confusion (%00)</span>
    <span class="pill pill-warn">tag fragmentation</span><span class="pill pill-warn">mixed encoding</span>
    <span class="pill pill-warn">comment splitting (/**/)</span><span class="pill pill-warn">double URL encode</span>
  </div>
</div>
<div class="card">
  <div class="card-header"><span class="card-title">Context → Payload Examples</span></div>
  <table class="tbl">
    <tr><th>Context</th><th>Generated Payload</th><th>Evasion</th></tr>
    <tr><td class="mono t2">HTML body</td><td class="mono" style="color:var(--crit);font-size:10px">&lt;img src=x onerror=window.__xscan_exec(`TOKEN`)&gt;</td><td class="t2">none</td></tr>
    <tr><td class="mono t2">HTML attr (dquoted)</td><td class="mono" style="color:var(--crit);font-size:10px">" autofocus onfocus=window.__xscan_exec(`TOKEN`) x="</td><td class="t2">quote breakout</td></tr>
    <tr><td class="mono t2">JS string</td><td class="mono" style="color:var(--crit);font-size:10px">'-window.__xscan_exec(`TOKEN`)-'</td><td class="t2">string termination</td></tr>
    <tr><td class="mono t2">Script block</td><td class="mono" style="color:var(--crit);font-size:10px">&lt;/script&gt;&lt;svg onload=window.__xscan_exec(`TOKEN`)&gt;</td><td class="t2">script termination</td></tr>
    <tr><td class="mono t2">WAF (Cloudflare)</td><td class="mono" style="color:var(--crit);font-size:10px">&lt;ımg src=x onerror=window.__xscan_exec(`TOKEN`)&gt;</td><td class="t2">unicode ı</td></tr>
    <tr><td class="mono t2">CSP unsafe-eval</td><td class="mono" style="color:var(--crit);font-size:10px">eval(atob('d2luZG93...'))</td><td class="t2">base64 bypass</td></tr>
  </table>
</div>`,

  // ── REFLECTION §5 ─────────────────────────────────────────────────
  reflect: () => `
<div class="card card-cyan">
  <div class="card-header"><span class="card-title">Injection Context Grid — §5</span><span class="card-sub">8 contexts analysed per parameter</span></div>
  <div class="ctx-grid">
    <div class="ctx-cell ctx-vuln">⚠ HTML body<br/><span style="font-size:8px">unescaped</span></div>
    <div class="ctx-cell ctx-vuln">⚠ HTML attr<br/><span style="font-size:8px">unquoted</span></div>
    <div class="ctx-cell ctx-safe">JS string<br/><span style="font-size:8px">escaped</span></div>
    <div class="ctx-cell ctx-partial">Script block<br/><span style="font-size:8px">partial enc.</span></div>
    <div class="ctx-cell ctx-partial">URL context<br/><span style="font-size:8px">partial enc.</span></div>
    <div class="ctx-cell ctx-safe">CSS context<br/><span style="font-size:8px">encoded</span></div>
    <div class="ctx-cell ctx-vuln">⚠ SVG context<br/><span style="font-size:8px">raw</span></div>
    <div class="ctx-cell ctx-safe">JSON context<br/><span style="font-size:8px">encoded</span></div>
  </div>
</div>
<div class="g2">
  <div class="card card-red">
    <div class="card-header"><span class="card-title">Encoding / Sanitisation State — §5</span></div>
    <table class="tbl">
      <tr><th>Transform Check</th><th>Applied</th></tr>
      <tr><td class="mono">HTML entity encoded</td><td><span class="badge badge-critical">checked</span></td></tr>
      <tr><td class="mono">Quote escaped</td><td><span class="badge badge-critical">checked</span></td></tr>
      <tr><td class="mono">Filtered (blocklist)</td><td><span class="badge badge-critical">checked</span></td></tr>
      <tr><td class="mono">Sanitised (DOMPurify)</td><td><span class="badge badge-critical">checked</span></td></tr>
      <tr><td class="mono">Double encoded</td><td><span class="badge badge-info">checked</span></td></tr>
      <tr><td class="mono">Partially transformed</td><td><span class="badge badge-medium">detected</span></td></tr>
    </table>
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">Classification — §5</span></div>
    <div style="display:flex;flex-direction:column;gap:5px">
      <span class="pill pill-red" style="justify-content:flex-start">⚠ potentially-executable</span>
      <span class="pill pill-on"  style="justify-content:flex-start">✓ sanitized-reflection</span>
      <span class="pill"          style="justify-content:flex-start">  dead-reflection</span>
      <span class="pill"          style="justify-content:flex-start">  self-XSS only</span>
    </div>
  </div>
</div>
<div class="card">
  <div class="card-header"><span class="card-title">Live Reflection Findings</span><span class="card-sub" id="badge-reflect-count">0 found</span></div>
  <div id="reflect-findings-list">
    <div class="empty-state"><i class="fa fa-magnifying-glass"></i><p>Reflections will appear here during scan</p></div>
  </div>
</div>`,

  // ── DOM / AST §6 ──────────────────────────────────────────────────
  dom: () => `
<div class="tab-bar">
  <div class="tab active" onclick="domTab(this,'dom-taint')">Taint Flows</div>
  <div class="tab" onclick="domTab(this,'dom-sinks')">Dangerous Sinks</div>
  <div class="tab" onclick="domTab(this,'dom-sources')">Controllable Sources</div>
  <div class="tab" onclick="domTab(this,'dom-parsers')">AST Parsers</div>
</div>
<div id="dom-tab-content">
  <div class="card card-red">
    <div class="card-header"><span class="card-title">Taint Flow Tracking — §6 · source → transform → sink</span></div>
    <div id="dom-taint-live">
      <div class="empty-state"><i class="fa fa-code"></i><p>Taint flows appear here when DOM sinks are detected during scan</p></div>
    </div>
  </div>
</div>`,

  // ── CONTEXT VERIFY §7 ─────────────────────────────────────────────
  ctxverify: () => `
<div class="notif notif-amber"><i class="fa fa-triangle-exclamation"></i> Scanner analyses escape opportunities <strong>before</strong> sending payloads — §7. Only confirmed-escapable contexts receive payloads, minimising noise.</div>
${[
  {sev:'critical',opp:'Quote breakout',url:'/comment?text=',detail:"Single-quote in HTML attribute unescaped → inject: ' onmouseover='window.__xscan_exec(`T`) — no tag injection needed."},
  {sev:'critical',opp:'Script block termination',url:'/search?q=',detail:"</script> not encoded inside <script>var q='INPUT'</script> — payload: </script><svg onload=window.__xscan_exec(`T`)>"},
  {sev:'high',opp:'Event handler injection',url:'/comment?text=',detail:"onmouseover, onerror, onload accepted without stripping. Direct event handler injection in attribute context."},
  {sev:'high',opp:'Parser confusion',url:'/embed?src=',detail:"Null byte (%00) before tag causes server filter to miss payload. Browser HTML parser ignores null bytes."},
  {sev:'high',opp:'postMessage exploitation',url:'/app/#/widget',detail:"No origin check on addEventListener('message'). Arbitrary JS injectable via postMessage() from any origin."},
  {sev:'high',opp:'Template injection',url:'/render?tpl=',detail:"Angular $compile evals user input. {{constructor.constructor('window.__xscan_exec(`T`)')()}} bypasses sandbox."},
  {sev:'medium',opp:'DOM clobbering',url:'/profile?name=',detail:"id= attributes in user-controlled HTML clobber document.getElementById() references used in app logic."},
  {sev:'medium',opp:'Attribute breakout',url:'/img?alt=',detail:"alt= reflected without encoding. Inject space + attribute: onfocus=window.__xscan_exec(`T`) autofocus"},
].map(c=>`<div class="card card-${c.sev==='critical'?'red':c.sev==='high'?'amber':'green'}">
  <div class="card-header">${`<span class="badge badge-${c.sev}">${c.sev.toUpperCase()}</span>`}<span class="card-title" style="margin-left:8px">${c.opp}</span><span class="card-sub">${c.url}</span></div>
  <p style="font-size:11px;color:var(--t1);line-height:1.7">${c.detail}</p>
</div>`).join('')}`,

  // ── CSP §9 ────────────────────────────────────────────────────────
  csp: () => `
<div class="stat-row">
  <div class="stat-card sc-cyan"><div class="stat-label">Policies Analysed</div><div class="stat-val cyan" id="sv-csp-policies">0</div></div>
  <div class="stat-card sc-red"><div class="stat-label">Critical Weaknesses</div><div class="stat-val red" id="sv-csp-issues">0</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">Bypasses Found</div><div class="stat-val amber" id="sv-csp-bypasses">0</div></div>
  <div class="stat-card sc-purple"><div class="stat-label">Nonce Reuse</div><div class="stat-val purple" id="sv-csp-nonce">0</div></div>
</div>
<div class="card card-red">
  <div class="card-header"><span class="card-title">Weaknesses Detected — §9</span></div>
  <div id="csp-findings-live">
    <div class="empty-state"><i class="fa fa-lock"></i><p>CSP findings appear here during scan</p></div>
  </div>
</div>
<div class="card card-amber">
  <div class="card-header"><span class="card-title">Weakness Taxonomy — §9</span></div>
  <div class="pills">
    <span class="pill pill-red">unsafe-inline</span><span class="pill pill-red">unsafe-eval</span>
    <span class="pill pill-red">wildcard (*)</span><span class="pill pill-warn">nonce-reuse</span>
    <span class="pill pill-warn">trusted JSONP domain</span><span class="pill pill-warn">missing base-uri</span>
    <span class="pill pill-warn">Angular gadget</span><span class="pill pill-warn">React gadget</span>
    <span class="pill">missing strict-dynamic</span><span class="pill">insecure http origin</span>
  </div>
</div>`,

  // ── WAF §10 ───────────────────────────────────────────────────────
  waf: () => `
<div class="card card-amber">
  <div class="card-header"><span class="card-title">WAF Detections — §10</span></div>
  <div id="waf-findings-live">
    <div class="empty-state"><i class="fa fa-wall-brick"></i><p>WAF detections appear here during scan</p></div>
  </div>
</div>
<div class="card card-green">
  <div class="card-header"><span class="card-title">Adaptive Evasion — §10</span></div>
  <div class="pills">
    <span class="pill pill-on">per-domain concurrency limits</span><span class="pill pill-on">exponential backoff</span>
    <span class="pill pill-on">retry handling</span><span class="pill pill-on">WAF-aware pacing</span>
  </div>
</div>
<div class="card">
  <div class="card-header"><span class="card-title">Response Analysis Signals — §10</span></div>
  <table class="tbl">
    <tr><th>Signal</th><th>Detection Method</th></tr>
    <tr><td class="t2">Status code anomaly</td><td class="mono t2">403/406/429 differential vs baseline</td></tr>
    <tr><td class="t2">Block page fingerprint</td><td class="mono t2">Body pattern match (CF, AWS, Akamai, Sucuri…)</td></tr>
    <tr><td class="t2">WAF header presence</td><td class="mono t2">CF-Ray, X-Sucuri-Id, x-amzn-waf headers</td></tr>
    <tr><td class="t2">Timing anomaly</td><td class="mono t2">Probe latency &gt; 3× baseline avg</td></tr>
    <tr><td class="t2">Payload normalization</td><td class="mono t2">Marker absent + status diff</td></tr>
  </table>
</div>`,

  // ── HISTORICAL §13 ────────────────────────────────────────────────
  hist: () => `
<div class="notif notif-amber"><i class="fa fa-clock-rotate-left"></i> Historical endpoints often contain weak sanitisation, outdated libraries, legacy DOM sinks, and no CSP. (§13)</div>
<div class="stat-row">
  <div class="stat-card sc-amber"><div class="stat-label">Deprecated Endpoints</div><div class="stat-val amber" id="sv-hist-depr">0</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">Archived JS Files</div><div class="stat-val amber" id="sv-hist-js">0</div></div>
  <div class="stat-card sc-red"><div class="stat-label">Legacy Admin Panels</div><div class="stat-val red" id="sv-hist-admin">0</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">Old API Versions</div><div class="stat-val amber" id="sv-hist-api">0</div></div>
</div>
<div class="card">
  <div class="card-header"><span class="card-title">Historical Findings — §13</span><span class="card-sub">Sources: Wayback · Gau · Katana · OTX · CommonCrawl</span></div>
  <div id="hist-findings-live">
    <div class="empty-state"><i class="fa fa-clock-rotate-left"></i><p>Historical endpoints appear here during scan</p></div>
  </div>
</div>`,

  // ── FP ELIMINATION §12 ────────────────────────────────────────────
  fp: () => `
<div class="notif notif-green"><i class="fa fa-shield-halved"></i> No vulnerability reported without runtime browser verification. (§12) All confirmed findings executed in Chromium.</div>
<div class="g2">
  <div class="card card-red">
    <div class="card-header"><span class="card-title">FP Detection Checks — §12</span></div>
    <table class="tbl">
      <tr><th>Check</th><th>Method</th></tr>
      <tr><td class="t2">Escaped reflection</td><td class="mono t2">JS escape sequence detection near marker</td></tr>
      <tr><td class="t2">Encoded reflection</td><td class="mono t2">HTML entity decode + compare</td></tr>
      <tr><td class="t2">Dead reflection</td><td class="mono t2">JSON/unknown context classification</td></tr>
      <tr><td class="t2">Sanitised sink</td><td class="mono t2">DOMPurify / innerHTML encode detection</td></tr>
      <tr><td class="t2">Non-executable context</td><td class="mono t2">CSS / inert attribute classification</td></tr>
      <tr><td class="t2">Inert payload</td><td class="mono t2">Runtime token not in execHits</td></tr>
      <tr><td class="t2">Browser verify</td><td class="mono t2">alert() hook + DOM mutation observer</td></tr>
    </table>
  </div>
  <div class="card card-green">
    <div class="card-header"><span class="card-title">Classification Breakdown — §12</span></div>
    <table class="tbl">
      <tr><th>Type</th><th>Count</th></tr>
      <tr><td class="t2">Executable XSS — confirmed</td><td class="mono red" id="fp-confirmed">0</td></tr>
      <tr><td class="t2">Reflection only (not executable)</td><td class="mono amber" id="fp-potential">0</td></tr>
      <tr><td class="t2">DOM sinks (taint-reachable)</td><td class="mono cyan" id="fp-dom">0</td></tr>
      <tr><td class="t2">Self-XSS only</td><td class="mono t2">—</td></tr>
      <tr><td class="t2">Sanitised / dead reflections</td><td class="mono t2">filtered</td></tr>
    </table>
  </div>
</div>`,

  // ── FINDINGS §12 §16 ─────────────────────────────────────────────
  findings: () => `
<div class="stat-row">
  <div class="stat-card sc-red">  <div class="stat-label">Confirmed XSS</div><div class="stat-val red"    id="sv-confirmed">0</div><div class="stat-sub">browser verified</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">Potential XSS</div><div class="stat-val amber"  id="sv-potential">0</div><div class="stat-sub">needs manual verify</div></div>
  <div class="stat-card sc-cyan"> <div class="stat-label">DOM Sinks</div>    <div class="stat-val cyan"   id="sv-dom_sinks">0</div><div class="stat-sub">taint-reachable</div></div>
  <div class="stat-card sc-green"><div class="stat-label">URLs Scanned</div> <div class="stat-val green"  id="sv-scanned2">0</div><div class="stat-sub">deduped</div></div>
</div>
<div id="findings-list"></div>
<div class="detail-panel" id="finding-detail" style="display:none">
  <div class="det-title" id="det-title"></div>
  <div class="det-row"><span class="det-key">Endpoint</span><span class="det-val mono" id="det-url"></span></div>
  <div class="det-row"><span class="det-key">Parameter</span><span class="det-val mono" id="det-param"></span></div>
  <div class="det-row"><span class="det-key">Type</span><span class="det-val" id="det-type"></span></div>
  <div class="det-row"><span class="det-key">Context</span><span class="det-val" id="det-ctx"></span></div>
  <div class="det-row"><span class="det-key">Sink</span><span class="det-val mono" id="det-sink"></span></div>
  <div class="det-row"><span class="det-key">Browser Verified</span><span class="det-val" id="det-ver"></span></div>
  <div class="det-row"><span class="det-key">WAF Present</span><span class="det-val" id="det-waf"></span></div>
  <div class="det-row"><span class="det-key">CSP Bypass</span><span class="det-val" id="det-csp"></span></div>
  <div class="det-row"><span class="det-key">Risk</span><span class="det-val" id="det-risk"></span></div>
  <div class="sl">Payload Used</div><div class="code-block" id="det-payload"></div>
  <div class="sl">Reproduction Steps</div><div class="code-block" id="det-repro"></div>
  <div class="sl">Evidence</div><div class="evidence-grid" id="det-evidence-grid"></div>
</div>`,

  // ── BROWSER VERIFY §11 ────────────────────────────────────────────
  browser: () => `
<div class="card card-cyan">
  <div class="card-header"><span class="card-title">Verification Engine — §11 · Chromium via Playwright</span></div>
  <div class="g2">
    <div>
      <div style="font-size:9px;color:var(--t2);font-weight:700;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px">Hooks Injected</div>
      <div class="pills" style="flex-direction:column;align-items:flex-start">
        <span class="pill pill-on" style="margin:2px 0">✓ alert() / confirm() / prompt() hook</span>
        <span class="pill pill-on" style="margin:2px 0">✓ console.log monitor</span>
        <span class="pill pill-on" style="margin:2px 0">✓ DOM MutationObserver</span>
        <span class="pill pill-on" style="margin:2px 0">✓ JS callback intercept (window.__xscan_exec)</span>
        <span class="pill pill-on" style="margin:2px 0">✓ CSP violation observer</span>
        <span class="pill pill-on" style="margin:2px 0">✓ Runtime sink monitor (innerHTML, eval, doc.write…)</span>
      </div>
    </div>
    <div>
      <div style="font-size:9px;color:var(--t2);font-weight:700;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px">Evidence Collected</div>
      <div class="pills" style="flex-direction:column;align-items:flex-start">
        <span class="pill pill-cyan" style="margin:2px 0">✓ Screenshot (PNG)</span>
        <span class="pill pill-cyan" style="margin:2px 0">✓ DOM snapshot (HTML)</span>
        <span class="pill pill-cyan" style="margin:2px 0">✓ Console log</span>
        <span class="pill pill-cyan" style="margin:2px 0">✓ Network HAR</span>
        <span class="pill pill-cyan" style="margin:2px 0">✓ Reproduction steps</span>
      </div>
    </div>
  </div>
</div>
<div id="browser-findings-live">
  <div class="empty-state"><i class="fa fa-display"></i><p>Browser-verified findings appear here. Enable "Browser Verify" in Configuration to activate Playwright verification.</p></div>
</div>`,

  // ── PERFORMANCE §14 §17 ───────────────────────────────────────────
  performance: () => `
<div class="stat-row">
  <div class="stat-card sc-green"> <div class="stat-label">URLs / Minute §17</div><div class="stat-val green"  id="sv-rate">0</div><div class="stat-sub">target: thousands/min</div></div>
  <div class="stat-card sc-cyan">  <div class="stat-label">Active Workers §14</div><div class="stat-val cyan"   id="sv-workers">—</div><div class="stat-sub">configured</div></div>
  <div class="stat-card sc-amber"> <div class="stat-label">Elapsed</div>         <div class="stat-val amber"  id="sv-elapsed">0s</div><div class="stat-sub">scan time</div></div>
  <div class="stat-card sc-cyan">  <div class="stat-label">URLs Scanned</div>   <div class="stat-val cyan"   id="sv-scanned3">0</div><div class="stat-sub">completed</div></div>
</div>
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">Distributed Scan Config — §14</span></div>
    <div class="pills">
      <span class="pill pill-on">asyncio worker pools</span><span class="pill pill-on">async queues</span>
      <span class="pill pill-on">horizontal scaling ready</span><span class="pill pill-on">retry handling</span>
      <span class="pill pill-on">session persistence</span>
    </div>
    <div class="code-block" style="margin-top:10px">python scanner.py --workers 100</div>
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">Throughput — §17</span><span class="card-sub">URLs / interval</span></div>
    <div class="mini-bars" id="throughput-bars">
      ${new Array(20).fill(0).map((_,i)=>`<div class="mini-bar" style="height:${5+Math.random()*60}%;background:linear-gradient(to top,var(--cyan2),var(--cyan));opacity:.5"></div>`).join('')}
    </div>
  </div>
</div>`,

  // ── LIVE LOGS ─────────────────────────────────────────────────────
  logs: () => `
<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
  <span style="font-family:var(--head);font-size:13px;font-weight:700;flex:1">LIVE LOG STREAM</span>
  <button class="btn" onclick="$('log-area').innerHTML='';STATE.logs=[]"><i class="fa fa-trash"></i> Clear</button>
</div>
<div class="log-area" id="log-area" style="height:460px"></div>`,

  // ── STORAGE §15 ───────────────────────────────────────────────────
  storage: () => `
<div class="stat-row">
  <div class="stat-card sc-cyan"><div class="stat-label">Reflection Results</div><div class="stat-val cyan" id="sv-potential2">0</div></div>
  <div class="stat-card sc-cyan"><div class="stat-label">Payload Attempts</div><div class="stat-val cyan">—</div></div>
  <div class="stat-card sc-cyan"><div class="stat-label">DOM Sink Mappings</div><div class="stat-val cyan" id="sv-dom_sinks2">0</div></div>
  <div class="stat-card sc-amber"><div class="stat-label">Retry Queue</div><div class="stat-val amber">—</div></div>
</div>
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">Backend Config — §15</span></div>
    <div class="field"><label>Backend</label>
      <select disabled><option>SQLite (active)</option><option>PostgreSQL</option><option>Redis</option></select>
    </div>
    <div class="pills" style="margin-top:10px">
      <span class="pill pill-on">session persistence</span><span class="pill pill-on">resumable</span>
      <span class="pill pill-on">retry queue</span><span class="pill pill-on">scan progress</span>
    </div>
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">Stored Tables — §15</span></div>
    <table class="tbl">
      <tr><th>Table</th><th>Description</th></tr>
      <tr><td class="mono">findings</td><td class="t2">All detected findings</td></tr>
      <tr><td class="mono">processed_urls</td><td class="t2">Seen URLs (dedup)</td></tr>
      <tr><td class="mono">retries</td><td class="t2">Failed URL retry queue</td></tr>
      <tr><td class="mono">frontier</td><td class="t2">URL queue with leasing</td></tr>
      <tr><td class="mono">checkpoints</td><td class="t2">Resume state</td></tr>
    </table>
  </div>
</div>
<div class="card card-green">
  <div class="card-header"><span class="card-title">Session Progress</span></div>
  <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--t2);margin-bottom:4px">
    <span id="storage-progress-label">0 / 0 URLs</span>
  </div>
  <div class="pbar-wrap"><div class="pbar-fill pbar-cyan" id="storage-progress-bar" style="width:0%"></div></div>
  <div style="font-size:9px;color:var(--t3);margin-top:6px;font-family:var(--mono)">Resume: python scanner.py --resume session.db</div>
</div>`,

  // ── PLUGINS / CLI §18 ─────────────────────────────────────────────
  plugins: () => `
<div class="g2">
  <div class="card card-purple">
    <div class="card-header"><span class="card-title">Plugin Architecture — §18</span></div>
    <table class="tbl">
      <tr><th>File</th><th>Type</th><th>Section</th></tr>
      ${[
        ['reflected_xss.py','scanner','§5'],['stored_xss.py','scanner','§5'],
        ['dom_xss.py','scanner','§6'],['csp_analyser.py','analyser','§9'],
        ['waf_detector.py','analyser','§10'],['browser_verify.py','verifier','§11'],
        ['historical.py','recon','§13'],['payload_engine.py','engine','§8'],
        ['fp_eliminator.py','filter','§12'],
      ].map(([f,t,s])=>`<tr><td class="mono">${f}</td><td class="t2">${t}</td><td class="mono t2">${s}</td></tr>`).join('')}
    </table>
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">CLI Reference — §18</span></div>
    <div class="code-block" style="font-size:10px;line-height:1.9"><span class="kw">python</span> scanner.py [OPTIONS]

  <span class="cmt">## Input</span>
  -l, --list FILE         <span class="cmt">URL list (§1)</span>
  --chunk INT             <span class="cmt">Stream chunk size (§2)</span>
  --resume                <span class="cmt">Resume session (§2)</span>

  <span class="cmt">## Execution</span>
  --workers INT           <span class="cmt">Concurrency (§14)</span>
  --timeout FLOAT         <span class="cmt">HTTP timeout seconds</span>
  --browser ENGINE        <span class="cmt">Playwright browser (§11)</span>
  --verify-budget INT     <span class="cmt">Max browser calls (§11)</span>

  <span class="cmt">## Auth §18</span>
  --auth-header STR       <span class="cmt">Authorization: Bearer …</span>
  --auth-cookie STR       <span class="cmt">session=abc123</span>

  <span class="cmt">## Storage §15</span>
  --storage BACKEND       <span class="cmt">sqlite/postgres/redis</span>
  --db FILE               <span class="cmt">SQLite file path</span>

  <span class="cmt">## Output §16</span>
  --out FILE              <span class="cmt">Primary JSON output</span>
  --out-dir DIR           <span class="cmt">Report directory</span>

  <span class="cmt">## Plugins §18</span>
  --plugin module:Class   <span class="cmt">Load custom plugin</span></div>
  </div>
</div>`,

  // ── REPORT §16 ────────────────────────────────────────────────────
  report: () => `
<div class="g2">
  <div class="card card-cyan">
    <div class="card-header"><span class="card-title">Report Contents — §16</span></div>
    <div class="tags">
      ${['✓ Vulnerable endpoint','✓ Vulnerable parameter','✓ Reflection context','✓ Sink details',
         '✓ Payload used','✓ Browser execution proof','✓ CSP analysis','✓ WAF observations',
         '✓ Risk explanation','✓ Reproduction steps'].map(t=>`<span class="tag tag-on" onclick="toggleTag(this)">${t}</span>`).join('')}
    </div>
  </div>
  <div class="card">
    <div class="card-header"><span class="card-title">Current Scan</span></div>
    <div class="det-row"><span class="det-key">Scan ID</span><span class="det-val mono" id="current-scan-id">—</span></div>
    <div class="det-row"><span class="det-key">Status</span><span class="det-val" id="report-status">—</span></div>
    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
      <button class="btn btn-cyan" onclick="API.downloadReport('json')"><i class="fa fa-download"></i> JSON</button>
      <button class="btn btn-amber" onclick="API.downloadReport('markdown')"><i class="fa fa-file-lines"></i> Markdown</button>
      <button class="btn" onclick="API.downloadReport('html')"><i class="fa fa-globe"></i> HTML</button>
    </div>
  </div>
</div>
<div class="card card-red">
  <div class="card-header"><span class="card-title">Categorised Output Files — §16</span></div>
  <table class="tbl">
    <tr><th>File</th><th>Contents</th><th>Count</th></tr>
    <tr><td class="mono">confirmed_xss.txt</td><td class="t2">Browser-verified, executable XSS</td><td class="mono red" id="rpt-confirmed">0</td></tr>
    <tr><td class="mono">potential_xss.txt</td><td class="t2">Reflections not yet verified</td><td class="mono amber" id="rpt-potential">0</td></tr>
    <tr><td class="mono">dom_xss.txt</td><td class="t2">Taint-reachable DOM sinks</td><td class="mono cyan" id="rpt-dom">0</td></tr>
    <tr><td class="mono">csp_bypass.txt</td><td class="t2">CSP weaknesses and bypass paths</td><td class="mono amber" id="rpt-csp">0</td></tr>
    <tr><td class="mono">waf_detected.txt</td><td class="t2">WAF fingerprints and evasion log</td><td class="mono amber" id="rpt-waf">0</td></tr>
  </table>
</div>`,
};

// ── DOM TAB SWITCHER ──────────────────────────────────────────────────────────
function domTab(el, id) {
  el.closest('.tab-bar').querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  const content = $('dom-tab-content');
  if (!content) return;

  const tabContents = {
    'dom-taint': `<div class="card card-red">
      <div class="card-header"><span class="card-title">Taint Flows — §6 · source → transform → sink</span></div>
      <div id="dom-taint-live">${renderDomFindings('taint')}</div>
    </div>`,
    'dom-sinks': `<div class="card card-red">
      <div class="card-header"><span class="card-title">Dangerous Sinks — §6</span></div>
      <div class="pills">${['innerHTML','outerHTML','document.write','eval()','Function()','setTimeout(str)','setInterval(str)','insertAdjacentHTML','dangerouslySetInnerHTML','jQuery .html()','srcdoc','location.href'].map(s=>`<span class="pill pill-red">${s}</span>`).join('')}</div>
      <div style="margin-top:12px" id="dom-sinks-live">${renderDomFindings('sinks')}</div>
    </div>`,
    'dom-sources': `<div class="card card-cyan">
      <div class="card-header"><span class="card-title">Controllable Sources — §6</span></div>
      <div class="pills">${['location','location.hash','location.search','document.URL','document.referrer','window.name','postMessage data','localStorage.getItem','sessionStorage.getItem','URLSearchParams'].map(s=>`<span class="pill pill-red">${s}</span>`).join('')}</div>
    </div>`,
    'dom-parsers': `<div class="card card-cyan">
      <div class="card-header"><span class="card-title">AST Parsers — §6</span></div>
      <table class="tbl">
        <tr><th>Parser</th><th>Purpose</th><th>Status</th></tr>
        <tr><td class="mono">Tree-sitter</td><td class="t2">Fast incremental AST — primary</td><td><span class="badge badge-info">active</span></td></tr>
        <tr><td class="mono">esprima</td><td class="t2">ES5/ES6 full parse, source maps</td><td><span class="badge badge-info">active</span></td></tr>
        <tr><td class="mono">Babel parser</td><td class="t2">JSX / TypeScript / ES2023+</td><td><span class="badge badge-info">active</span></td></tr>
        <tr><td class="mono">Acorn</td><td class="t2">Lightweight, legacy fallback</td><td><span class="badge badge-muted">standby</span></td></tr>
      </table>
    </div>`,
  };
  content.innerHTML = tabContents[id] || '';
}

function renderDomFindings(mode) {
  const domFindings = STATE.findings.filter(f => f.type === 'dom_sink');
  if (!domFindings.length) return '<div class="empty-state"><i class="fa fa-code"></i><p>DOM sink findings appear here during scan</p></div>';
  return domFindings.map(f => {
    const ev = f.evidence || {};
    return `<div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid var(--border0)">
      <div class="taint-flow">
        <div class="tnode tnode-src">${esc(ev.source||'?')}</div>
        <span class="tarrow">→</span>
        <div class="tnode tnode-tr">${esc(ev.taint_path?.split('->')[1]?.trim()||'?')}</div>
        <span class="tarrow">→</span>
        <div class="tnode tnode-sink">${esc(ev.sink||'?')}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-top:4px">
        <span style="font-size:9px;color:var(--t3);font-family:var(--mono)">${esc(ev.notes||'')}</span>
        <span class="badge badge-${f.severity}">${f.severity}</span>
      </div>
    </div>`;
  }).join('');
}

// ── LIVE FINDING UPDATE HOOKS ─────────────────────────────────────────────────
// Called from WS.handle when new findings arrive
const _origHandle = WS.handle.bind(WS);
WS.handle = function(msg) {
  _origHandle(msg);
  if (msg.type !== 'finding') return;
  const f = msg.data;

  // Update FP panel counts
  const fpC = $('fp-confirmed'), fpP = $('fp-potential'), fpD = $('fp-dom');
  if (fpC) fpC.textContent = STATE.stats.confirmed;
  if (fpP) fpP.textContent = STATE.stats.potential;
  if (fpD) fpD.textContent = STATE.stats.dom_sinks;

  // Update report panel counts
  ['rpt-confirmed','rpt-potential','rpt-dom','rpt-csp','rpt-waf'].forEach((id,i) => {
    const el = $(id);
    if (!el) return;
    const vals = [STATE.stats.confirmed, STATE.stats.potential, STATE.stats.dom_sinks, STATE.stats.csp_issues, STATE.stats.waf_hits];
    el.textContent = vals[i];
  });

  // Append to specialised panels
  if (f.type === 'csp_weakness') {
    const el = $('csp-findings-live');
    if (el) {
      el.querySelector('.empty-state')?.remove();
      const w = (f.evidence?.weaknesses || []).join(', ');
      el.innerHTML += `<div class="card card-red" style="margin-bottom:6px">
        <div class="card-header"><span class="badge badge-${f.severity}">${f.severity}</span><span class="card-title" style="margin-left:8px">${esc(w||'CSP weakness')}</span></div>
        <div style="font-size:10px;color:var(--t2)">${esc(f.url)}</div>
      </div>`;
      const c = $('sv-csp-issues'); if (c) c.textContent = STATE.stats.csp_issues;
    }
  }

  if (f.type === 'waf_signal') {
    const el = $('waf-findings-live');
    if (el) {
      el.querySelector('.empty-state')?.remove();
      const reasons = (f.evidence?.reasons || []).join(', ');
      el.innerHTML += `<div class="card card-amber" style="margin-bottom:6px">
        <div class="card-header"><span class="badge badge-medium">WAF</span><span class="card-title" style="margin-left:8px">${esc(reasons||'WAF detected')}</span></div>
        <div style="font-size:10px;color:var(--t2)">${esc(f.url)}</div>
        <div class="waf-bar-wrap"><div class="waf-bar-fill" style="width:${Math.min(100,f.evidence?.score||50)}%;background:var(--crit)"></div></div>
      </div>`;
    }
  }

  if (f.type === 'historical_endpoint') {
    const el = $('hist-findings-live');
    if (el) {
      el.querySelector('.empty-state')?.remove();
      el.innerHTML += `<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--border0)">
        <span class="mono t2" style="flex:1;font-size:10px">${esc(f.evidence?.endpoint||f.url)}</span>
        <span class="badge badge-info">historical</span>
      </div>`;
      const h = $('sv-hist-depr'); if (h) h.textContent = parseInt(h.textContent||0) + 1;
    }
  }

  if (f.type === 'verified_reflected_xss' || f.type === 'verified_execution') {
    const el = $('browser-findings-live');
    if (el) {
      el.querySelector('.empty-state')?.remove();
      const rt = f.evidence?.runtime || {};
      el.innerHTML += `<div class="card card-red">
        <div class="card-header"><span class="badge badge-critical">CONFIRMED</span><span class="card-title" style="margin-left:8px">${esc(f.type)}</span><span class="card-sub">${esc(f.url)}</span></div>
        <div class="evidence-grid">
          ${rt.screenshot_path ? `<div class="ev-item"><div class="ev-icon ev-screenshot"><i class="fa fa-image"></i></div><div><div class="ev-label">Screenshot</div><div class="ev-sub">${esc(rt.screenshot_path)}</div></div></div>` : ''}
          ${rt.dom_snapshot_path ? `<div class="ev-item"><div class="ev-icon ev-dom"><i class="fa fa-code"></i></div><div><div class="ev-label">DOM Snapshot</div><div class="ev-sub">${esc(rt.dom_snapshot_path)}</div></div></div>` : ''}
          <div class="ev-item"><div class="ev-icon ev-console"><i class="fa fa-terminal"></i></div><div><div class="ev-label">Console</div><div class="ev-sub" style="color:var(--low)">alert() fired · token confirmed</div></div></div>
        </div>
        <div style="font-size:9px;color:var(--t2);margin-top:6px;font-family:var(--mono)">${esc((rt.executed_payload||'').slice(0,80))}</div>
      </div>`;
    }
  }

  if (f.type === 'reflection') {
    const el = $('reflect-findings-list');
    if (el) {
      el.querySelector('.empty-state')?.remove();
      const rc = $('badge-reflect-count');
      if (rc) rc.textContent = STATE.stats.potential + ' found';
      el.innerHTML += `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border0)">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <span class="mono t2" style="flex:1;font-size:10px">${esc(f.url)}[${esc(f.param||'')}]</span>
        <span class="badge badge-muted">${esc(f.evidence?.context||'?')}</span>
      </div>`;
    }
  }

  // Sync second stat cards
  const sv2 = $('sv-scanned2'); if (sv2) sv2.textContent = STATE.stats.scanned;
  const sv3 = $('sv-scanned3'); if (sv3) sv3.textContent = STATE.stats.scanned;
  const sv4 = $('sv-potential2'); if (sv4) sv4.textContent = STATE.stats.potential;
  const sv5 = $('sv-dom_sinks2'); if (sv5) sv5.textContent = STATE.stats.dom_sinks;
};

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => UI.init());
