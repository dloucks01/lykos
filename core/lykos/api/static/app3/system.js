// System screen: what THIS host can run (GET /doctor = `lykos doctor`), which lykos build is
// serving (GET /version, GET /health), and the tool's own validation gates (GET/POST /selftest,
// GET /selftest/history = `lykos archgate` / `realgate` / `eval` / `dashboard`).
// Everything shown is what the server returned; nothing here is example data.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";

// The module's stylesheet, loaded once (next.html carries the shared tokens; this adds the rest).
(function loadCss() {
  if (typeof document === "undefined" || document.querySelector('link[data-lykos-css="system"]')) return;
  const l = document.createElement("link");
  l.rel = "stylesheet";
  l.href = new URL("./system.css", import.meta.url).href;
  l.dataset.lykosCss = "system";
  document.head.appendChild(l);
})();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TIERS = [
  ["required", "Required", "the platform does not work without these"],
  ["recommended", "Recommended", "a whole class of targets or checks is lost without these"],
  ["optional", "Optional", "extra engines and cross-checks; the analysis runs without them"],
];
const when = (t) => (t ? new Date(t * 1000).toLocaleString() : "");
const day = (s) => (s ? String(s).slice(0, 10) : null);

// "12/14: aarch64 ..." -> the probe found only part of a multi-part tool (some guests, some
// headers). Present, but with a gap the install line closes.
function partialOf(found) {
  const m = /^(\d+)\s*\/\s*(\d+)\b/.exec(String(found || ""));
  return m && +m[1] < +m[2] ? { have: +m[1], of: +m[2] } : null;
}

function CopyCmd({ cmd }) {
  const [ok, setOk] = useState(false);
  if (!cmd) return null;
  const copy = async () => {
    try { await navigator.clipboard.writeText(cmd); setOk(true); setTimeout(() => setOk(false), 1500); }
    catch (_e) { /* no clipboard (insecure context): the command is selectable text */ }
  };
  return html`<div class="sy-cmd"><code class="mono">${cmd}</code>
    <button class="btn sm" onClick=${copy} title="copy the fix">${ok ? "copied" : "copy"}</button></div>`;
}

// ---- build + server ---------------------------------------------------------------------------
function BuildPanel() {
  const [health, setHealth] = useState(null);
  const [info, setInfo] = useState(null);
  const [err, setErr] = useState(null);
  const load = () => {
    api.health().then((h) => setHealth((h && h.status) || "unknown")).catch((e) => setHealth(`down (${e.message || e})`));
    api.version().then((v) => { setInfo(v); setErr(null); }).catch((e) => setErr(String(e.message || e)));
  };
  useEffect(load, []);
  const rows = info ? [
    ["Version", info.version],
    ["Commit", info.commit ? `${info.short || info.commit.slice(0, 12)}${info.branch ? ` on ${info.branch}` : ""}` : null],
    ["Commit date", info.built],
    ["Newest source file", info.code_mtime],
    ["Toolchain built", info.toolchain_built],
    ["Stamp from", info.source],
    ["Label", info.label],
  ].filter(([, v]) => v != null && v !== "") : [];
  return html`
    <section class="panel pad sy-build">
      <div class="sy-h"><h2>This lykos</h2>
        <span class=${"chip" + (health === "ok" ? " on" : "")}><span class=${"dot" + (health === "ok" ? " live" : "")}></span>
          server ${health == null ? "…" : health === "ok" ? "ready" : health}</span>
        <button class="btn sm" style="margin-left:auto" onClick=${load}>Reload</button></div>
      ${info ? html`<div class="sy-display mono">${info.display || `lykos ${info.version || ""}`}</div>` : null}
      ${info && info.source === "none" ? html`<div class="sy-warn">No commit stamp — this build cannot be identified.
        Check it against the disc or checkout it came from before trusting results across machines.</div>` : null}
      ${info && info.error ? html`<div class="sy-warn">Build info incomplete: ${info.error}</div>` : null}
      ${err ? html`<div class="sy-warn">Could not read the build: ${err}</div>` : null}
      ${rows.length ? html`<dl class="sy-dl">${rows.map(([k, v]) => html`<dt>${k}</dt><dd class="mono">${String(v)}</dd>`)}</dl>` : null}
      ${info && day(info.built) && day(info.code_mtime) && day(info.code_mtime) > day(info.built) ? html`
        <div class="dim sy-note">Source files are newer than the commit (${day(info.code_mtime)} vs ${day(info.built)}):
          this is a working tree with uncommitted changes.</div>` : null}
    </section>`;
}

// ---- doctor -----------------------------------------------------------------------------------
function useDoctor() {
  const [doc, setDoc] = useState(null);
  const token = useRef(0);
  const load = async (refresh = false) => {
    const me = ++token.current;
    let d = null;
    for (let i = 0; i < 120; i++) {
      try { d = await api.doctor(refresh && i === 0); } catch (e) { d = { state: "error", error: e.message || String(e) }; }
      if (me !== token.current) return;
      setDoc(d);
      if (!d || d.state !== "probing") return;
      await sleep(1500);
    }
    // Gave up waiting (3 min): say so and re-enable Re-check, instead of a "probing…" chip and a
    // disabled button forever. The probe may still finish server-side; Re-check reads it.
    if (me === token.current) {
      setDoc({ ...(d || {}), state: "stalled",
               error: "the engine probe is still running after 3 minutes — Re-check to read it again" });
    }
  };
  useEffect(() => { load(false); return () => { token.current++; }; }, []);
  return [doc, load];
}

function ToolRow({ t }) {
  const part = t.present ? partialOf(t.found) : null;
  const cls = !t.present ? "miss" : part ? "part" : "ok";
  return html`
    <div class=${"sy-tool " + cls}>
      <span class="sy-mark" aria-label=${cls === "ok" ? "ready" : cls === "part" ? "partly present" : "missing"}>${cls === "ok" ? "✓" : cls === "part" ? "◐" : "✕"}</span>
      <div class="sy-tool-b">
        <div class="sy-tool-t">${t.title}
          ${cls === "part" ? html`<span class="chip sy-amber">partial ${part.have}/${part.of}</span>` : null}
          ${cls === "miss" ? html`<span class="chip sy-amber">missing</span>` : null}</div>
        ${t.unlocks ? html`<div class="sy-unl"><span class="dim">gives</span> ${t.unlocks}</div>` : null}
        ${t.present && t.found ? html`<div class="mono dim sy-found" title=${t.found}>${t.found}</div>` : null}
        ${!t.present && t.without ? html`<div class="sy-without"><span class="dim">without it</span> ${t.without}</div>` : null}
        ${!t.present || part ? html`<${CopyCmd} cmd=${t.install} />` : null}
      </div>
    </div>`;
}

function DoctorPanel() {
  const [doc, load] = useDoctor();
  const [only, setOnly] = useState("all");                // all | gaps
  const tools = (doc && doc.tools) || [];
  const probing = doc && doc.state === "probing";
  const missing = tools.filter((t) => !t.present);
  const partial = tools.filter((t) => t.present && partialOf(t.found));
  const missBy = (tier) => missing.filter((t) => t.tier === tier).length;
  const gaps = missing.concat(partial);
  const shown = only === "gaps" ? gaps : tools;
  const tone = missBy("required") ? "bad" : missBy("recommended") ? "warn" : missing.length || partial.length ? "info" : "ok";
  return html`
    <section class="panel sy-doctor">
      <div class="pad sy-h">
        <h2>What this machine can run</h2>
        <span class="dim" style="font-size:12px">${doc && doc.checked_at ? `probed ${when(doc.checked_at)}` : ""}</span>
        ${probing ? html`<span class="chip on"><span class="dot live"></span>probing every engine…</span>` : null}
        <button class="btn sm" style="margin-left:auto" disabled=${probing} title="probe every engine again (runs each tool's own version check)"
          onClick=${() => load(true)}>Re-check</button>
      </div>
      ${!doc ? html`<div class="pad dim">Asking the server…</div>`
        : !tools.length ? html`<div class="pad">
            ${probing ? html`<span class="muted">Checking which engines work on this machine — each tool is run, not just looked up.</span>`
              : html`<span class="sy-warn">${doc.state === "stalled" ? "Engine check not finished" : "Engine check unavailable"}${doc.error ? ` — ${doc.error}` : ""}.</span>`}</div>`
        : html`
        <div class=${"sy-verdict t-" + tone}>
          ${tone === "bad" ? html`<b>${missBy("required")} required engine${missBy("required") === 1 ? "" : "s"} missing</b> — analyses on this host will not work until ${missBy("required") === 1 ? "it is" : "they are"} installed.`
            : tone === "warn" ? html`<b>Usable, with gaps.</b> ${missBy("recommended")} recommended engine${missBy("recommended") === 1 ? " is" : "s are"} missing — the capabilities below are lost on this host.`
            : tone === "info" ? html`<b>Every required and recommended engine is installed.</b>${" "}${[
                missing.length ? `${missing.length} optional engine${missing.length === 1 ? " is" : "s are"} missing` : null,
                partial.length ? `${partial.length} (${partial.map((t) => t.title).join(", ")}) ${partial.length === 1 ? "is" : "are"} only partly present` : null,
              ].filter(Boolean).join("; ")} — see the fixes below.`
            : html`<b>Every engine lykos knows about was probed and works here.</b>`}
        </div>
        <div class="kpis pad" style="padding-top:12px;padding-bottom:4px">
          <div class=${"kpi" + (doc.present === doc.total ? " blue" : "")}><b>${doc.present}/${doc.total}</b><span>engines ready</span></div>
          ${TIERS.map(([k, label]) => html`<div class="kpi"><b class=${missBy(k) && k !== "optional" ? "sy-amber-tx" : ""}>${missBy(k)}</b><span>${label.toLowerCase()} missing</span></div>`)}
          <div class="kpi"><b class=${partial.length ? "sy-amber-tx" : ""}>${partial.length}</b><span>partly present</span></div>
        </div>
        ${doc.toolchain ? html`<div class="pad mono dim sy-tc">${doc.toolchain}</div>` : null}
        ${gaps.length ? html`
          <div class="pad sy-gaps">
            <div class="sy-sub">What this host cannot do, and the fix</div>
            ${gaps.map((t) => html`<div class="sy-gap">
              <span class=${"lvl" + (t.tier === "optional" ? "" : " amber")}>${t.tier}</span>
              <div style="min-width:0;flex:1 1 auto">
                <div><b>${t.title}</b>${t.present ? html` <span class="dim">— only ${t.found}</span>` : null}</div>
                <div class="muted" style="font-size:12.5px">${t.present ? `Only part of it is here. It gives: ${t.unlocks || "—"}` : t.without}</div>
                <${CopyCmd} cmd=${t.install} />
              </div></div>`)}
          </div>` : null}
        <div class="pad sy-h" style="padding-bottom:6px">
          <span class="sy-sub" style="margin:0">Every engine, by tier</span>
          <div class="seg" style="margin-left:auto">
            <button class=${only === "all" ? "on" : ""} onClick=${() => setOnly("all")}>All ${tools.length}</button>
            <button class=${only === "gaps" ? "on" : ""} onClick=${() => setOnly("gaps")} disabled=${!gaps.length}>Gaps ${gaps.length}</button>
          </div>
        </div>
        ${TIERS.map(([k, label, gloss]) => {
          const ts = shown.filter((t) => t.tier === k);
          if (!ts.length) return null;
          return html`<div class="sy-tier">
            <div class="sy-tier-h"><b>${label}</b> <span class="dim">${gloss}</span>
              <span class="dim" style="margin-left:auto">${ts.filter((t) => t.present).length}/${ts.length} ready</span></div>
            ${ts.map((t) => html`<${ToolRow} key=${t.key} t=${t} />`)}
          </div>`;
        })}
        ${tools.some((t) => !TIERS.find(([k]) => k === t.tier)) ? html`<div class="sy-tier">
          <div class="sy-tier-h"><b>Other</b></div>
          ${shown.filter((t) => !TIERS.find(([k]) => k === t.tier)).map((t) => html`<${ToolRow} key=${t.key} t=${t} />`)}
        </div>` : null}`}
    </section>`;
}

// ---- self-test --------------------------------------------------------------------------------
const GATES = [
  { kind: "archgate", label: "Architecture gate", cli: "lykos archgate",
    what: "every instruction-set architecture still reaches its PoC level" },
  { kind: "realgate", label: "Real-program gate", cli: "lykos realgate",
    what: "detect → PoC → attribution on real programs" },
  { kind: "eval", opts: { stage: "static" }, label: "Detection benchmark", cli: "lykos eval",
    what: "static detection precision and recall on the bundled corpus" },
  { kind: "eval", opts: { stage: "dynamic" }, label: "Crash-reproduction benchmark", cli: "lykos eval --stage dynamic",
    what: "fuzzing reproduces the corpus's crashes" },
];

// POST /selftest {kind, options}. Sent directly: app/api.js's startSelftest passes the payload
// as request options rather than as the body, so the server receives {} and refuses it.
async function startGate(kind, options) {
  const r = await fetch("/selftest", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kind, options: options || {} }) });
  let d = null;
  try { d = await r.json(); } catch (_e) { /* empty */ }
  if (!r.ok) throw new Error((d && d.error) || `${r.status} ${r.statusText}`);
  return d;
}

function gateName(kind, opts) {
  const g = GATES.find((x) => x.kind === kind && (!x.opts || (opts && opts.stage === x.opts.stage)));
  return g ? g.label : kind || "self-test";
}

function SelftestPanel() {
  const [st, setSt] = useState(null);
  const [err, setErr] = useState(null);
  const [hist, setHist] = useState(null);
  const [histBusy, setHistBusy] = useState(false);
  const [now, setNow] = useState(Date.now() / 1000);
  const [starting, setStarting] = useState(false);
  const token = useRef(0);
  const poll = async () => {
    const me = ++token.current;
    for (;;) {
      let s;
      try { s = await api.selftest(); } catch (e) { s = { state: "error", error: e.message || String(e) }; }
      if (me !== token.current) return;
      setSt(s);
      if (!s || !s.running) return;
      await sleep(2000);
    }
  };
  useEffect(() => { poll(); return () => { token.current++; }; }, []);
  const running = !!(st && st.running);
  useEffect(() => {
    if (!running) return undefined;
    const t = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(t);
  }, [running]);
  // The CLI's gate options: --only / --timeout (archgate, realgate), --min-state and --record
  // (eval). Each gate gets only the options it takes.
  const [gopt, setGopt] = useState({ only: "", timeout: "", min_state: "candidate", record: false, label: "" });
  const optsFor = (g) => {
    const o = { ...(g.opts || {}) };
    if (g.kind === "archgate" || g.kind === "realgate") {
      if (gopt.only.trim()) o.only = gopt.only.split(",").map((x) => x.trim()).filter(Boolean);
      const t = parseFloat(gopt.timeout);
      if (isFinite(t) && t > 0) o.timeout = t;
    } else if (g.kind === "eval") {
      if (o.stage === "static" && gopt.min_state !== "candidate") o.min_state = gopt.min_state;
      if (gopt.record) { o.record = true; if (gopt.label.trim()) o.label = gopt.label.trim(); }
    }
    return o;
  };
  const start = async (g) => {
    if (running || starting) return;
    setErr(null); setStarting(true);
    try { await startGate(g.kind, optsFor(g)); } catch (e) { setErr(String(e.message || e)); }
    setStarting(false);
    poll();
  };
  const loadHist = async () => {
    setHistBusy(true);
    try { setHist(await api.selftestHistory()); } catch (e) { setHist({ error: e.message || String(e) }); }
    setHistBusy(false);
  };
  const res = st && st.result;
  const tone = res ? (res.verdict === "PASS" ? "ok" : res.verdict === "SKIP" ? "info" : "bad") : null;
  const lines = (st && st.lines) || [];
  const outRef = useRef(null);
  useEffect(() => { if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight; }, [lines.length]);
  const took = st && st.started ? ((st.ended || (running ? now : null)) || st.started) - st.started : null;
  return html`
    <section class="panel sy-self">
      <div class="pad sy-h"><h2>Self-test</h2>
        <span class="muted" style="font-size:12.5px">Check this lykos build — the tool, not a target.</span></div>
      <div class="pad" style="padding-top:0">
        <div class="sy-note muted">Each gate takes minutes and runs to completion once started — it cannot be stopped from here.
          One at a time; it keeps running if you leave this screen.</div>
        <div class="sy-gates">
          ${GATES.map((g) => html`<button class="sy-gate" disabled=${running || starting} onClick=${() => start(g)}
              title=${`${g.what} (${g.cli})`}>
            <b>${g.label}</b><span class="muted">${g.what}</span><span class="mono dim">${g.cli}</span></button>`)}
        </div>
        <details class="sy-opts">
          <summary>Gate options <span class="dim">— the CLI's flags; each gate uses the ones it takes</span></summary>
          <div class="sy-opts-b">
            <label class="field">Only these cases <span class="dim">(architecture / real-program gate; comma-separated labels — the CLI's --only)</span>
              <input type="text" class="mono" placeholder="all cases" value=${gopt.only} onInput=${(e) => setGopt({ ...gopt, only: e.target.value })} /></label>
            <label class="field">Per-detonation timeout, s <span class="dim">(architecture / real-program gate; default 30)</span>
              <input type="number" min="1" step="1" placeholder="30" value=${gopt.timeout} onInput=${(e) => setGopt({ ...gopt, timeout: e.target.value })} /></label>
            <label class="field">Lowest finding state counted <span class="dim">(detection benchmark — the CLI's --min-state)</span>
              <select value=${gopt.min_state} onChange=${(e) => setGopt({ ...gopt, min_state: e.target.value })}>
                ${["candidate", "corroborated", "confirmed"].map((x) => html`<option value=${x}>${x}</option>`)}</select></label>
            <label class="row-c" style="gap:6px;font-size:12.5px"><input type="checkbox" checked=${gopt.record}
              onChange=${(e) => setGopt({ ...gopt, record: e.target.checked })} />
              Record benchmark runs in the history <span class="dim">(the CLI's eval --record; shown under Benchmark history)</span></label>
            ${gopt.record ? html`<label class="field">History label
              <input type="text" placeholder="gui" value=${gopt.label} onInput=${(e) => setGopt({ ...gopt, label: e.target.value })} /></label>` : null}
          </div>
        </details>
        ${err ? html`<div class="sy-warn">Could not start: ${err}</div>` : null}
        ${st && st.state !== "idle" ? html`
          <div class="sy-run">
            <div class="row-c" style="flex-wrap:wrap">
              ${running ? html`<span class="chip on"><span class="dot live"></span>running</span>`
                : tone ? html`<span class=${"sy-verdict-chip t-" + tone}>${res.verdict}</span>`
                : st.state === "error" ? html`<span class="sy-verdict-chip t-bad">ERROR</span>` : null}
              <b>${gateName(st.kind, st.options)}</b>
              ${st.options && Object.keys(st.options).length ? html`<span class="mono dim" style="font-size:11.5px">${Object.entries(st.options).map(([k, v]) => `${k}=${v}`).join(" ")}</span>` : null}
              <span class="dim" style="font-size:12px;margin-left:auto">${st.started ? `started ${when(st.started)}` : ""}${took != null ? ` · ${Math.round(took)} s` : ""}</span>
            </div>
            ${res ? html`<div class=${"sy-reason t-" + tone}>${res.reason}</div>` : null}
            ${st.error ? html`<div class="sy-warn">${st.kind} self-test failed: ${st.error}</div>` : null}
            ${res && res.table ? html`<pre class="sy-pre">${res.table}</pre>`
              : lines.length ? html`<pre class="sy-pre" ref=${outRef}>${lines.join("\n")}</pre>`
              : running ? html`<div class="dim" style="font-size:12.5px">Started; no progress line yet.</div>` : null}
          </div>` : null}
        <div class="sy-h" style="margin-top:14px">
          <span class="sy-sub" style="margin:0">Benchmark history</span>
          <span class="dim" style="font-size:12px">the recorded detection-quality runs (lykos dashboard)</span>
          <button class="btn sm" style="margin-left:auto" disabled=${histBusy} onClick=${loadHist}>${hist ? "Reload" : "Show"}</button>
        </div>
        ${hist ? html`
          <div class="dim" style="font-size:12px;margin-top:6px">${hist.runs || 0} recorded run${hist.runs === 1 ? "" : "s"}${hist.path ? html` · <span class="mono">${hist.path}</span>` : null}
            ${(hist.regressions || []).length ? html` · <b class="sy-amber-tx">${hist.regressions.length} series regressed</b>` : null}</div>
          ${(hist.regressions || []).length ? html`<ul class="sy-reg">${hist.regressions.map((r) => html`<li class="mono">${typeof r === "string" ? r : JSON.stringify(r)}</li>`)}</ul>` : null}
          <pre class="sy-pre">${hist.error || hist.text || "no history recorded yet"}</pre>` : null}
      </div>
    </section>`;
}

// ---- weakness classes (GET /cwe-coverage = `lykos cwe-coverage`) -------------------------------
// Every CWE class: how lykos detects it, and the furthest rung it can carry a sound exploit of the
// class TODAY. A rung below L3 (or none) is lykos's reach -- a technique not yet built -- never a
// property of any target. With a case open, the classes that case actually has, and how far each got.
const CEIL = {
  rce: ["code execution", 0], primitive: ["corruption primitive", 1], leak: ["disclosure", 2],
  dos: ["denial of service", 3], logic: ["logic / auth / crypto", 4],
};
const CEIL_NONE = ["not yet built", 5];
const METHOD = { pattern: "static pattern", taint: "taint", runtime: "runtime oracle", binary: "binary image", na: "not applicable" };
const STATE_RANK = { candidate: 0, corroborated: 1, confirmed: 2, "poc-backed": 3 };
const RUNG_RANK = { L0: 0, L1: 1, L2: 2, L3: 3 };
const cweNum = (c) => Number(String(c || "").replace(/^CWE-/i, "")) || 1e9;
const ceilOf = (r) => (r.ceiling && CEIL[r.ceiling]) || CEIL_NONE;
const caseFromHash = () => {
  try { return new URLSearchParams(location.hash.slice(1)).get("case"); } catch (_e) { return null; }
};
const CWE_SORTS = {
  cwe: (a, b) => cweNum(a.cwe) - cweNum(b.cwe),
  name: (a, b) => String(a.name).localeCompare(String(b.name)),
  method: (a, b) => String(a.method || "~").localeCompare(String(b.method || "~")) || cweNum(a.cwe) - cweNum(b.cwe),
  ceiling: (a, b) => ((RUNG_RANK[b.ceiling_level] ?? -1) - (RUNG_RANK[a.ceiling_level] ?? -1))
    || ceilOf(a)[1] - ceilOf(b)[1] || cweNum(a.cwe) - cweNum(b.cwe),
  here: (a, b) => ((b.here && b.here.count) || 0) - ((a.here && a.here.count) || 0) || cweNum(a.cwe) - cweNum(b.cwe),
};

function CweCoveragePanel() {
  const [caseId, setCaseId] = useState(caseFromHash);
  const [m, setM] = useState(undefined);
  const [err, setErr] = useState(null);
  const [q, setQ] = useState("");
  const [method, setMethod] = useState("");
  const [ceil, setCeil] = useState("");
  const [onlyHere, setOnlyHere] = useState(false);
  const [sort, setSort] = useState({ key: "cwe", dir: 1 });
  useEffect(() => {
    const f = () => setCaseId(caseFromHash());
    window.addEventListener("hashchange", f);
    window.addEventListener("popstate", f);
    return () => { window.removeEventListener("hashchange", f); window.removeEventListener("popstate", f); };
  }, []);
  useEffect(() => {
    let stop = false;
    const get = async (cid) => {
      const r = await fetch(`/cwe-coverage${cid ? `?case=${encodeURIComponent(cid)}` : ""}`);
      if (r.status === 404 && cid) return get(null);           // a deleted case: the matrix alone
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    };
    get(caseId).then((d) => { if (!stop) { setM(d); setErr(null); } })
      .catch((e) => { if (!stop) { setErr(String(e.message || e)); setM(null); } });
    return () => { stop = true; };
  }, [caseId]);
  const cs = m && m.case;
  const all = useMemo(() => {
    if (!m) return [];
    const here = new Map(((cs && cs.rows) || []).map((r) => [r.cwe, r]));
    return (m.classes || []).map((r) => ({ ...r, here: here.get(r.cwe) || null }));
  }, [m]);
  if (m === undefined) return html`<section class="panel pad dim">Loading the weakness-class matrix…</section>`;
  if (!m) return html`<section class="panel pad"><h2>Weakness classes</h2><div class="sy-warn">Could not read the class matrix: ${err}</div></section>`;
  const known = new Set(all.map((r) => r.cwe));
  const outside = ((cs && cs.rows) || []).filter((r) => !known.has(r.cwe));
  const ql = q.trim().toLowerCase();
  const rows = all.filter((r) => (!ql || r.cwe.toLowerCase().includes(ql) || String(r.name).toLowerCase().includes(ql)
      || String(r.family || "").toLowerCase().includes(ql))
    && (!method || r.method === method)
    && (!ceil || (ceil === "none" ? !r.ceiling : r.ceiling === ceil))
    && (!onlyHere || r.here));
  rows.sort((a, b) => sort.dir * CWE_SORTS[sort.key](a, b));
  const dist = {};
  for (const r of all) { const k = r.ceiling || "none"; dist[k] = (dist[k] || 0) + 1; }
  const nCli = all.filter((r) => !r.catalog_only).length;
  const th = (key, label) => html`<button class=${"sy-th" + (sort.key === key ? " on" : "")} role="columnheader"
      aria-sort=${sort.key === key ? (sort.dir > 0 ? "ascending" : "descending") : "none"}
      onClick=${() => setSort((s) => ({ key, dir: s.key === key ? -s.dir : 1 }))}>${label}${sort.key === key ? (sort.dir > 0 ? " ▲" : " ▼") : ""}</button>`;
  return html`
    <section class="panel pad sy-cwe">
      <div class="sy-h"><h2>Weakness classes</h2>
        <span class="dim" style="font-size:12.5px">every CWE class — how lykos detects it, and the furthest rung it carries a sound exploit of it today (lykos cwe-coverage)</span></div>
      <div class="sy-cwe-sum">
        <span><b>${all.length}</b> classes${all.length !== nCli ? html`${" "}<span class="dim">(${nCli} named by the detectors, ${all.length - nCli} more covered by the function sweep)</span>` : null}</span>
        ${Object.entries(CEIL).concat([["none", CEIL_NONE]]).filter(([k]) => dist[k]).map(([k, [label]]) => html`
          <button class=${"sy-cwe-d c-" + k + (ceil === k ? " on" : "")} onClick=${() => setCeil(ceil === k ? "" : k)}
            title=${ceil === k ? "show every ceiling" : `show only: ${label}`}><b>${dist[k]}</b>${" "}${label}</button>`)}
      </div>
      ${cs ? html`<div class="sy-cwe-case">On case${" "}<b>${cs.name || cs.id}</b>: ${cs.classes_present} ${cs.classes_present === 1 ? "class" : "classes"} found ·${" "}
        ${cs.demonstrated_classes} carried to confirmed or PoC-backed ·${" "}${cs.l3_class_count} driven to a validated L3${(cs.l3_classes || []).length ? html`${" "}<span class="mono dim">(${cs.l3_classes.join(", ")})</span>` : null}</div>` : null}
      <div class="dim sy-note">The ceiling is lykos's current reach for the class: below L3, or none, means the technique is not yet built — never a property of a target. L3 means the class's own validated impact: code execution, a validated disclosure, a demonstrated denial of service, or the logic weakness reached.</div>
      <div class="sy-cwe-f">
        <input type="text" placeholder="filter: CWE number, name, family" value=${q} onInput=${(e) => setQ(e.target.value)} aria-label="filter classes" />
        <select value=${method} onChange=${(e) => setMethod(e.target.value)} aria-label="detection method">
          <option value="">every detection method</option>
          ${Object.entries(METHOD).map(([k, l]) => html`<option value=${k}>${l}</option>`)}</select>
        <select value=${ceil} onChange=${(e) => setCeil(e.target.value)} aria-label="ceiling">
          <option value="">every ceiling</option>
          ${Object.entries(CEIL).concat([["none", CEIL_NONE]]).map(([k, [l]]) => html`<option value=${k}>${l}</option>`)}</select>
        ${cs ? html`<label class="row-c" style="gap:6px;font-size:12.5px"><input type="checkbox" checked=${onlyHere} onChange=${(e) => setOnlyHere(e.target.checked)} /> only classes found on this case</label>` : null}
        <span class="dim" style="font-size:12px;margin-left:auto">${rows.length} of ${all.length}</span>
      </div>
      <details class="sy-cwe-leg"><summary class="muted">How each detection method works</summary>
        <dl class="sy-dl">${Object.entries(m.methods || {}).map(([k, v]) => html`<dt><span class=${"sy-mchip m-" + k}>${METHOD[k] || k}</span></dt><dd>${v}</dd>`)}</dl></details>
      <div class=${"sy-cwe-t" + (cs ? " here" : "")} role="table" aria-label="weakness classes">
        <div class="sy-cwe-r head" role="row">${th("cwe", "CWE")}${th("name", "Class")}${th("method", "Detection")}${th("ceiling", "Ceiling today")}${cs ? th("here", "Found here") : null}</div>
        ${rows.map((r) => {
          const [cl] = ceilOf(r);
          return html`<div class=${"sy-cwe-r" + (r.here ? " hit" : "")} role="row">
            <span class="mono sy-cwe-id">${r.cwe}</span>
            <span class="sy-cwe-nm">${r.name}${r.family ? html`${" "}<span class="dim">· ${r.family}</span>` : null}</span>
            <span class="sy-cwe-m">${r.method ? html`<span class=${"sy-mchip m-" + r.method} title=${r.method_label || ""}>${METHOD[r.method] || r.method}</span>` : html`<span class="dim">—</span>`}
              ${r.severity ? html`<span class="dim">${r.severity} severity${r.detected === false ? " · excluded" : ""}</span>` : null}</span>
            <span class="sy-cwe-c">
              <span class="row-c" style="gap:6px;flex-wrap:wrap">${r.ceiling_level ? html`<span class=${"sy-rung r-" + r.ceiling_level}>${r.ceiling_level}</span>` : html`<span class="sy-rung r-none">—</span>`}
                <span class=${"c-" + (r.ceiling || "none")}>${cl}</span></span>
              <span class="dim">${r.ceiling_why}</span></span>
            ${cs ? html`<span class="sy-cwe-h">${r.here ? html`<span><b>${r.here.count}</b>${" "}<span class="dim">${r.here.count === 1 ? "finding" : "findings"}</span></span>
                <span class="row-c" style="gap:4px;flex-wrap:wrap"><span class=${"sy-st s-" + r.here.best_state}>${r.here.best_state}</span>
                  ${r.here.best_level ? html`<span class=${"sy-rung r-" + r.here.best_level}>PoC ${r.here.best_level}</span>` : null}</span>`
              : html`<span class="dim">—</span>`}</span>` : null}
          </div>`;
        })}
        ${!rows.length ? html`<div class="dim" style="padding:12px 14px;font-size:12.5px">No class matches the filter.</div>` : null}
      </div>
      ${outside.length ? html`<div class="sy-note"><span class="dim">Also found on this case, outside the class catalog:</span>${" "}
        ${outside.map((r) => html`<span class="chip" style="margin:2px 4px 0 0" title=${`${r.count} finding(s), best ${r.best_state}`}><span class="mono">${r.cwe}</span>${" "}${r.count}</span>`)}</div>` : null}
    </section>`;
}

export function SystemScreen() {
  return html`
    <div style="display:flex;flex-direction:column;gap:2px">
      <h1>System</h1>
      <span class="muted" style="font-size:13px">What this machine can run, which lykos build is serving,
        the tool's own validation gates, and what it covers across every weakness class.</span>
    </div>
    <div class="sy-grid">
      <div class="sy-col"><${DoctorPanel} /></div>
      <div class="sy-col"><${BuildPanel} /><${SelftestPanel} /></div>
    </div>
    <${CweCoveragePanel} />`;
}
