// System screen: what THIS host can run (GET /doctor = `lykos doctor`), which lykos build is
// serving (GET /version, GET /health), and the tool's own validation gates (GET/POST /selftest,
// GET /selftest/history = `lykos archgate` / `realgate` / `eval` / `dashboard`).
// Everything shown is what the server returned; nothing here is example data.
import { useEffect, useRef, useState } from "preact/hooks";
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
    for (let i = 0; i < 120; i++) {
      let d;
      try { d = await api.doctor(refresh && i === 0); } catch (e) { d = { state: "error", error: e.message || String(e) }; }
      if (me !== token.current) return;
      setDoc(d);
      if (!d || d.state !== "probing") return;
      await sleep(1500);
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
              : html`<span class="sy-warn">Engine check unavailable${doc.error ? ` — ${doc.error}` : ""}.</span>`}</div>`
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
  const start = async (g) => {
    setErr(null);
    try { await startGate(g.kind, g.opts || {}); } catch (e) { setErr(String(e.message || e)); }
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
          ${GATES.map((g) => html`<button class="sy-gate" disabled=${running} onClick=${() => start(g)}
              title=${`${g.what} (${g.cli})`}>
            <b>${g.label}</b><span class="muted">${g.what}</span><span class="mono dim">${g.cli}</span></button>`)}
        </div>
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

export function SystemScreen() {
  return html`
    <div style="display:flex;flex-direction:column;gap:2px">
      <h1>System</h1>
      <span class="muted" style="font-size:13px">What this machine can run, which lykos build is serving,
        and the tool's own validation gates.</span>
    </div>
    <div class="sy-grid">
      <div class="sy-col"><${DoctorPanel} /></div>
      <div class="sy-col"><${BuildPanel} /><${SelftestPanel} /></div>
    </div>`;
}
