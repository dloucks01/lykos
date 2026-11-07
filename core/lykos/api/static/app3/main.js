// The redesigned workbench (next.html). Built screen by screen against the design canvas; the
// existing GUI (index.html) stays the default until this one covers what it does.
// Screen 1 here: Run -- the live console of everything the autopilot does + one window per
// fuzzing technique, fed by GET /cases/{id}/console (jobs/runlog on the server).
import { render } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { CodeScreen } from "./code.js";
import { Console, FuzzWindows, NowRunning, PlanStrip, RunProgress, TargetSummary, pollDelay, useOnVisible } from "./console.js";
import { BUDGET_OPTIONS, startSettings, useCaseData } from "./data.js";
import { Lazy, useModule } from "./lazy.js";
import { EngagementScreen } from "./engagement.js";
import { FindingDetail, ProofScreen } from "./proof.js";

const POLL_MS = 800;
const MAX_RECS = 8000;

// Tails GET /cases/{id}/console by byte offset. Every record gets a stable `_i` (the console's
// row key). A failed poll keeps the cursor (an error body has no `next`: treating it as 0 used to
// replay the whole log from byte 0); a log that SHRANK under the cursor (truncated / replaced)
// starts over from its tail. Polls fast only while a run is live and the tab is in view.
function useCaseConsole(caseId, running) {
  const [recs, setRecs] = useState([]);
  const live = useRef(running);
  live.current = running;
  const kick = useRef(null);
  useEffect(() => {
    if (!caseId) return undefined;
    let next = null, stop = false, timer = null, busy = false, seq = 0;
    setRecs([]);
    const tick = async () => {
      if (stop || busy) return;
      clearTimeout(timer);
      busy = true;
      let delay = pollDelay(POLL_MS, 5000, live.current);
      try {
        const q = next === null ? "tail=600000" : `after=${next}`;
        const res = await fetch(`/cases/${caseId}/console?${q}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const r = await res.json();
        if (stop) return;
        if (next !== null && typeof r.size === "number" && r.size < next) {
          next = null;                       // the log shrank: re-read its tail
          setRecs([]);
          delay = 0;
        } else {
          if (typeof r.next === "number") next = r.next;
          const lines = Array.isArray(r.lines) ? r.lines : [];
          if (lines.length) {
            for (const x of lines) x._i = ++seq;
            setRecs((old) => {
              const all = old.concat(lines);
              return all.length > MAX_RECS ? all.slice(all.length - MAX_RECS) : all;
            });
          }
          if (lines.length >= 2000) delay = 50;   // a large backlog: keep reading without waiting
        }
      } catch (_e) {
        delay *= 3;
      } finally {
        busy = false;
        if (!stop) timer = setTimeout(tick, delay);
      }
    };
    kick.current = tick;
    tick();
    return () => { stop = true; clearTimeout(timer); kick.current = null; };
  }, [caseId]);
  // a run just started, or the tab came back: read now instead of waiting out the slow delay
  useEffect(() => { if (running && kick.current) kick.current(); }, [running]);
  useOnVisible(() => kick.current && kick.current());
  return recs;
}

// The case's autopilot status. Tagged with the case it was read for, so a case switch never shows
// (or lets Stop act on) the previous case's run; polled fast only while a run is live.
function useAutopilot(caseId) {
  const [st, setSt] = useState({ cid: null, s: null });
  const kick = useRef(null);
  useEffect(() => {
    if (!caseId) return undefined;
    let stop = false, timer = null, busy = false, last = null;
    const tick = async () => {
      if (stop || busy) return;
      clearTimeout(timer);
      busy = true;
      try { const s = await api.backgroundStatus(caseId); if (!stop) { last = s; setSt({ cid: caseId, s }); } }
      catch (_e) { /* keep last */ }
      busy = false;
      const on = !!(last && (last.running || last.state === "running"));
      if (!stop) timer = setTimeout(tick, pollDelay(2000, 6000, on));
    };
    kick.current = tick;
    tick();
    return () => { stop = true; clearTimeout(timer); kick.current = null; };
  }, [caseId]);
  useOnVisible(() => kick.current && kick.current());
  const cur = st.cid === caseId ? st.s : null;
  return [cur, (s) => setSt({ cid: caseId, s })];
}

function RunControls({ caseId, targets, ap, onChanged }) {
  const [budget, setBudget] = useState(600);
  const [opts, setOpts] = useState({});
  const [showOpts, setShowOpts] = useState(false);
  const settingsMod = useModule("./results.js");
  useEffect(() => { if (settingsMod && settingsMod.loadRunOptions) setOpts(settingsMod.loadRunOptions()); }, [settingsMod]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  // a start was accepted but the status poll has not reported the run yet: keep Start locked, so
  // a second click is not a 409 "already running"
  const [launched, setLaunched] = useState(false);
  const running = ap && (ap.running || ap.state === "running");
  const paused = ap && (ap.paused || ap.state === "paused");
  const stopping = !!(ap && ap.stopping);
  useEffect(() => {
    if (running || !launched) { if (running) setLaunched(false); return undefined; }
    const t = setTimeout(() => setLaunched(false), 15000);
    return () => clearTimeout(t);
  }, [running, launched]);
  const act = async (fn, after) => {
    setBusy(true); setErr(null);
    try { await fn(); if (after) after(); onChanged && onChanged(); } catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };
  return html`<div>
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;justify-content:flex-end">
      ${running ? html`
        <span class="chip on"><span class="dot live"></span>${stopping ? "Stopping…" : paused ? (ap.pause_waiting ? "Paused" : "Pausing…") : "Running"}</span>
        ${ap.stage ? html`<span class="chip mono">${ap.stage}</span>` : null}
        ${paused
          ? html`<button class="btn sm" disabled=${busy || stopping} onClick=${() => act(() => api.resumeBackground(caseId))}>Resume</button>`
          : html`<button class="btn sm" disabled=${busy || stopping} title="finish the stage in flight, then wait" onClick=${() => act(() => api.pauseBackground(caseId))}>Pause</button>`}
        <button class="btn sm" disabled=${busy || stopping} title="finish the stage in flight, then end the run"
          onClick=${() => act(() => api.cancelBackground(caseId))}>${stopping ? "Stopping…" : "Stop"}</button>`
      : html`
        <label class="muted" style="font-size:12px;display:flex;align-items:center;gap:6px">Budget
          <select value=${budget} onChange=${(e) => setBudget(+e.target.value)}>
            ${BUDGET_OPTIONS.map((o) => html`<option value=${o.secs}>${o.label}</option>`)}
          </select></label>
        <button class="btn sm" onClick=${() => setShowOpts(!showOpts)} aria-expanded=${showOpts}>Options${showOpts ? " ▴" : " ▾"}</button>
        <button class="btn primary sm" disabled=${busy || launched || !targets.length}
          onClick=${() => act(async () => api.startBackground(caseId, targets.map((t) => t.id), budget,
            ...(await startSettings(settingsMod, opts, caseId))), () => setLaunched(true))}>
          ${launched ? "Starting…" : "Start analysis"}</button>`}
      ${err ? html`<span style="color:var(--amber-tx);font-size:12px">${err}</span>` : null}
    </div>
    ${running ? html`<div style="display:flex;justify-content:flex-end;margin-top:6px"><${RunProgress} ap=${ap} /></div>` : null}
    ${showOpts && !running ? html`<div class="panel pad" style="margin-top:10px">
      <${Lazy} path="./results.js" name="RunOptions" props=${{ value: opts, onChange: setOpts, caseId }}
        fallback=${html`<span class="dim">Run options are not available.</span>`} /></div>` : null}
  </div>`;
}

function RunScreen({ caseId, targets, ap, refreshAp, go }) {
  const running = !!(ap && (ap.running || ap.state === "running"));
  const recs = useCaseConsole(caseId, running);
  const [stage, setStage] = useState("");
  const multi = !!(ap && (ap.targets > 1 || (ap.per_target || []).length > 1));
  const planTitle = ap && ap.target_name && multi
    ? `Plan — ${running ? "current target" : "last target"}: ${ap.target_name}${ap.targets > 1 ? ` (${ap.target || 1} of ${ap.targets})` : ""}`
    : "Plan";
  return html`
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px">
      <div style="display:flex;flex-direction:column;gap:2px">
        <h1>Run</h1>
        <span class="muted" style="font-size:13px">Everything the autopilot does, as it does it —
          every stage, every execution of the target, every tool, every fuzzing campaign.</span>
      </div>
      <${RunControls} caseId=${caseId} targets=${targets} ap=${ap} onChanged=${refreshAp} />
    </div>
    <${NowRunning} recs=${recs} plan=${ap && ap.plan} running=${running} now=${ap && ap.now} />
    <${PlanStrip} plan=${ap && ap.plan} stage=${stage} setStage=${setStage} title=${planTitle} />
    <${TargetSummary} perTarget=${ap && ap.per_target} running=${running}
      onFocusTarget=${go ? (tid) => go("proof", { targetId: targets.some((t) => t.id === tid) ? tid : null }) : undefined} />
    <${Console} recs=${recs} caseId=${caseId} targets=${targets} stage=${stage} setStage=${setStage} />
    <${FuzzWindows} recs=${recs} />
    <details class="panel" style="padding:0">
      <summary class="pad" style="cursor:pointer;font-weight:600">Drive a target by hand <span class="dim" style="font-weight:400;font-size:12px">— interactive sandboxed console</span></summary>
      <div style="padding:0 0 2px"><${Lazy} path="./interact.js" name="InteractiveConsole" props=${{ targets, caseId }} /></div>
    </details>
    <${Lazy} path="./results.js" name="RunResults" fallback=${html``}
      props=${{ caseId, ap, targets, running,
                onOpenStage: (st) => { setStage(st); window.scrollTo({ top: 0, behavior: "smooth" }); },
                onOpenFinding: go ? (id) => go("finding", { findingId: id }) : undefined,
                onFocusTarget: go ? (tid) => go("proof", { targetId: targets.some((t) => t.id === tid) ? tid : null }) : undefined }} />
    <${Lazy} path="./history.js" name="RunHistory" fallback=${html``}
      props=${{ caseId, running, onOpenFinding: go ? (id) => go("finding", { findingId: id }) : undefined }} />`;
}

const NAV = [["engagement", "Engagement"], ["run", "Run"], ["proof", "Proof"], ["code", "Code"], ["system", "System"]];

function readHash() {
  const h = new URLSearchParams(location.hash.slice(1));
  return { caseId: h.get("case"), view: h.get("view") || "run", targetId: h.get("target"),
           findingId: h.get("finding"), addr: h.get("addr"), src: h.get("src") };
}

function App() {
  const [cases, setCases] = useState([]);
  const [r, setR] = useState(readHash);              // route: case, view, target, finding, addr, src (path:line)
  const [refresh, setRefresh] = useState(0);
  const go = (view, extra = {}) => setR((o) => ({ ...o, view, findingId: null, addr: null, src: null, ...extra }));
  const setCaseId = (id) => setR({ caseId: id, view: "engagement", targetId: null, findingId: null, addr: null, src: null });
  // Proof -> Code: a binary site is an address; a source site is "path:line" (tree-relative or a
  // bare basename, never a server path), opened in the code view's source pane.
  const toCode = (t, addr, src) => go("code", { targetId: t, addr: addr || null, src: src || null });
  // The URL is the route. A move to another screen / case / target / finding is a HISTORY ENTRY
  // (Back and Forward work); a change of address within the code view only replaces it. An
  // edited or pasted link, and Back/Forward, are read back in. replaceState-only used to make
  // Back leave the app and a pasted link do nothing until a reload.
  useEffect(() => {
    const onNav = () => setR(readHash());
    window.addEventListener("popstate", onNav);
    window.addEventListener("hashchange", onNav);
    return () => { window.removeEventListener("popstate", onNav); window.removeEventListener("hashchange", onNav); };
  }, []);
  useEffect(() => {
    const h = new URLSearchParams();
    for (const k of ["caseId", "view", "targetId", "findingId", "addr", "src"]) {
      if (r[k]) h.set({ caseId: "case", targetId: "target", findingId: "finding" }[k] || k, r[k]);
    }
    const want = "#" + h.toString();
    if (location.hash === want) return;
    const o = readHash();
    const moved = o.caseId !== r.caseId || (o.view || "run") !== (r.view || "run")
      || (o.targetId || null) !== (r.targetId || null) || (o.findingId || null) !== (r.findingId || null);
    if (moved && location.hash) history.pushState(null, "", want);
    else history.replaceState(null, "", want);
  }, [r]);
  const caseId = r.caseId;
  const [ap, setAp] = useAutopilot(caseId);
  const running = !!(ap && (ap.running || ap.state === "running"));
  // findings change while an analysis runs: reload the case data every 15 s then, and once at the end
  useEffect(() => {
    if (!running) { setRefresh((x) => x + 1); return undefined; }
    const t = setInterval(() => setRefresh((x) => x + 1), 15000);
    return () => clearInterval(t);
  }, [running]);
  const data = useCaseData(caseId, refresh);
  const [casesLoaded, setCasesLoaded] = useState(false);
  const reloadCases = () => api.listCases().then((x) => {
    const cs = Array.isArray(x) ? x : (x.cases || []);
    setCases(cs);
    setCasesLoaded(true);
    return cs;
  }).catch(() => []);
  // first load with no case in the URL: pick the newest case, KEEP the requested view
  // GET /cases is newest FIRST (ORDER BY created_at DESC); pick by created_at to not depend on it
  useEffect(() => { reloadCases().then((cs) => {
    if (caseId || !cs.length) return;
    const newest = cs.reduce((a, c) => ((c.created_at || 0) > (a.created_at || 0) ? c : a), cs[0]);
    setR((o) => ({ ...o, caseId: newest.id }));
  }); }, []);
  const refreshAp = () => api.backgroundStatus(caseId).then(setAp).catch(() => {});
  const cur = cases.find((c) => c.id === caseId);
  const [version, setVersion] = useState(null);
  useEffect(() => { api.version().then((v) => setVersion(v ? (v.display || [v.version, v.short].filter(Boolean).join(" · ")) : null)).catch(() => {}); }, []);
  const proven = data.findings.filter((f) => f.state === "poc-backed").length;
  const navOn = r.view === "finding" ? "proof" : r.view;

  let body;
  if (caseId && casesLoaded && !cur) body = html`<div class="empty">
      <p>There is no case <span class="mono">${caseId}</span> on this server — the link may be from
      another lykos instance, or the case was deleted.</p>
      <${EngagementScreen} cases=${cases} caseId=${null} setCaseId=${setCaseId} data=${data} go=${go} reloadCases=${reloadCases} /></div>`;
  else if (!caseId) body = html`<div class="empty">No case yet.
      <${EngagementScreen} cases=${cases} caseId=${null} setCaseId=${setCaseId} data=${data} go=${go} reloadCases=${reloadCases} /></div>`;
  else if (r.view === "run") body = html`<${RunScreen} caseId=${caseId} targets=${data.targets} ap=${ap} refreshAp=${refreshAp} go=${go} />`;
  else if (r.view === "proof") body = html`<${ProofScreen} data=${data} targetId=${r.targetId}
      open=${(id) => go("finding", { findingId: id })} focusTarget=${(t) => setR((o) => ({ ...o, targetId: t }))}
      toCode=${toCode} />`;
  else if (r.view === "finding") body = html`<${FindingDetail} data=${data} findingId=${r.findingId}
      back=${() => go("proof")} toCode=${toCode}
      open=${(id) => go("finding", { findingId: id })} />`;
  else if (r.view === "code") body = html`<${CodeScreen} data=${data} targetId=${r.targetId} focusAddr=${r.addr} focusSrc=${r.src}
      focusTarget=${(t) => go("code", { targetId: t })} openFinding=${(id) => go("finding", { findingId: id })}
      onLocate=${(x) => setR((o) => ({ ...o, addr: x.addr || null, src: x.src || null }))} />`;
  else if (r.view === "system") body = html`<${Lazy} path="./system.js" name="SystemScreen" />`;
  else body = html`<${EngagementScreen} cases=${cases} caseId=${caseId} setCaseId=${setCaseId} data=${data}
      go=${go} reloadCases=${reloadCases} running=${running} />`;

  return html`
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#6EA8FE" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 18 L10 6 L14 14 L20 4"></path><circle cx="20" cy="4" r="1.6"></circle></svg>
          lykos
        </div>
        ${cur ? html`<span class="chip">Case · ${cur.name || cur.id}</span>` : null}
        ${running ? html`<button class="chip on" style="cursor:pointer" onClick=${() => go("run")}><span class="dot live"></span>analysis running</button>` : null}
        <div style="flex:1 1 auto"></div>
        ${version ? html`<span class="chip mono" title="lykos build">${version}</span>` : null}
        <a class="chip" href="/workbench-v1.html" title="the previous workbench">Previous workbench</a>
      </header>
      <div class="body">
        <nav class="nav" aria-label="Workbench">
          ${NAV.map(([k, l]) => html`<button class=${navOn === k ? "on" : ""} onClick=${() => go(k)}>${l}
            ${k === "proof" && proven ? html`<span style="margin-left:auto;font-size:12px;color:var(--blue-tx)">${proven}</span>` : null}</button>`)}
          <div class="sep"></div>
          <span class="dim" style="font-size:11px;padding:0 13px;letter-spacing:.05em">TARGETS</span>
          ${data.targets.map((t) => html`<button class=${"tgt" + (r.targetId === t.id ? " on" : "")} title=${t.filename}
            onClick=${() => go(r.view === "code" ? "code" : "proof", { targetId: t.id })}>${t.filename || t.id}</button>`)}
        </nav>
        <main class="main">${body}</main>
      </div>
    </div>`;
}

render(html`<${App} />`, document.getElementById("app"));
