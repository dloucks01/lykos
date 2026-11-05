// The redesigned workbench (next.html). Built screen by screen against the design canvas; the
// existing GUI (index.html) stays the default until this one covers what it does.
// Screen 1 here: Run -- the live console of everything the autopilot does + one window per
// fuzzing technique, fed by GET /cases/{id}/console (jobs/runlog on the server).
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { Console, FuzzWindows, NowRunning } from "./console.js";

const POLL_MS = 800;
const MAX_RECS = 8000;

function useCaseConsole(caseId) {
  const [recs, setRecs] = useState([]);
  useEffect(() => {
    if (!caseId) return undefined;
    let next = null, stop = false, timer = null;
    setRecs([]);
    const tick = async () => {
      try {
        const q = next === null ? "tail=600000" : `after=${next}`;
        const r = await fetch(`/cases/${caseId}/console?${q}`).then((x) => x.json());
        if (stop) return;
        next = r.next ?? next ?? 0;
        if (r.lines && r.lines.length) {
          setRecs((old) => {
            const all = old.concat(r.lines);
            return all.length > MAX_RECS ? all.slice(all.length - MAX_RECS) : all;
          });
        }
        // a large backlog: keep reading without waiting
        timer = setTimeout(tick, r.lines && r.lines.length >= 2000 ? 50 : POLL_MS);
      } catch (_e) {
        if (!stop) timer = setTimeout(tick, POLL_MS * 3);
      }
    };
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [caseId]);
  return recs;
}

function useAutopilot(caseId) {
  const [st, setSt] = useState(null);
  useEffect(() => {
    if (!caseId) return undefined;
    let stop = false, timer = null;
    const tick = async () => {
      try { const s = await api.backgroundStatus(caseId); if (!stop) setSt(s); } catch (_e) { /* keep last */ }
      if (!stop) timer = setTimeout(tick, 2000);
    };
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [caseId]);
  return [st, setSt];
}

function fmtDur(s) {
  if (s == null || !isFinite(s)) return "—";
  s = Math.max(0, Math.round(s));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function RunControls({ caseId, targets, ap, onChanged }) {
  const [budget, setBudget] = useState(600);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const running = ap && (ap.running || ap.state === "running");
  const paused = ap && (ap.paused || ap.state === "paused");
  const act = async (fn) => {
    setBusy(true); setErr(null);
    try { await fn(); onChanged && onChanged(); } catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };
  return html`
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px">
      ${running ? html`
        <span class="chip on"><span class="dot live"></span>${paused ? "Paused" : "Running"}
          ${(() => {
            const b = (ap.budget && typeof ap.budget === "object") ? ap.budget : {};
            const el = ap.now && ap.started ? ap.now - ap.started : b.elapsed;
            const tot = b.total ?? ap.budget_seconds;
            return el != null ? ` · ${b.phase ? b.phase + " phase · " : ""}${fmtDur(el)}${tot ? ` of ${fmtDur(tot)}` : ""}` : "";
          })()}</span>
        ${ap.stage ? html`<span class="chip mono">${ap.stage}</span>` : null}
        ${paused
          ? html`<button class="btn sm" disabled=${busy} onClick=${() => act(() => api.resumeBackground(caseId))}>Resume</button>`
          : html`<button class="btn sm" disabled=${busy} onClick=${() => act(() => api.pauseBackground(caseId))}>Pause</button>`}
        <button class="btn sm" disabled=${busy} onClick=${() => act(() => api.cancelBackground(caseId))}>Stop</button>`
      : html`
        <label class="muted" style="font-size:12px;display:flex;align-items:center;gap:6px">Budget
          <select value=${budget} onChange=${(e) => setBudget(+e.target.value)}>
            <option value="300">5 min</option><option value="600">10 min</option>
            <option value="1800">30 min</option><option value="7200">2 h</option>
          </select></label>
        <button class="btn primary sm" disabled=${busy || !targets.length}
          onClick=${() => act(() => api.startBackground(caseId, targets.map((t) => t.id), budget))}>
          Start analysis</button>`}
      ${err ? html`<span style="color:var(--amber-tx);font-size:12px">${err}</span>` : null}
    </div>`;
}

function RunScreen({ caseId, targets, ap, refreshAp }) {
  const recs = useCaseConsole(caseId);
  return html`
    <div style="display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:12px">
      <div style="display:flex;flex-direction:column;gap:2px">
        <h1>Run</h1>
        <span class="muted" style="font-size:13px">Everything the autopilot does, as it does it —
          every stage, every execution of the target, every tool, every fuzzing campaign.</span>
      </div>
      <${RunControls} caseId=${caseId} targets=${targets} ap=${ap} onChanged=${refreshAp} />
    </div>
    <${NowRunning} recs=${recs} />
    <${Console} recs=${recs} caseId=${caseId} targets=${targets} />
    <${FuzzWindows} recs=${recs} />`;
}

function EngagementScreen({ cases, caseId, setCaseId, targets, goRun }) {
  return html`
    <h1>Engagement</h1>
    <div class="panel" style="padding:14px 16px;display:flex;flex-wrap:wrap;gap:10px;align-items:center">
      <span class="muted">Case</span>
      <select value=${caseId || ""} onChange=${(e) => setCaseId(e.target.value)}>
        ${cases.map((c) => html`<option value=${c.id}>${c.name || c.id}</option>`)}
      </select>
      <span class="dim" style="font-size:12px">${targets.length} target(s)</span>
    </div>
    <div class="panel" style="overflow:hidden">
      ${targets.length ? targets.map((t) => html`
        <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:center;padding:12px 16px;border-top:1px solid var(--line)">
          <span class="mono" style="flex:1 1 260px;min-width:0;overflow:hidden;text-overflow:ellipsis">${t.filename || t.id}</span>
          <span class="dim" style="font-size:12px">${[t.arch, t.linking, t.stripped ? "stripped" : null].filter(Boolean).join(" · ")}</span>
          <button class="btn sm" onClick=${goRun}>Open run</button>
        </div>`) : html`<div class="empty">No targets in this case yet.</div>`}
    </div>`;
}

function App() {
  const [cases, setCases] = useState([]);
  const [caseId, setCaseIdRaw] = useState(() => new URLSearchParams(location.hash.slice(1)).get("case"));
  const [targets, setTargets] = useState([]);
  const [view, setView] = useState("run");
  const [ap, setAp] = useAutopilot(caseId);
  const setCaseId = (id) => { setCaseIdRaw(id); location.hash = `case=${id}`; };

  useEffect(() => {
    api.listCases().then((r) => {
      const cs = Array.isArray(r) ? r : (r.cases || []);
      setCases(cs);
      if (!caseId && cs.length) setCaseId(cs[cs.length - 1].id);
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (!caseId) return;
    api.listTargets(caseId).then((r) => setTargets(Array.isArray(r) ? r : (r.targets || []))).catch(() => setTargets([]));
  }, [caseId]);
  const refreshAp = () => api.backgroundStatus(caseId).then(setAp).catch(() => {});
  const cur = cases.find((c) => c.id === caseId);

  return html`
    <div class="shell">
      <header class="topbar">
        <div class="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#6EA8FE" stroke-width="2"
               stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 18 L10 6 L14 14 L20 4"></path><circle cx="20" cy="4" r="1.6"></circle></svg>
          lykos
        </div>
        ${cur ? html`<span class="chip">Case · ${cur.name || cur.id}</span>` : null}
        <div style="flex:1 1 auto"></div>
        <a class="chip" href="/">Current workbench</a>
      </header>
      <div class="body">
        <nav class="nav" aria-label="Workbench">
          <button class=${view === "engagement" ? "on" : ""} onClick=${() => setView("engagement")}>Engagement</button>
          <button class=${view === "run" ? "on" : ""} onClick=${() => setView("run")}>Run</button>
          <button disabled title="next screen to build" style="opacity:.45">Proof</button>
          <button disabled title="next screen to build" style="opacity:.45">Code</button>
          <div class="sep"></div>
          <span class="dim" style="font-size:11px;padding:0 13px;letter-spacing:.05em">TARGETS</span>
          ${targets.map((t) => html`<span class="tgt" style="padding:4px 13px" title=${t.filename}>${t.filename || t.id}</span>`)}
        </nav>
        <main class="main">
          ${!caseId ? html`<div class="empty">No case yet — create one in the current workbench.</div>`
            : view === "run" ? html`<${RunScreen} caseId=${caseId} targets=${targets} ap=${ap} refreshAp=${refreshAp} />`
            : html`<${EngagementScreen} cases=${cases} caseId=${caseId} setCaseId=${setCaseId}
                     targets=${targets} goRun=${() => setView("run")} />`}
        </main>
      </div>
    </div>`;
}

render(html`<${App} />`, document.getElementById("app"));
