// The redesigned workbench (next.html). Built screen by screen against the design canvas; the
// existing GUI (index.html) stays the default until this one covers what it does.
// Screen 1 here: Run -- the live console of everything the autopilot does + one window per
// fuzzing technique, fed by GET /cases/{id}/console (jobs/runlog on the server).
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { CodeScreen } from "./code.js";
import { Console, FuzzWindows, NowRunning, PlanStrip } from "./console.js";
import { startSettings, useCaseData } from "./data.js";
import { Lazy, useModule } from "./lazy.js";
import { EngagementScreen } from "./engagement.js";
import { FindingDetail, ProofScreen } from "./proof.js";

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
  const [opts, setOpts] = useState({});
  const [showOpts, setShowOpts] = useState(false);
  const settingsMod = useModule("./results.js");
  useEffect(() => { if (settingsMod && settingsMod.loadRunOptions) setOpts(settingsMod.loadRunOptions()); }, [settingsMod]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const running = ap && (ap.running || ap.state === "running");
  const paused = ap && (ap.paused || ap.state === "paused");
  const act = async (fn) => {
    setBusy(true); setErr(null);
    try { await fn(); onChanged && onChanged(); } catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };
  return html`<div>
    <div style="display:flex;flex-wrap:wrap;align-items:center;gap:10px;justify-content:flex-end">
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
        <button class="btn sm" onClick=${() => setShowOpts(!showOpts)} aria-expanded=${showOpts}>Options${showOpts ? " ▴" : " ▾"}</button>
        <button class="btn primary sm" disabled=${busy || !targets.length}
          onClick=${() => act(async () => api.startBackground(caseId, targets.map((t) => t.id), budget,
            ...(await startSettings(settingsMod, opts, caseId))))}>
          Start analysis</button>`}
      ${err ? html`<span style="color:var(--amber-tx);font-size:12px">${err}</span>` : null}
    </div>
    ${showOpts && !running ? html`<div class="panel pad" style="margin-top:10px">
      <${Lazy} path="./results.js" name="RunOptions" props=${{ value: opts, onChange: setOpts, caseId }}
        fallback=${html`<span class="dim">Run options are not available.</span>`} /></div>` : null}
  </div>`;
}

function RunScreen({ caseId, targets, ap, refreshAp, go }) {
  const recs = useCaseConsole(caseId);
  const [stage, setStage] = useState("");
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
    <${PlanStrip} plan=${ap && ap.plan} stage=${stage} setStage=${setStage} />
    <${Console} recs=${recs} caseId=${caseId} targets=${targets} stage=${stage} setStage=${setStage} />
    <${FuzzWindows} recs=${recs} />
    <details class="panel" style="padding:0">
      <summary class="pad" style="cursor:pointer;font-weight:600">Drive a target by hand <span class="dim" style="font-weight:400;font-size:12px">— interactive sandboxed console</span></summary>
      <div style="padding:0 0 2px"><${Lazy} path="./interact.js" name="InteractiveConsole" props=${{ targets }} /></div>
    </details>
    <${Lazy} path="./results.js" name="RunResults" fallback=${html``}
      props=${{ caseId, ap, targets, running: !!(ap && (ap.running || ap.state === "running")),
                onOpenStage: (st) => { setStage(st); window.scrollTo({ top: 0, behavior: "smooth" }); },
                onOpenFinding: go ? (id) => go("finding", { findingId: id }) : undefined,
                onFocusTarget: go ? (tid) => go("proof", { targetId: targets.some((t) => t.id === tid) ? tid : null }) : undefined }} />`;
}

const NAV = [["engagement", "Engagement"], ["run", "Run"], ["proof", "Proof"], ["code", "Code"], ["system", "System"]];

function readHash() {
  const h = new URLSearchParams(location.hash.slice(1));
  return { caseId: h.get("case"), view: h.get("view") || "run", targetId: h.get("target"),
           findingId: h.get("finding"), addr: h.get("addr") };
}

function App() {
  const [cases, setCases] = useState([]);
  const [r, setR] = useState(readHash);              // route: case, view, target, finding, addr
  const [refresh, setRefresh] = useState(0);
  const go = (view, extra = {}) => setR((o) => ({ ...o, view, findingId: null, addr: null, ...extra }));
  const setCaseId = (id) => setR({ caseId: id, view: "engagement", targetId: null, findingId: null, addr: null });
  useEffect(() => {
    const h = new URLSearchParams();
    for (const k of ["caseId", "view", "targetId", "findingId", "addr"]) {
      if (r[k]) h.set({ caseId: "case", targetId: "target", findingId: "finding" }[k] || k, r[k]);
    }
    history.replaceState(null, "", "#" + h.toString());
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
  const reloadCases = () => api.listCases().then((x) => {
    const cs = Array.isArray(x) ? x : (x.cases || []);
    setCases(cs);
    return cs;
  }).catch(() => []);
  // first load with no case in the URL: pick the newest case, KEEP the requested view
  useEffect(() => { reloadCases().then((cs) => { if (!caseId && cs.length) setR((o) => ({ ...o, caseId: cs[cs.length - 1].id })); }); }, []);
  const refreshAp = () => api.backgroundStatus(caseId).then(setAp).catch(() => {});
  const cur = cases.find((c) => c.id === caseId);
  const [version, setVersion] = useState(null);
  useEffect(() => { api.version().then((v) => setVersion(v ? (v.display || [v.version, v.short].filter(Boolean).join(" · ")) : null)).catch(() => {}); }, []);
  const proven = data.findings.filter((f) => f.state === "poc-backed").length;
  const navOn = r.view === "finding" ? "proof" : r.view;

  let body;
  if (!caseId) body = html`<div class="empty">No case yet.
      <${EngagementScreen} cases=${cases} caseId=${null} setCaseId=${setCaseId} data=${data} go=${go} reloadCases=${reloadCases} /></div>`;
  else if (r.view === "run") body = html`<${RunScreen} caseId=${caseId} targets=${data.targets} ap=${ap} refreshAp=${refreshAp} go=${go} />`;
  else if (r.view === "proof") body = html`<${ProofScreen} data=${data} targetId=${r.targetId}
      open=${(id) => go("finding", { findingId: id })} focusTarget=${(t) => setR((o) => ({ ...o, targetId: t }))}
      toCode=${(t, addr) => go("code", { targetId: t, addr })} />`;
  else if (r.view === "finding") body = html`<${FindingDetail} data=${data} findingId=${r.findingId}
      back=${() => go("proof")} toCode=${(t, addr) => go("code", { targetId: t, addr })}
      open=${(id) => go("finding", { findingId: id })} />`;
  else if (r.view === "code") body = html`<${CodeScreen} data=${data} targetId=${r.targetId} focusAddr=${r.addr}
      focusTarget=${(t) => go("code", { targetId: t })} openFinding=${(id) => go("finding", { findingId: id })} />`;
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
