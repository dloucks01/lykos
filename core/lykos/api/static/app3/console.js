// The Run screen's two live views over the run console records (jobs/runlog):
//   Console     -- a terminal of everything: stages, target executions, tools, notes, results
//   FuzzWindows -- one window per fuzzing technique (engine x stage), its live numbers + output
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";

const FILTERS = [
  ["all", "Everything", null],
  ["stages", "Stages", new Set(["stage", "done"])],
  ["runs", "Target runs", new Set(["run", "runs", "crash"])],
  ["tools", "Tools", new Set(["tool"])],
  ["crashes", "Crashes", new Set(["crash"])],
];
const KIND = { stage: "STAGE", run: "RUN", runs: "RUNS", tool: "TOOL", crash: "CRASH",
               note: "·", done: "DONE", fuzz: "FUZZ" };

function clock(t) {
  const d = new Date(t * 1000);
  return d.toTimeString().slice(0, 8) + "." + String(Math.floor((t % 1) * 10));
}
function n(v) { return v == null ? "—" : (typeof v === "number" ? v.toLocaleString() : String(v)); }
// Program output as a console line: printable text as-is (whitespace folded), mostly-binary
// output (an image decoder writing pixels to stdout) as a short marker, never a wall of glyphs.
function outText(label, s) {
  if (!s) return null;
  const bad = (s.match(/[\uFFFD\u0000-\u0008\u000E-\u001F]/g) || []).length;
  if (bad > s.length * 0.15) return `${label}: [binary output, ${s.length} chars shown of the tail]`;
  return `${label}: ` + s.replace(/\s+/g, " ").slice(0, 220);
}
function exitText(r) {
  if (r.sig) return r.sig;
  if (r.timeout) return "timeout";
  return r.rc == null ? "" : `exit ${r.rc}`;
}

// One record -> [main text, extra lines]
function lineOf(r) {
  switch (r.k) {
    case "stage":
      if (r.state === "start") {
        const p = r.params ? Object.entries(r.params).slice(0, 5).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(",") : v}`).join(" ") : "";
        return [`▶ ${r.stage} started${p ? "  " + p : ""}`, []];
      }
      return [`■ ${r.stage} ${r.outcome || "ended"}${r.secs != null ? ` · ${r.secs}s` : ""}`, []];
    case "run":
    case "crash": {
      const bits = [r.cmd, r.bytes != null ? `${r.bytes} B` : null, r.mode && r.mode !== "stdin" ? r.mode : null,
                    exitText(r), r.pc ? `pc ${r.pc}` : null, r.addr ? `addr ${r.addr}` : null,
                    r.ms != null ? `${r.ms} ms` : null, r.iso || null].filter(Boolean);
      const extra = [outText("stdout", r.out), outText("stderr", r.err)].filter(Boolean);
      return [bits.join("   "), extra];
    }
    case "runs": {
      const ex = Object.entries(r.exits || {}).map(([k, v]) => `${/^-?\d+$/.test(k) ? "exit " + k : k} ×${v}`).join(", ");
      return [`× ${r.n} executions   ${ex}   avg ${r.avg_ms} ms   last: ${r.last || ""}`, []];
    }
    case "tool": {
      const extra = [];
      if (r.out) extra.push(r.out.replace(/\s+/g, " ").slice(0, 220));
      if (r.err) extra.push("stderr: " + r.err.replace(/\s+/g, " ").slice(0, 220));
      return [`${r.cmd}   ${r.rc != null ? "rc " + r.rc : ""}   ${r.ms != null ? r.ms + " ms" : ""}`, extra];
    }
    case "done": return [`${r.event}: ${(r.summary || "").slice(0, 260)}`, []];
    case "fuzz": return [`${ENGINE[r.engine] || r.engine} finished · ${n(r.execs)} execs · ${n(r.crashes)} crashes${r.status ? " · " + r.status : ""}`, []];
    default: return [r.text || "", []];
  }
}

// How long a poll loop waits: quick while a run is live and the tab is in view, slow when nothing
// runs, slower still in a hidden tab (a background tab polling at 800 ms forever was the default).
export function pollDelay(liveMs, idleMs, running) {
  if (typeof document !== "undefined" && document.hidden) return Math.max(idleMs, 15000);
  return running ? liveMs : idleMs;
}

// Re-run `kick` as soon as the tab comes back into view (a poll loop waiting out its hidden delay).
export function useOnVisible(kick) {
  const ref = useRef(kick);
  ref.current = kick;
  useEffect(() => {
    const on = () => { if (!document.hidden && ref.current) ref.current(); };
    document.addEventListener("visibilitychange", on);
    return () => document.removeEventListener("visibilitychange", on);
  }, []);
}

// What is running NOW, from the server's plan (the console is a sliding window of records: a stage
// that started before it, or one that never logged an end, cannot be judged from it).
export function NowRunning({ recs, plan, running, now }) {
  const live = running ? (plan || []).filter((p) => p.state === "running") : [];
  const last = useMemo(() => {
    for (let i = recs.length - 1; i >= 0; i--) if (recs[i].k === "note") return recs[i];
    return null;
  }, [recs]);
  if (!live.length) return null;
  return html`
    <div class="now" role="status">
      <span style="font-size:11.5px;font-weight:700;letter-spacing:.06em;color:var(--blue-tx)">NOW RUNNING</span>
      ${live.map((p) => html`<span style="font-weight:600">${p.label || p.stage}
        ${p.started ? html`<span class="mono dim" style="font-size:11.5px;font-weight:400">${" "}since ${clock(p.started)}${now ? ` · ${fmtSecs(now - p.started)}` : ""}</span>` : null}</span>`)}
      ${last ? html`<span class="muted" style="flex:1 1 100%;font-size:13px">${last.stage}: ${last.text}</span>` : null}
    </div>`;
}

function fmtSecs(s) {
  if (s == null || !isFinite(s)) return "";
  s = Math.max(0, Math.round(s));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
  return h ? `${h}h ${String(m).padStart(2, "0")}m` : m ? `${m}m ${String(x).padStart(2, "0")}s` : `${x}s`;
}

const SHOWN_MAX = 1500;     // console rows in the DOM; the rest stay in memory / the download

export function Console({ recs, caseId, targets = [], stage: stageProp, setStage: setStageProp }) {
  const tname = useMemo(() => Object.fromEntries(targets.map((t) => [t.id, t.filename || t.id])), [targets]);
  const multi = targets.length > 1;
  const [filter, setFilter] = useState("all");
  const [follow, setFollow] = useState(true);
  const [stageLocal, setStageLocal] = useState("");
  const stage = stageProp !== undefined ? stageProp : stageLocal;
  const setStage = setStageProp || setStageLocal;
  const body = useRef(null);
  const set = FILTERS.find((f) => f[0] === filter)[2];
  const stages = useMemo(() => [...new Set(recs.filter((r) => r.k === "stage").map((r) => r.stage))], [recs]);
  const filtered = useMemo(() => recs.filter((r) =>
    (r.k !== "fuzz" || r.final) && (!set || set.has(r.k)) && (!stage || r.stage === stage)
  ).slice(-SHOWN_MAX), [recs, filter, stage]);
  // Reading back (follow off): freeze what is on screen, so new lines do not slide it away under
  // the reader. Following again (or changing the filter) picks the live view back up.
  const frozen = useRef(null);
  if (follow) frozen.current = null;
  else if (!frozen.current || frozen.current.key !== filter + "|" + stage) frozen.current = { key: filter + "|" + stage, rows: filtered };
  const shown = follow ? filtered : frozen.current.rows;
  const pending = follow ? 0 : Math.max(0, (filtered.length && shown.length
    ? filtered.length - filtered.findIndex((r) => r._i === shown[shown.length - 1]._i) - 1 : 0));
  useEffect(() => { if (follow && body.current) body.current.scrollTop = body.current.scrollHeight; }, [shown, follow]);
  // the WHOLE log from the server (this view only holds a recent window of it)
  const downloadUrl = `/cases/${caseId}/console?download=1`;
  return html`
    <section class="term" aria-label="Console">
      <div class="term-bar">
        <span style="font-weight:600;font-size:13px;margin-right:6px">Console</span>
        ${FILTERS.map(([k, label]) => html`<button class=${"tab" + (filter === k ? " on" : "")} aria-pressed=${filter === k} onClick=${() => setFilter(k)}>${label}</button>`)}
        <select value=${stage} onChange=${(e) => setStage(e.target.value)} style="padding:4px 8px;font-size:12px" aria-label="Show one stage">
          <option value="">all stages</option>
          ${(stage && !stages.includes(stage) ? [stage, ...stages] : stages).map((s) => html`<option value=${s}>${s}</option>`)}
        </select>
        <div style="flex:1 1 auto"></div>
        <span class="mono dim" style="font-size:11px">${recs.length.toLocaleString()} recent records${shown.length < recs.length ? ` · ${shown.length.toLocaleString()} shown` : ""} · routine executions sampled, crashes in full</span>
        <button class="btn sm" onClick=${() => setFollow(!follow)}>${follow ? "Pause scroll" : (pending ? `Follow (${pending.toLocaleString()} new)` : "Follow")}</button>
        <a class="btn sm" href=${downloadUrl} download=${`lykos-console-${caseId}.jsonl`} title="the whole console log of this case, as JSON lines">Download</a>
      </div>
      <div class="term-body" ref=${body}
           onScroll=${(e) => { const el = e.currentTarget; const atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
                               if (atEnd !== follow) setFollow(atEnd); }}>
        ${shown.length ? shown.map((r) => {
          const [text, extra] = lineOf(r);
          return html`<div key=${r._i}>
            <div class="ln"><span class="t">${clock(r.t)}</span><span class=${"k k-" + r.k}>${KIND[r.k] || r.k}</span>
              <span class="st">${r.stage}${multi && r.target ? html`<br /><span class="dim" style="font-size:10.5px">${(tname[r.target] || r.target).slice(0, 18)}</span>` : null}</span><span class=${r.k === "crash" ? "k-crash" : r.k === "stage" ? "k-stage" : ""}>${text}</span></div>
            ${extra.map((x) => html`<div class="ln x-out">${x}</div>`)}
          </div>`;
        }) : html`<div class="dim">${stage
          ? `No console output from ${stage} yet — it has not run in this case, or it was declined before starting.`
          : "Nothing yet. Start an analysis — every stage, execution and tool it runs appears here."}</div>`}
      </div>
    </section>`;
}

const SPARK = 24;
// the engine ids the server reports -> what a person calls the technique
const ENGINE = { fuzz: "Mutation fuzzing", directed: "Directed fuzzing", directed_fuzz: "Directed fuzzing",
                 env_fuzz: "Environment fuzzing", net_fuzz: "Network fuzzing", boundary_fuzz: "IPC boundary fuzzing",
                 session: "Session fuzzing", libfuzzer: "libFuzzer" };

export function FuzzWindows({ recs }) {
  const [now, setNow] = useState(Date.now() / 1000);
  const wins = useMemo(() => {
    const m = new Map();
    for (const r of recs) {
      if (r.k !== "fuzz") continue;
      const key = `${r.engine}|${r.stage}|${r.target || ""}`;
      let w = m.get(key);
      if (!w) { w = { key, engine: r.engine, stage: r.stage, hist: [] }; m.set(key, w); }
      w.last = r;
      w.hist.push(r.cov ?? r.execs ?? 0);
      if (w.hist.length > SPARK) w.hist.shift();
    }
    return [...m.values()].sort((a, b) => b.last.t - a.last.t);
  }, [recs]);
  // The 1 s clock that ages a window from "live" to finished runs only while some campaign could
  // still be live, and not in a hidden tab (it re-rendered every window every second, forever).
  const maybeLive = wins.some((w) => !w.last.final && Date.now() / 1000 - w.last.t < 30);
  useEffect(() => {
    if (!maybeLive) { setNow(Date.now() / 1000); return undefined; }
    const t = setInterval(() => { if (!document.hidden) setNow(Date.now() / 1000); }, 1000);
    return () => clearInterval(t);
  }, [maybeLive]);
  return html`
    <section style="display:flex;flex-direction:column;gap:10px" aria-label="Fuzzing techniques">
      <div style="display:flex;align-items:baseline;gap:12px">
        <h2>Fuzzing techniques</h2>
        <span class="muted" style="font-size:12.5px">one live window per campaign; finished ones keep their final numbers</span>
      </div>
      ${wins.length ? html`<div class="fgrid">${wins.map((w) => {
        const r = w.last;
        const live = !r.final && now - r.t < 6;
        const max = Math.max(1, ...w.hist);
        return html`<article class=${"win" + (live ? " live" : "")}>
          <div class="win-h">
            <span class=${"dot" + (live ? " live" : "")}></span>
            <span style="font-weight:600;font-size:13.5px">${ENGINE[w.engine] || w.engine}</span>
            <span class="mono dim" style="font-size:11px">${w.stage}</span>
            <span class="muted" style="margin-left:auto;font-size:11.5px">${live ? (r.status || "running") : (r.status || "done")}</span>
          </div>
          <div class="stats">
            <div class="stat"><b>${n(r.execs)}</b><span>execs</span></div>
            <div class="stat"><b>${n(r.eps)}</b><span>per sec</span></div>
            <div class="stat"><b>${n(r.cov)}</b><span>${r.cov_label || "coverage"}</span></div>
            <div class="stat"><b style=${r.crashes ? "color:var(--amber-tx)" : ""}>${n(r.crashes)}</b><span>${r.crash_label || "crashes"}</span></div>
          </div>
          <div class="spark" aria-hidden="true">${w.hist.map((v) => html`<i style=${`height:${Math.max(4, Math.round(100 * v / max))}%`}></i>`)}</div>
          <div class="win-out">${(r.out || []).map((o) => html`<div>${o}</div>`)}</div>
        </article>`;
      })}</div>` : html`<div class="panel empty">No fuzzing campaign has run in this case yet.</div>`}
    </section>`;
}

// The autopilot's plan as one strip: a cell per stage, coloured by its state; hover for the
// stage's own words, click to show only that stage in the console.
const PLAN_STYLE = {
  done: "background:#3A4F6E", running: "background:var(--blue);box-shadow:0 0 0 3px rgba(110,168,254,.25)",
  pending: "background:#232A35", declined: "background:transparent;border:1px solid #2E3541",
  skipped: "background:transparent;border:1px dashed #3A4352", error: "background:var(--amber)",
  timeout: "background:var(--amber)", cancelled: "background:#4A3F2A",
};
export function PlanStrip({ plan, stage, setStage, title }) {
  if (!plan || !plan.length) return null;
  const count = {};
  for (const p of plan) count[p.state] = (count[p.state] || 0) + 1;
  const order = ["running", "done", "pending", "declined", "skipped", "error", "timeout", "cancelled"];
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:9px">
    <div class="row-c" style="flex-wrap:wrap;gap:12px">
      <h2>${title || "Plan"}</h2>
      ${order.filter((k) => count[k]).map((k) => html`<span class="dim" style="font-size:12px">
        <span style=${"display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:-1px;" + (PLAN_STYLE[k] || "")}></span>${count[k]} ${k === "declined" ? "not applicable" : k}</span>`)}
      ${stage ? html`<button class="btn sm" style="margin-left:auto" onClick=${() => setStage("")}>Show all stages</button>` : null}
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:3px">
      ${plan.map((p) => html`<button aria-label=${`${p.label || p.stage}: ${p.state}`}
        title=${`${p.label || p.stage} — ${p.state}${p.detail ? ": " + p.detail : ""}`}
        onClick=${() => setStage(stage === p.stage ? "" : p.stage)}
        style=${"width:18px;height:18px;border-radius:3px;border:none;padding:0;cursor:pointer;"
          + (PLAN_STYLE[p.state] || PLAN_STYLE.pending) + (stage === p.stage ? ";outline:2px solid var(--tx);outline-offset:1px" : "")}></button>`)}
    </div>
  </section>`;
}

// The live run's progress line: which target of how many, the run's clock against its ceiling,
// the current target's phase and what is left of its slice, and Stop / Pause feedback. Reads only
// the autopilot status (GET /cases/{id}/autopilot).
export function RunProgress({ ap }) {
  if (!ap) return null;
  const b = (ap.budget && typeof ap.budget === "object") ? ap.budget : {};
  // whole-run clock against the whole-run ceiling (budget_seconds); `budget` is the CURRENT
  // target's slice, so its total must not be paired with the run's elapsed time
  const el = ap.now && ap.started ? ap.now - ap.started : null;
  const tot = ap.budget_seconds;
  const bits = [];
  if (ap.stopping) bits.push("stopping — finishing the current stage");
  else if (ap.paused) bits.push(ap.pause_waiting ? "paused between stages" : "pausing after the current stage");
  if (ap.targets > 1) bits.push(`target ${ap.target || 1} of ${ap.targets}${ap.target_name ? ` · ${ap.target_name}` : ""}`);
  else if (ap.target_name) bits.push(ap.target_name);
  if (el != null) bits.push(`${fmtSecs(el)}${tot ? ` of ${fmtSecs(tot)}` : ap.converge ? " · to convergence" : ""}`);
  if (b.phase) bits.push(`${b.phase} phase`);
  if (b.remaining != null && b.total) bits.push(`${fmtSecs(b.remaining)} left for this target`);
  return html`<span class="mono dim" style="font-size:12px" role="status">${bits.join(" · ")}</span>`;
}

// One row per target the run has FINISHED (status.per_target, written as each target ends): the
// plan strip is rebuilt for every target, so without this a finished multi-target run showed only
// its last target's plan.
const SUM_STATES = [["done", "done"], ["declined", "not applicable"], ["skipped", "skipped"],
                    ["error", "error"], ["timeout", "timeout"], ["slice-ended", "slice ended"], ["cancelled", "cancelled"]];
export function TargetSummary({ perTarget, running, onFocusTarget }) {
  const rows = Array.isArray(perTarget) ? perTarget : [];
  if (!rows.length) return null;
  return html`<section class="panel" style="overflow:hidden" aria-label="Targets finished in this run">
    <div class="pad" style="padding-bottom:6px;display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">
      <h2>${running ? "Targets finished so far" : "Every target in this run"}</h2>
      <span class="dim" style="font-size:12px">${rows.length} target${rows.length === 1 ? "" : "s"} · stages per state, time, and what each produced</span>
    </div>
    <div class="ts-t" role="table">
      <div class="ts-r head" role="row"><span>target</span><span>stages</span><span class="n">time</span>
        <span class="n">findings</span><span class="n">confirmed</span><span class="n">PoC-backed</span></div>
      ${rows.map((r) => {
        const st = r.stages || {};
        return html`<div class="ts-r" role="row" key=${r.target_id}>
          <span class="mono" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=${r.filename}>${onFocusTarget
            ? html`<button class="xref" style="color:var(--tx)" onClick=${() => onFocusTarget(r.target_id)}>${r.filename || r.target_id}</button>`
            : (r.filename || r.target_id)}</span>
          <span class="dim" style="font-size:12px">${SUM_STATES.filter(([k]) => st[k]).map(([k, l]) => `${st[k]} ${l}`).join(" · ") || "—"}${r.skipped_for_budget ? html`${" "}<b class="rs-amber" title="skipped because this target's budget was spent">(${r.skipped_for_budget} for budget)</b>` : null}</span>
          <span class="n mono" data-l="time">${fmtSecs(r.elapsed) || "—"}</span>
          <span class="n" data-l="findings">${r.findings ?? "—"}</span>
          <span class="n" data-l="confirmed">${r.confirmed ?? "—"}</span>
          <span class=${"n" + (r.poc_backed ? " ts-hi" : "")} data-l="PoC-backed">${r.poc_backed ?? "—"}</span>
        </div>`;
      })}
    </div>
  </section>`;
}
