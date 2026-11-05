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
      const extra = [];
      if (r.out) extra.push("stdout: " + r.out.replace(/\s+/g, " ").slice(0, 220));
      if (r.err) extra.push("stderr: " + r.err.replace(/\s+/g, " ").slice(0, 220));
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

export function NowRunning({ recs }) {
  const live = useMemo(() => {
    const open = new Map();
    for (const r of recs) {
      if (r.k !== "stage") continue;
      const key = r.run || r.stage;
      if (r.state === "start") open.set(key, r); else open.delete(key);
    }
    return [...open.values()];
  }, [recs]);
  const last = useMemo(() => {
    for (let i = recs.length - 1; i >= 0; i--) if (recs[i].k === "note") return recs[i];
    return null;
  }, [recs]);
  if (!live.length) return null;
  return html`
    <div class="now">
      <span style="font-size:11.5px;font-weight:700;letter-spacing:.06em;color:var(--blue-tx)">NOW RUNNING</span>
      ${live.map((r) => html`<span style="font-weight:600">${r.stage}
        <span class="mono dim" style="font-size:11.5px;font-weight:400"> since ${clock(r.t)}</span></span>`)}
      ${last ? html`<span class="muted" style="flex:1 1 100%;font-size:13px">${last.stage}: ${last.text}</span>` : null}
    </div>`;
}

export function Console({ recs, caseId }) {
  const [filter, setFilter] = useState("all");
  const [follow, setFollow] = useState(true);
  const [stage, setStage] = useState("");
  const body = useRef(null);
  const set = FILTERS.find((f) => f[0] === filter)[2];
  const stages = useMemo(() => [...new Set(recs.filter((r) => r.k === "stage").map((r) => r.stage))], [recs]);
  const shown = useMemo(() => recs.filter((r) =>
    (r.k !== "fuzz" || r.final) && (!set || set.has(r.k)) && (!stage || r.stage === stage)
  ).slice(-3000), [recs, filter, stage]);
  useEffect(() => { if (follow && body.current) body.current.scrollTop = body.current.scrollHeight; }, [shown, follow]);
  const download = () => {
    const blob = new Blob([recs.map((r) => JSON.stringify(r)).join("\n") + "\n"], { type: "application/x-ndjson" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `lykos-console-${caseId}.jsonl`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  };
  return html`
    <section class="term" aria-label="Console">
      <div class="term-bar">
        <span style="font-weight:600;font-size:13px;margin-right:6px">Console</span>
        ${FILTERS.map(([k, label]) => html`<button class=${"tab" + (filter === k ? " on" : "")} onClick=${() => setFilter(k)}>${label}</button>`)}
        <select value=${stage} onChange=${(e) => setStage(e.target.value)} style="padding:4px 8px;font-size:12px">
          <option value="">all stages</option>
          ${stages.map((s) => html`<option value=${s}>${s}</option>`)}
        </select>
        <div style="flex:1 1 auto"></div>
        <span class="mono dim" style="font-size:11px">${recs.length.toLocaleString()} records · routine executions sampled, crashes in full</span>
        <button class="btn sm" onClick=${() => setFollow(!follow)}>${follow ? "Pause scroll" : "Follow"}</button>
        <button class="btn sm" onClick=${download} disabled=${!recs.length}>Download</button>
      </div>
      <div class="term-body" ref=${body}
           onScroll=${(e) => { const el = e.currentTarget; const atEnd = el.scrollHeight - el.scrollTop - el.clientHeight < 30;
                               if (atEnd !== follow) setFollow(atEnd); }}>
        ${shown.length ? shown.map((r) => {
          const [text, extra] = lineOf(r);
          return html`<div>
            <div class="ln"><span class="t">${clock(r.t)}</span><span class=${"k k-" + r.k}>${KIND[r.k] || r.k}</span>
              <span class="st">${r.stage}</span><span class=${r.k === "crash" ? "k-crash" : r.k === "stage" ? "k-stage" : ""}>${text}</span></div>
            ${extra.map((x) => html`<div class="ln x-out">${x}</div>`)}
          </div>`;
        }) : html`<div class="dim">Nothing yet. Start an analysis — every stage, execution and tool it runs appears here.</div>`}
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
  useEffect(() => { const t = setInterval(() => setNow(Date.now() / 1000), 1000); return () => clearInterval(t); }, []);
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
