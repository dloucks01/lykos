// Run history + run comparison, on the Run screen below "what this run did".
//   GET /cases/{id}/runs-history               the case's recorded autopilot runs (newest first) +
//                                              a synthetic "current state" entry built from the DB now
//   GET /autopilot-runs/compare?a=<id>&b=<id>  new / gone / changed findings A -> B (A and B may be
//                                              runs of DIFFERENT cases -- two cases of one tree)
// Records are durable (case store), so a server restart keeps them. Read-only; nothing here sends
// or shows a server path (sites are tree-relative or basenames).
// Exports: RunHistory.
import { useEffect, useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { getJSON } from "./data.js";

(function loadCss() {
  if (typeof document === "undefined" || document.querySelector('link[data-lykos-css="history"]')) return;
  const l = document.createElement("link");
  l.rel = "stylesheet";
  l.href = new URL("./history.css", import.meta.url).href;
  l.dataset.lykosCss = "history";
  document.head.appendChild(l);
})();

const PAGE = 50;
const OUTCOME = { done: "done", stopped: "stopped", error: "error", interrupted: "interrupted",
                  running: "running", current: "current state" };
const SUM_STATES = [["done", "done"], ["skipped", "skipped"], ["declined", "declined"], ["error", "error"],
                    ["timeout", "timed out"], ["slice-ended", "slice ended"], ["cancelled", "cancelled"]];

const fmtI = (n) => (n == null || isNaN(n) ? "—" : Number(n).toLocaleString());
function fmtSecs(s) {
  if (s == null || isNaN(s)) return "—";
  s = Math.max(0, Math.round(Number(s)));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60 ? ` ${s % 60}s` : ""}`;
  const m = Math.round((s % 3600) / 60);
  return `${Math.floor(s / 3600)}h${m ? ` ${m}m` : ""}`;
}
function when(t) {
  if (!t) return "—";
  return new Date(t * 1000).toLocaleString([], { year: "numeric", month: "short", day: "numeric",
                                                 hour: "2-digit", minute: "2-digit" });
}
const runLabel = (r) => (r.synthetic ? "Current state (now)"
  : `${when(r.started)} · ${OUTCOME[r.outcome] || r.outcome || "?"}${r.counts ? ` · ${fmtI(r.counts.distinct)} findings` : ""}`);
const duration = (r) => (r.started && r.ended ? r.ended - r.started : null);

function useRunsOf(caseId, key) {
  const [st, setSt] = useState({ cid: null, runs: null, err: null });
  useEffect(() => {
    if (!caseId) return undefined;
    let live = true;
    getJSON(`/cases/${encodeURIComponent(caseId)}/runs-history`)
      .then((r) => { if (live) setSt({ cid: caseId, runs: Array.isArray(r.runs) ? r.runs : [], err: null }); })
      .catch((e) => { if (live) setSt({ cid: caseId, runs: [], err: String(e.message || e) }); });
    return () => { live = false; };
  }, [caseId, key]);
  return st.cid === caseId ? st : { cid: caseId, runs: null, err: null };
}

function Outcome({ r }) {
  return html`<span class=${"rh-out o-" + (r.outcome || "")} title=${r.error || ""}>${OUTCOME[r.outcome] || r.outcome || "?"}${r.result && r.outcome === "done" ? ` · ${r.result}` : ""}</span>`;
}

function PerTarget({ r }) {
  const rows = r.per_target || [];
  const ov = r.overrides && Object.keys(r.overrides).length
    ? Object.entries(r.overrides).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(" ") : v}`).join(", ") : null;
  return html`<div class="rh-pt">
    <div class="rh-meta">
      <span>${fmtI((r.targets || []).length)} target${(r.targets || []).length === 1 ? "" : "s"} ${r.synthetic ? "in the case" : "handed"}</span>
      ${r.converge ? html`<span>to convergence</span>` : null}
      ${(r.skip_stages || []).length ? html`<span>stages off: <span class="mono">${r.skip_stages.join(", ")}</span></span>` : null}
      ${ov ? html`<span>options: <span class="mono">${ov}</span></span>` : null}
      ${r.counts ? html`<span>${fmtI(r.counts.findings)} findings (${fmtI(r.counts.distinct)} distinct)</span>` : null}
      ${r.target_errors ? html`<span class="rs-amber">${r.target_errors} target(s) failed</span>` : null}
      ${(r.targets_skipped_for_budget || []).length ? html`<span class="rs-amber">skipped for budget: ${r.targets_skipped_for_budget.join(", ")}</span>` : null}
      ${r.error ? html`<span class="rs-amber">error: ${r.error}</span>` : null}
    </div>
    ${rows.length ? html`<div role="table">
      <div class="ts-r head" role="row"><span>target</span><span>stages</span><span class="n">time</span>
        <span class="n">findings</span><span class="n">confirmed</span><span class="n">PoC-backed</span></div>
      ${rows.map((t, i) => {
        const st = t.stages || {};
        return html`<div class="ts-r" role="row" key=${t.filename || i}>
          <span class="mono" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=${t.filename}>${t.filename || "—"}</span>
          <span class="dim" style="font-size:12px">${SUM_STATES.filter(([k]) => st[k]).map(([k, l]) => `${st[k]} ${l}`).join(" · ") || "—"}${t.skipped_for_budget ? html`${" "}<b class="rs-amber">(${t.skipped_for_budget} for budget)</b>` : null}</span>
          <span class="n mono" data-l="time">${t.elapsed != null ? fmtSecs(t.elapsed) : "—"}</span>
          <span class="n" data-l="findings">${fmtI(t.findings)}</span>
          <span class="n" data-l="confirmed">${fmtI(t.confirmed)}</span>
          <span class=${"n" + (t.poc_backed ? " ts-hi" : "")} data-l="PoC-backed">${fmtI(t.poc_backed)}</span>
        </div>`;
      })}</div>`
      : html`<div class="dim" style="font-size:12.5px;padding:6px 0">${r.outcome === "running" ? "No target has finished yet." : "No per-target account was recorded for this run."}</div>`}
  </div>`;
}

function RunList({ runs, sel, pick }) {
  const [open, setOpen] = useState({});
  const isSel = (r, side) => sel[side] && sel[side].runId === r.run_id;
  return html`<div role="table" aria-label="Past runs of this case">
    <div class="rh-r head" role="row"><span></span><span>when</span><span>outcome</span><span class="n">budget</span>
      <span class="n">took</span><span class="n">targets</span><span class="n">findings</span><span class="n">confirmed</span>
      <span class="n">with PoC</span><span class="n">compare</span></div>
    ${runs.map((r) => {
      const c = r.counts || {};
      const pt = r.per_target || [];
      const nT = r.synthetic ? (r.targets || []).length : (pt.length || (r.targets || []).length);
      const o = !!open[r.run_id];
      return html`<div key=${r.run_id}>
        <div class=${"rh-r" + (isSel(r, "a") ? " sel-a" : "") + (isSel(r, "b") ? " sel-b" : "")} role="row">
          <button class="rh-tog" aria-expanded=${o} aria-label="per-target detail" disabled=${!pt.length && r.synthetic}
            onClick=${() => setOpen({ ...open, [r.run_id]: !o })}>${o ? "▾" : "▸"}</button>
          <span style="min-width:0">${r.synthetic ? html`<b>Current state</b>${" "}<span class="dim" style="font-size:12px">— the case's findings now</span>` : when(r.started)}</span>
          <span><${Outcome} r=${r} /></span>
          <span class="n m mono" data-l="budget">${r.synthetic ? "—" : r.budget_seconds ? fmtSecs(r.budget_seconds) : "default"}</span>
          <span class="n m mono" data-l="took">${fmtSecs(duration(r))}</span>
          <span class="n m" data-l="targets">${fmtI(nT)}</span>
          <span class="n m" data-l="findings" title=${c.findings != null ? `${c.findings} finding rows` : ""}>${fmtI(c.distinct)}</span>
          <span class="n m" data-l="confirmed">${fmtI(c.confirmed)}</span>
          <span class=${"n m" + (c.with_poc ? " ts-hi" : "")} data-l="with PoC">${fmtI(c.with_poc)}</span>
          <span class="rh-ab m">
            <button class=${isSel(r, "a") ? "on-a" : ""} title="compare FROM this run" onClick=${() => pick("a", r)}>A</button>
            <button class=${isSel(r, "b") ? "on-b" : ""} title="compare TO this run" onClick=${() => pick("b", r)}>B</button>
          </span>
        </div>
        ${o ? html`<${PerTarget} r=${r} />` : null}
      </div>`;
    })}
  </div>`;
}

function SidePicker({ side, label, cases, sel, setSel, refreshKey }) {
  const cid = sel ? sel.caseId : "";
  const runs = useRunsOf(cid, refreshKey);
  // a case picked without a run: take its newest entry (the recorded run, else the current state)
  useEffect(() => {
    if (sel && !sel.runId && runs.runs && runs.runs.length) setSel({ caseId: cid, runId: runs.runs[0].run_id });
  }, [runs.runs, sel && sel.runId]);
  return html`<fieldset class=${side}>
    <legend>${label}</legend>
    <select aria-label=${`${label}: case`} value=${cid} onChange=${(e) => setSel(e.target.value ? { caseId: e.target.value, runId: null } : null)}>
      <option value="">choose a case…</option>
      ${cases.map((c) => html`<option value=${c.id}>${c.name || c.id}</option>`)}
    </select>
    <select aria-label=${`${label}: run`} value=${(sel && sel.runId) || ""} disabled=${!cid || !runs.runs}
      onChange=${(e) => setSel({ caseId: cid, runId: e.target.value || null })}>
      ${!runs.runs ? html`<option value="">loading…</option>` : null}
      ${(runs.runs || []).map((r) => html`<option value=${r.run_id}>${runLabel(r)}</option>`)}
    </select>
  </fieldset>`;
}

function StateLvl({ s, l }) {
  return html`<span><span class=${"rh-st s-" + (s || "")}>${s || "—"}</span>${l ? html`${" "}<span class="lvl">${l}</span>` : null}</span>`;
}

function FindingRows({ items, kind, linkCase, caseId, onOpenFinding }) {
  const [n, setN] = useState(PAGE);
  useEffect(() => setN(PAGE), [items]);
  if (!items.length) return html`<div class="rh-note dim">Nothing ${kind === "new" ? "new in B" : kind === "gone" ? "gone from A" : "changed"}.</div>`;
  const canOpen = onOpenFinding && linkCase === caseId;
  return html`<div role="table">
    <div class="rh-f head" role="row"><span>CWE</span><span>site</span><span>finding</span>
      <span class="st">${kind === "changed" ? "A → B" : kind === "gone" ? "in A" : "in B"}</span></div>
    ${items.slice(0, n).map((e) => html`<div class="rh-f" role="row" key=${e.key}>
      <span class="mono" style="font-size:12px">${e.cwe || "—"}</span>
      <span class="site" title=${e.site || ""}>${e.site || ((e.targets || []).length ? html`<span class="dim">in ${e.targets.join(", ")}</span>` : "—")}</span>
      <span class="ttl" title=${`${e.title || ""}${e.detector ? ` · ${e.detector}` : ""}${e.n > 1 ? ` · ${e.n} rows` : ""}${(e.targets || []).length ? ` · ${e.targets.join(", ")}` : ""}`}>${canOpen && e.fid
        ? html`<button class="rh-link" onClick=${() => onOpenFinding(e.fid)}>${e.title || e.key}</button>`
        : (e.title || e.key)}${e.n > 1 ? html`${" "}<span class="dim" style="font-size:11.5px">×${e.n}</span>` : null}</span>
      <span class="st">${kind === "changed"
        ? html`<${StateLvl} s=${e.from.state} l=${e.from.level} /><span class=${"rh-arrow " + e.direction}>${e.direction === "up" ? "▲" : "▼"}</span><${StateLvl} s=${e.to.state} l=${e.to.level} />`
        : html`<${StateLvl} s=${e.state} l=${e.level} />`}</span>
    </div>`)}
    ${items.length > n ? html`<div class="rh-more"><button class="rh-link" onClick=${() => setN(n + PAGE)}>Show ${Math.min(PAGE, items.length - n)} more</button>
      <span class="dim">${" "}of ${fmtI(items.length - n)} not shown</span></div>` : null}
  </div>`;
}

function CompareResult({ a, b, caseId, onOpenFinding }) {
  const [res, setRes] = useState({ key: null, d: null, err: null });
  const [tab, setTab] = useState("new");
  const [q, setQ] = useState("");
  const key = `${a.runId}|${b.runId}`;
  useEffect(() => {
    let live = true;
    setRes({ key, d: null, err: null });
    getJSON(`/autopilot-runs/compare?a=${encodeURIComponent(a.runId)}&b=${encodeURIComponent(b.runId)}`)
      .then((d) => { if (live) setRes({ key, d, err: null }); })
      .catch((e) => { if (live) setRes({ key, d: null, err: String(e.message || e) }); });
    return () => { live = false; };
  }, [key]);
  const d = res.key === key ? res.d : null;
  const items = useMemo(() => {
    if (!d) return [];
    const all = d[tab] || [];
    const s = q.trim().toLowerCase();
    if (!s) return all;
    return all.filter((e) => [e.cwe, e.site, e.title, e.detector, (e.targets || []).join(" ")]
      .some((x) => x && String(x).toLowerCase().includes(s)));
  }, [d, tab, q]);
  if (res.err && res.key === key) return html`<div class="rh-note rs-amber">Comparison failed: ${res.err}</div>`;
  if (!d) return html`<div class="rh-note dim">Comparing…</div>`;
  const sm = d.summary || {};
  const side = (h) => `${h.case_name || h.case_id}${h.synthetic ? " · current state" : ` · ${when(h.started)}`}`;
  const ca = (d.a && d.a.counts) || {}, cb = (d.b && d.b.counts) || {};
  const trunc = d.truncated && d.truncated[tab];
  const KPI = (k, label, n, extra) => html`<button class=${`rh-kpi k-${k}` + (tab === k ? " on" : "")} aria-pressed=${tab === k}
      onClick=${() => setTab(k)}><b>${fmtI(n)}</b><span>${label}${extra || ""}</span></button>`;
  const ptd = (d.per_target_delta || []).filter((r) => r.delta && (r.delta.findings || r.delta.confirmed || r.delta.poc_backed || !r.a || !r.b));
  const sgn = (v) => (v > 0 ? `+${v}` : v < 0 ? `${v}` : "0");
  return html`<div>
    <div class="rh-meta" style="padding:0 16px 10px">
      <span><b style="color:var(--violet)">A</b>${" "}${side(d.a)} — ${fmtI(ca.distinct)} distinct findings, ${fmtI(ca.confirmed)} confirmed, ${fmtI(ca.with_poc)} with a PoC</span>
      <span><b style="color:var(--blue-tx)">B</b>${" "}${side(d.b)} — ${fmtI(cb.distinct)} distinct findings, ${fmtI(cb.confirmed)} confirmed, ${fmtI(cb.with_poc)} with a PoC</span>
    </div>
    <div class="rh-sum" role="group" aria-label="What changed from A to B">
      ${KPI("new", "new in B", sm.new)}
      ${KPI("gone", "gone from A", sm.gone)}
      ${KPI("changed", "changed", sm.changed, sm.changed ? ` (▲${sm.up} ▼${sm.down})` : "")}
      <div class="rh-kpi static"><b>${fmtI(sm.same)}</b><span>unchanged</span></div>
      <label class="field" style="margin-left:auto;flex:0 1 260px">Filter
        <input type="search" placeholder="CWE, file, title, target…" value=${q} onInput=${(e) => setQ(e.target.value)} /></label>
    </div>
    <${FindingRows} items=${items} kind=${tab} caseId=${caseId} onOpenFinding=${onOpenFinding}
      linkCase=${tab === "gone" ? d.a.case_id : d.b.case_id} />
    ${trunc ? html`<div class="rh-more dim">${fmtI(trunc)} more not returned by the server.</div>` : null}
    ${ptd.length ? html`<details class="rh-sec" style="border-top:1px solid var(--line)">
      <summary class="pad" style="cursor:pointer;font-weight:600;font-size:13px">Per-target change <span class="dim" style="font-weight:400">— ${ptd.length} target${ptd.length === 1 ? "" : "s"}, matched by filename</span></summary>
      <div role="table">
        <div class="ts-r head" role="row"><span>target</span><span>in</span><span class="n">findings</span>
          <span class="n">Δ findings</span><span class="n">Δ confirmed</span><span class="n">Δ PoC-backed</span></div>
        ${ptd.map((r) => html`<div class="ts-r" role="row" key=${r.filename}>
          <span class="mono" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=${r.filename}>${r.filename}</span>
          <span class="dim" style="font-size:12px">${r.a && r.b ? "A and B" : r.a ? "A only" : "B only"}</span>
          <span class="n" data-l="findings">${fmtI(r.a ? r.a.findings : null)} → ${fmtI(r.b ? r.b.findings : null)}</span>
          <span class="n mono" data-l="Δ findings">${sgn(r.delta.findings)}</span>
          <span class="n mono" data-l="Δ confirmed">${sgn(r.delta.confirmed)}</span>
          <span class=${"n mono" + (r.delta.poc_backed > 0 ? " ts-hi" : "")} data-l="Δ PoC-backed">${sgn(r.delta.poc_backed)}</span>
        </div>`)}
      </div></details>` : null}
  </div>`;
}

export function RunHistory({ caseId, running, onOpenFinding }) {
  const [tick, setTick] = useState(0);
  const rkey = `${tick}|${running ? 1 : 0}`;
  const mine = useRunsOf(caseId, rkey);
  const [cases, setCases] = useState([]);
  const [sel, setSelState] = useState({ for: null, a: null, b: null });
  useEffect(() => {
    api.listCases().then((x) => setCases(Array.isArray(x) ? x : (x.cases || []))).catch(() => {});
  }, [caseId]);
  // default: B = this case's newest entry, A = the one before it (a case with one entry leaves A
  // for the operator to pick -- e.g. another case of the same tree)
  useEffect(() => {
    if (!mine.runs || sel.for === caseId) return;
    const rs = mine.runs;
    setSelState({ for: caseId, b: rs[0] ? { caseId, runId: rs[0].run_id } : null,
                  a: rs[1] ? { caseId, runId: rs[1].run_id } : null });
  }, [mine.runs, caseId]);
  const setSide = (side) => (v) => setSelState((o) => ({ ...o, [side]: v }));
  const pick = (side, r) => setSide(side)({ caseId: r.case_id || caseId, runId: r.run_id });
  const runs = mine.runs || [];
  const recorded = runs.filter((r) => !r.synthetic).length;
  const ready = sel.a && sel.a.runId && sel.b && sel.b.runId && sel.a.runId !== sel.b.runId;
  return html`<div class="rh">
    <section class="panel rh-sec" aria-label="Run history">
      <div class="rh-h">
        <h2>Run history</h2><span class="rh-n">${recorded}</span>
        <span class="dim" style="font-size:12px">every autopilot run of this case, kept across server restarts</span>
        <button class="btn sm r" onClick=${() => setTick((x) => x + 1)}>Refresh</button>
      </div>
      ${mine.err ? html`<div class="rh-note rs-amber">The run history could not be read: ${mine.err}</div>` : null}
      ${!mine.runs ? html`<div class="rh-note dim">Loading…</div>`
        : html`${!recorded ? html`<div class="rh-note dim">No run of this case has been recorded yet (runs are recorded from now on);
            the current state below still compares against any other case.</div>` : null}
          <${RunList} runs=${runs} sel=${sel} pick=${pick} />`}
    </section>
    <section class="panel rh-sec" aria-label="Compare two runs">
      <div class="rh-h"><h2>Compare runs</h2>
        <span class="dim" style="font-size:12px">what is new, gone or changed from A to B — B may be a run of another case of the same tree; findings are matched by CWE and source site (file:line), not by target id</span></div>
      <div class="rh-pick">
        <${SidePicker} side="a" label="A — from" cases=${cases} sel=${sel.a} setSel=${setSide("a")} refreshKey=${rkey} />
        <${SidePicker} side="b" label="B — to" cases=${cases} sel=${sel.b} setSel=${setSide("b")} refreshKey=${rkey} />
      </div>
      ${ready ? html`<${CompareResult} a=${sel.a} b=${sel.b} caseId=${caseId} onOpenFinding=${onOpenFinding} />`
        : html`<div class="rh-note dim">${sel.a && sel.b && sel.a.runId && sel.a.runId === sel.b.runId
          ? "A and B are the same run — pick a different one for either side."
          : "Pick a run for A and for B (the A / B buttons in the list above, or a case and run here)."}</div>`}
    </section>
  </div>`;
}
