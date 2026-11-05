// "What this run did": the panels below the live console on the Run screen. Everything here is
// read from the server's event-log-backed views, so a reopened case or a CLI-produced case shows
// the same account as a live one:
//   GET /cases/{id}/scorecard     per target: executions, capabilities worked/declined, budget, PoCs,
//                                 and fuzz_health (which engines ran / were skipped / failed, and why)
//   GET /cases/{id}/run-signals   honesty signals (failed target, degraded sandbox, capped crashes...)
//   GET /cases/{id}/timing        time and yield per technique
//   GET /cases/{id}/coverage      the coverage ledger (checks run, weaponization, code exercised, CWEs)
//   GET /cases/{id}/attempt-logs  per-attempt fuzz logs; GET /artifacts/{sha}/attempts pages one
//   GET/POST/DELETE /cases/{id}/seeds   operator seed files (the CLI's --seed)
// Exports: RunResults, RunOptions, buildRunSettings, DEFAULT_RUN_OPTIONS, loadRunOptions,
//          saveRunOptions, SeedsField, AttemptLogModal.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { fmtElapsed, operatorSettings, runSignalChips } from "../app/util.js";

(function loadCss() {
  if (typeof document === "undefined" || document.querySelector('link[data-lykos-css="results"]')) return;
  const l = document.createElement("link");
  l.rel = "stylesheet";
  l.href = new URL("./results.css", import.meta.url).href;
  l.dataset.lykosCss = "results";
  document.head.appendChild(l);
})();

const POLL_MS = 8000;

// ---- formatting -------------------------------------------------------------------------------
function fmtN(n) {
  if (n == null || isNaN(n)) return "—";
  n = Number(n);
  if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(1)}k`;
  return Math.round(n).toLocaleString();
}
const fmtI = (n) => (n == null || isNaN(n) ? "—" : Number(n).toLocaleString());
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;
const clock = (t) => (t ? new Date(t * 1000).toLocaleTimeString() : "");

// The engine ids the server reports -> what a person calls the technique.
export const ENGINE_LABEL = {
  coverage_fuzz: "Coverage-guided (AFL++)", coverage: "Coverage-guided (AFL++)", fuzz: "Black-box fuzzing",
  directed_fuzz: "Sink-directed fuzzing", directed: "Sink-directed fuzzing", net_fuzz: "Network / socket fuzzing",
  boundary_fuzz: "IPC boundary fuzzing", env_fuzz: "Environment fuzzing", libfuzzer: "libFuzzer (source)",
  concolic: "Concolic solver", harness: "Emulated function harness", session: "Session fuzzing",
};
const engineName = (e) => ENGINE_LABEL[e] || e;

// fuzz/health.py status -> label + tone. "ran" vs "nothing ran" is kept explicit below.
const HEALTH = {
  ok: ["ran", "ok"], failed: ["FAILED", "bad"], error: ["error", "bad"], noprogress: ["no progress", "warn"],
  starved: ["starved", "warn"], no_gain: ["no gain", "warn"], stalled: ["stalled", "warn"],
  declined: ["not applicable", "mute"], skipped: ["skipped", "mute"], not_run: ["not run", "mute"],
};

// fuzz/attempts.py outcomes
const OUTCOMES = [
  ["clean_exit", "ran clean"], ["error_exit", "error exit"], ["timeout", "timeout"],
  ["crash", "crash"], ["no_start", "never reached the program"],
];
const OUTCOME_LABEL = Object.fromEntries(OUTCOMES);
const PHASES = ["seed", "mutate", "minimize", "reproduce", "confirm", "afl-seed", "afl-queue", "afl-crash", "afl-hang"];

export function OutcomeBar({ counts, legend = true }) {
  const c = counts || {};
  const total = OUTCOMES.reduce((a, [k]) => a + (Number(c[k]) || 0), 0);
  if (!total) return null;
  const parts = OUTCOMES.filter(([k]) => Number(c[k]) > 0);
  return html`<span class="rs-ob">
    <span class="rs-ob-bar" role="img" aria-label=${parts.map(([k, l]) => `${l} ${c[k]}`).join(", ")}>
      ${parts.map(([k, l]) => html`<i class=${"o-" + k} title=${`${l}: ${fmtI(c[k])} (${Math.round(100 * c[k] / total)}%)`}
        style=${`width:${Math.max(1.5, 100 * c[k] / total)}%`}></i>`)}
    </span>
    ${legend ? html`<span class="rs-ob-legend">${parts.map(([k, l]) => html`<span><i class=${"o-" + k}></i>${l} ${Math.round(100 * c[k] / total)}%</span>`)}</span>` : null}
  </span>`;
}

function Bar({ pct, tone }) {
  const w = pct == null ? 0 : Math.max(pct > 0 ? 2 : 0, Math.min(100, pct));
  return html`<span class=${"rs-bar" + (tone ? " " + tone : "")}><i style=${`width:${w}%`}></i></span>`;
}

function Section({ title, sub, right, children, id }) {
  return html`<section class="panel rs-sec" id=${id}>
    <div class="rs-sec-h"><h2>${title}</h2>${sub ? html`<span class="dim rs-sec-sub">${sub}</span>` : null}
      ${right ? html`<span class="rs-sec-r">${right}</span>` : null}</div>
    ${children}
  </section>`;
}

function Fold({ label, n, children, open = false }) {
  return html`<details class="rs-fold" open=${open}>
    <summary>${label}${n != null ? html` <span class="rs-n">${n}</span>` : null}</summary>
    <div class="rs-fold-b">${children}</div>
  </details>`;
}

// ---- data -------------------------------------------------------------------------------------
const SOURCES = [
  ["scorecard", (c) => api.scorecard(c)],
  ["signals", (c) => api.runSignals(c)],
  ["timing", (c) => api.timing(c)],
  ["ledger", (c) => api.coverage(c)],
  ["logs", (c) => api.attemptLogs(c)],
  ["seeds", (c) => api.seeds(c)],
];

// Every results view for a case: polled while `running`, read once more when it stops.
function useRunResults(caseId, running) {
  const [st, setSt] = useState({ caseId: null });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!caseId) return undefined;
    let stop = false, timer = null;
    const load = async () => {
      const res = await Promise.allSettled(SOURCES.map(([, f]) => f(caseId)));
      if (stop) return;
      setSt((o) => {
        const n = { ...(o.caseId === caseId ? o : {}), caseId, at: Date.now() / 1000, err: {} };
        SOURCES.forEach(([k], i) => {
          const r = res[i];
          if (r.status === "fulfilled") n[k] = r.value;
          else n.err[k] = String((r.reason && r.reason.message) || r.reason);
        });
        return n;
      });
      if (running && !stop) timer = setTimeout(load, POLL_MS);
    };
    load();
    return () => { stop = true; clearTimeout(timer); };
  }, [caseId, running, tick]);
  const d = st.caseId === caseId ? st : { err: {} };
  return [d, () => setTick((x) => x + 1)];
}

// ---- honesty signals --------------------------------------------------------------------------
function SignalsStrip({ signals, ap, targets, err }) {
  const chips = runSignalChips(signals, ap, targets);
  if (err && !signals) return html`<div class="rs-sig rs-sig-warn"><span class="rs-sig-lbl">run signals</span>
    <span class="muted">could not be read: ${err}</span></div>`;
  if (!signals) return null;
  if (!chips.length) {
    return html`<div class="rs-sig rs-sig-ok"><span class="rs-sig-lbl">run signals</span>
      <span class="muted">none raised — no failed target, degraded sandbox, partial recovery, capped crash list,
        hang or unopened startup gate${signals.window && signals.window.running ? " so far" : ""}.</span></div>`;
  }
  const worst = chips.some((c) => c.tone === "bad") ? "bad" : chips.some((c) => c.tone === "warn") ? "warn" : "info";
  return html`<details class=${"rs-sig rs-sig-" + worst}>
    <summary><span class="rs-sig-lbl">run signals</span>
      ${chips.map((c) => html`<span key=${c.key} class=${"rs-sig-chip t-" + c.tone} title=${(c.detail || []).join("\n")}>${c.label}</span>`)}
      <span class="rs-sig-more">why</span></summary>
    <ul class="rs-sig-d">${chips.flatMap((c) => (c.detail || []).map((d, i) => html`<li key=${c.key + i} class=${"t-" + c.tone}>${d}</li>`))}</ul>
  </details>`;
}

// When no dynamic engine executed the target the result is static-only: say so, and that the
// deterministic analysis + PoC recipes are the deliverable (execution only adds confirmation).
function DynamicBanner({ health }) {
  if (!health || !Array.isArray(health.engines) || !health.engines.length) return null;
  const v = health.verdict;
  if (v !== "none" && v !== "degraded") return null;
  return html`<div class="rs-dyn">
    <div class="rs-dyn-h">${v === "none" ? "Dynamic verification unavailable" : "Dynamic verification degraded"}
      <span class="dim"> — rungs are candidates, not executed here</span></div>
    ${health.note ? html`<div class="rs-dyn-b">${health.note}</div>` : null}
    ${v === "none" ? html`<div class="rs-dyn-b muted">The deterministic analysis — static recovery, taint, the exploit
      synthesizers — ran regardless and produced findings and PoC / exploit recipes without executing anything; those
      are the deliverable. Running the target (point <b>target libraries dir</b> at its loader and .so files, or ingest
      it as a directory) only adds confirmation: it turns a candidate rung into an executed one.</div>` : null}
  </div>`;
}

// ---- scorecard --------------------------------------------------------------------------------
function Kpi({ v, label, sub, tone }) {
  return html`<div class=${"kpi rs-kpi" + (tone ? " " + tone : "")}><b>${v}</b><span>${label}</span>
    ${sub ? html`<span class="rs-kpi-sub">${sub}</span>` : null}</div>`;
}

function Scorecard({ card, running, onOpenStage }) {
  const ex = card.executions || {};
  const cap = card.capability || {};
  const bud = card.budget || {};
  const ab = card.absorbed || {};
  const base = card.baseline || {};
  const poc = card.poc || {};
  const st = card.stages || {};
  const declined = Object.entries(card.declined || {});
  const never = cap.never_scheduled || [];
  const skippedBud = bud.skipped_for_budget || [];
  const byEngine = Object.entries(ex.by_engine || {}).sort((a, b) => b[1] - a[1]);
  const ip = card.in_process;
  const stageBtn = (s) => (onOpenStage
    ? html`<button class="rs-link mono" onClick=${() => onOpenStage(s)}>${s}</button>` : html`<span class="mono">${s}</span>`);
  return html`
    ${card.settled === false ? html`<div class="rs-note-warn"><b>Incomplete</b> — a stage was still finishing when this card
      was built${running ? " (the run is live)" : ""}, so the counts are a floor, not a total.</div>` : null}
    <div class="kpis rs-kpis">
      <${Kpi} v=${fmtN(ex.total || 0)} label="target executions"
        sub=${ex.per_second ? `${ex.per_second}/s` : (ex.total ? null : "nothing executed the target")} tone=${ex.total ? "" : "warn"} />
      <${Kpi} v=${poc.level ? `L${poc.level}` : "none"} label="best verified PoC"
        sub=${`${poc.verified || 0} verified of ${plural(poc.total || 0, "PoC")}`} tone=${poc.level ? "blue" : ""} />
      <${Kpi} v=${card.crashes != null ? fmtI(card.crashes) : "—"} label="crashes recorded" />
      <${Kpi} v=${`${(cap.worked || []).length}/${cap.registered || 0}`} label="capabilities did work"
        sub=${`${(cap.declined || []).length} declined · ${(cap.errored || []).length} errored · ${never.length} never scheduled`}
        tone=${(cap.errored || []).length ? "warn" : ""} />
      <${Kpi} v=${bud.elapsed != null ? fmtElapsed(bud.elapsed) || "0s" : "—"} label=${bud.total ? `of ${fmtElapsed(bud.total)} budget` : "elapsed"}
        sub=${[bud.phase ? `${bud.phase} phase` : null, card.search_seconds != null ? `${card.search_seconds}s executing` : null].filter(Boolean).join(" · ")} />
      <${Kpi} v=${ab.total != null ? fmtI(ab.total) : "—"} label="absorbed errors"
        sub=${ab.total ? `at ${plural(ab.sites || 0, "site")}` : ab.total === 0 ? "no step failed quietly" : "not recorded"}
        tone=${ab.total ? "warn" : ""} />
    </div>
    <div class="rs-facts">
      <div><span class="dim">Baseline</span><span>${base.ran === undefined ? "not recorded"
        : base.ran ? (base.crashed ? html`<b class="rs-amber">ran and FAULTED</b>` : "ran, exited normally")
        : html`<b class="rs-amber">did not run</b> — ${base.note || "no reason recorded"}`}
        ${base.isolation ? html` <span class="chip mono">${base.isolation}</span>` : null}</span></div>
      ${byEngine.length ? html`<div><span class="dim">Executions by engine</span>
        <span>${byEngine.map(([k, v]) => html`<span class="rs-kv">${engineName(k)} <b>${fmtI(v)}</b></span>`)}</span></div>` : null}
      <div><span class="dim">Stages</span><span>${Object.entries(st).map(([k, v]) => html`<span class="rs-kv">${k} <b>${v}</b></span>`)}</span></div>
      ${bud.advice && bud.advice.note ? html`<div><span class="dim">Budget</span><span>${bud.advice.note}${bud.advice.short_by ? html` <b class="rs-amber">— short by ${fmtElapsed(bud.advice.short_by)}</b>` : null}</span></div>` : null}
    </div>
    ${ip ? html`<${Fold} label="In-process entry points fuzzed" n=${`${ip.entry_points}/${ip.planned}`} open=${true}>
      <div class="rs-list">${(ip.doors || []).map((d) => html`<div class="rs-li">
        <span class="mono">${d.entry || "?"}</span><span class="chip">${d.kind || "harness"}</span>
        <span class=${d.built ? "" : "rs-amber"}>${d.built ? `${fmtI(d.execs)} execs · ${plural(d.findings, "finding")}` : "not built"}</span>
        ${d.why ? html`<span class="muted">${d.why}</span>` : null}</div>`)}</div></${Fold}>` : null}
    ${declined.length ? html`<${Fold} label="Ran, but could not apply here" n=${declined.length}>
      <div class="rs-list">${declined.map(([s, why]) => html`<div class="rs-li">${stageBtn(s)}<span class="muted">${why}</span></div>`)}</div></${Fold}>` : null}
    ${skippedBud.length ? html`<${Fold} label="Skipped: the budget was spent first" n=${new Set(skippedBud.map((x) => x.stage)).size} open=${true}>
      <div class="rs-list">${[...new Map(skippedBud.map((x) => [x.stage, x])).values()].map((x) => html`<div class="rs-li">${stageBtn(x.stage)}<span class="muted">${x.why}</span></div>`)}</div>
      <div class="dim rs-foot">A bigger budget (or to-convergence mode) gives these stages time; the rest of the pipeline is unaffected.</div></${Fold}>` : null}
    ${never.length ? html`<${Fold} label="Never scheduled for this target" n=${never.length}>
      <div class="rs-chips">${never.map((s) => html`<span class="chip mono">${s}</span>`)}</div>
      <div class="dim rs-foot">Registered capabilities the planner did not pick for this target type — not run, so they say nothing about it.</div></${Fold}>` : null}
    ${ab.top && ab.top.length ? html`<${Fold} label="Where steps failed quietly" n=${ab.top.length}>
      <div class="rs-list">${ab.top.map((e) => html`<div class="rs-li"><b>${e.count}×</b><span class="mono">${e.site}</span></div>`)}</div></${Fold}>` : null}`;
}

// ---- time and yield ---------------------------------------------------------------------------
function TimeYield({ timing, cards, onOpenStage }) {
  const [all, setAll] = useState(false);
  const ov = timing.overall || {};
  const techs = timing.techniques || [];
  const compute = ov.compute_seconds || 0;
  // a stage that DECLINED did not run its technique: "not applicable" is not "no yield"
  const declined = {};
  for (const c of cards || []) for (const [s, why] of Object.entries(c.declined || {})) if (!declined[s]) declined[s] = why;
  const busy = techs.filter((t) => t.seconds > 0 || t.findings || t.crashes);
  const rows = all ? techs : busy;
  const maxS = Math.max(1, ...techs.map((t) => t.seconds || 0));
  if (!techs.length) return html`<div class="pad dim">No technique has finished a run in this case yet.</div>`;
  return html`
    <div class="pad rs-tm-sum">Wall-clock <b>${ov.wall_human || "—"}</b> · compute <b>${ov.compute_human || "—"}</b>${" "}across ${plural(techs.length, "technique")} (${plural(ov.runs || 0, "run")})${" "}<span class="dim">— compute exceeds wall-clock when targets run in parallel. Yield = findings + reproduced crashes.</span></div>
    <div class="rs-tm" role="table" aria-label="Time and yield per technique">
      <div class="rs-tm-r head" role="row"><span>technique</span><span>time</span><span>share of compute</span>
        <span class="n">runs</span><span class="n">findings</span><span class="n">crashes</span><span>yield</span></div>
      ${rows.map((t) => {
        const pct = compute ? Math.round((100 * t.seconds) / compute) : 0;
        const yielded = t.findings || t.crashes;
        const why = !yielded && declined[t.stage];
        const verdict = yielded ? html`<span class="rs-y ok">yield</span>`
          : why ? html`<span class="rs-y mute" title=${why}>not applicable</span>`
          : t.seconds > 0 ? html`<span class="rs-y warn">no yield</span>`
          : html`<span class="rs-y mute">under 1 s</span>`;
        return html`<div class=${"rs-tm-r" + (!yielded && t.seconds > 0 && !why ? " noy" : "")} role="row" key=${t.stage}>
          <span class="rs-tm-l">${onOpenStage
            ? html`<button class="rs-link" title="open this stage" onClick=${() => onOpenStage(t.stage)}>${t.label}</button>`
            : t.label}<span class="mono dim rs-tm-s">${t.stage}</span></span>
          <span class="mono rs-tm-t">${t.human}</span>
          <span class="rs-tm-bar"><${Bar} pct=${(100 * (t.seconds || 0)) / maxS} tone=${yielded ? "blue" : ""} /><span class="dim">${pct}%</span></span>
          <span class="n" data-l="runs">${t.runs}</span><span class=${"n" + (t.findings ? " rs-hi" : "")} data-l="findings">${t.findings}</span>
          <span class=${"n" + (t.crashes ? " rs-amber" : "")} data-l="crashes">${t.crashes}</span>
          <span class="rs-tm-y">${verdict}${why ? html`<span class="dim rs-why">${why}</span>` : null}</span>
        </div>`;
      })}
    </div>
    ${techs.length > busy.length ? html`<div class="pad" style="padding-top:8px">
      <button class="btn sm" onClick=${() => setAll(!all)}>${all ? "Hide" : "Show"} ${techs.length - busy.length} that took under a second with no yield</button></div>` : null}`;
}

// ---- engine health ----------------------------------------------------------------------------
function valueLine(v) {
  if (!v || !["blocks", "behaviours", "edges"].includes(v.unit) || v.gained == null) return null;
  const bits = [`+${fmtN(v.gained)} ${v.unit} beyond seeds (seeds reached ${fmtN(v.seed_coverage || 0)})`];
  if (v.last_gain_s != null && v.gained) bits.push(`last gain at ${fmtElapsed(v.last_gain_s) || "0s"}${v.idle_tail_pct != null ? `, idle for the last ${v.idle_tail_pct}%` : ""}`);
  else if (v.gained === 0) bits.push("never gained");
  if (v.kept != null) bits.push(`${fmtI(v.kept)} kept in corpus`);
  return bits.join(" · ");
}

function EngineHealth({ health, onOpenLog }) {
  const engines = health.engines || [];
  const v = health.verdict;
  const tone = v === "ok" ? "ok" : v === "none" ? "bad" : "warn";
  return html`
    <div class=${"pad rs-eh-v t-" + tone}><b>${v === "ok" ? "Executing" : v === "idle" ? "Idle" : v === "none" ? "Nothing dynamic ran" : v === "degraded" ? "Degraded" : v || "—"}</b>
      ${health.note ? html` — ${health.note}` : null}</div>
    <div class="rs-eh" role="table" aria-label="Engine health">
      <div class="rs-eh-r head" role="row"><span>engine</span><span>status</span><span class="n">executions</span><span>coverage</span><span>why / what it gained</span><span></span></div>
      ${engines.map((e) => {
        const [label, t] = HEALTH[e.status] || [e.status, "mute"];
        const execd = (e.execs || 0) > 0;
        const val = valueLine(e.value);
        return html`<div class="rs-eh-r" role="row" key=${e.engine}>
          <span><b>${engineName(e.engine)}</b><span class="mono dim rs-tm-s">${e.engine}</span></span>
          <span><span class=${"rs-st t-" + t}>${label}</span></span>
          <span class="n">${execd ? html`${fmtI(e.execs)}${e.afl_execs && e.afl_execs !== e.execs ? html`<span class="dim rs-why">AFL ${fmtI(e.afl_execs)}</span>` : null}` : html`<span class="dim">nothing ran</span>`}</span>
          <span class="mono rs-cov">${e.coverage || "—"}</span>
          <span class="rs-eh-why">
            ${e.reason ? html`<span class=${t === "bad" ? "rs-bad" : t === "warn" ? "rs-amber" : "muted"}>${e.reason}</span>` : (e.status === "ok" ? html`<span class="muted">executed the target</span>` : null)}
            ${val ? html`<span class="dim">${val}</span>` : null}
            ${e.outcomes ? html`<${OutcomeBar} counts=${e.outcomes} />` : null}
          </span>
          <span>${e.log && onOpenLog ? html`<button class="btn sm" title="every attempt this engine made: what was sent and how it ended"
            onClick=${() => onOpenLog(e.log, e.engine)}>attempts</button>` : null}</span>
        </div>`;
      })}
    </div>`;
}

// ---- coverage + ledger ------------------------------------------------------------------------
const covTone = (p) => (p == null ? "" : p >= 60 ? "blue" : p >= 25 ? "" : "warn");

function CodeCoverage({ ledger, cards, onFocusTarget }) {
  const code = (ledger && ledger.code) || [];
  const idOf = (name) => ((cards || []).find((c) => c.filename === name) || {}).target_id || null;
  // per-engine reach from the health report (edge counts AFL reports have no honest percentage)
  const engineCov = [];
  for (const c of cards || []) for (const e of ((c.fuzz_health || {}).engines || [])) {
    if (e.coverage) engineCov.push({ target: c.filename, engine: e.engine, coverage: e.coverage, value: e.value });
  }
  const multi = (cards || []).length > 1;
  if (!code.length && !engineCov.length) return html`<div class="pad dim">No coverage measured yet.</div>`;
  return html`
    ${code.map((c) => {
      const u = c.undriven;
      const body = html`
        <span class="rs-cv-n mono" title=${c.target}>${c.target}</span>
        <${Bar} pct=${c.block_pct} tone=${covTone(c.block_pct)} />
        <span class="rs-cv-v"><b>${c.block_pct != null ? `${c.block_pct}%` : "—"}</b>
          <span class="dim">${c.blocks_hit != null ? `${fmtI(c.blocks_hit)}/${fmtI(c.blocks_known)} basic blocks executed` : "no block coverage measured"}</span></span>
        <span class="rs-cv-d muted">${c.functions_recovered != null ? `${fmtI(c.functions_recovered)} functions recovered` : ""}${u && u.total
          ? ` · a harness entry statically reaches ${fmtI(u.reachable)} of ${fmtI(u.total)} (${u.pct}%), ${fmtI(u.count)} undriven` : ""}</span>`;
      const id = idOf(c.target);
      return onFocusTarget
        ? html`<button class="rs-cv clk" title="browse this target's code" onClick=${() => onFocusTarget(id || c.target, c.target)}>${body}</button>`
        : html`<div class="rs-cv">${body}</div>`;
    })}
    ${engineCov.length ? html`<div class="rs-cv-e">
      <div class="dim rs-mini-h">Reached per engine</div>
      ${engineCov.map((e) => html`<div class="rs-li"><span>${multi ? html`<span class="mono dim">${e.target}</span> ` : null}${engineName(e.engine)}</span>
        <span class="mono">${e.coverage}</span>${e.value && e.value.gained != null ? html`<span class=${e.value.gained ? "muted" : "rs-amber"}>+${fmtN(e.value.gained)} ${e.value.unit} beyond seeds</span>` : null}</div>`)}
    </div>` : null}
    <div class="pad dim rs-foot" style="padding-top:6px">Low coverage next to "0 crashes" means the clean result says little:
      the search did not reach most of the code.</div>`;
}

const STATE_TONE = { "poc-backed": "blue", confirmed: "blue", corroborated: "amber", candidate: "", "false-positive": "" };

function Ledger({ ledger, onOpenFinding, onFilterCwe, onShortlist }) {
  const chk = ledger.checks || {}, wpn = ledger.weaponization || {}, gaps = ledger.gaps || [];
  const bld = ledger.build || null;
  const classes = chk.classes_checked || [];
  const notRun = chk.not_run || [];
  const partial = (chk.items || []).filter((i) => i.status === "partial");
  const cands = wpn.unweaponized || [];
  const candTotal = Math.max(cands.length, (wpn.findings || 0) - (wpn.weaponized || 0));
  const cc = ledger.cwe_coverage || null;
  const ccRows = (cc && cc.run && cc.run.rows) || [];
  const cweBtn = (c) => (onFilterCwe ? html`<button class="chip mono rs-clk" onClick=${() => onFilterCwe(c)} title="show this class's findings">${c}</button>`
    : html`<span class="chip mono">${c}</span>`);
  const ver = wpn.verification || {};
  return html`
    ${bld && bld.built === false ? html`<div class="rs-note-bad pad-m"><b>The build produced no binaries — static-source analysis only.</b>
        ${bld.reason ? html`<div class="mono">${bld.reason}</div>` : null}<div>${bld.caveat}</div>${stageList(bld)}</div>`
      : bld && bld.partial ? html`<div class="rs-note-warn pad-m"><b>Partial build — binary analysis covers the compiled subset only.</b>
        <div>${bld.caveat}</div>${stageList(bld)}</div>`
      : bld && bld.caveat ? html`<div class="dim pad-m">Build: ${bld.caveat}</div>` : null}
    <div class="rs-axes">
      <div class="rs-ax">
        <div class="rs-ax-h"><b>Checks run</b><span class="dim">which weakness classes were looked for</span>
          <span class="rs-ax-v">${chk.ran ?? "—"}/${chk.total ?? "—"}</span></div>
        <${Bar} pct=${chk.total ? (100 * chk.ran) / chk.total : null} tone=${chk.total && chk.ran === chk.total ? "blue" : ""} />
        <div class="dim rs-ax-n">${plural(classes.length, "class", "classes")} looked for${notRun.length ? ` · ${plural(notRun.length, "check")} did not run` : ""}${partial.length ? ` · ${partial.length} partial` : ""}</div>
        ${classes.length ? html`<div class="rs-chips">${classes.map(cweBtn)}</div>` : null}
        ${notRun.length || partial.length ? html`<${Fold} label="Checks that did not run, or only partly" n=${notRun.length + partial.length}>
          <div class="rs-list">${notRun.concat(partial).map((c) => html`<div class="rs-li">
            <span class=${"rs-st t-" + (c.status === "partial" ? "warn" : "mute")}>${c.status === "not_run" ? "not run" : c.status}</span>
            <span>${c.label}</span><span class="mono dim">${c.stage}</span>
            ${(c.classes || []).filter((x) => x !== "*").length ? html`<span class="dim">${c.classes.filter((x) => x !== "*").join(", ")}</span>` : null}</div>`)}</div>
        </${Fold}>` : null}
      </div>
      <div class="rs-ax">
        <div class="rs-ax-h"><b>Findings weaponized</b><span class="dim">verified PoC or corroborated recipe</span>
          <span class="rs-ax-v">${wpn.weaponized || 0}/${wpn.findings || 0}${wpn.pct != null ? ` · ${wpn.pct}%` : ""}</span></div>
        <${Bar} pct=${wpn.pct} tone=${covTone(wpn.pct)} />
        ${wpn.distinct && wpn.distinct.raw && wpn.distinct.issues < wpn.distinct.raw ? html`<div class="rs-ax-n"><b>${wpn.distinct.issues}</b> distinct issues,
          ${wpn.distinct.weaponized} weaponized <span class="dim">(${wpn.distinct.raw} raw: one source bug counts once per target that compiles it)</span></div>` : null}
        ${ver.shortlist || ver.off_surface || ver.noise ? html`<div class="rs-ax-n">
          ${onShortlist && ver.shortlist ? html`<button class="rs-link" onClick=${() => onShortlist()}><b>${ver.shortlist}</b> on the prove-out shortlist →</button>`
            : html`<span><b>${ver.shortlist || 0}</b> on the prove-out shortlist</span>`}
          <span class="dim"> · ${ver.off_surface || 0} off the attack surface · ${ver.noise || 0} instrumentation artifacts</span></div>` : null}
        ${ledger.grounding && ledger.grounding.annotated ? html`<div class="rs-ax-n"><b>${ledger.grounding.shortlist}</b> of ${ledger.grounding.annotated} grounded findings are attacker-reachable
          <span class="dim">— set aside: ${Object.entries(ledger.grounding.by_verdict || {}).filter(([k]) => k !== "exploitable-candidate" && k !== "unreached").map(([k, n]) => `${k} ${n}`).join(", ") || "none"}</span></div>` : null}
        ${Object.keys(wpn.by_state || {}).length ? html`<div class="rs-chips">${Object.entries(wpn.by_state).sort().map(([s, n]) => html`<span class=${"chip rs-state " + (STATE_TONE[s] || "")}>${s} · ${n}</span>`)}</div>` : null}
        ${candTotal ? html`<${Fold} label="Weaponization worklist: bare candidates" n=${candTotal}>
          <div class="rs-list">${cands.map((f) => html`<div class="rs-li">
            <span class="mono dim rs-cwe">${f.cwe || "—"}</span>
            ${onOpenFinding ? html`<button class="rs-link" onClick=${() => onOpenFinding(f.id)}>${f.title || "(untitled)"}</button>` : html`<span>${f.title || "(untitled)"}</span>`}
            ${f.detector ? html`<span class="mono dim">${f.detector}</span>` : null}</div>`)}
            ${candTotal > cands.length ? html`<div class="rs-li dim">…and ${candTotal - cands.length} more not listed</div>` : null}</div>
        </${Fold}>` : null}
      </div>
      ${cc && cc.summary ? html`<div class="rs-ax">
        <div class="rs-ax-h"><b>Weakness classes present</b><span class="dim">how far each climbed, and the class's ceiling</span>
          <span class="rs-ax-v">${(cc.run && cc.run.demonstrated_classes) || 0}/${(cc.run && cc.run.classes_present) || 0} reached confirmed / PoC</span></div>
        <div class="dim rs-ax-n">lykos detects ${cc.summary.detected_classes} classes; ${cc.summary.rce_capable} can reach code execution.</div>
        ${ccRows.length ? html`<div class="rs-cwet">${ccRows.map((e) => html`<div class="rs-cwet-r">
          ${cweBtn(e.cwe)}<span class="rs-cwet-n">${e.name}</span>
          <span class=${"chip rs-state " + (STATE_TONE[e.best_state] || "")}>${e.best_state}${e.best_level ? ` · ${e.best_level}` : ""}</span>
          <span class="dim">${e.count ? plural(e.count, "finding") : ""}${e.ceiling ? ` · ceiling ${e.ceiling}` : ""}</span></div>`)}</div>`
          : html`<div class="dim rs-ax-n">No classified findings in this case.</div>`}
      </div>` : null}
    </div>
    ${gaps.length ? html`<div class="rs-gaps"><div class="rs-mini-h">Gaps worklist — what to close next</div>
      <ul>${gaps.map((g) => html`<li>${g}</li>`)}</ul></div>`
      : html`<div class="rs-gaps clean"><div class="rs-mini-h">No gaps flagged — every check ran and every finding is weaponized.</div></div>`}`;
}

function stageList(bld) {
  if (!bld || !bld.stage || !bld.stage.length) return null;
  return html`<div style="margin-top:6px">Stage these before re-ingesting <span class="dim">(<span class="mono">lykos deps &lt;dir&gt;</span> for detail)</span>:
    <div class="rs-chips">${bld.stage.map((t) => html`<span class="chip mono">${t}</span>`)}</div></div>`;
}

// ---- attempt logs -----------------------------------------------------------------------------
export function AttemptLogModal({ sha, engine, onClose }) {
  const [f, setF] = useState({ outcome: "", phase: "", errorsOnly: false, offset: 0 });
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const limit = 200;
  const box = useRef(null);
  useEffect(() => {
    let live = true;
    setErr(null);
    api.attemptLog(sha, { ...f, limit }).then((d) => { if (live) setData(d); }).catch((e) => { if (live) setErr(e.message || String(e)); });
    return () => { live = false; };
  }, [sha, f.outcome, f.phase, f.errorsOnly, f.offset]);
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", k);
    if (box.current) box.current.focus();
    return () => document.removeEventListener("keydown", k);
  }, []);
  if (!sha) return null;
  const sm = (data && data.summary) || {};
  const rows = (data && data.rows) || [];
  const matched = data ? data.matched : 0;
  const tops = Object.entries(sm.top_errors || {}).flatMap(([o, l]) => (l || []).slice(0, 3).map((t) => ({ o, ...t })));
  const pick = (patch) => setF((o) => ({ ...o, ...patch, offset: 0 }));
  return html`
    <div class="rs-modal-back" onClick=${onClose}>
      <div class="rs-modal" role="dialog" aria-modal="true" tabindex="-1" ref=${box}
        aria-label=${`Attempt log for ${engineName(engine)}`} onClick=${(e) => e.stopPropagation()}>
        <div class="rs-modal-h">
          <div><h2>Attempt log — ${engineName(engine)}</h2>
            <span class="dim" style="font-size:12px">${data ? `${fmtI(data.total)} attempts` : "loading…"}${sm.verdict ? ` · verdict ${sm.verdict}` : ""}${data && data.header && data.header.unit ? ` · coverage unit ${data.header.unit}` : ""}${data && data.truncated ? " · log truncated" : ""}</span></div>
          <span class="row-c" style="margin-left:auto">
            <a class="btn sm" href=${api.artifactUrl(sha)} download=${`${engine}-attempts.jsonl.gz`}>Download full log</a>
            <button class="btn sm" onClick=${onClose}>Close</button></span>
        </div>
        ${sm.verdict_note ? html`<div class=${"rs-att-v" + (sm.verdict === "erroring" ? " bad" : "")}>${sm.verdict_note}</div>` : null}
        ${sm.counts ? html`<div style="padding:0 16px"><${OutcomeBar} counts=${sm.counts} /></div>` : null}
        ${tops.length ? html`<div class="rs-att-tops"><div class="rs-mini-h">Most common endings</div>
          ${tops.map((t) => html`<div class="rs-li"><span class=${"rs-o o-" + t.o}>${OUTCOME_LABEL[t.o] || t.o}</span>
            <b>×${fmtI(t.count)}</b>${t.rc != null ? html`<span class="mono dim">rc ${t.rc}</span>` : null}
            <span class="mono rs-att-msg">${t.msg || "(no stderr)"}</span></div>`)}</div>` : null}
        <div class="rs-att-f">
          <button class=${"chip" + (!f.outcome && !f.errorsOnly ? " on" : "")} onClick=${() => pick({ outcome: "", errorsOnly: false })}>all</button>
          <button class=${"chip" + (f.errorsOnly ? " on" : "")} onClick=${() => pick({ outcome: "", errorsOnly: true })}>not clean</button>
          ${OUTCOMES.map(([o, l]) => html`<button class=${"chip" + (f.outcome === o ? " on" : "")} onClick=${() => pick({ outcome: o, errorsOnly: false })}>
            <i class=${"rs-dot o-" + o}></i>${l}${sm.counts && sm.counts[o] != null ? ` ${fmtN(sm.counts[o])}` : ""}</button>`)}
          <select value=${f.phase} onChange=${(e) => pick({ phase: e.target.value })} style="padding:4px 8px;font-size:12px">
            <option value="">every phase</option>${PHASES.map((p) => html`<option value=${p}>${p}</option>`)}</select>
        </div>
        ${err ? html`<div class="rs-att-v bad">${err}</div>` : null}
        <div class="rs-att-t">
          <table><thead><tr><th>#</th><th>t (s)</th><th>phase</th><th>outcome</th><th>rc / sig</th><th>ms</th><th>len</th><th>new</th><th>input (first bytes, hex)</th><th>stderr / note</th></tr></thead>
            <tbody>${rows.map((r) => html`<tr key=${r.i}>
              <td class="n">${r.i}</td><td class="n">${r.t != null ? Number(r.t).toFixed(2) : ""}</td><td>${r.ph}</td>
              <td><span class=${"rs-o o-" + r.o}>${OUTCOME_LABEL[r.o] || r.o}</span>${r.kept ? html` <span class="chip on rs-kept" title="joined the corpus">kept</span>` : null}</td>
              <td class="mono">${r.sig || (r.rc == null ? "" : r.rc)}</td><td class="n">${r.ms ?? ""}</td><td class="n">${r.len ?? ""}</td><td class="n">${r.new || ""}</td>
              <td class="mono rs-hex" title=${`sha256 ${r.in}…${r.argv ? `\nflags: ${r.argv.join(" ")}` : ""}`}>${r.head}</td>
              <td class="mono rs-att-msg">${r.err || r.note || ""}</td></tr>`)}</tbody></table>
          ${data && !rows.length ? html`<div class="pad dim">No attempts match this filter.</div>` : null}
        </div>
        <div class="rs-att-p">
          <span class="dim">${matched ? `${fmtI(f.offset + 1)}–${fmtI(f.offset + rows.length)} of ${fmtI(matched)}` : ""}</span>
          <button class="btn sm" disabled=${f.offset === 0} onClick=${() => setF((o) => ({ ...o, offset: Math.max(0, o.offset - limit) }))}>Previous</button>
          <button class="btn sm" disabled=${f.offset + rows.length >= matched} onClick=${() => setF((o) => ({ ...o, offset: o.offset + limit }))}>Next</button>
        </div>
      </div>
    </div>`;
}

function AttemptLogs({ logs, names, onOpen }) {
  return html`<div class="rs-list">${logs.map((l) => html`<div class="rs-li rs-al" key=${l.sha256}>
    <span class="rs-al-e"><b>${engineName(l.engine)}</b>${names[l.target_id] ? html`<span class="mono dim rs-tm-s">${names[l.target_id]}</span>` : null}</span>
    <span class="mono">${fmtI(l.attempts)} attempts</span>
    <span class="rs-al-b"><${OutcomeBar} counts=${l.counts} legend=${false} /></span>
    <span class="muted rs-al-n" title=${l.verdict_note || ""}>${l.verdict}${l.verdict_note ? ` — ${l.verdict_note}` : ""}</span>
    <span class="dim" style="font-size:11.5px">${l.created_at ? new Date(l.created_at * 1000).toLocaleString() : ""}</span>
    <button class="btn sm" onClick=${() => onOpen(l.sha256, l.engine)}>Open</button>
  </div>`)}</div>`;
}

// ---- seeds ------------------------------------------------------------------------------------
// Operator seed files (the CLI's --seed): uploaded into the case, handed to the fuzzers by hash.
// `selected` (a Set of sha256) + `onSelect` turn it into the run's seed picker.
function seedsChanged(caseId, added) {
  try { document.dispatchEvent(new CustomEvent("lykos:seeds-changed", { detail: { caseId, added } })); } catch (_e) { /* no DOM */ }
}

export function SeedsField({ caseId, seeds, maxBytes, maxSeeds, onChanged, selected, onSelect }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const list = seeds || [];
  const add = async (files) => {
    setBusy(true); setErr(null);
    const added = [];
    for (const f of files) {
      try { const r = await api.uploadSeed(caseId, f); if (r && r.sha256) added.push(r.sha256); }
      catch (e) { setErr(`${f.name}: ${e.message || e}`); }
    }
    setBusy(false);
    seedsChanged(caseId, added);
    onChanged && onChanged(added);
  };
  const rm = async (sha) => {
    setErr(null);
    try { await api.deleteSeed(caseId, sha); } catch (e) { setErr(`could not remove the seed: ${e.message || e}`); }
    seedsChanged(caseId, []);
    onChanged && onChanged([]);
  };
  return html`<div class="rs-seeds">
    <div class="dim" style="font-size:12px">Real example inputs — a config, a sample document, a known reproducer — the fuzzers start from
      (the CLI's <span class="mono">--seed</span>). Stored in this case${maxBytes ? `, at most ${fmtN(maxBytes / 1024)} KiB each` : ""}${maxSeeds ? `, ${maxSeeds} per case` : ""}.
      Without them a structured parser is rarely reached in a short budget.</div>
    <div class="rs-chips">
      ${list.map((s) => html`<span class=${"rs-seed" + (selected && selected.has(s.sha256) ? " on" : "")} key=${s.sha256}
          title=${`${s.name} · ${fmtI(s.size)} bytes · sha256 ${s.sha256}`}>
        ${onSelect ? html`<input type="checkbox" checked=${selected.has(s.sha256)} aria-label=${`use seed ${s.name}`}
          onChange=${(e) => onSelect(s.sha256, e.target.checked)} />` : null}
        <span class="mono">${s.name}</span><span class="dim">${fmtI(s.size)} B</span>
        <button class="rs-x" aria-label=${`remove seed ${s.name}`} onClick=${() => rm(s.sha256)}>✕</button></span>`)}
      <label class=${"btn sm" + (busy ? " busy" : "")} style="display:inline-flex;align-items:center">
        ${busy ? "uploading…" : "Add seed files"}
        <input type="file" multiple hidden disabled=${busy || !caseId}
          onChange=${(e) => { const fl = [...(e.target.files || [])]; e.target.value = ""; if (fl.length) add(fl); }} /></label>
    </div>
    ${!list.length ? html`<div class="dim" style="font-size:12px">No seed files in this case — the autopilot seeds itself (format models, dictionaries, entry parameters).</div>` : null}
    ${err ? html`<div class="rs-amber" style="font-size:12px">${err}</div>` : null}
  </div>`;
}

// ---- the panel set ----------------------------------------------------------------------------
// RunResults({ caseId, running, ap?, targets?, onOpenStage?, onOpenFinding?, onFilterCwe?,
//              onFocusTarget?, onShortlist? })
//   ap      -- the autopilot status (api.backgroundStatus) for live failed-target signals
//   targets -- [{id, filename}] for names; falls back to the scorecard's
export function RunResults({ caseId, running, ap, targets, onOpenStage, onOpenFinding, onFilterCwe, onFocusTarget, onShortlist }) {
  const [d, reload] = useRunResults(caseId, running);
  useEffect(() => {
    const on = (e) => { if (!e.detail || e.detail.caseId === caseId) reload(); };
    document.addEventListener("lykos:seeds-changed", on);
    return () => document.removeEventListener("lykos:seeds-changed", on);
  }, [caseId]);
  const [sel, setSel] = useState(null);
  const [log, setLog] = useState(null);
  const cards = (d.scorecard && d.scorecard.cards) || [];
  const card = cards.find((c) => c.target_id === sel) || cards[0] || null;
  const tlist = targets && targets.length ? targets : cards.map((c) => ({ id: c.target_id, filename: c.filename }));
  const names = useMemo(() => Object.fromEntries(tlist.map((t) => [t.id, t.filename])), [tlist]);
  const logs = Array.isArray(d.logs) ? d.logs : [];
  const seeds = (d.seeds && d.seeds.seeds) || [];
  const health = card && card.fuzz_health;
  const err = d.err || {};
  const errLine = (k, what) => (err[k] ? html`<div class="pad rs-amber" style="font-size:12.5px">Could not read ${what}: ${err[k]}</div>` : null);
  if (!caseId) return null;
  return html`
    <div class="rs">
      <div class="rs-top">
        <h2 style="font-size:17px">What this run did</h2>
        <span class="dim" style="font-size:12px">${d.at ? `read ${clock(d.at)}${running ? ` · refreshing every ${POLL_MS / 1000} s while the run is live` : ""}` : "loading…"}</span>
        <button class="btn sm" style="margin-left:auto" onClick=${reload}>Refresh</button>
      </div>
      <${SignalsStrip} signals=${d.signals} ap=${ap} targets=${tlist} err=${err.signals} />
      <${DynamicBanner} health=${health} />

      <${Section} title="Scorecard" sub="a null result is only worth something next to the work behind it"
        right=${cards.length > 1 ? html`<div class="seg">${cards.map((c) => html`<button class=${card && c.target_id === card.target_id ? "on" : ""}
          onClick=${() => setSel(c.target_id)}>${c.filename || c.target_id.slice(0, 8)}</button>`)}</div>`
          : card ? html`<span class="mono dim">${card.filename}</span>` : null}>
        ${card ? html`<div class="pad" style="padding-top:4px"><${Scorecard} card=${card} running=${running} onOpenStage=${onOpenStage} /></div>`
          : errLine("scorecard", "the scorecard") || html`<div class="pad dim">${d.scorecard ? (running
            ? "The scorecard is written as each target finishes; this run has not finished one yet."
            : "No scorecard: no autopilot run has finished in this case.") : "loading…"}</div>`}
      </${Section}>

      <${Section} title="Time and yield per technique" sub="which techniques earned their clock">
        ${d.timing ? html`<${TimeYield} timing=${d.timing} cards=${cards} onOpenStage=${onOpenStage} />`
          : errLine("timing", "the timing") || html`<div class="pad dim">loading…</div>`}
      </${Section}>

      <${Section} title="Engine health" sub=${card ? `which dynamic engines ran, were not applicable, or failed — and why${cards.length > 1 ? ` · ${card.filename}` : ""}` : "which dynamic engines ran, were not applicable, or failed — and why"}>
        ${health && (health.engines || []).length ? html`<${EngineHealth} health=${health} onOpenLog=${(sha, eng) => setLog({ sha, engine: eng })} />`
          : html`<div class="pad dim">${card ? "No engine-health report on this target's scorecard." : running ? "Reported when a target finishes." : "No engine-health report yet."}</div>`}
      </${Section}>

      <${Section} title="Coverage" sub="how much of each target's recovered code the search actually executed">
        ${d.ledger || cards.length ? html`<${CodeCoverage} ledger=${d.ledger} cards=${cards} onFocusTarget=${onFocusTarget} />`
          : errLine("ledger", "the coverage") || html`<div class="pad dim">loading…</div>`}
      </${Section}>

      <${Section} title="Coverage ledger" sub="the gap along three axes, and the worklist to close it">
        ${d.ledger && d.ledger.checks ? html`<div class="pad" style="padding-top:4px"><${Ledger} ledger=${d.ledger} onOpenFinding=${onOpenFinding}
            onFilterCwe=${onFilterCwe} onShortlist=${onShortlist} /></div>`
          : errLine("ledger", "the coverage ledger") || html`<div class="pad dim">${d.ledger ? "No coverage ledger yet — run an analysis first." : "loading…"}</div>`}
      </${Section}>

      <details class="panel rs-sec rs-coll" open=${false}>
        <summary class="rs-sec-h"><h2>Fuzz attempt logs</h2><span class="rs-n">${logs.length}</span>
          <span class="dim rs-sec-sub">one per engine per run: every execution, what was sent and how it ended</span></summary>
        ${logs.length ? html`<div class="pad" style="padding-top:0"><${AttemptLogs} logs=${logs} names=${names} onOpen=${(sha, eng) => setLog({ sha, engine: eng })} /></div>`
          : errLine("logs", "the attempt logs") || html`<div class="pad dim">No fuzz engine has stored an attempt log in this case.</div>`}
      </details>

      <details class="panel rs-sec rs-coll" open=${false}>
        <summary class="rs-sec-h"><h2>Seed files</h2><span class="rs-n">${seeds.length}</span>
          <span class="dim rs-sec-sub">operator inputs the fuzzers start from</span></summary>
        <div class="pad" style="padding-top:0">${errLine("seeds", "the seeds")}
          <${SeedsField} caseId=${caseId} seeds=${seeds} maxBytes=${d.seeds && d.seeds.max_bytes}
            maxSeeds=${d.seeds && d.seeds.max_seeds} /></div>
      </details>
      ${log ? html`<${AttemptLogModal} sha=${log.sha} engine=${log.engine} onClose=${() => setLog(null)} />` : null}
    </div>`;
}

// ---- run options ------------------------------------------------------------------------------
// The operator's run settings. buildRunSettings(value) -> {overrides, skipStages}, the same shape
// app/util.js operatorSettings() gives the old GUI, for
//   api.startBackground(caseId, targetIds, budget, overrides, value.converge, skipStages)
// Seeds: the server uses ONLY the seed hashes it is sent (no fallback to the case's seeds), so
// RunOptions keeps `seeds` resolved to explicit hashes -- every case seed in "all" mode (the old
// GUI's behaviour), the operator's pick in "pick" mode.
export const DEFAULT_RUN_OPTIONS = {
  converge: false, blackBox: true, covFuzz: true, dirFuzz: true, concolicOn: true, libfuzzerOn: true,
  deepSeed: false, sysroot: "", invArgv: "", invMode: "auto",
  seedMode: "all",      // "all" = every seed in the case | "pick" = only `seeds`
  seeds: [],            // [sha256]; kept current by RunOptions while it is mounted
};

// caseSeeds (optional, [{sha256}] from api.seeds) resolves "all" mode when RunOptions was never
// mounted to resolve it.
export function buildRunSettings(value, caseSeeds) {
  const v = { ...DEFAULT_RUN_OPTIONS, ...(value || {}) };
  const raw = v.seedMode !== "pick" && Array.isArray(caseSeeds) ? caseSeeds : (v.seeds || []);
  const seeds = raw.map((x) => (typeof x === "string" ? { sha256: x } : x)).filter((x) => x && x.sha256);
  return operatorSettings({ invArgv: v.invArgv || "", invMode: v.invMode || "auto", sysroot: v.sysroot || "",
    deepSeed: !!v.deepSeed, seeds, blackBox: v.blackBox !== false, covFuzz: v.covFuzz !== false,
    dirFuzz: v.dirFuzz !== false, concolicOn: v.concolicOn !== false, libfuzzerOn: v.libfuzzerOn !== false });
}

const RUNOPTS_KEY = "lykos.next.runopts";
// Per-browser convenience: the last options used. The seed choice is per case, so it is not kept.
export function loadRunOptions() {
  try {
    const o = JSON.parse(localStorage.getItem(RUNOPTS_KEY) || "{}") || {};
    delete o.seeds; delete o.seedMode;
    return { ...DEFAULT_RUN_OPTIONS, ...o };
  } catch (_e) { return { ...DEFAULT_RUN_OPTIONS }; }
}
export function saveRunOptions(value) {
  try {
    const { seeds: _s, seedMode: _m, ...rest } = value || {};
    localStorage.setItem(RUNOPTS_KEY, JSON.stringify(rest));
  } catch (_e) { /* storage off: options just are not remembered */ }
}

const ENGINES = [
  ["blackBox", "Black-box fuzzing", "fuzz", "the built-in mutation fuzzer; the rest of the pipeline still runs without it"],
  ["covFuzz", "Coverage-guided", "coverage_fuzz", "AFL++ qemu-mode"],
  ["dirFuzz", "Directed fuzzing", "directed_fuzz", "steered at flagged sinks and leads"],
  ["concolicOn", "Concolic", "concolic", "angr / SymQEMU solve guarded branches; can be the slowest stage"],
  ["libfuzzerOn", "libFuzzer", "libfuzzer", "source campaign; applies only when source is available"],
];
const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// RunOptions({ value, onChange, caseId?, hideInvocation? })
//   caseId          -- enables the seed picker (lists, uploads, removes the case's seeds)
//   hideInvocation  -- hide argv / input channel when the host screen already has those fields
export function RunOptions({ value, onChange, caseId, hideInvocation }) {
  const v = { ...DEFAULT_RUN_OPTIONS, ...(value || {}) };
  const vref = useRef(v), cb = useRef(onChange);
  vref.current = v; cb.current = onChange;
  // through refs: loadSeeds runs from an effect / event listener bound on the first render
  const set = (patch) => { const n = { ...vref.current, ...patch }; vref.current = n; if (cb.current) cb.current(n); };
  const [seedList, setSeedList] = useState(null);
  const loadSeeds = (added = []) => {
    if (!caseId) return;
    api.seeds(caseId).then((r) => {
      const list = (r && r.seeds) || [];
      setSeedList(r || { seeds: [] });
      const cur = vref.current;
      const have = list.map((s) => s.sha256);
      // "all": every case seed. "pick": the pick, minus removed seeds, plus one just uploaded.
      const next = cur.seedMode === "pick"
        ? (cur.seeds || []).filter((s) => have.includes(s)).concat((added || []).filter((s) => have.includes(s) && !(cur.seeds || []).includes(s)))
        : have;
      if (!sameList(next, cur.seeds || [])) set({ seeds: next });
    }).catch((e) => setSeedList({ seeds: [], error: String(e.message || e) }));
  };
  useEffect(() => {
    setSeedList(null);
    loadSeeds();
    // seeds added / removed elsewhere (the Seed files panel) keep this picker current
    const on = (e) => { if (!e.detail || e.detail.caseId === caseId) loadSeeds((e.detail && e.detail.added) || []); };
    document.addEventListener("lykos:seeds-changed", on);
    return () => document.removeEventListener("lykos:seeds-changed", on);
  }, [caseId]);
  const allSeeds = (seedList && seedList.seeds) || [];
  const chosen = new Set(v.seedMode === "pick" ? v.seeds : allSeeds.map((s) => s.sha256));
  const pickSeed = (sha, on) => {
    const cur = new Set(chosen);
    if (on) cur.add(sha); else cur.delete(sha);
    set({ seedMode: "pick", seeds: allSeeds.map((s) => s.sha256).filter((s) => cur.has(s)) });
  };
  const off = ENGINES.filter(([k]) => v[k] === false);
  return html`<div class="rs-opts">
    <fieldset class="rs-fs"><legend>Search</legend>
      <label class="rs-chk" title="Keep fuzzing until coverage stops growing; the budget becomes the safety ceiling instead of a fixed clock">
        <input type="checkbox" checked=${v.converge} onChange=${(e) => set({ converge: e.target.checked })} />
        <span><b>Run to convergence</b> <span class="dim">— fuzz until coverage plateaus; the budget becomes the ceiling. The non-fuzzing analysis is complete either way.</span></span></label>
      <label class="rs-chk" title="Synthesize parser-buffer seeds for daemon / library functions entry-point seeding cannot reach">
        <input type="checkbox" checked=${v.deepSeed} onChange=${(e) => set({ deepSeed: e.target.checked })} />
        <span><b>Deep seed discovery</b> <span class="dim">— parser-buffer seeds for code the entry point cannot reach; its findings are candidate-tier (reachability assumed, not proven). Normal auto-seeding runs regardless.</span></span></label>
    </fieldset>
    <fieldset class="rs-fs"><legend>Engines</legend>
      <div class="rs-eng">${ENGINES.map(([k, label, stage, gloss]) => html`
        <label class=${"rs-engb" + (v[k] !== false ? " on" : "")} title=${`${gloss} (stage ${stage})`}>
          <input type="checkbox" checked=${v[k] !== false} onChange=${(e) => set({ [k]: e.target.checked })} />
          <span>${label}</span></label>`)}</div>
      <div class="dim" style="font-size:12px">${off.length ? `Off for this run: ${off.map(([, l]) => l).join(", ")} — the server skips those stages; everything else (static analysis, the exploit ladder) still runs.`
        : "Every engine on. Each one still declines on its own when it does not apply to the target."}</div>
    </fieldset>
    <fieldset class="rs-fs"><legend>Target environment</legend>
      <label class="field">Target libraries directory
        <input type="text" placeholder="blank = this host's libraries" value=${v.sysroot} onInput=${(e) => set({ sysroot: e.target.value })} />
        <span class="dim" style="font-size:11.5px">A directory on the server with the target's own loader (ld-linux…) and .so files, used as QEMU_LD_PREFIX —
          the fix for "symbol lookup error" or "fork server handshake failed" on a binary built against another glibc.</span></label>
      ${hideInvocation ? null : html`<div class="rs-inv">
        <label class="field" style="flex:2 1 220px">Invocation
          <input type="text" class="mono" placeholder="blank = discovered (e.g.  -c @@)" value=${v.invArgv} onInput=${(e) => set({ invArgv: e.target.value })} />
          <span class="dim" style="font-size:11.5px">How the binary is really run; <span class="mono">@@</span> is the input file. Same as the CLI's --argv.</span></label>
        <label class="field" style="flex:1 1 140px">Input channel
          <select value=${v.invMode} onChange=${(e) => set({ invMode: e.target.value })}>
            <option value="auto">auto</option><option value="stdin">stdin</option><option value="file">file (@@)</option>
            <option value="arg">first argument</option><option value="env">environment variable</option></select></label>
      </div>`}
    </fieldset>
    ${caseId ? html`<fieldset class="rs-fs"><legend>Seeds for this run</legend>
      ${seedList && seedList.error ? html`<div class="rs-amber" style="font-size:12px">Could not list the case's seeds: ${seedList.error}</div>` : null}
      ${allSeeds.length ? html`<div class="dim" style="font-size:12px">${chosen.size} of ${allSeeds.length} used${v.seedMode === "pick" ? "" : " (all, by default)"}
        ${v.seedMode === "pick" ? html` · <button class="rs-link" onClick=${() => set({ seedMode: "all", seeds: allSeeds.map((s) => s.sha256) })}>use all</button>` : null}</div>` : null}
      <${SeedsField} caseId=${caseId} seeds=${allSeeds} maxBytes=${seedList && seedList.max_bytes} maxSeeds=${seedList && seedList.max_seeds}
        selected=${chosen} onSelect=${pickSeed} />
    </fieldset>` : null}
  </div>`;
}
