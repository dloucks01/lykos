// Presentational components. No fetching, no orchestration -- they render what app.js hands
// them. Keeping them pure is what makes the workbench maintainable: the old GUI was one
// 160 KB file where markup, state, and network calls were braided together.

import { h } from "preact";
import { useState, useRef, useEffect } from "preact/hooks";
import htm from "htm";
import {
  STATE_LABEL, STATE_GLOSS, isDemonstrated, fmtBytes, shortHash, runTone, stageLabel, fmtElapsed,
  SEV_ORDER, maxPocLevel, histogram, CURATION_STATUSES, CURATION_LABEL, CURATION_FILTERS,
  runSignalChips,
} from "./util.js";

const html = htm.bind(h);
export { html };

// Tooltip text for a CWE badge: the id, its name, and the plain-language description the backend
// now ships (finding.cwe_name / finding.cwe_desc). Rendered through the native `title` attribute so
// hovering a CWE anywhere in the workbench explains it without leaving the tool or looking it up.
const cweTip = (f) =>
  f && f.cwe_name
    ? `${f.cwe}: ${f.cwe_name}${f.cwe_desc ? "\n\n" + f.cwe_desc : ""}`
    : (f && f.cwe) || "";

export function Spinner({ label }) {
  return html`<span class="spin" role="status"><span class="dot"></span>${label ? html`<span class="spin-lbl">${label}</span>` : null}</span>`;
}

export function Badge({ state }) {
  return html`<span class=${`badge state-${state}`}>${STATE_LABEL[state] || state}</span>`;
}

export function SevDot({ severity }) {
  const s = (severity || "").toLowerCase();
  return html`<span class=${`sev sev-${s}`} title=${severity}>${s ? s[0].toUpperCase() : "?"}</span>`;
}

// The Autopilot pipeline PLAN: what is done, what is running, and what is still to come -- fed by
// the server-side background run's status.plan, so a glance shows progress, not just a scrolling
// log. Each step carries a state (pending/running/done/skipped/error/cancelled) and an optional
// detail. Conditional steps the run never reached show as "skipped".
const _PLAN_ICON = { done: "✓", error: "✕", skipped: "–", cancelled: "■",
                     declined: "⊘", timeout: "⧖" };
// A COMPACT progress summary -- deliberately not a stage list (the Run log already is one). It
// gives what the log does not: overall progress at a glance, the step running right now, and the
// shape of what is still ahead (the dot strip, each dot a stage; hover for its name + detail).
export function PipelinePlan({ plan, targetName, target, targets, now }) {
  if (!plan || !plan.length) return null;
  const active = plan.filter((p) => p.state !== "skipped");
  const done = active.filter((p) => p.state === "done").length;
  const total = active.length || plan.length;
  const running = plan.find((p) => p.state === "running");
  const errored = plan.find((p) => p.state === "error");
  const timedout = plan.find((p) => p.state === "timeout");
  const declined = active.filter((p) => p.state === "declined").length;
  const pct = Math.round((100 * done) / Math.max(1, total));
  // Elapsed for a stage: a finished stage carries its own `elapsed`; a RUNNING one is timed live
  // against the server clock (`now`) so a growing number proves it is alive, not hung.
  const elapsedOf = (p) => (p.state === "running" && now && p.started) ? (now - p.started)
    : (typeof p.elapsed === "number" ? p.elapsed : null);
  const runElapsed = running ? elapsedOf(running) : null;
  const dotTitle = (p) => {
    const e = elapsedOf(p);
    const et = e != null ? ` · ${fmtElapsed(e)}` : "";
    const st = p.state === "timeout" ? " (cut short — out of budget)"
      : p.state === "declined" ? " (declined — could not run on this target)"
      : p.state === "skipped" ? " (skipped)" : p.state === "cancelled" ? " (stopped)"
      : p.state === "error" ? " (error)" : "";
    return `${p.label}${st}${p.detail ? ` — ${p.detail}` : ""}${et}`;
  };
  return html`
    <div class="plan card compact">
      <div class="plan-head">
        <span>Pipeline${target && targets > 1 ? ` · target ${target}/${targets}` : ""}${
          targetName ? html` · <span class="mono">${targetName}</span>` : null}</span>
        <span class="plan-count">${done}/${total}</span>
      </div>
      <div class="plan-bar"><div class=${`plan-fill${errored ? " err" : ""}`} style=${`width:${Math.max(3, pct)}%`}></div></div>
      <div class="plan-now">
        ${running ? html`<${Spinner} label=${running.label
              + (runElapsed != null ? ` · ${fmtElapsed(runElapsed)}` : "")
              + (running.detail ? ` — ${running.detail}` : "")} />`
          : errored ? html`<span class="plan-nowerr">✕ ${errored.label}${errored.detail ? ` — ${errored.detail}` : " failed"}</span>`
          : timedout ? html`<span class="plan-nowtimeout">⧖ ${timedout.label} cut short — out of budget (raise it to let it finish)</span>`
          : declined ? html`<span class="plan-nowdecl">⊘ ${done}/${total} ran · ${declined} declined (could not run on this target — see the log)</span>`
          : html`<span class="plan-nowok">✓ all ${total} steps complete</span>`}
      </div>
      <div class="plan-dots">
        ${plan.map((p) => html`<span class=${`plan-dot dot-${p.state}`} key=${p.stage}
          title=${dotTitle(p)}></span>`)}
      </div>
    </div>`;
}

// The upload surface. A drop target AND a click-to-pick, because the whole design goal is the
// fewest clicks: drag a binary onto the page and Autopilot can start on the next click. Accepts
// several files at once -- multiple binaries in one case unlock the cross-binary analyses.
export function DropZone({ onFiles, busy, compact }) {
  const take = (fl) => { if (fl && fl.length) onFiles(fl); };
  // Toggle the "drag" affordance straight on the element (no re-render): onDragOver fires
  // continuously so it re-asserts the class while the pointer hovers a child, and onDragLeave /
  // onDrop clear it on the true exit.
  const setDrag = (el, on) => { if (el && el.classList) el.classList.toggle("drag", !!on && !busy); };
  const onDrop = (e) => { e.preventDefault(); setDrag(e.currentTarget, false); if (!busy) take(e.dataTransfer && e.dataTransfer.files); };
  const onPick = (e) => { take(e.target.files); e.target.value = ""; };
  // A folder pick is a SOURCE TREE: the whole directory is packed and uploaded as a source
  // project (dependency-CVE + the source bug scanners). Browsers expose it via `webkitdirectory`.
  const folderRef = { current: null };
  const onPickFolder = (e) => { take(e.target.files); e.target.value = ""; };
  return html`
    <label class=${`dropzone${busy ? " busy" : ""}${compact ? " compact" : ""}`}
           onDragOver=${(e) => { e.preventDefault(); setDrag(e.currentTarget, true); }}
           onDragLeave=${(e) => setDrag(e.currentTarget, false)} onDrop=${onDrop}>
      <input type="file" multiple class="visually-hidden" onChange=${onPick} disabled=${busy}
        aria-label=${compact ? "Add binaries or firmware to this case" : "Choose binaries or firmware images to analyse"} />
      <input type="file" webkitdirectory directory multiple class="visually-hidden" disabled=${busy}
        ref=${(el) => (folderRef.current = el)} onChange=${onPickFolder}
        aria-label="Choose a source-code folder to analyse" />
      <div class="dz-inner">
        <div class="dz-icon">⇪</div>
        <div class="dz-title">${compact ? "Add more binaries to this case" : "Drop one or more binaries or firmware images here"}</div>
        <div class="dz-sub">${compact ? "several binaries unlock IPC modelling and cross-binary taint" : "or click to choose files — analysis starts on the next click"}</div>
        <button type="button" class="dz-folder" disabled=${busy}
          onClick=${(e) => { e.preventDefault(); e.stopPropagation(); if (folderRef.current) folderRef.current.click(); }}>
          ${compact ? "+ source folder" : "📁 or choose a source-code folder (analyse the whole tree)"}
        </button>
      </div>
    </label>`;
}

// Exploitation-relevant imports: the dangerous sinks whose mere presence shapes the attack
// surface. Highlighted so an analyst sees the memory-unsafe and command/format sinks at a glance.
const DANGEROUS_IMPORTS = new Set([
  "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "memmove",
  "alloca", "system", "popen", "execve", "execl", "execlp", "execvp", "exec", "fscanf",
  "printf", "fprintf", "snprintf", "read", "recv", "fread", "getenv", "strncpy", "strncat",
]);

// Each mitigation as a badge, coloured by whether it HELPS a defender. NX on / PIE on / full
// RELRO / canary on are good (green); off is a weakened defence (red). This is the first thing
// an exploit developer reads: it decides whether L3 is even reachable.
const MIT_GOOD = {
  nx: (v) => v === "on", pie: (v) => v === "on", canary: (v) => v === "on",
  fortify: (v) => v === "on", relro: (v) => v === "full",
};
function Mitigations({ m }) {
  if (!m) return null;
  const order = [["nx", "NX"], ["pie", "PIE"], ["canary", "Canary"], ["relro", "RELRO"], ["fortify", "Fortify"]];
  return html`<div class="mits">${order.filter(([k]) => m[k] != null).map(([k, lab]) => {
    const good = MIT_GOOD[k] ? MIT_GOOD[k](m[k]) : false;
    return html`<span class=${`mit ${good ? "mit-good" : "mit-weak"}`} title=${`${lab}: ${m[k]}`}>${lab} ${m[k]}</span>`;
  })}</div>`;
}

export function TargetSummary({ target, advice, index, onBrowseFunctions }) {
  if (!target) return null;
  const d = target.details || {};
  const fnCount = d.function_count != null ? d.function_count : (Array.isArray(d.functions) ? d.functions.length : null);
  const fnLabel = fnCount != null ? `${fnCount} ${fnCount === 1 ? "function" : "functions"}` : null;
  const elf = (d.format_details && d.format_details.elf) || {};
  const imp = d.imports || {};
  const impSyms = imp.symbols || [];
  const dangerous = impSyms.filter((s) => DANGEROUS_IMPORTS.has(s));
  const entry = d.entry_point || (elf.entry != null ? `0x${elf.entry.toString(16)}` : null);
  const facts = [
    ["Type", d.detected || target.file_type],
    ["Arch", [target.arch, target.bits ? `${target.bits}-bit` : null, target.endianness].filter(Boolean).join(" ")],
    ["Linking", target.linking],
    ["Entry", entry],
    ["Interpreter", d.interpreter || elf.interpreter],
    ["Sections", elf.sections],
    ["Imports", imp.functions_count != null ? `${imp.functions_count} from ${(imp.libraries || []).join(", ") || "—"}` : null],
    ["Exports", d.exports_count],
    ["Stripped", target.stripped ? "yes" : "no"],
    ["Size", fmtBytes(target.size)],
    ["Toolchain", d.toolchain_hint],
    ["Entropy", d.entropy && d.entropy.overall != null
      ? `${d.entropy.overall}${d.entropy.packed_hint ? " (packed?)" : ""}` : null],
  ].filter(([, v]) => v != null && v !== "");
  return html`
    <div class="card summary">
      <div class="sum-head">
        <div class="sum-name">${index != null ? html`<span class="sum-ix">${index}</span>` : null}${target.filename}${target.source ? html` <span class="src-badge" title=${`compiled with ${target.source.sanitizers || "sanitizers"}`}>source · ASan</span>` : null}</div>
        <${Mitigations} m=${target.mitigations} />
      </div>
      <div class="facts">
        ${facts.map(([k, v]) => html`<div class="fact"><span class="fk">${k}</span><span class="fv">${v}</span></div>`)}
      </div>
      ${onBrowseFunctions && fnCount ? html`
        <button class="disasm-drill" onClick=${() => onBrowseFunctions(target.id)}
          title="browse the recovered functions and open any one's disassembly / decompilation">
          <span class="dd-ico">⟨⟩</span>
          <span class="dd-lbl">Disassembly</span>
          <span class="dd-n">${fnLabel}</span>
          <span class="dd-go">browse →</span>
        </button>` : null}
      ${dangerous.length ? html`
        <div class="dang">
          <span class="dang-lbl">Dangerous imports</span>
          ${dangerous.map((s) => html`<code class="dang-sym">${s}</code>`)}
        </div>` : null}
      <div class="hashes">
        ${[["SHA-256", target.sha256], ["MD5", target.md5], ["SHA-1", target.sha1]]
          .filter(([, v]) => v).map(([k, v]) => html`
            <div class="hash-row"><span class="hk">${k}</span><code class="hv" title=${v}>${v}</code></div>`)}
      </div>
      ${advice && advice.headline ? html`<div class="headline">${advice.headline}</div>` : null}
    </div>`;
}

// A single log row. A STAGE row shows a status icon that transitions in place -- a spinner while
// running, a green check when done, a red cross on error -- so "what is still running" is one
// glance, never two lines. An INFO row is a plain note (advice headline, "N distinct crashes").
function LogRow({ e }) {
  if (e.kind === "stage") {
    // Each terminal status gets its OWN mark. Only "done" is a green check; a stage that declined,
    // was skipped, timed out or was cancelled did NOT accomplish its work and must say so.
    const MARK = { error: ["st-bad", "✕"], timeout: ["st-decl", "⧖"],
                   declined: ["st-decl", "⊘"], skipped: ["st-skip", "–"],
                   cancelled: ["st-skip", "■"], done: ["st-ok", "✓"] };
    const [cls, ch] = MARK[e.status] || MARK.done;
    const icon = e.status === "running" ? html`<span class="st-run"></span>`
      : html`<span class=${`st-ico ${cls}`}>${ch}</span>`;
    return html`
      <li class=${`log-row st-${e.status}`}>
        ${icon}
        <span class="log-label">${e.label}</span>
        ${e.status === "running" && e.progress
          ? html`<span class="log-progress">${e.progress}</span>`
          : (e.detail ? html`<span class="log-detail">${e.detail === "cached" ? "" : e.detail}</span>` : null)}
        ${e.cached ? html`<span class="log-cached">cached</span>` : null}
      </li>`;
  }
  return html`
    <li class=${`log-row info tone-${e.tone || "info"}`}>
      <span class="log-dot"></span><span class="log-text">${e.text}</span>
    </li>`;
}

// The live log of what Autopilot is doing. A header calls out the CURRENT stage while running.
export function ProgressLog({ entries, running }) {
  if (!entries.length && !running) return null;
  const current = running ? [...entries].reverse().find((e) => e.kind === "stage" && e.status === "running") : null;
  return html`
    <div class="card log">
      <div class="log-head">
        ${running
          ? html`<${Spinner} label=${current ? current.label : "Autopilot running"} />`
          : "Run log"}
      </div>
      <ol class="log-list">
        ${entries.map((e) => html`<${LogRow} key=${e.id} e=${e} />`)}
      </ol>
    </div>`;
}

// The LIVE FUZZING panel: a real-time readout of the campaign in flight, so a long run is never a
// black box. Fed by the stage's `.progress` heartbeat (every ~3 s, even when the target is slow),
// it shows how far through the budget it is, the execution rate, coverage reached, and the running
// crash tally -- the numbers an operator otherwise had to guess at for half an hour.
function _fmtN(n) {
  if (n == null || isNaN(n)) return "—";
  n = Number(n);
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
}
// U2 live state badge: Running (coverage growing) / coverage steady (plateauing — the convergence
// signal) / stalled (heartbeats stopped). Colours: ok=green, warn=amber, bad=red.
const _FS_COLOR = { ok: "#2ec28a", warn: "#d9a441", bad: "#e5534b" };
function FuzzStateBadge({ state }) {
  if (!state || !state.label) return null;
  const c = _FS_COLOR[state.tone] || "#8a94a6";
  return html`<span style=${`margin-left:8px;font-size:.72rem;font-weight:600;color:${c};`
    + `border:1px solid ${c}55;border-radius:10px;padding:1px 8px;white-space:nowrap`}>${state.label}</span>`;
}

// A persistent, whole-run live header for the Console (the activity hub). FuzzConsole only renders
// during a fuzz stage -- it needs live `.progress` telemetry -- so recover / detect / prove showed
// nothing live. This shows for EVERY phase, driven by the background status (`bg`): the current
// stage, how far through the plan, which target (when multi-binary), and elapsed / budget / ETA,
// whether the run is foreground or detached. It reuses the fz-* card styling (no new CSS).
export function RunHeader({ bg }) {
  if (!bg) return null;
  if (!(bg.running || bg.state === "running" || bg.state === "starting")) return null;
  const now = Number(bg.now) || Date.now() / 1000;
  const started = Number(bg.started) || now;
  const elapsed = Math.max(0, now - started);
  const budget = Number(bg.budget_seconds) || 0;
  const converge = !!bg.converge;
  const eta = budget && elapsed < budget ? budget - elapsed : null;
  const pct = budget ? Math.min(100, 100 * elapsed / budget) : 0;
  const plan = bg.plan || [];
  const DONE = { done: 1, skipped: 1, declined: 1, cancelled: 1, error: 1, timeout: 1 };
  const done = plan.filter((p) => DONE[p.state]).length;
  const cur = bg.stage ? plan.find((p) => p.stage === bg.stage) : null;
  const stageLabel = bg.paused ? "Paused" : (cur ? cur.label : (bg.stage || "starting"));
  const multi = Number(bg.targets) > 1;
  const stat = (label, value, cls) => html`
    <div class="fz-stat"><div class="fz-stat-v ${cls || ""}">${value}</div><div class="fz-stat-k">${label}</div></div>`;
  return html`
    <div class="card fz">
      <div class="fz-head">
        <${Spinner} label=${bg.paused ? "Paused" : `Run — ${stageLabel}`} />
        <span class="fz-budget">${fmtElapsed(elapsed)}${budget ? ` / ${fmtElapsed(budget)}` : ""}${
          eta != null ? html` · <span class="fz-eta">${converge
            ? `ceiling ~${fmtElapsed(eta)}` : `~${fmtElapsed(eta)} left`}</span>` : ""}</span>
      </div>
      ${budget ? html`<div class="fz-bar"><div class="fz-fill" style=${`width:${Math.max(2, Math.min(100, pct))}%`}></div></div>` : null}
      <div class="fz-stats">
        ${stat("stage", plan.length ? `${done}/${plan.length}` : "—")}
        ${multi ? stat("target", `${(Number(bg.target) || 0) + 1}/${bg.targets}`) : null}
      </div>
    </div>`;
}

// How each fuzz attempt ENDED (fuzz/attempts.py). The palette reads at a glance: green ran
// cleanly, grey exited with an error (normal for most mutated inputs), amber hung, red crashed,
// and the dark-red "never reached the program" is the error-loop signal.
export const OUTCOME_META = {
  clean_exit: { label: "ran clean", color: "var(--ok)" },
  error_exit: { label: "error exit", color: "var(--info)" },
  timeout: { label: "timeout", color: "var(--warn)" },
  crash: { label: "crash", color: "var(--high)" },
  no_start: { label: "never reached", color: "var(--bad)" },
};
const _OUTCOME_ORDER = ["clean_exit", "error_exit", "timeout", "crash", "no_start"];

// A thin stacked bar + legend of attempt outcomes. `counts` is {outcome: n}.
export function OutcomeBar({ counts, compact }) {
  const c = counts || {};
  const total = _OUTCOME_ORDER.reduce((a, k) => a + (Number(c[k]) || 0), 0);
  if (!total) return null;
  const parts = _OUTCOME_ORDER.filter((k) => Number(c[k]) > 0);
  return html`
    <span class=${`ob${compact ? " ob-compact" : ""}`}>
      <span class="ob-bar" role="img" aria-label=${parts.map((k) => `${OUTCOME_META[k].label} ${c[k]}`).join(", ")}>
        ${parts.map((k) => html`<span class="ob-seg" title=${`${OUTCOME_META[k].label}: ${_fmtN(c[k])} (${Math.round(100 * c[k] / total)}%)`}
          style=${`width:${Math.max(1.5, 100 * c[k] / total)}%;background:${OUTCOME_META[k].color}`}></span>`)}
      </span>
      ${compact ? null : html`<span class="ob-legend">${parts.map((k) => html`
        <span class="ob-key"><i style=${`background:${OUTCOME_META[k].color}`}></i>${OUTCOME_META[k].label} ${Math.round(100 * c[k] / total)}%</span>`)}</span>`}
    </span>`;
}

// Live: is this campaign an error loop? True once enough attempts are in and (almost) none reached
// the program -- the one live signal worth shouting about.
function _liveErroring(oc) {
  const c = oc || {};
  const total = _OUTCOME_ORDER.reduce((a, k) => a + (Number(c[k]) || 0), 0);
  return total >= 20 && (Number(c.no_start) || 0) >= 0.9 * total;
}

export function FuzzConsole({ live, state, converge, compact }) {
  if (!live) return null;
  const budget = Number(live.budget) || 0;
  const elapsed = Number(live.elapsed) || 0;
  const pct = live.pct != null ? Number(live.pct) : (budget ? Math.min(100, 100 * elapsed / budget) : 0);
  const eta = budget && elapsed < budget ? budget - elapsed : null;
  const edges = live.blocks_hit != null ? live.blocks_hit : null;
  const known = live.blocks_known || 0;
  const cov = (edges != null && known) ? `${edges}/${known} (${Math.round(100 * edges / known)}%)`
    : (edges != null ? `${edges}` : "—");
  // Compact: a single-line pulse for the always-on top strip, so live fuzzing is visible on every
  // tab WITHOUT repeating the full telemetry card that the Console tab already owns. The user saw
  // the big panel twice (top + Console); this is the top half, deliberately slim.
  if (compact) {
    return html`
      <div class="card fz fz-compact">
        <${Spinner} label=${live.label || "Fuzzing"} />
        <${FuzzStateBadge} state=${state} />
        <span class="fz-compact-stats">
          <span><b>${_fmtN(live.execs)}</b> execs</span>
          <span><b>${_fmtN(live.execs_per_sec)}</b>/s</span>
          <span>cov <b>${cov}</b></span>
          <span class=${Number(live.crashes) > 0 ? "fz-hit" : ""}><b>${_fmtN(live.crashes)}</b> crashes</span>
          ${live.outcomes ? html`<${OutcomeBar} counts=${live.outcomes} compact=${true} />` : null}
          ${_liveErroring(live.outcomes) ? html`<span class="fz-err">erroring: no attempt is reaching the program</span>` : null}
        </span>
        <span class="fz-budget">${fmtElapsed(elapsed)}${budget ? ` / ${fmtElapsed(budget)}` : ""}${
          eta != null ? html` · <span class="fz-eta">${converge
            ? `ceiling ~${fmtElapsed(eta)}` : `~${fmtElapsed(eta)} left`}</span>` : ""}</span>
        <span class="fz-compact-hint">full telemetry in the Console tab →</span>
      </div>`;
  }
  const stat = (label, value, cls) => html`
    <div class="fz-stat">
      <div class="fz-stat-v ${cls || ""}">${value}</div>
      <div class="fz-stat-k">${label}</div>
    </div>`;
  return html`
    <div class="card fz">
      <div class="fz-head">
        <${Spinner} label=${live.label || "Fuzzing"} />
        <${FuzzStateBadge} state=${state} />
        <span class="fz-budget">${fmtElapsed(elapsed)}${budget ? ` / ${fmtElapsed(budget)}` : ""}${
          eta != null ? html` · <span class="fz-eta">${converge
            ? `ceiling ~${fmtElapsed(eta)}` : `~${fmtElapsed(eta)} left`}</span>` : ""}</span>
      </div>
      <div class="fz-bar"><div class="fz-fill" style=${`width:${Math.max(2, Math.min(100, pct))}%`}></div></div>
      <div class="fz-stats">
        ${stat("execs", _fmtN(live.execs))}
        ${stat("exec/s", _fmtN(live.execs_per_sec))}
        ${stat("coverage", cov)}
        ${stat("behaviours", _fmtN(live.behaviours))}
        ${stat("crashes", _fmtN(live.crashes), (Number(live.crashes) > 0 ? "fz-hit" : ""))}
      </div>
      ${live.outcomes ? html`
        <div class="fz-outcomes">
          <span class="fz-outcomes-k">how attempts are ending</span>
          <${OutcomeBar} counts=${live.outcomes} />
        </div>` : null}
      ${_liveErroring(live.outcomes) ? html`
        <div class="fz-err-banner">Erroring: ${_fmtN(live.outcomes.no_start)} attempts so far never reached the
          program (it is not starting, or the input is not being delivered). Nothing is being tested —
          the engine's attempt log will quote the error when it finishes.</div>` : null}
    </div>`;
}

// R1 (doc 47): per-engine fuzzing health. The honest answer to "why did this run find nothing
// dynamically" -- afl could not instrument the target (handshake/loader), a campaign was starved,
// the target reached no code because it needs a config/args, or the engine was simply not
// applicable (no source for libFuzzer, not a server for net_fuzz). A `verdict` of "none" is the
// alert that a static-only result here is a tooling outcome, not a clean binary. Fed by the
// server's `fuzz.health` event / scorecard, so the GUI never silently presents an empty run.
const _FH_COLOR = { ok: "#2ec28a", failed: "#e5534b", error: "#e5534b", noprogress: "#d9a441",
                    starved: "#d9a441", no_gain: "#d9a441", stalled: "#d9a441", declined: "#8a94a6", skipped: "#8a94a6",
                    not_run: "#8a94a6" };
const _FH_LABEL = { ok: "ran", failed: "FAILED", error: "error", noprogress: "no progress",
                    starved: "starved", no_gain: "no gain", stalled: "stalled", declined: "n/a", skipped: "skipped",
                    not_run: "—" };

// "Did it earn its time": coverage the seeds reached vs. what mutation added, and when it last grew.
function _valueLine(v) {
  if (!v || !["blocks", "behaviours", "edges"].includes(v.unit) || v.gained == null) return null;
  const bits = [`+${_fmtN(v.gained)} ${v.unit} beyond seeds (seeds: ${_fmtN(v.seed_coverage || 0)})`];
  if (v.last_gain_s != null) {
    bits.push(`last gain at ${fmtElapsed(v.last_gain_s)}${v.idle_tail_pct != null ? `, idle the last ${v.idle_tail_pct}%` : ""}`);
  } else if (v.gained === 0) {
    bits.push("never gained");
  }
  return bits.join(" · ");
}
const _FH_ENGINE = { coverage_fuzz: "coverage-guided (AFL)", fuzz: "blind fuzz",
                     directed_fuzz: "sink-directed", net_fuzz: "network/socket",
                     boundary_fuzz: "IPC/boundary", env_fuzz: "environment",
                     libfuzzer: "libFuzzer (source)", concolic: "concolic solver" };

// The results-tab counterpart to FuzzHealthPanel. When no dynamic engine ran (verdict "none") the
// point is NOT "go make it run" -- the deterministic synthesizers (synthesize_poc, build_exploit
// auto, synthesize_injection, concolic) are supposed to carry static findings to L2/L3 *candidates*
// with no execution at all. So this banner reports that dynamic VERIFICATION was unavailable (so
// rungs are candidate, not confirmed) and tells the operator execution is an OPTIONAL extra
// verifier -- it does not frame library-staging as the way to get results.
export function DynamicCoverageBanner({ health, ran }) {
  if (!ran || !health || !Array.isArray(health.engines) || !health.engines.length) return null;
  const v = health.verdict;
  if (v !== "none" && v !== "degraded") return null;
  const none = v === "none";
  const color = none ? "#d9a441" : "#d9a441";
  const bg = "rgba(217,164,65,.08)";
  return html`
    <div class="card" style=${`border-left:3px solid ${color};background:${bg};padding:12px 14px;margin-bottom:12px`}>
      <div style="font-weight:700;font-size:13px;display:flex;align-items:center;gap:8px">
        <span style=${`color:${color}`}>${none ? "Dynamic verification unavailable" : "Dynamic verification degraded"}</span>
        <span style="font-weight:500;opacity:.7;font-size:12px">— rungs below are candidates, not executed here</span>
      </div>
      <div style="font-size:12.5px;opacity:.9;margin-top:6px;line-height:1.5">${health.note}</div>
      ${none ? html`
        <div style="font-size:12px;opacity:.85;margin-top:8px;line-height:1.5">
          The deterministic analysis — static recovery, taint, the exploit synthesizers — runs
          regardless and produces findings and PoC/exploit <i>recipes</i> without executing anything.
          Those are the deliverables here. Running the target (optional: point the <b>target
          libraries dir</b> field at its loader + <code>.so</code>s, or ingest it as a directory)
          only adds <i>confirmation</i> — it turns a candidate rung into an executed one. It is not
          required to get the PoC.
        </div>` : null}
    </div>`;
}

export function FuzzHealthPanel({ health, onOpenLog }) {
  if (!health || !Array.isArray(health.engines) || !health.engines.length) return null;
  const v = health.verdict;
  const banner = v === "ok" ? "#2ec28a" : (v === "degraded" || v === "idle") ? "#d9a441" : "#e5534b";
  return html`
    <div class="card" style="padding:10px 12px">
      <div style=${`border-left:3px solid ${banner};padding-left:10px;margin-bottom:8px`}>
        <div style="font-weight:600;font-size:13px">Fuzzing engine health</div>
        <div style="font-size:12px;opacity:.8;margin-top:2px">${health.note}</div>
      </div>
      <div>
        ${health.engines.map((e) => {
          const val = _valueLine(e.value);
          return html`
          <div key=${e.engine} class="fh-row">
            <div style="display:flex;gap:10px;align-items:baseline;font-size:12px">
              <span style="flex:0 0 150px">${_FH_ENGINE[e.engine] || e.engine}</span>
              <span style=${`flex:0 0 72px;font-weight:600;color:${_FH_COLOR[e.status] || "#8a94a6"}`}>${_FH_LABEL[e.status] || e.status}</span>
              <span style="flex:1;opacity:.75;min-width:0">${
                e.status === "ok"
                  ? `${_fmtN(e.execs)} execs${e.afl_execs ? ` (AFL: ${_fmtN(e.afl_execs)})` : ""}${e.coverage ? ` · ${e.coverage}` : ""}${e.reason ? ` — ${e.reason}` : ""}`
                  : (e.reason || "")}</span>
              ${e.log && onOpenLog ? html`<button class="btn xsmall ghost" title="every attempt this engine made: what was sent and how it ended"
                onClick=${() => onOpenLog(e.log, e.engine)}>attempt log</button>` : null}
            </div>
            ${e.outcomes || val ? html`
              <div class="fh-detail">
                ${e.outcomes ? html`<${OutcomeBar} counts=${e.outcomes} />` : null}
                ${val ? html`<span class="fh-value">${val}</span>` : null}
              </div>` : null}
          </div>`; })}
      </div>
    </div>`;
}

// A live console: the actual tool commands (rizin, angr, afl, pypcode worker...) and a tail of
// their I/O, streamed from the server's job.exec events. Separate from the Run log (which is the
// human "what it found"): this is the "what it is doing right now", proof that work is happening.
function fmtMs(ms) {
  if (ms == null) return "";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

export function ConsolePanel({ lines }) {
  const [open, setOpen] = useState(true);
  const bodyRef = useRef(null);
  const atBottom = useRef(true);
  const shown = (lines || []).slice(-250);
  // Auto-scroll to the newest line, but only if the user is already at the bottom (so scrolling
  // up to read history is not yanked away every time a command completes).
  useEffect(() => {
    const el = bodyRef.current;
    if (el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [shown.length, open]);
  if (!lines || !lines.length) return null;
  const onScroll = (e) => {
    const el = e.target;
    atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };
  return html`
    <div class="card console">
      <button class="console-head" onClick=${() => setOpen(!open)}>
        <span class="console-title">▚ Console</span>
        <span class="console-sub">tool commands &amp; I/O</span>
        <span class="console-count">${lines.length}</span>
        <span class="console-toggle">${open ? "▾" : "▸"}</span>
      </button>
      ${open ? html`
        <div class="console-body" ref=${bodyRef} onScroll=${onScroll}>
          ${shown.map((l) => html`
            <div class=${`con-line con-${l.note ? "kill" : (l.rc === 0 ? "ok" : (l.rc == null ? "kill" : "bad"))}`} key=${l.id}>
              <div class="con-cmd"><span class="con-prompt">$</span> <span class="con-text">${l.cmd}</span>
                <span class="con-meta">${l.note ? html`<span class="con-note">${l.note}</span>`
                  : html`<span class="con-rc">${l.rc === 0 ? "ok" : `rc ${l.rc}`}</span>`}${l.ms != null ? html` <span class="con-ms">${fmtMs(l.ms)}</span>` : null}</span>
              </div>
              ${l.out ? html`<pre class="con-out">${l.out}</pre>` : null}
              ${l.err ? html`<pre class="con-out con-err">${l.err}</pre>` : null}
            </div>`)}
        </div>` : null}
    </div>`;
}

// One finding, results-first. Demonstrated findings are visually loud; candidates are quiet.
// The PoC bundle and the exploit steps are the payload the user came for, so they lead.
// Pull the exploitability rating (EXPLOITABLE 90/100 ...) out of the evidence trail.
function exploitabilityOf(evList) {
  const e = (evList || []).find((x) => x && x.channel === "exploitability");
  if (!e) return null;
  const m = /exploitability:\s*([A-Z_]+)\s*\((\d+)\/100\)\s*(?:--\s*)?(.*)/.exec(e.detail || "");
  if (!m) return { text: e.detail };
  return { rating: m[1], score: +m[2], why: m[3] };
}
const RATING_CLASS = {
  EXPLOITABLE: "exp-hi", PROBABLY_EXPLOITABLE: "exp-hi",
  UNKNOWN: "exp-mid", PROBABLY_NOT_EXPLOITABLE: "exp-lo", NOT_EXPLOITABLE: "exp-lo",
};
function fmtAddr(a) {
  if (a == null) return null;
  if (typeof a === "string") return a;
  try { return `0x${a.toString(16)}`; } catch { return String(a); }
}

// Concrete exploitation next-steps by fault class. Not a promise the tool will do it -- a
// pointer to what an analyst does next, tuned by the binary's mitigations (a stack overwrite
// with NX on needs ROP; with PIE off the gadgets are at fixed addresses).
const NEXT_STEPS = {
  "stack-return-overwrite": (m) => [
    "The saved return address is overwritten — find the exact offset to RIP.",
    (m && m.nx === "on")
      ? "NX is on: chain gadgets (ROP) or ret2libc; try one_gadget if the libc is known."
      : "NX is off: you may be able to jump straight to shellcode on the stack.",
    (m && m.pie === "off")
      ? "PIE is off: gadget and function addresses are fixed — build the chain directly."
      : "PIE is on: leak a code address first to defeat ASLR.",
    (m && m.canary === "on") ? "A stack canary is present: you need an info-leak to read it first." : null,
  ],
  "heap-buffer-overflow": () => [
    "Overflow reaches adjacent heap memory — corrupt a neighbouring object's pointer or size.",
    "Aim for a function pointer, vtable, or allocator metadata reachable after the overwrite.",
  ],
  "null-pointer-dereference": () => [
    "A NULL/near-NULL dereference is usually a denial of service.",
    "Escalate only if the offset from NULL is attacker-controlled into mapped memory.",
  ],
  "out-of-bounds-read": () => [
    "Out-of-bounds read leaks adjacent memory — use it as an info-leak.",
    "Leak a stack canary or a code/libc address, then pair it with a write primitive.",
  ],
  "control-flow-hijack": (m) => [
    "Execution was redirected — you already control the instruction pointer.",
    (m && m.pie === "off") ? "PIE off: point it at a chosen gadget/function directly." : "Leak a code address, then aim the control.",
  ],
};
function faultClassOf(rootCause) {
  const m = /^([a-z-]+)\s*\(/.exec((rootCause || "").trim());
  return m ? m[1] : null;
}

// One finding, results-first. The exploitation section is the payload: the exploitability
// rating, the mechanism (root cause), how the crash is reached, where it faults, and the
// downloadable verified reproducer. This is "how the binary can actually be exploited."
// The operator's triage of a finding (doc 47 P3): false positive / true positive / needs review,
// plus a note. Hook-free on purpose (the note editor is an uncontrolled form read on submit), so the
// card stays a pure function of its props. It sits BESIDE the tool's own state badge and never
// replaces it -- the tool's evidence and L-level are unchanged by anything the operator marks here.
const CURATION_TIP = {
  false_positive: "Mark as a false positive: hidden from the default findings list (the tool's evidence and level are kept)",
  true_positive: "Mark as a real issue you have reviewed (operator judgement, separate from the tool's 'confirmed' state)",
  needs_review: "Flag for follow-up",
};
export function CurationChip({ curation }) {
  const st = curation && curation.status;
  if (!st && !(curation && curation.note)) return null;
  return html`<span class=${`cur-chip cur-${st || "note"}`}
    title=${`operator triage${curation.note ? ": " + curation.note : ""}`}>
    ${st ? CURATION_LABEL[st] || st : "note"}</span>`;
}
export function CurationBar({ finding, onCurate }) {
  if (!onCurate) return null;
  const cur = finding.curation || null;
  const status = cur && cur.status;
  const note = (cur && cur.note) || "";
  // Clicking the active status clears it (the note is kept).
  const set = (st) => onCurate(finding, st === status ? null : st, note);
  const n = finding.group_count > 1 ? finding.group_count : 0;
  return html`
    <div class="curation">
      <span class="cur-lbl">Triage${n ? html` <span class="cur-grp" title="this card folds several findings; the triage applies to all of them">(${n})</span>` : null}</span>
      ${CURATION_STATUSES.map((st) => html`<button type="button" key=${st}
        class=${`cur-btn cur-${st}${status === st ? " on" : ""}`} aria-pressed=${status === st ? "true" : "false"}
        title=${status === st ? "click again to clear" : CURATION_TIP[st]} onClick=${() => set(st)}>
        ${CURATION_LABEL[st]}</button>`)}
      <details class="cur-note">
        <summary>${note ? "✎ edit note" : "+ note"}</summary>
        <form key=${(cur && cur.updated_at) || 0} onSubmit=${(e) => {
          e.preventDefault();
          const el = e.currentTarget && e.currentTarget.elements && e.currentTarget.elements.note;
          onCurate(finding, status, el ? el.value : note);
        }}>
          <textarea name="note" rows="3" maxlength="4000" aria-label="triage note"
            placeholder="why — e.g. unreachable from input, test-only code, reproduced manually…"
            defaultValue=${note}></textarea>
          <button class="btn xsmall" type="submit">Save note</button>
        </form>
      </details>
      ${note ? html`<div class="cur-note-text">${note}</div>` : null}
    </div>`;
}

// Operator-triage filter for the findings list, with what each choice hides counted, so a hidden
// false positive is never invisible -- the count says it is there and one click shows it.
export function CurationFilter({ mode, onChange, counts }) {
  const c = counts || {};
  const hidden = mode === "hide_fp" ? (c.false_positive || 0) : 0;
  return html`
    <div class="cur-filter">
      <label>Triage
        <select value=${mode} onChange=${(e) => onChange && onChange(e.target.value)} aria-label="filter findings by triage">
          ${CURATION_FILTERS.map(([v, lbl]) => html`<option key=${v} value=${v}>${lbl}${
            v === "false_positive" || v === "true_positive" || v === "needs_review" ? ` (${c[v] || 0})`
            : v === "uncurated" ? ` (${c.uncurated || 0})` : ""}</option>`)}
        </select>
      </label>
      ${hidden ? html`<button type="button" class="btn xsmall ghost" onClick=${() => onChange && onChange("all")}>
        ${hidden} marked false positive hidden — show</button>` : null}
    </div>`;
}

export function FindingCard({ finding, pocs, reportUrl, artifactUrl, onViewCode, mitigations, onInspect, onCurate, onShowInGraph, onStage }) {
  const inspect = (ch) => onInspect && onInspect(finding, ch);
  const demo = isDemonstrated(finding);
  const evRaw = finding.evidence;
  const evList = Array.isArray(evRaw) ? evRaw : [];
  const legacySteps = !Array.isArray(evRaw) && evRaw ? (evRaw.exploit_steps || evRaw.steps) : null;
  const exp = exploitabilityOf(evList);
  const rootCause = (evList.find((x) => x.channel === "root-cause") || {}).detail;
  const inputPoc = (pocs || []).find((p) => p.input_sha);
  const steps = (NEXT_STEPS[faultClassOf(rootCause)] || (() => []))(mitigations || {}).filter(Boolean);
  const howFound = evList.filter((x) => x.channel === "dynamic" && !/PoC verified/i.test(x.detail || "")).map((x) => x.detail);
  const other = evList.filter((x) => !["exploitability", "root-cause", "dynamic", "poc", "effects"].includes(x.channel)).map((x) => x.detail);
  // The end effects the defect can reach -- what the PoC strives to achieve -- each with a
  // status (demonstrated: a PoC gets there; potential: the class implies it) and, when
  // demonstrated, a PROOF artifact (the crashing input for DoS, the L2 primitive bundle for
  // RCE/write/leak) so the badge is backed by real evidence, not just a label.
  let effects = [];
  try { effects = JSON.parse((evList.find((x) => x.channel === "effects") || {}).detail || "[]"); }
  catch { effects = []; }
  const site = fmtAddr(finding.site_addr) || fmtAddr(finding.function_addr);
  const bundle = (pocs || []).find((p) => p.verified) || (pocs || [])[0];
  return html`
    <div class=${`card finding${demo ? " demo" : ""}${finding.curation && finding.curation.status === "false_positive" ? " cur-dim" : ""}`}>
      <div class="find-top">
        <${SevDot} severity=${finding.severity} />
        <div class="find-id">
          <div class="find-title">${finding.title || finding.detector || finding.cwe}</div>
          <div class="find-meta">
            <span class="cwe cwe-info" title=${cweTip(finding)}>${finding.cwe}</span>
            ${finding.detector ? html`<span class="det">via ${finding.detector}</span>` : null}
            ${finding.stage_label ? (onStage && finding.stage
              ? html`<button class="det stage-prov clk" title="show every finding this pipeline stage discovered"
                  onClick=${() => onStage(finding.stage, finding.stage_label)}>found by ${finding.stage_label}</button>`
              : html`<span class="det stage-prov" title="the pipeline stage that discovered this finding">found by ${finding.stage_label}</span>`) : null}
            ${site ? html`<span class="at">at <code>${site}</code></span>` : null}
            ${finding.group_count > 1 ? html`<span class="sites">${finding.group_count} occurrences</span>` : (finding.site_count ? html`<span class="sites">${finding.site_count} site${finding.site_count === 1 ? "" : "s"}${finding.proven_sites ? ` · ${finding.proven_sites} proven` : ""}</span>` : null)}
          </div>
        </div>
        <${CurationChip} curation=${finding.curation} />
        <${Badge} state=${finding.state} />
      </div>
      <div class="find-gloss">${STATE_GLOSS[finding.state] || ""}</div>

      ${finding.analysis ? html`
        <div class="find-ladder">
          <div class="fl-why"><b>${finding.analysis.state}:</b> ${finding.analysis.why_state}</div>
          ${finding.analysis.to_promote ? html`<div class="fl-next">
            <b>To reach ${finding.analysis.next_state}:</b> ${finding.analysis.to_promote}</div>` : null}
        </div>` : null}

      ${finding.reachability && finding.reachability.attack_surface ? html`
        <div class=${`find-surface ${finding.reachability.attack_surface === "on" ? "surf-on" : "surf-off"}`}
          title="whether this finding's code is compiled into an in-tree fuzz harness">
          ${finding.reachability.attack_surface === "on"
            ? "On the fuzzed attack surface — higher remote-reachability priority"
            : "Off the fuzzed attack surface — lower remote-reachability priority, not dismissed"}
        </div>` : null}

      ${finding.exploitability ? html`
        <div class="find-exploit2">
          <div class="fx-head">Exploitability</div>
          <ul>
            ${finding.exploitability.class_primitive ? html`<li>
              <span class="fx-k">Primitive (class)</span> ${finding.exploitability.class_primitive}</li>` : null}
            ${finding.exploitability.demonstrated_level ? html`<li>
              <span class="fx-k">Demonstrated</span> a verified PoC reached ${finding.exploitability.demonstrated_level}</li>` : null}
            ${finding.exploitability.ceiling ? html`<li>
              <span class="fx-k">Ceiling</span> weaponization reached ${finding.exploitability.ceiling} and stopped${finding.exploitability.ceiling_reason ? ` — ${finding.exploitability.ceiling_reason}` : ""}</li>` : null}
            ${finding.exploitability.targets_live ? html`<li>
              <span class="fx-k">Live target</span> this recipe targets ${finding.exploitability.targets_live}</li>` : null}
            ${(finding.exploitability.mitigations_in_way || []).map((m) => html`<li>
              <span class="fx-k">In the way</span> ${m}</li>`)}
          </ul>
        </div>` : null}

      ${effects.length ? html`
        <div class="effects-block">
          <div class="effects">
            <span class="effects-head">End effect</span>
            ${effects.map((e) => html`<span class=${`effect-badge ${e.status === "demonstrated" ? "eff-demo" : "eff-pot"}`}
              title=${e.status === "demonstrated" ? "a proof-of-concept achieves this" : "the defect class can be driven to this; not yet demonstrated"}>
              ${e.status === "demonstrated" ? "✓ " : "○ "}${e.title}<span class="eff-status">${e.status}</span></span>`)}
          </div>
          ${effects.filter((e) => e.status === "demonstrated" && (e.detail || e.proof)).length ? html`
            <ul class="effect-proofs">
              ${effects.filter((e) => e.status === "demonstrated").map((e) => html`
                <li>
                  <span class="ep-k">${e.title}</span>
                  ${e.proof && e.proof.note ? html`<span class="ep-note">${e.proof.note}</span>`
                    : (e.detail ? html`<span class="ep-note">${e.detail}</span>` : null)}
                  ${e.proof && e.proof.sha ? html`<a class="btn xsmall" href=${artifactUrl(e.proof.sha)} download
                    title=${e.proof.type === "bundle" ? "the PoC bundle that demonstrates this effect"
                      : e.proof.type === "artifact" ? "the captured evidence (e.g. leaked memory)"
                      : "the input that achieves this effect"}>⬇ ${
                    e.proof.type === "bundle" ? "proof PoC" : e.proof.type === "artifact" ? "leaked bytes" : "proof input"}</a>` : null}
                </li>`)}
            </ul>` : null}
        </div>` : null}

      ${exp ? html`
        <div class=${`exploit-rating ${RATING_CLASS[exp.rating] || "exp-mid"}${onInspect ? " clk" : ""}`}
          onClick=${() => inspect("exploitability")} title=${onInspect ? "inspect the exploitability evidence" : null}>
          <span class="er-badge">${exp.rating ? exp.rating.replace(/_/g, " ") : "assessed"}${exp.score != null ? ` · ${exp.score}/100` : ""}</span>
          ${exp.why || exp.text ? html`<span class="er-why">${exp.why || exp.text}</span>` : null}
        </div>` : null}

      ${(rootCause || howFound.length || other.length || legacySteps) ? html`
        <div class="exploit">
          <div class="exploit-head">How it can be exploited${onInspect ? html` <span class="ev-hint">— click any line to go deeper</span>` : null}</div>
          <ol class=${`exploit-trail${onInspect ? " clk" : ""}`}>
            ${rootCause ? html`<li onClick=${() => inspect("root-cause")}><span class="et-k">Mechanism</span> ${rootCause}</li>` : null}
            ${howFound.map((h) => html`<li onClick=${() => inspect("dynamic")}><span class="et-k">Reached</span> ${h}</li>`)}
            ${other.map((o) => html`<li onClick=${() => inspect(null)}><span class="et-k">Evidence</span> ${o}</li>`)}
            ${legacySteps ? (Array.isArray(legacySteps) ? legacySteps : String(legacySteps).split("\n")).filter(Boolean).map((s) => html`<li onClick=${() => inspect(null)}>${typeof s === "string" ? s : (s.text || "")}</li>`) : null}
          </ol>
        </div>` : null}

      ${demo && steps.length ? html`
        <div class="nextsteps">
          <div class="steps-head">What an attacker does next</div>
          <ul>${steps.map((s) => html`<li>${s}</li>`)}</ul>
        </div>` : null}

      <div class="poc-row">
        ${bundle && bundle.bundle_sha ? html`
          <a class="btn small" href=${artifactUrl(bundle.bundle_sha)} download>⬇ PoC bundle${bundle.verified ? " (verified)" : ""}</a>
          ${bundle.level != null ? html`<span class="poc-level">${String(bundle.level).replace(/^L?/, "L")}</span>` : null}
          ${bundle.signal ? html`<span class="poc-sig">${bundle.signal}</span>` : null}
        ` : null}
        ${inputPoc && inputPoc.input_sha
          ? html`<a class="btn small ghost" href=${artifactUrl(inputPoc.input_sha)} download title="the exact input that triggers the crash">⬇ Crashing input</a>` : null}
        ${(finding.function_addr || finding.site_addr) && onViewCode
          ? html`<button class="btn small ghost" onClick=${() => onViewCode(finding)}>⟨⟩ View code</button>` : null}
        ${(finding.function_addr || finding.site_addr) && onShowInGraph
          ? html`<button class="btn small ghost" title="show this finding's function in the target's call graph"
              onClick=${() => onShowInGraph(finding)}>◎ Call graph</button>` : null}
        ${onInspect ? html`<button class="btn small ghost" onClick=${() => inspect(null)}>🔍 Inspect evidence</button>` : null}
        ${finding.verification ? html`<${VerifyBadge} v=${finding.verification} />` : null}
      </div>
      <${CurationBar} finding=${finding} onCurate=${onCurate} />
    </div>`;
}

// The result of the false-positive review: re-running a demonstrated finding's own crashing
// input several times. Deterministic every time -> real. Flaky -> flagged, not silently trusted.
export function VerifyBadge({ v }) {
  if (!v || v.runs == null) return null;
  const ok = v.crashed === v.runs;
  return html`<span class=${`verify ${ok ? "verify-ok" : "verify-flaky"}`}
    title=${`replayed the crashing input ${v.runs}x; crashed ${v.crashed}x${v.signal ? ` (${v.signal})` : ""}`}>
    ${ok ? `✓ verified ${v.crashed}/${v.runs}` : `⚠ flaky ${v.crashed}/${v.runs}`}</span>`;
}

// Click any piece of evidence -> the full trail, uncut. Every channel's complete detail, the end
// effects with their proof artifacts, the PoC bundle and crashing input, and a raw-JSON view for
// the power user -- so "why do you say this?" is always one click from an answer.
export function EvidenceModal({ finding, pocs, artifactUrl, onViewCode, onClose, focus, onShowInGraph }) {
  if (!finding) return null;
  const [raw, setRaw] = useState(false);
  const evList = Array.isArray(finding.evidence) ? finding.evidence : [];
  let effects = [];
  try { effects = JSON.parse((evList.find((x) => x.channel === "effects") || {}).detail || "[]"); } catch { effects = []; }
  const bundle = (pocs || []).find((p) => p.verified) || (pocs || [])[0];
  const inputPoc = (pocs || []).find((p) => p.input_sha);
  const site = fmtAddr(finding.site_addr) || fmtAddr(finding.function_addr);
  const chLabel = { "root-cause": "Root cause", dynamic: "Reached / how found", poc: "Proof of concept",
    exploitability: "Exploitability", effects: "End effects", exploit: "Exploit" };
  return html`
    <div class="modal-back" onClick=${onClose}>
      <div class="modal evidence" role="dialog" aria-modal="true" tabindex="-1"
        aria-label=${`Evidence for ${finding.title || finding.cwe || "finding"}`} onClick=${(e) => e.stopPropagation()}>
        <div class="ev-head">
          <div>
            <div class="ev-title"><${SevDot} severity=${finding.severity} /> ${finding.title || finding.cwe}</div>
            <div class="ev-sub"><span class="cwe cwe-info" title=${cweTip(finding)}>${finding.cwe}</span>
              ${finding.cwe_name ? html`<span class="cwe-name">${finding.cwe_name}</span>` : null}
              ${finding.detector ? html`<span class="det">via ${finding.detector}</span>` : null}
              ${site ? html`<span class="at">at <code>${site}</code></span>` : null}
              <${Badge} state=${finding.state} /> <${CurationChip} curation=${finding.curation} /></div>
            ${finding.curation && finding.curation.note ? html`<div class="cur-note-text">Triage note: ${finding.curation.note}</div>` : null}
          </div>
          <button class="btn ghost small" onClick=${onClose}>✕ Close</button>
        </div>

        ${effects.length ? html`
          <div class="ev-sec">
            <div class="ev-sec-h">End effects</div>
            <ul class="ev-effects">
              ${effects.map((e) => html`<li class=${e.status === "demonstrated" ? "eff-demo" : "eff-pot"}>
                <span class="ev-eff-t">${e.status === "demonstrated" ? "✓ " : "○ "}${e.title}</span>
                <span class="eff-status">${e.status}</span>
                ${(e.proof && e.proof.note) || e.detail ? html`<div class="ev-eff-note">${(e.proof && e.proof.note) || e.detail}</div>` : null}
                ${e.proof && e.proof.sha ? html`<a class="btn xsmall" href=${artifactUrl(e.proof.sha)} download>⬇ ${e.proof.type === "bundle" ? "proof PoC" : e.proof.type === "artifact" ? "captured bytes" : "proof input"}</a>` : null}
              </li>`)}
            </ul>
          </div>` : null}

        <div class="ev-sec">
          <div class="ev-sec-h">Evidence trail <span class="ev-count">${evList.length}</span></div>
          <ol class="ev-trail">
            ${evList.filter((e) => e.channel !== "effects").map((e) => html`
              <li class=${focus && focus === e.channel ? "ev-focus" : ""}>
                <span class="ev-ch">${chLabel[e.channel] || e.channel}</span>
                <span class="ev-detail">${e.detail || "(no detail)"}</span>
              </li>`)}
          </ol>
        </div>

        <div class="ev-sec ev-artifacts">
          ${bundle && bundle.bundle_sha ? html`<a class="btn small" href=${artifactUrl(bundle.bundle_sha)} download>⬇ PoC bundle${bundle.verified ? " (verified)" : ""}</a>` : null}
          ${inputPoc && inputPoc.input_sha ? html`<a class="btn small ghost" href=${artifactUrl(inputPoc.input_sha)} download>⬇ Crashing input</a>` : null}
          ${(finding.function_addr || finding.site_addr) && onViewCode ? html`<button class="btn small ghost" onClick=${() => { onClose(); onViewCode(finding); }}>⟨⟩ View code at ${site || "site"}</button>` : null}
          ${(finding.function_addr || finding.site_addr) && onShowInGraph ? html`<button class="btn small ghost" onClick=${() => { onClose(); onShowInGraph(finding); }}>◎ Show in call graph</button>` : null}
          <button class="btn small ghost" onClick=${() => setRaw((v) => !v)}>${raw ? "Hide" : "Show"} raw JSON</button>
        </div>
        ${raw ? html`<pre class="ev-raw">${JSON.stringify(finding, null, 2)}</pre>` : null}
      </div>
    </div>`;
}

// Browse the recovered functions and drill into any one -- reached from the disassembly summary
// and from the coverage panel. Filter by name/address; click a row to open its code. Functions
// with a real body (blocks > 0) sort first; the rest are thunks/stubs.
export function FunctionsModal({ name, functions, onOpen, onClose }) {
  const [q, setQ] = useState("");
  const loading = functions == null;
  const fns = functions || [];
  const ql = q.trim().toLowerCase();
  const filt = ql ? fns.filter((f) => (f.name || "").toLowerCase().includes(ql)
    || (f.addr || "").toLowerCase().includes(ql)) : fns;
  const sorted = [...filt].sort((a, b) => (b.blocks || 0) - (a.blocks || 0) || (b.size || 0) - (a.size || 0));
  const shown = sorted.slice(0, 600);
  return html`
    <div class="modal-back" onClick=${onClose}>
      <div class="modal funcs" role="dialog" aria-modal="true" tabindex="-1"
        aria-label=${`Functions in ${name}`} onClick=${(e) => e.stopPropagation()}>
        <div class="fn-head">
          <div class="fn-title">Functions · <span class="mono">${name}</span>
            <span class="fn-count">${loading ? "…" : fns.length}</span></div>
          <button class="btn ghost small" onClick=${onClose}>✕ Close</button>
        </div>
        <input class="fn-search" placeholder="filter by name or address…" value=${q}
          onInput=${(e) => setQ(e.target.value)} />
        ${loading ? html`<div class="fn-loading"><${Spinner} label="loading functions" /></div>` : html`
          <ol class="fn-list">
            ${shown.map((f) => html`
              <li class=${`fn-row${f.blocks ? "" : " fn-thin"}`} key=${f.id || f.addr} onClick=${() => onOpen(f)}
                title=${f.signature || (f.blocks ? "open code" : "stub / no body")}>
                <span class="fn-name">${f.name || "(unnamed)"}</span>
                <span class="fn-addr mono">${f.addr}</span>
                <span class="fn-meta">${f.blocks ? `${f.blocks} blk` : "stub"}${f.size ? ` · ${f.size}B` : ""}</span>
              </li>`)}
          </ol>
          ${sorted.length > shown.length ? html`<div class="fn-more">showing ${shown.length} of ${sorted.length} — filter to narrow</div>` : null}
          ${!sorted.length ? html`<div class="fn-more">no function matches "${q}"</div>` : null}`}
      </div>
    </div>`;
}

export function EmptyResults({ ran }) {
  return html`
    <div class="card empty">
      ${ran
        ? "No defects demonstrated on this input. The static findings above, if any, are capability evidence, not confirmed bugs."
        : "Findings will appear here, most-demonstrated first, as Autopilot works."}
    </div>`;
}

export function StageChip({ stage, status }) {
  return html`<span class=${`chip tone-${runTone(status)}`}>${stageLabel(stage)}</span>`;
}

// Is the decompiled text real code, or a tool's "install me" placeholder / empty stub?
function usableDecompile(s) {
  if (!s || s.trim().length < 24) return false;
  return !/you need to install|r2pm|not available|no decompiler/i.test(s);
}
// A hex address for matching a fault/sink site against an instruction.
function hexEq(a, b) {
  const n = (x) => (typeof x === "string" ? parseInt(x, 16) || parseInt(x, 10) : x);
  return a != null && b != null && n(a) === n(b);
}

// The code view: the actual function behind a finding. Decompiled C when the decompiler is
// wired, otherwise the disassembly the detectors ran on -- always something to read. The stack
// frame flags the buffers, the fault/sink site is highlighted, and the call edges let an analyst
// walk in and out. This is what turns "CWE-121 at 0x401156" into "here is the code, and here is
// A focused ("ego") call graph around ONE function: who calls it (top row) and what it calls
// (bottom row), drawn as an SVG the analyst clicks to re-center on a neighbour. Self-contained --
// no graph library, which is what makes it work in the air-gapped bundle. The full per-target edge
// list backs cross-binary navigation elsewhere; here it answers the question asked at a finding:
// how is this function reached, and what does it reach? Uses the callers/callees the function detail
// already carries, and the same onNavigate the text cross-refs use.
export function CallGraphMini({ fn, onNavigate }) {
  if (!fn) return null;
  const up = [...new Set((fn.callers || []).map((c) => c.src_name || c.name).filter(Boolean))];
  const dn = [...new Set((fn.callees || []).map((c) => c.dst_name || c.name).filter(Boolean))];
  if (!up.length && !dn.length) return null;
  const CAP = 7;
  const callers = up.slice(0, CAP), callees = dn.slice(0, CAP);
  const moreUp = up.length - callers.length, moreDn = dn.length - callees.length;
  const W = 720, nodeW = 92, nodeH = 26, gap = 10;
  const H = 200, yUp = 34, yC = H / 2, yDn = H - 34, xC = W / 2;
  const xAt = (n, i) => {
    const total = n * nodeW + (n - 1) * gap, start = (W - total) / 2;
    return start + i * (nodeW + gap) + nodeW / 2;
  };
  const trunc = (s) => (s.length > 13 ? s.slice(0, 12) + "…" : s);
  const node = (name, x, y, kind) => html`
    <g class=${`cg-node cg-${kind}`} onClick=${() => kind !== "center" && onNavigate && onNavigate(name)}>
      <rect x=${x - nodeW / 2} y=${y - nodeH / 2} width=${nodeW} height=${nodeH} rx="6"/>
      <text x=${x} y=${y + 4} text-anchor="middle">${trunc(name)}</text>
      <title>${name}${kind === "center" ? "" : " — click to open"}</title>
    </g>`;
  return html`
    <div class="callgraph">
      <div class="cg-lbl">Call graph <span class="cg-hint">${(up.length || dn.length) ? "click a node to follow it" : ""}</span></div>
      <svg viewBox=${`0 0 ${W} ${H}`} class="cg-svg" preserveAspectRatio="xMidYMid meet" role="img" aria-label="call graph">
        ${callers.map((n, i) => html`<line class="cg-edge" x1=${xAt(callers.length, i)} y1=${yUp + nodeH / 2} x2=${xC} y2=${yC - nodeH / 2}/>`)}
        ${callees.map((n, i) => html`<line class="cg-edge" x1=${xC} y1=${yC + nodeH / 2} x2=${xAt(callees.length, i)} y2=${yDn - nodeH / 2}/>`)}
        ${callers.map((n, i) => node(n, xAt(callers.length, i), yUp, "caller"))}
        ${node(fn.name || "sub", xC, yC, "center")}
        ${callees.map((n, i) => node(n, xAt(callees.length, i), yDn, "callee"))}
        ${moreUp > 0 ? html`<text class="cg-more" x=${W - 6} y=${yUp + 4} text-anchor="end">+${moreUp} more</text>` : null}
        ${moreDn > 0 ? html`<text class="cg-more" x=${W - 6} y=${yDn + 4} text-anchor="end">+${moreDn} more</text>` : null}
      </svg>
    </div>`;
}

// the overrun."
export function CodeView({ fn, finding, source, onClose, onNavigate, onFollowCaller, crumbs, xbinCallers }) {
  if (!fn) return null;
  const nav = (name) => onNavigate && name && onNavigate(name);
  const frame = fn.frame || {};
  const vars = frame.vars || frame.stack_vars || frame.locals || [];
  const buffers = (Array.isArray(vars) ? vars : []).filter((v) => /\[|char\s*\*|buf/i.test(`${v.type || ""}${v.name || ""}`));
  const site = (finding && (finding.site_addr || finding.function_addr));
  const dec = fn.decompiled;
  const blocks = (fn.ir && fn.ir.blocks) || [];
  const insns = [];
  for (const b of blocks) for (const ins of (b.instructions || [])) insns.push(ins);
  return html`
    <div class="modal-back" onClick=${onClose}>
      <div class="modal code" role="dialog" aria-modal="true" tabindex="-1"
        aria-label=${`Code for ${fn.name || "function"}`} onClick=${(e) => e.stopPropagation()}>
        <div class="code-head">
          <div>
            <div class="code-name">${fn.name || "sub"} <span class="code-addr">@ ${fn.addr}</span></div>
            ${fn.signature ? html`<code class="code-sig">${fn.signature}</code>` : null}
            ${crumbs && crumbs.length > 1 ? html`<div class="code-crumbs">${crumbs.map((c, i) => html`${i ? html`<span class="cb-sep">→</span>` : null}<span class="cb">${c}</span>`)}</div>` : null}
          </div>
          <button class="btn ghost small" onClick=${onClose}>✕ Close</button>
        </div>
        ${buffers.length ? html`
          <div class="frame">
            <span class="frame-lbl">Stack buffers</span>
            ${buffers.map((v) => html`<code class="frame-buf">${v.name || "?"}${v.type ? `: ${v.type}` : ""}${v.size != null ? ` (${v.size}B)` : ""}</code>`)}
          </div>` : null}
        <div class="code-body">
          ${source && source.source ? html`
            <div class="code-note">Compiled from source ${source.filename ? html`(${source.filename})` : ""} with ${source.sanitizers || "sanitizers"}. Every sanitizer catch is a source-attributed crash.</div>
            <pre class="code-pre src">${source.source}</pre>
          ` : usableDecompile(dec) ? html`
            <pre class="code-pre">${dec}</pre>
          ` : insns.length ? html`
            <div class="code-note">Decompiled C is unavailable (needs rz-ghidra); showing disassembly the detectors analysed.</div>
            <pre class="code-pre asm">${insns.map((ins) => {
              const hit = site && hexEq(ins.addr, site);
              return html`<div class=${`asm-line${hit ? " asm-hit" : ""}`}><span class="asm-a">${typeof ins.addr === "number" ? "0x" + ins.addr.toString(16) : ins.addr}</span>${ins.text || ins.disasm || ""}${hit ? html`  <span class="asm-tag">◀ ${finding.cwe} site</span>` : ""}</div>`;
            })}</pre>
          ` : html`<div class="code-note">No code recovered for this function.</div>`}
        </div>
        ${xbinCallers && xbinCallers.length ? html`
          <div class="xrefs xbin">
            <div class="xref"><span class="xref-k xbin-k">Reached from</span>${xbinCallers.map((xc) => html`
              <button class="xref-n nav xbin-n" onClick=${() => onFollowCaller && onFollowCaller(xc)} title=${`follow ${xc.symbol} back into ${xc.filename}`}>${xc.filename} → ${xc.symbol}()</button>`)}</div>
            <div class="xref-hint">This function is reached from another binary — follow the call back across the boundary.</div>
          </div>` : null}
        ${(fn.callees && fn.callees.length) || (fn.callers && fn.callers.length) ? html`
          <${CallGraphMini} fn=${fn} onNavigate=${nav} />
          <div class="xrefs">
            ${fn.callers && fn.callers.length ? html`<div class="xref"><span class="xref-k">Called by</span>${fn.callers.slice(0, 8).map((c) => {
              const n = c.src_name || c.name || c.src_addr; return n ? html`<button class="xref-n nav" onClick=${() => nav(c.src_name || c.name)}>${n}</button>` : null; })}</div>` : null}
            ${fn.callees && fn.callees.length ? html`<div class="xref"><span class="xref-k">Calls</span>${fn.callees.slice(0, 14).map((c) => {
              const n = c.dst_name || c.name || c.dst_addr; return n ? html`<button class="xref-n nav" onClick=${() => nav(c.dst_name || c.name)} title="follow this call">${n}</button>` : null; })}</div>` : null}
          </div>
          ${onNavigate ? html`<div class="xref-hint">Click a call to follow it — across binaries too, when it resolves to another component.</div>` : null}` : null}
      </div>
    </div>`;
}

// The cross-binary picture: the resolved component graph for a multi-binary case. This IS the
// multi-binary analysis made visible -- link_case resolves each binary's imports against the
// others' exports, and every edge here is a real call boundary that IPC modelling, cross-binary
// taint and whole-system detonation then drive. Cross-component findings are flagged in Results.
export function SystemMap({ map }) {
  const edges = (map && map.edges) || [];
  const nodes = (map && map.nodes) || [];
  if (nodes.length < 2) return null;
  const nameOf = (id) => (nodes.find((n) => n.id === id) || {}).filename || id.slice(0, 8);
  // Collapsible: the edge list of a multi-binary case can be long and pushes the results off
  // screen. A native <details> (no hook) starts open only while the list is short.
  return html`
    <details class="card sysmap" open=${edges.length <= 6}>
      <summary class="sysmap-head" style="cursor:pointer;display:flex;align-items:center;gap:8px">
        <span>Case components — cross-binary analysis</span>
        ${edges.length ? html`<span class="tab-n">${edges.length}</span>` : null}
      </summary>
      ${edges.length ? html`
        <div class="sysmap-sub">${edges.length} resolved call boundar${edges.length === 1 ? "y" : "ies"} between binaries. These are what IPC modelling, cross-binary taint and whole-system detonation drive.</div>
        <ul class="sysmap-edges">
          ${edges.map((e, i) => html`
            <li key=${i}>
              <span class="sm-node">${nameOf(e.src)}</span>
              <span class="sm-arrow">→</span>
              <span class="sm-node">${nameOf(e.dst)}</span>
              <span class="sm-sym">${(e.symbols || (e.symbol ? [e.symbol] : [])).filter(Boolean).join(", ") || e.kind}</span>
            </li>`)}
        </ul>
      ` : html`<div class="sysmap-sub">No call boundary resolves between these binaries — they do not import each other's symbols, so there is no cross-binary path to analyse.</div>`}
    </details>`;
}

// How much of each binary the fuzzing actually reached. A coverage bar per target makes "the
// fuzzer barely ran" impossible to miss: a red sliver next to "0 crashes" says the clean result
// is meaningless, where a full green bar next to "0 crashes" is real evidence of robustness.
function covTone(pct) { return pct == null ? "mid" : pct >= 60 ? "hi" : pct >= 25 ? "mid" : "lo"; }
export function CoveragePanel({ coverage, targets, onDrill }) {
  const rows = Object.entries(coverage || {});
  if (!rows.length) return null;
  const nameOf = (id) => ((targets || []).find((t) => t.id === id) || {}).filename || id.slice(0, 8);
  return html`
    <div class="card cov">
      <div class="cov-head">Fuzzing coverage</div>
      <div class="cov-sub">How much of each binary's recovered code the search actually exercised.${onDrill ? " Click a row to drill into its functions." : ""}</div>
      ${rows.map(([tid, c]) => html`
        <div class=${`cov-row${onDrill ? " clk" : ""}`} key=${tid}
          onClick=${() => onDrill && onDrill(tid)} title=${onDrill ? "browse this binary's functions" : null}>
          <span class="cov-name">${nameOf(tid)}</span>
          <div class="cov-bar"><div class=${`cov-fill cov-${covTone(c.pct)}`} style=${`width:${c.pct != null ? Math.max(2, Math.min(100, c.pct)) : 0}%`}></div></div>
          <span class="cov-val">${c.pct != null ? `${c.pct}%` : "—"} <span class="cov-detail">${c.kind === "edge" ? `${c.edges || "?"} edges` : `${c.hit}/${c.known} blocks`}</span></span>
        </div>`)}
    </div>`;
}

// ── The coverage ledger ─────────────────────────────────────────────────────────────────────
// The "how close to 100%?" dashboard. Full coverage is an asymptote, so this is the honest
// substitute: the gap along three axes -- which analysis CHECKS ran (which vuln classes were
// looked for), how many findings are WEAPONIZED (a verified PoC or a corroborated recipe), and
// how much CODE the search exercised -- plus the combined gaps worklist that is the to-do list to
// close it. Fed by GET /cases/{id}/coverage (analyze/coverage_ledger.py build_ledger); read-only.

// Tone for a finding-state chip: proven states green, corroborated amber, bare candidates muted.
const _STATE_TONE = { "poc-backed": "hi", confirmed: "hi", corroborated: "mid",
  candidate: "lo", "false-positive": "lo" };

// One axis progress bar, reusing the coverage-bar visuals (one source of truth for the tones).
function _axisBar(pct) {
  return html`<div class="cov-bar"><div class=${`cov-fill cov-${covTone(pct)}`}
    style=${`width:${pct != null ? Math.max(2, Math.min(100, pct)) : 0}%`}></div></div>`;
}

export function LedgerPanel({ ledger, busy, onOpenFinding, onFilterCwe, onFocusTarget }) {
  const [showChecks, setShowChecks] = useState(false);
  const [showCands, setShowCands] = useState(false);
  if (busy && !ledger) {
    return html`<div class="card ledger"><${Spinner} label="building the coverage ledger…" /></div>`;
  }
  if (!ledger || !ledger.checks) {
    return html`<div class="card empty">No coverage ledger yet — run an analysis first.</div>`;
  }
  const chk = ledger.checks, wpn = ledger.weaponization || {}, code = ledger.code || [],
    gaps = ledger.gaps || [];
  const chkPct = chk.total ? Math.round((100 * chk.ran) / chk.total) : 0;
  const classes = chk.classes_checked || [];
  const notRun = chk.not_run || [];
  const cands = wpn.unweaponized || [];
  // The true count of bare candidates -- the endpoint caps the listed sample (unweaponized[:200]),
  // so label the worklist with findings − weaponized, not the length of the capped list.
  const candTotal = Math.max(cands.length, (wpn.findings || 0) - (wpn.weaponized || 0));
  const byState = wpn.by_state || {};
  return html`
    <div class="card ledger">
      <div class="ledger-head">Coverage ledger</div>
      <div class="ledger-sub">Full coverage is an asymptote, so this is the honest account of the gap
        along three axes — which checks ran, which findings are weaponized, and how much code the
        search exercised — with the worklist to close it.</div>

      <!-- Axis B: analysis checks / weakness classes -->
      <div class="ledger-axis">
        <div class="ax-top">
          <span class="ax-name">Checks run <span class="ax-tag">vuln classes</span></span>
          <span class="ax-val">${chk.ran}/${chk.total} checks</span>
        </div>
        ${_axisBar(chkPct)}
        <div class="ax-note">${classes.length} weakness class${classes.length === 1 ? "" : "es"} looked for${
          notRun.length ? ` · ${notRun.length} check${notRun.length === 1 ? "" : "s"} did not run` : ""}</div>
        ${classes.length ? html`<div class="ledger-chips">
          ${classes.map((c) => (onFilterCwe
            ? html`<button class="lchip cwe clk" key=${c} title="show this class's findings"
                onClick=${() => onFilterCwe(c)}>${c}</button>`
            : html`<span class="lchip cwe" key=${c}>${c}</span>`))}
        </div>` : null}
        ${notRun.length ? html`
          <button class="btn small ghost ledger-toggle" onClick=${() => setShowChecks((s) => !s)}>
            ${showChecks ? "▾" : "▸"} ${notRun.length} check${notRun.length === 1 ? "" : "s"} did not run
          </button>
          ${showChecks ? html`<div class="ledger-list">
            ${notRun.map((c) => html`<div class="ll-row" key=${c.stage}>
              <span class=${`ll-status s-${c.status}`}>${c.status === "not_run" ? "not run" : c.status}</span>
              <span class="ll-label">${c.label}</span>
              ${(c.classes || []).filter((x) => x !== "*").length ? html`<span class="ll-classes">${
                c.classes.filter((x) => x !== "*").join(", ")}</span>` : null}
            </div>`)}
          </div>` : null}
        ` : null}
      </div>

      <!-- Axis C: weaponization -->
      <div class="ledger-axis">
        <div class="ax-top">
          <span class="ax-name">Findings weaponized <span class="ax-tag">verified PoC or recipe</span></span>
          <span class="ax-val">${wpn.weaponized || 0}/${wpn.findings || 0}${wpn.pct != null ? ` · ${wpn.pct}%` : ""}</span>
        </div>
        ${_axisBar(wpn.pct)}
        ${Object.keys(byState).length ? html`<div class="ledger-chips">
          ${Object.entries(byState).sort().map(([st, n]) => html`<span
            class=${`lchip st-${_STATE_TONE[st] || "lo"}`} key=${st}>${st} · ${n}</span>`)}
        </div>` : null}
        ${candTotal ? html`
          <button class="btn small ghost ledger-toggle" onClick=${() => setShowCands((s) => !s)}>
            ${showCands ? "▾" : "▸"} ${candTotal} bare candidate${candTotal === 1 ? "" : "s"} — weaponization worklist
          </button>
          ${showCands ? html`<div class="ledger-list">
            ${cands.map((f) => (onOpenFinding
              ? html`<button class="ll-row clk" key=${f.id} title="open this finding's evidence"
                  onClick=${() => onOpenFinding(f.id)}>
                  <span class="ll-cwe">${f.cwe || "—"}</span>
                  <span class="ll-label">${f.title || "(untitled)"}</span>
                  ${f.detector ? html`<span class="ll-classes">${f.detector}</span>` : null}
                </button>`
              : html`<div class="ll-row" key=${f.id}>
                  <span class="ll-cwe">${f.cwe || "—"}</span>
                  <span class="ll-label">${f.title || "(untitled)"}</span>
                  ${f.detector ? html`<span class="ll-classes">${f.detector}</span>` : null}
                </div>`))}
            ${candTotal > cands.length ? html`<div class="ll-row ll-more">…and ${candTotal - cands.length} more not listed</div>` : null}
          </div>` : null}
        ` : null}
      </div>

      <!-- Axis A: code exercised, per target -->
      <div class="ledger-axis">
        <div class="ax-top"><span class="ax-name">Code exercised <span class="ax-tag">per target</span></span></div>
        ${code.length ? code.map((c) => {
          const detail = html`
            <span class="lc-name" title=${c.target}>${c.target}</span>
            ${_axisBar(c.block_pct)}
            <span class="lc-val">${c.block_pct != null ? `${c.block_pct}%` : "—"}
              <span class="lc-detail">${c.blocks_hit != null
                ? `${c.blocks_hit}/${c.blocks_known} blocks`
                : "no coverage measured"}${c.undriven && c.undriven.pct != null
                  ? ` · harness reaches ${c.undriven.pct}% of ${c.functions_recovered} fns`
                  : ""}</span>
            </span>`;
          return onFocusTarget
            ? html`<button class="ledger-code-row clk" key=${c.target}
                title="browse this target's functions and call graph"
                onClick=${() => onFocusTarget(c.target)}>${detail}</button>`
            : html`<div class="ledger-code-row" key=${c.target}>${detail}</div>`;
        }) : html`<div class="ax-note">No targets analysed.</div>`}
      </div>

      <!-- The combined gaps worklist -->
      ${gaps.length ? html`<div class="ledger-gaps">
        <div class="lg-head">Gaps worklist</div>
        <ul>${gaps.map((g, i) => html`<li key=${i}>${g}</li>`)}</ul>
      </div>` : html`<div class="ledger-gaps clean"><div class="lg-head">No gaps flagged — every check ran, every finding weaponized.</div></div>`}
    </div>`;
}

// ── Verdict layer ───────────────────────────────────────────────────────────────────────────
// The answer, up top. Everything below (target facts, findings, the analysis drawer) is the
// working; these components are the verdict: per binary, the worst effect an attacker can drive it
// to, whether that is proven, and how far the exploit chain got. Fed by util.js's buildVerdicts.

// The short "what happened" for a verdict: the worst effect's title when there is one, otherwise a
// plain crash / no-crash statement.
function verdictEffectLabel(v) {
  if (v.headline) return v.headline.title || v.headline.kind || "effect";
  return v.crashed ? "crash reproduced" : "no crash";
}
// The exploitation-reached tag: the level the chain got to, or why there is no level.
function verdictLevelTag(v) {
  if (v.level) return `L${v.level}`;
  if (v.crashed) return "crash";
  return v.staticCount ? "static-only" : "no crash";
}
const VERDICT_CLASS = { demonstrated: "vc-demo", potential: "vc-pot", none: "vc-none" };

// A horizontal row of per-target verdict chips for a multi-binary case. Each chip is the target
// plus its worst effect and the level reached; clicking it jumps to that target's VerdictCard.
export function VerdictStrip({ verdicts, onSelect }) {
  if (!verdicts || verdicts.length < 2) return null;
  return html`
    <div class="verdict-strip" role="list">
      ${verdicts.map((v) => html`
        <button class=${`verdict-chip ${VERDICT_CLASS[v.status] || "vc-none"}`} role="listitem"
          key=${v.target.id} onClick=${() => onSelect && onSelect(v.target.id)}
          title=${`${v.target.filename} — ${verdictEffectLabel(v)}${v.status === "demonstrated" ? " (demonstrated)" : v.status === "potential" ? " (potential)" : ""}`}>
          <span class="vchip-name">${v.target.filename}</span>
          <span class="vchip-eff">${verdictEffectLabel(v)}</span>
          <span class="vchip-lvl">${verdictLevelTag(v)}</span>
        </button>`)}
    </div>`;
}

// The verdict for one target, at the top of the case view. Headline = the worst DEMONSTRATED
// effect (or the worst potential one, muted, when nothing is demonstrated); an L1▸L2▸L3 ladder
// showing how far the exploit chain got; and, when demonstrated, direct links to the proof
// artifacts. When no crash reproduced it says so plainly with the static-findings/coverage count.
export function VerdictCard({ verdict, artifactUrl }) {
  const v = verdict;
  if (!v) return null;
  const demo = v.status === "demonstrated";
  const cls = demo ? "vd-demo" : v.status === "potential" ? "vd-pot" : "vd-none";
  const head = v.headline;
  const proof = head && head.proof;
  return html`
    <div class=${`card verdict-card ${cls}`} id=${`verdict-${v.target.id}`} tabindex="-1">
      <div class="vd-head">
        <span class="vd-target">${v.index != null ? html`<span class="sum-ix">${v.index}</span>` : null}${v.target.filename}</span>
        <span class=${`vd-status-pill vs-${v.status}`}>${demo ? "demonstrated" : v.status === "potential" ? "potential" : v.crashed ? "crash" : "no crash"}</span>
      </div>
      <div class="vd-headline">
        ${head ? html`
          <span class="vd-eff">${demo ? "✓ " : "○ "}${head.title || head.kind}</span>
          <span class="vd-eff-sub">${demo
            ? "demonstrated by a working proof-of-concept"
            : "reachable in principle for this defect class — not yet demonstrated"}</span>
        ` : html`
          <span class="vd-eff neutral">No crash reproduced</span>
          <span class="vd-eff-sub">${v.staticCount} static finding${v.staticCount === 1 ? "" : "s"}${v.coverage != null ? `, ${v.coverage}% covered` : ""}</span>
        `}
      </div>
      <div class="vd-ladder" title="how far the exploit chain got">
        <span class="vd-ladder-lbl">Chain</span>
        ${[1, 2, 3].map((n) => html`
          ${n > 1 ? html`<span class=${`vd-arrow${v.level >= n ? " filled" : ""}`}>▸</span>` : null}
          <span class=${`vd-rung${v.level >= n ? " filled" : ""}`} key=${n}>L${n}</span>
        `)}
        <span class="vd-ladder-cap">${v.level ? `reached L${v.level}` : v.crashed ? "crash, no primitive built" : "static only"}</span>
      </div>
      ${demo ? html`
        <div class="vd-proofs">
          ${v.bundlePoc && v.bundlePoc.bundle_sha ? html`<a class="btn small" href=${artifactUrl(v.bundlePoc.bundle_sha)} download>⬇ PoC bundle${v.bundlePoc.verified ? " (verified)" : ""}</a>` : null}
          ${v.inputPoc && v.inputPoc.input_sha ? html`<a class="btn small ghost" href=${artifactUrl(v.inputPoc.input_sha)} download>⬇ Crashing input</a>` : null}
          ${proof && proof.sha ? html`<a class="btn small ghost" href=${artifactUrl(proof.sha)} download>⬇ ${proof.type === "bundle" ? "proof PoC" : proof.type === "artifact" ? "leaked bytes" : "proof input"}</a>` : null}
        </div>` : null}
    </div>`;
}

// A single collapsible drawer that holds the PROCESS -- the pipeline plan, the run log, the tool
// console and the coverage panel. Expanded while a run is in flight (so you can watch it work),
// collapsed once it has finished (so the verdict + findings above are what you land on). The
// children self-hide when empty, so an idle drawer is just its header.
export function AnalysisDrawer({ running, children }) {
  const [open, setOpen] = useState(!!running);
  const wasRunning = useRef(!!running);
  useEffect(() => {
    if (running && !wasRunning.current) setOpen(true);        // a run started -> reveal the work
    else if (!running && wasRunning.current) setOpen(false);  // it finished -> tuck it away
    wasRunning.current = running;
  }, [running]);
  return html`
    <div class="card drawer">
      <button class="drawer-head" onClick=${() => setOpen((o) => !o)} aria-expanded=${open}>
        <span class="drawer-title">⚙ Analysis</span>
        <span class="drawer-sub">pipeline, run log, console &amp; coverage</span>
        ${running ? html`<${Spinner} />` : null}
        <span class="drawer-toggle">${open ? "▾" : "▸"}</span>
      </button>
      ${open ? html`<div class="drawer-body">${children}</div>` : null}
    </div>`;
}

// The capabilities Autopilot did NOT run on this target, and why. "Deep" is only honest if it
// says what it left out -- a firmware carve on an executable, a boundary fuzz with no IPC. Each
// row names the capability and the server's reason it cannot apply here.
export function UnavailablePanel({ items }) {
  if (!items || !items.length) return null;
  return html`
    <div class="card unavail">
      <div class="unavail-head">Not applicable to this target (${items.length})</div>
      <div class="unavail-sub">Every other capability was attempted. These cannot run here:</div>
      <ul class="unavail-list">
        ${items.map((u) => html`
          <li key=${u.stage}>
            <span class="unavail-name">${u.label || u.stage}</span>
            <span class="unavail-why">${u.why || "not applicable"}</span>
          </li>`)}
      </ul>
    </div>`;
}


export function RunScorecard({ cards, targetName }) {
  if (!cards || !cards.length) return null;
  const card = (targetName && cards.find((c) => c.filename === targetName)) || cards[0];
  if (!card) return null;
  const ex = card.executions || {};
  const cap = card.capability || {};
  const declined = card.declined || {};
  const ab = card.absorbed || {};
  const base = card.baseline || {};
  const byEngine = Object.entries(ex.by_engine || {}).sort((a, b) => b[1] - a[1]);
  const rate = ex.per_second ? ` (${ex.per_second}/s)` : "";
  const never = cap.never_scheduled || [];
  return html`
    <div class="card scorecard">
      <div class="unavail-head">What this run did${card.filename ? ` — ${card.filename}` : ""}</div>
      <div class="unavail-sub">
        A null result is only worth something next to the work behind it. Two targets with no
        crashes look identical until you know one executed thousands of times and the other
        executed zero because a stage upstream took the budget.
      </div>
      ${card.settled === false ? html`<div class="unavail-sub">
        <strong>Incomplete</strong> — a stage was still finishing when this card was built, so the
        counts below are a floor, not a total.</div>` : null}
      <ul class="unavail-list">
        <li><span class="unavail-name">Baseline</span><span class="unavail-why">${
          base.ran === undefined ? "not recorded"
            : base.ran ? (base.crashed ? "ran, FAULTED" : "ran, exited normally")
            : `DID NOT RUN — ${base.note || "no reason recorded"}`}</span></li>
        <li><span class="unavail-name">Executions</span><span class="unavail-why">${
          (ex.total || 0).toLocaleString()}${rate}${byEngine.length
            ? ` — ${byEngine.map(([k, v]) => `${k} ${v.toLocaleString()}`).join(", ")}` : ""}</span></li>
        <li><span class="unavail-name">Capabilities</span><span class="unavail-why">${
          (cap.worked || []).length} did work, ${(cap.declined || []).length} declined, ${
          (cap.errored || []).length} errored, ${never.length} never scheduled (of ${
          cap.registered || 0} registered)</span></li>
        ${card.crashes != null ? html`<li><span class="unavail-name">Crashes</span>
          <span class="unavail-why">${card.crashes} recorded</span></li>` : null}
        ${never.length ? html`<li><span class="unavail-name">Not reached</span>
          <span class="unavail-why">${never.slice(0, 8).join(", ")}${
            never.length > 8 ? " …" : ""}</span></li>` : null}
        ${/* Errors the run absorbed on purpose. Zero is the useful reading: it says a thin
              result is the target's doing and not ours. */ ""}
        <li><span class="unavail-name">Absorbed</span><span class="unavail-why">${
          ab.total ? `${ab.total} best-effort step(s) failed quietly at ${ab.sites} site(s)`
            : ab.total === 0 ? "nothing — no step failed quietly in this run"
            : "not recorded"}</span></li>
      </ul>
      ${ab.top && ab.top.length ? html`
        <ul class="unavail-list">
          ${ab.top.slice(0, 4).map((e) => html`<li key=${e.site}>
            <span class="unavail-name">${e.count}×</span>
            <span class="unavail-why">${e.site}</span></li>`)}
        </ul>` : null}
      ${Object.keys(declined).length ? html`
        <div class="unavail-sub">Ran, but could not apply here:</div>
        <ul class="unavail-list">
          ${Object.entries(declined).slice(0, 10).map(([stage, why]) => html`
            <li key=${stage}><span class="unavail-name">${stage}</span>
              <span class="unavail-why">${why}</span></li>`)}
        </ul>` : null}
    </div>`;
}


// ── Workbench shell (C²) components ──────────────────────────────────────────────────────
// A shield icon (checked when a live exploit was demonstrated).
function shieldSvg(stroke, checked) {
  return html`<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke=${stroke}
    stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 2 3 7v6c0 5 4 8 9 9 5-1 9-4 9-9V7z"/>${checked ? html`<path d="m9 12 2 2 4-4"/>` : null}</svg>`;
}

// A compact, horizontal verdict header for the shell: worst effect + mini L1▸L2▸L3 ladder + the
// bundle download. Mirrors VerdictCard but sized for a persistent header, not a stacked card.
export function ShellVerdict({ verdict, artifactUrl }) {
  const v = verdict;
  if (!v) return null;
  const demo = v.status === "demonstrated";
  const head = v.headline;
  const cls = demo ? "vd-demo" : v.status === "potential" ? "vd-pot" : "vd-none";
  const accent = demo ? "var(--bad)" : "var(--ok)";
  return html`
    <div class=${`card wb-verdict ${cls}`}>
      <div class="vv-icon">${shieldSvg(accent, demo)}</div>
      <div class="vv-body">
        <div class="vv-eff">${demo ? "✓ " : "○ "}${head ? (head.title || head.kind) : "No crash reproduced"}</div>
        <div class="vv-sub">${demo
          ? "working proof-of-concept · confirmed under the debugger"
          : head ? "reachable in principle for this defect class — not yet demonstrated"
          : `${v.staticCount} static finding${v.staticCount === 1 ? "" : "s"}${v.coverage != null ? `, ${v.coverage}% covered` : ""}`}</div>
      </div>
      <div class="vv-right">
        <div class="vv-mini-ladder" title="how far the exploit chain got (verified PoCs only)">
          ${[1, 2, 3].map((n) => html`${n > 1 ? html`<span class=${`vd-arrow${v.level >= n ? " filled" : ""}`}>▸</span>` : null}<span class=${`vd-rung${v.level >= n ? " filled" : ""}`} key=${n}>L${n}</span>`)}
        </div>
        ${v.candidateLevel ? html`<div class="vv-cand" title="a PoC/exploit recipe for this level exists but was not verified by execution here">candidate L${v.candidateLevel} · not executed</div>` : null}
        ${demo && v.bundlePoc && v.bundlePoc.bundle_sha
          ? html`<a class="btn small" href=${artifactUrl(v.bundlePoc.bundle_sha)} download>⬇ PoC bundle${v.bundlePoc.verified ? " (verified)" : ""}</a>` : null}
      </div>
    </div>`;
}

function pocLvlNum(p) { const m = /(\d)/.exec((p && p.level) || ""); return m ? +m[1] : 0; }

// The demonstrated-effect narrative for a finding (the chain_primitive/root-cause detail), pulled
// from its effects-channel evidence -- what the L3 rung shows as "how it works".
function exploitDetail(f) {
  if (!f || !f.evidence) return null;
  for (const e of f.evidence) {
    if (e.channel === "effects") {
      try { const a = JSON.parse(e.detail); const d = a.find((x) => x.status === "demonstrated") || a[0]; if (d && (d.detail || (d.proof && d.proof.note))) return d.detail || d.proof.note; } catch { /* not json */ }
    }
  }
  const e = (f.evidence || []).find((x) => x.detail);
  return e && e.detail;
}

// Live inspector for a confirmed L3 PoC bundle: fetches the bundle's INNER files (loadBundle(sha))
// and shows the exploit itself -- the real reproduce command + script, a hexdump of the payload,
// the primitive/technique notes, and the file manifest -- instead of a hardcoded placeholder. Tabs
// keep it compact; every view is derived from the actual bundle, never faked.
export function ExploitInspector({ sha, loadBundle, artifactUrl }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [tab, setTab] = useState("repro");
  useEffect(() => {
    let live = true;
    if (!sha || !loadBundle) return;
    setData(null); setErr(null);
    loadBundle(sha).then((d) => { if (live) setData(d); }).catch((e) => { if (live) setErr(e.message || String(e)); });
    return () => { live = false; };
  }, [sha]);
  if (err) return html`<div class="insp insp-err">bundle unavailable: ${err}</div>`;
  if (!data) return html`<div class="insp insp-load">reading bundle…</div>`;
  const files = data.files || [];
  const byBase = (b) => files.find((f) => f.name.split("/").pop() === b);
  const script = byBase("exploit.py");
  const runner = byBase("runner.sh");
  const payload = files.find((f) => f.kind === "payload");
  const primitive = byBase("PRIMITIVE.txt");
  const readme = byBase("README.txt");
  const meta = data.meta || {};
  const runLine = script ? "python3 ./exploit.py ./target.bin" : "sh ./runner.sh";
  const TABS = [["repro", "Reproduce"], ["payload", "Payload"], ["technique", "Technique"], ["files", "Files"]];
  return html`
    <div class="insp">
      <div class="insp-tabs">
        ${TABS.map(([k, label]) => (k === "payload" && !payload) ? null : html`
          <button key=${k} class=${`insp-tab${tab === k ? " on" : ""}`} onClick=${() => setTab(k)}>${label}</button>`)}
      </div>
      ${tab === "repro" ? html`
        <div class="insp-body">
          <div class="insp-note">Offline, air-gapped — unpack the bundle and run:</div>
          <pre class="insp-cmd">${`$ tar -xzf poc-bundle.tar.gz && cd poc\n$ ${runLine}`}</pre>
          ${script ? html`<div class="insp-cap">exploit.py <span class="insp-dim">(self-contained re-driver)</span></div>
            <pre class="insp-code">${script.text}</pre>`
            : runner ? html`<div class="insp-cap">runner.sh</div><pre class="insp-code">${runner.text}</pre>` : null}
        </div>` : null}
      ${tab === "payload" && payload ? html`
        <div class="insp-body">
          <div class="insp-cap">${payload.name.split("/").pop()} <span class="insp-dim">(${fmtBytes(payload.size)}${payload.preview_len < payload.size ? `, first ${payload.preview_len} shown` : ""})</span></div>
          <pre class="insp-hex">${payload.hexdump}</pre>
        </div>` : null}
      ${tab === "technique" ? html`
        <div class="insp-body">
          <table class="insp-meta">
            ${["exploit", "arch", "offset", "libc_base", "target"].map((k) => meta[k] != null ? html`
              <tr key=${k}><td>${k}</td><td>${String(meta[k])}</td></tr>` : null)}
          </table>
          ${primitive ? html`<pre class="insp-code">${primitive.text}</pre>` : null}
          ${readme ? html`<details class="insp-more"><summary>README</summary><pre class="insp-code">${readme.text}</pre></details>` : null}
        </div>` : null}
      ${tab === "files" ? html`
        <div class="insp-body">
          <table class="insp-files">
            ${files.map((f) => html`<tr key=${f.name}><td class="insp-fn">${f.name}</td><td class="insp-dim">${f.kind}</td><td>${fmtBytes(f.size)}</td></tr>`)}
          </table>
          <a class="btn small ghost" href=${artifactUrl(data.download.split("/").pop())} download>⬇ full bundle (.tar.gz)</a>
        </div>` : null}
    </div>`;
}

// The Exploits tab: the L1▸L2▸L3 ladder for one target, each rung with its artifacts and verified
// state, and the L3 rung expanded with how the exploit works + a live bundle inspector.
export function ExploitsPanel({ verdict, pocs, topFinding, artifactUrl, loadBundle }) {
  const v = verdict || {};
  const lvl = v.level || 0;
  const byLvl = {};
  for (const p of pocs || []) { const n = pocLvlNum(p); if (!byLvl[n] || (p.verified && !byLvl[n].verified)) byLvl[n] = p; }
  const inputSha = (byLvl[1] && byLvl[1].input_sha) || (v.inputPoc && v.inputPoc.input_sha) || (byLvl[2] && byLvl[2].input_sha);
  const bundleSha = v.bundlePoc && v.bundlePoc.bundle_sha;
  const detail = exploitDetail(topFinding);
  if (!lvl && !(pocs || []).length) return html`<div class="wb-soon">No exploit built for this target yet — run Autopilot, and any crash → primitive → working exploit will appear here as the chain progresses.</div>`;
  return html`
    <div class="xp-ladder">
      <div class="xp-rung">
        <div class=${`xp-lvl ${lvl >= 1 ? "done" : "pend"}`}>L1</div>
        <div class="xp-body">
          <div class="xp-t">Crash reproduced ${lvl >= 1 ? html`<span class="xp-ok">✓ verified</span>` : ""}</div>
          <div class="xp-sub">${v.crashed ? "a fault fired reliably under the sandbox" : "no crash reproduced"}</div>
        </div>
        ${inputSha ? html`<a class="btn small ghost" href=${artifactUrl(inputSha)} download>⬇ crashing input</a>` : null}
      </div>
      <div class="xp-rung">
        <div class=${`xp-lvl ${lvl >= 2 ? "done" : "pend"}`}>L2</div>
        <div class="xp-body">
          <div class="xp-t">Primitive proven ${lvl >= 2 ? html`<span class="xp-ok">✓ confirmed</span>` : ""}</div>
          <div class="xp-sub">${lvl >= 2 ? "an instruction pointer / memory location is attacker-controlled" : "no primitive built yet"}</div>
        </div>
      </div>
      ${lvl >= 3 ? html`
        <div class="xp-rung xp-l3">
          <div class="xp-l3-head">
            <div class="xp-lvl crit">L3</div>
            <div class="xp-body">
              <div class="xp-t">Working exploit${topFinding ? ` — ${topFinding.title}` : ""}</div>
              <div class="xp-sub">arrival confirmed under the debugger · negative control passed</div>
            </div>
          </div>
          <div class="xp-steps"><span class="xp-k">HOW IT WORKS</span>${detail || "control flow was hijacked to attacker-chosen code."}</div>
          ${bundleSha ? html`<${ExploitInspector} sha=${bundleSha} loadBundle=${loadBundle} artifactUrl=${artifactUrl} />` : null}
          <div class="xp-actions">
            ${bundleSha ? html`<a class="btn" href=${artifactUrl(bundleSha)} download>⬇ PoC bundle (verified)</a>` : null}
            ${inputSha ? html`<a class="btn ghost" href=${artifactUrl(inputSha)} download>⬇ exploit input</a>` : null}
          </div>
        </div>` : html`
        <div class="xp-rung">
          <div class="xp-lvl pend">L3</div>
          <div class="xp-body">
            <div class="xp-t">Working exploit</div>
            <div class="xp-sub">not reached — no full exploit demonstrated for this target</div>
          </div>
        </div>`}
    </div>`;
}

// Right-drawer persistent context: the target's raw facts (mitigations, identity, hashes).
function mitTone(k, val) {
  const on = val === "on" || val === true || val === "full";
  const weakOff = ["pie", "nx", "canary"].includes(k);
  if (on) return "mit-good";
  return weakOff ? "mit-weak" : "";
}
export function DrawerFacts({ target, onBrowseFunctions }) {
  if (!target) return null;
  const t = target;
  const m = t.mitigations || {};
  return html`
    <div>
      <div class="rail-sec-h">Target</div>
      <div class="dr-target">${t.filename}</div>
      <div class="vv-sub">${(t.file_type || "").toUpperCase()} · ${t.arch || "?"} · ${fmtBytes(t.size)}</div>
      ${Object.keys(m).length ? html`<div class="mits" style="justify-content:flex-start;margin-top:12px;">
        ${Object.entries(m).map(([k, val]) => html`<span class=${`mit ${mitTone(k, val)}`} key=${k}>${k.toUpperCase()} ${val}</span>`)}
      </div>` : null}
    </div>
    <div>
      <div class="rail-sec-h">Identity</div>
      <div class="dr-kv"><span class="dr-k">arch</span><span class="dr-v">${t.arch || "?"} ${t.bits || ""}b ${t.endianness || ""}</span></div>
      <div class="dr-kv"><span class="dr-k">linking</span><span class="dr-v">${t.linking || "?"}</span></div>
      <div class="dr-kv"><span class="dr-k">stripped</span><span class="dr-v">${t.stripped ? "yes" : "no"}</span></div>
      ${t.entropy != null ? html`<div class="dr-kv"><span class="dr-k">entropy</span><span class="dr-v">${(+t.entropy).toFixed(3)}</span></div>` : null}
      <div class="dr-hashes" style="margin-top:10px;">sha256 ${t.sha256}</div>
    </div>
    ${onBrowseFunctions ? html`<button class="btn small ghost" onClick=${() => onBrowseFunctions(t.id)}>Browse functions →</button>` : null}`;
}


// Compact horizontal target strip — replaces the right drawer so the workbench is TWO panes and
// the main content gets the full width. Name + type + the exploitation-relevant mitigations sit on
// one line; the rest (linking, stripped, entropy, sha256, browse) hides behind a details toggle.
export function TargetBar({ target, onBrowseFunctions }) {
  const [open, setOpen] = useState(false);
  if (!target) return null;
  const t = target;
  const m = t.mitigations || {};
  return html`
    <div class="wb-metabar">
      <div class="mb-main">
        <span class="mb-name">${t.filename}</span>
        <span class="mb-sub">${(t.file_type || "").toUpperCase()} · ${t.arch || "?"} · ${fmtBytes(t.size)}</span>
        ${Object.keys(m).length ? html`<span class="mb-mits">
          ${Object.entries(m).map(([k, val]) => html`<span class=${`mit ${mitTone(k, val)}`} key=${k}>${k.toUpperCase()} ${val}</span>`)}
        </span>` : null}
        <button class="mb-details" onClick=${() => setOpen((o) => !o)}>${open ? "▾ details" : "▸ details"}</button>
      </div>
      ${open ? html`<div class="mb-more">
        <span><b>arch</b> ${t.arch || "?"} ${t.bits || ""}b ${t.endianness || ""}</span>
        <span><b>linking</b> ${t.linking || "?"}</span>
        <span><b>stripped</b> ${t.stripped ? "yes" : "no"}</span>
        ${t.entropy != null ? html`<span><b>entropy</b> ${(+t.entropy).toFixed(3)}</span>` : null}
        <span class="mb-hash"><b>sha256</b> ${t.sha256}</span>
        ${onBrowseFunctions ? html`<button class="btn small ghost" onClick=${() => onBrowseFunctions(t.id)}>Browse functions →</button>` : null}
      </div>` : null}
    </div>`;
}


// ── More workbench tabs: Functions / Strings / Disassembly / Diff / Crashes ──────────────
export function FunctionsPanel({ functions, onOpen }) {
  const [q, setQ] = useState("");
  if (!functions) return html`<div class="wb-soon"><${Spinner} label="Loading functions…" /></div>`;
  const ql = q.trim().toLowerCase();
  const rows = (functions || []).filter((f) => !ql || (f.name || "").toLowerCase().includes(ql) || fmtAddr(f.addr).includes(ql));
  return html`
    <div class="fnp">
      <input class="fn-search" style="margin:0 0 4px" placeholder="Filter functions…" value=${q} onInput=${(e) => setQ(e.target.value)} />
      <div class="fnp-hint">${rows.length} function${rows.length === 1 ? "" : "s"} · click one for its decompilation and ego call graph</div>
      <div class="fnp-list">
        ${rows.slice(0, 400).map((f) => html`
          <button class=${`fn-row${f.blocks ? "" : " fn-thin"}`} key=${f.id || f.addr} onClick=${() => onOpen(f)}>
            <span class="fn-name">${f.name || "(unnamed)"}</span>
            <span class="fn-addr">${fmtAddr(f.addr)}</span>
            <span class="fn-meta">${f.size ? f.size + " B" : ""}${f.blocks ? ` · ${f.blocks} blk` : ""}</span>
          </button>`)}
      </div>
      ${rows.length > 400 ? html`<div class="fn-more">Showing the first 400 — filter to narrow.</div>` : null}
    </div>`;
}

export function StringsPanel({ strings }) {
  const [q, setQ] = useState("");
  if (!strings) return html`<div class="wb-soon"><${Spinner} label="Loading strings…" /></div>`;
  const ql = q.trim().toLowerCase();
  const rows = (strings || []).filter((s) => !ql || (s.value || "").toLowerCase().includes(ql));
  return html`
    <div class="fnp">
      <input class="fn-search" style="margin:0 0 4px" placeholder="Filter strings…" value=${q} onInput=${(e) => setQ(e.target.value)} />
      <div class="fnp-hint">${rows.length} string${rows.length === 1 ? "" : "s"}</div>
      <div class="str-list">
        ${rows.slice(0, 600).map((s, i) => html`
          <div class="str-row" key=${i}>
            <span class="str-addr">${fmtAddr(s.addr)}</span>
            <span class="str-val" title=${s.value}>${s.value}</span>
            ${(() => { const n = Array.isArray(s.xrefs) ? s.xrefs.length : (s.xrefs || 0); return n ? html`<span class="str-x">${n} xref${n === 1 ? "" : "s"}</span>` : html`<span></span>`; })()}
          </div>`)}
      </div>
      ${rows.length > 600 ? html`<div class="fn-more">Showing the first 600 — filter to narrow.</div>` : null}
    </div>`;
}

function disasmText(d) {
  if (d && d.decompiled && usableDecompile(d.decompiled)) return d.decompiled;
  const ir = d && d.ir;
  if (ir && ir.blocks) return ir.blocks.map((b) => (b.instructions || []).map((i) => `${fmtAddr(i.addr)}  ${i.text}`).join("\n")).join("\n\n");
  return (d && d.decompiled) || "(no disassembly recovered for this function)";
}
export function DisasmPanel({ functions, detail, selectedId, onSelect, loading }) {
  const [q, setQ] = useState("");
  if (!functions) return html`<div class="wb-soon"><${Spinner} label="Loading functions…" /></div>`;
  const ql = q.trim().toLowerCase();
  const rows = (functions || []).filter((f) => f.blocks && (!ql || (f.name || "").toLowerCase().includes(ql) || fmtAddr(f.addr).includes(ql)));
  return html`
    <div class="dis">
      <div class="dis-list">
        <input class="fn-search" style="margin:0 0 8px;width:100%" placeholder="Filter…" value=${q} onInput=${(e) => setQ(e.target.value)} />
        ${rows.slice(0, 300).map((f) => html`
          <button class=${`fn-row${selectedId === f.id ? " active" : ""}`} key=${f.id} onClick=${() => onSelect(f)}>
            <span class="fn-name">${f.name || fmtAddr(f.addr)}</span>
            <span class="fn-addr">${fmtAddr(f.addr)}</span>
          </button>`)}
      </div>
      <div class="dis-body">
        ${loading ? html`<${Spinner} label="Disassembling…" />`
          : !detail ? html`<div class="wb-soon">Select a function to disassemble.</div>`
          : html`<div class="dis-h"><span class="code-name">${detail.name || fmtAddr(detail.addr)}</span> <span class="code-addr">${fmtAddr(detail.addr)}</span>${detail.signature ? html`<span class="code-sig">${detail.signature}</span>` : null}</div>
            <pre class=${`code-pre ${detail.decompiled && usableDecompile(detail.decompiled) ? "src" : "asm"}`}>${disasmText(detail)}</pre>`}
      </div>
    </div>`;
}

// Compare two targets' findings. Rough finding identity = CWE + the title's stable prefix; the diff
// shows what a candidate build FIXED (in A, gone in B), what is NEW (in B, not A), and what is the
// same. When there is only one target it prompts to add a second binary.
function diffKey(f) { return `${f.cwe || "?"}::${(f.title || "").replace(/\s*\(.*$/, "").replace(/[:—-].*$/, "").trim().toLowerCase()}`; }
// One replay row's verdict. A crash PoC reproduces by SIGNAL; a no-crash "win" exploit (method set)
// reproduces by reaching the win function (breakpoint) or re-printing its success output (marker).
function diffRowVerdict(r) {
  if (r.error) return "skipped (" + r.error + ")";
  if (r.method) {                                     // no-crash win exploit
    const how = r.method === "breakpoint"
      ? `${r.win || "win"} reached` : `win output "${r.marker || "marker"}"`;
    return r.reproduced ? `win reproduces — ${how}` : `fixed — win no longer reproduces`;
  }
  return r.reproduced ? "still faults (" + (r.signal || "crash") + ")" : "no fault";
}
export function DiffPanel({ targets, findings, onVerify, verify, onPatchDiff, patch }) {
  const ts = targets || [];
  const [a, setA] = useState(ts[0] && ts[0].id);
  const [b, setB] = useState(ts[1] && ts[1].id);
  if (ts.length < 2) return html`<div class="wb-soon">Add a second binary to this case to compare — lykos diffs the findings and, when a version has a working PoC, re-runs it against the other to confirm a fix.</div>`;
  const name = (id) => { const t = ts.find((x) => x.id === id); return t ? t.filename : id; };
  const fa = (findings || []).filter((f) => f.target_id === a);
  const fb = (findings || []).filter((f) => f.target_id === b);
  const ka = new Map(fa.map((f) => [diffKey(f), f])), kb = new Map(fb.map((f) => [diffKey(f), f]));
  const rows = [];
  for (const [k, f] of ka) rows.push(kb.has(k) ? { d: "same", f, a: f.state, b: kb.get(k).state } : { d: "fixed", f, a: f.state, b: null });
  for (const [k, f] of kb) if (!ka.has(k)) rows.push({ d: "new", f, a: null, b: f.state });
  const order = { fixed: 0, new: 1, same: 2 };
  rows.sort((x, y) => order[x.d] - order[y.d]);
  const nFixed = rows.filter((r) => r.d === "fixed").length, nNew = rows.filter((r) => r.d === "new").length;
  return html`
    <div class="fnp">
      <div class="diff-bar">
        <span style="color:var(--muted);font-size:.8rem">A</span>
        <select class="diff-sel" value=${a} onChange=${(e) => setA(e.target.value)}>${ts.map((t) => html`<option value=${t.id} key=${t.id}>${t.filename}</option>`)}</select>
        <span style="color:var(--faint)">→</span>
        <span style="color:var(--muted);font-size:.8rem">B</span>
        <select class="diff-sel" value=${b} onChange=${(e) => setB(e.target.value)}>${ts.map((t) => html`<option value=${t.id} key=${t.id}>${t.filename}</option>`)}</select>
        ${onPatchDiff ? html`<button class="btn small" style="margin-left:auto"
          title="Patch-diff: localize the functions whose body changed between A (baseline) and B, and file them as leads the search then steers at (N-day)."
          disabled=${patch && patch.running} onClick=${() => onPatchDiff(a, b)}>
          ${patch && patch.running ? "Diffing…" : "Find changed functions"}</button>` : null}
        ${onVerify ? html`<button class="btn small primary" style=${onPatchDiff ? "" : "margin-left:auto"}
          disabled=${verify && verify.running} onClick=${() => onVerify(a, b)}>
          ${verify && verify.running ? "Verifying…" : "Verify fix — re-run A's PoCs on B"}</button>` : null}
      </div>
      ${patch && patch.key === a + ">" + b ? (patch.running
        ? html`<${Spinner} label=${`Diffing ${name(a)} → ${name(b)} for changed functions…`} />`
        : patch.error ? html`<div class="cat-intro">Patch-diff failed: ${patch.error}</div>`
        : patch.data ? html`<div class="diff-verify dv-fixed">
            ${(patch.data.leads || 0) > 0
              ? `${patch.data.leads} changed function(s) localized as leads — the search now steers at them (see Findings).`
              : ((patch.data.changed || 0) > 0
                 ? `${patch.data.changed} function(s) changed, but none carried a usable address to steer at.`
                 : "No changed functions between these builds (or one side isn't disassembled yet).")}
          </div>` : null) : null}
      ${verify && verify.key === a + ">" + b ? (verify.running
        ? html`<${Spinner} label=${`Re-running ${name(a)}'s PoC inputs against ${name(b)}…`} />`
        : verify.error ? html`<div class="cat-intro">Verification failed: ${verify.error}</div>`
        : verify.data && verify.data.applicable !== false ? html`
          <div class=${`diff-verify ${verify.data.fixed ? "dv-fixed" : "dv-vuln"}`}>
            ${verify.data.fixed
              ? `✓ Fixed — none of ${name(a)}'s ${verify.data.checked} PoC input(s) reproduce against ${name(b)}`
              : `✗ Still vulnerable — ${verify.data.reproduced}/${verify.data.checked} PoC input(s) still reproduce against ${name(b)}`}
          </div>
          <div class="diff-verify-list">
            ${(verify.data.results || []).map((r, i) => html`<div class="dvr" key=${i}>${r.level} · ${(r.cwe || "input")} — ${diffRowVerdict(r)}</div>`)}
          </div>`
        : verify.data ? html`<div class="cat-intro">${verify.data.note || "Nothing to verify."}</div>` : null) : null}
      <div class="diff-sum">
        <span class="ds-fixed">${nFixed} fixed</span><span class="ds-new">${nNew} new</span>
        <span style="color:var(--muted)">${rows.length - nFixed - nNew} unchanged</span>
      </div>
      <div class="diff-table">
        <div class="diff-row dr-head"><span>Δ</span><span>CWE</span><span>Finding</span><span style="text-align:center">${name(a)}</span><span style="text-align:center">${name(b)}</span></div>
        ${rows.map((r, i) => html`
          <div class=${`diff-row dr-${r.d}`} key=${i}>
            <span class=${`dr-tag t-${r.d}`}>${r.d === "fixed" ? "FIXED" : r.d === "new" ? "NEW" : "same"}</span>
            <span class="dr-cwe">${(r.f.cwe || "").replace(/^CWE-/, "")}</span>
            <span>${(r.f.title || "").replace(/\s*\(.*$/, "")}</span>
            <span class="dr-state">${r.a || "—"}</span>
            <span class="dr-state">${r.b || "—"}</span>
          </div>`)}
      </div>
    </div>`;
}

// Operator scans (were CLI-only: variant-scan, weggli-scan, diff-test). Each runs as a stage on
// the case and shows its own result here; matches are CANDIDATES and say so. `scans` holds one
// {running, data, error} per kind; `onRun(kind, opts)` starts one.
const _SCAN_WHAT = { variant: "variant hunt", weggli: "source-pattern scan", diff: "differential test" };
export function ScanResult({ kind, st }) {
  if (!st) return null;
  const what = _SCAN_WHAT[kind] || kind;
  if (st.running) return html`<${Spinner} label=${`Running ${what}…`} />`;
  if (st.error) return html`<div class="cat-intro">${what} failed: ${st.error}</div>`;
  const r = st.data;
  if (!r) return null;
  if (r.applicable === false) return html`<div class="cat-intro">${r.note || "Not applicable here."}</div>`;
  if (kind === "variant") return html`
    <div class="diff-verify-list">
      <div class="dvr muted">${r.function} from ${r.reference} — ${r.matched} of ${(r.results || []).length} target(s) match. ${r.note}</div>
      ${(r.results || []).map((x) => html`<div class="dvr" key=${x.target_id}>
        ${!x.scanned ? html`<span class="muted">not scanned</span> ${x.filename} — ${x.note}`
          : x.hits.length ? html`<b>MATCH</b> ${x.filename} — ${x.hits[0].name || "(unnamed)"} @ ${x.hits[0].addr}, similarity ${x.hits[0].similarity}${x.hits.length > 1 ? ` (+${x.hits.length - 1} more)` : ""}`
          : html`<span class="muted">no match</span> ${x.filename} (${x.functions} functions)`}
      </div>`)}
    </div>`;
  if (kind === "weggli") {
    const fs = r.findings || [];
    return html`
      <div class="diff-verify-list">
        <div class="dvr muted">${fs.length} pattern(s) matched over ${r.queries_run} queries${fs.length ? " — filed as candidate findings (see Overview)" : ""}.${r.note ? " " + r.note : ""}</div>
        ${fs.map((f, i) => html`<div class="dvr" key=${i} title=${f.why}>
          [${f.severity}] ${f.cwe} ${f.name} ×${f.count}: ${f.files.slice(0, 4).join(", ")}${f.files.length > 4 ? ` (+${f.files.length - 4} more)` : ""}
        </div>`)}
      </div>`;
  }
  const ds = r.discrepancies || [], inc = Object.entries(r.inconclusive || {});
  return html`
    <div class=${`diff-verify ${r.compared ? (ds.length ? "dv-vuln" : "dv-fixed") : ""}`}>
      ${r.execs} input(s), ${r.delta_diversity} distinct behaviour combination(s), ${ds.length} disagreement(s). ${r.note}
    </div>
    ${inc.length ? html`<div class="cat-intro">Inconclusive runs (never started or timed out — not counted): ${inc.map(([n, c]) => `${n} ×${c}`).join(", ")}</div>` : null}
    <div class="diff-verify-list">
      ${ds.slice(0, 40).map((x, i) => html`<div class="dvr" key=${i}>
        <b>${x.kind}</b> on <code>${x.input.slice(0, 48)}${x.input.length > 48 ? "…" : ""}</code> —
        ${Object.entries(x.partitions).map(([o, names]) => `[${o}] ${names.join(", ")}`).join("  ")}
      </div>`)}
    </div>`;
}
export function ScansPanel({ targets, activeId, seeds, scans, onRun }) {
  const ts = targets || [];
  const sc = scans || {};
  const [ref, setRef] = useState(activeId || (ts[0] && ts[0].id));
  const [fn, setFn] = useState("");
  const [thr, setThr] = useState("0.9");
  const [src, setSrc] = useState(activeId || (ts[0] && ts[0].id));
  const [cpp, setCpp] = useState(false);
  const [picked, setPicked] = useState(() => ts.slice(0, 2).map((t) => t.id));
  const [mode, setMode] = useState("stdin");
  const [compare, setCompare] = useState("status");
  const [iters, setIters] = useState("2000");
  const [useSeeds, setUseSeeds] = useState(true);
  const opt = (t) => html`<option value=${t.id} key=${t.id}>${t.filename}</option>`;
  const toggle = (id) => setPicked((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]);
  const nSeeds = (seeds || []).length;
  return html`
    <div class="fnp scans">
      <h3 class="scan-h">Variant hunt <span class="muted">— find a known-vulnerable function in the other builds (N-day)</span></h3>
      <div class="diff-bar">
        <span class="muted">reference</span>
        <select class="diff-sel" value=${ref} onChange=${(e) => setRef(e.target.value)}>${ts.map(opt)}</select>
        <input class="scan-in" placeholder="function name, e.g. parse_header" value=${fn}
          onInput=${(e) => setFn(e.target.value)} />
        <span class="muted">similarity ≥</span>
        <input class="scan-in scan-num" type="number" min="0" max="1" step="0.05" value=${thr}
          onInput=${(e) => setThr(e.target.value)} />
        <button class="btn small" style="margin-left:auto" disabled=${!fn.trim() || ts.length < 2 || (sc.variant && sc.variant.running)}
          title=${ts.length < 2 ? "add the other builds to this case first" : "scan every other target in the case"}
          onClick=${() => onRun("variant", { targetId: ref, params: { function: fn.trim(), threshold: Number(thr) || 0.9 } })}>Hunt variants</button>
      </div>
      <${ScanResult} kind="variant" st=${sc.variant} />

      <h3 class="scan-h">Source patterns <span class="muted">— the weggli vulnerability-pattern pack over the uploaded source</span></h3>
      <div class="diff-bar">
        <span class="muted">target</span>
        <select class="diff-sel" value=${src} onChange=${(e) => setSrc(e.target.value)}>${ts.map(opt)}</select>
        <label class="muted"><input type="checkbox" checked=${cpp} onChange=${(e) => setCpp(e.target.checked)} /> C++</label>
        <button class="btn small" style="margin-left:auto" disabled=${!src || (sc.weggli && sc.weggli.running)}
          onClick=${() => onRun("weggli", { targetId: src, params: { cpp } })}>Scan source</button>
      </div>
      <${ScanResult} kind="weggli" st=${sc.weggli} />

      <h3 class="scan-h">Differential test <span class="muted">— fuzz 2+ implementations of the same thing and report where they disagree</span></h3>
      <div class="diff-bar scan-wrap">
        ${ts.map((t) => html`<label class="muted" key=${t.id}><input type="checkbox" checked=${picked.includes(t.id)} onChange=${() => toggle(t.id)} /> ${t.filename}</label>`)}
      </div>
      <div class="diff-bar">
        <span class="muted">input via</span>
        <select class="diff-sel" value=${mode} onChange=${(e) => setMode(e.target.value)}>
          <option value="stdin">stdin</option><option value="file">file</option><option value="arg">argument</option></select>
        <span class="muted">compare</span>
        <select class="diff-sel" value=${compare} onChange=${(e) => setCompare(e.target.value)}>
          <option value="status">accept / reject / crash</option><option value="output">also the output bytes</option></select>
        <span class="muted">inputs</span>
        <input class="scan-in scan-num" type="number" min="1" max="100000" value=${iters} onInput=${(e) => setIters(e.target.value)} />
        ${nSeeds ? html`<label class="muted"><input type="checkbox" checked=${useSeeds} onChange=${(e) => setUseSeeds(e.target.checked)} /> seed with the ${nSeeds} uploaded seed${nSeeds === 1 ? "" : "s"}</label>` : null}
        <button class="btn small" style="margin-left:auto" disabled=${picked.length < 2 || (sc.diff && sc.diff.running)}
          title=${picked.length < 2 ? "pick at least two implementations" : ""}
          onClick=${() => onRun("diff", { params: { target_ids: picked, mode, compare,
            iterations: Number(iters) || 2000,
            ...(useSeeds && nSeeds ? { seed_shas: seeds.map((x) => x.sha256) } : {}) } })}>Compare</button>
      </div>
      <${ScanResult} kind="diff" st=${sc.diff} />
    </div>`;
}

// The crash TRIAGE view (roadmap P1). A run can record hundreds of crashing inputs that are a
// handful of bugs; the server groups them with the prove loop's own bucket key (sanitizer defect
// key / fault PC / signal+channel) and ranks the groups by the best VERIFIED level, then
// exploitability (GET /targets/<id>/crash-triage). One row per root cause: how many inputs hit it,
// what the run made of it, and a link to its finding and PoC. An unverified PoC level is shown as a
// candidate, never as the group's level. The raw per-input list stays one click away.
const _EXP_CLASS = { EXPLOITABLE: "exp-hi", PROBABLY_EXPLOITABLE: "exp-hi", UNKNOWN: "exp-mid",
                     PROBABLY_NOT_EXPLOITABLE: "exp-lo", NOT_EXPLOITABLE: "exp-lo" };
function CrashGroupRow({ g, artifactUrl, onOpenFinding }) {
  const where = g.defect_key ? g.defect_key : g.fault_pc ? g.fault_pc
    : `no fault PC · ${g.channel}`;
  const ex = g.exploitability;
  const f = (g.findings || [])[0];
  return html`
    <div class="ct-row">
      <span class="ct-rank">#${g.rank}</span>
      <span class="ct-lvl">${g.best_level
        ? html`<span class="ct-lvl-v" title="verified PoC level">L${g.best_level}</span>`
        : g.candidate_level
          ? html`<span class="ct-lvl-c" title="an unverified PoC exists for this level — not executed/confirmed">cand. L${g.candidate_level}</span>`
          : html`<span class="ct-lvl-n" title="no PoC built from this crash yet">—</span>`}</span>
      <span class="ct-what">
        <span class="crash-sig">${g.signal}</span>
        <span class="ct-where" title=${g.resolved ? "the root-cause bucket" : "the fault PC could not be read (hijacked return / emulated target): grouped by signal and channel, may hold more than one defect"}>${where}</span>
        ${g.resolved ? null : html`<span class="ct-unres">unresolved</span>`}
      </span>
      <span class="ct-count" title=${`${g.count} crashing execution(s), ${g.input_count} distinct input(s)`}>×${g.count}</span>
      <span class="ct-exp">${ex && ex.rating
        ? html`<span class=${`exp ${_EXP_CLASS[ex.rating] || "exp-mid"}`} title=${ex.why || ""}>${ex.rating.replace(/_/g, " ").toLowerCase()} ${ex.score != null ? `${ex.score}` : ""}</span>` : null}</span>
      <span class="ct-links">
        ${f && onOpenFinding ? html`<button class="btn xsmall ghost" title=${`${f.cwe || ""} ${f.title || ""} (${f.state})`}
            onClick=${() => onOpenFinding(f.id)}>finding</button>` : null}
        ${g.poc && g.poc.bundle_sha ? html`<a class="btn xsmall ghost" href=${artifactUrl(g.poc.bundle_sha)} download
            title=${`verified ${g.poc.level || ""} PoC bundle`}>⬇ PoC</a>` : null}
        ${g.representative ? html`<a class="btn xsmall ghost" href=${artifactUrl(g.representative)} download
            title="the representative crashing input">⬇ input</a>` : null}
      </span>
    </div>`;
}

export function CrashesPanel({ crashes, triage, artifactUrl, onOpenFinding }) {
  if (!crashes) return html`<div class="wb-soon"><${Spinner} label="Loading crashes…" /></div>`;
  const c = (crashes || []).filter((x) => x.crashed);
  if (!c.length) return html`<div class="wb-soon">No reproduced crashes for this target.</div>`;
  const groups = (triage && triage.groups) || null;
  const rawList = html`
      <div class="crash-list">
        ${c.map((x, i) => html`
          <div class="crash-row" key=${i}>
            <span class="crash-sig">${x.signal || "crash"}</span>
            <span class="crash-pc">${x.fault_pc || ""}</span>
            <span class="crash-mode">${x.input_mode || "stdin"}${x.argv && x.argv.length ? " · " + x.argv.join(" ") : ""}${x.isolation ? " · " + x.isolation : ""}</span>
            ${x.input_sha ? html`<a class="btn small ghost" href=${artifactUrl(x.input_sha)} download>⬇ input</a>` : html`<span></span>`}
          </div>`)}
      </div>`;
  if (!groups) {
    return html`<div class="fnp"><div class="fnp-hint">${c.length} reproduced crash${c.length === 1 ? "" : "es"}${triage === undefined ? " · grouping…" : ""}</div>${rawList}</div>`;
  }
  return html`
    <div class="fnp">
      <div class="fnp-hint">
        <b>${groups.length}</b> distinct root cause${groups.length === 1 ? "" : "s"} from ${triage.crashes} crashing execution${triage.crashes === 1 ? "" : "s"} —
        ranked by verified level, then exploitability.
        ${triage.over_prove_cap ? html` <span class="ct-cap">The autopilot proves at most ${triage.prove_cap} distinct crashes per target; an unlevelled group may simply not have been worked on.</span>` : null}
      </div>
      <div class="ct-list">
        ${groups.map((g) => html`<${CrashGroupRow} key=${g.rank} g=${g} artifactUrl=${artifactUrl} onOpenFinding=${onOpenFinding} />`)}
      </div>
      <details class="ct-raw">
        <summary class="btn xsmall ghost ct-raw-toggle">all ${c.length} crashing input${c.length === 1 ? "" : "s"}</summary>
        ${rawList}
      </details>
    </div>`;
}

// The run's honesty signals as one compact strip under the run bar (visible on every tab): a
// failed target, a degraded sandbox, ranked taint, tiered recovery, capped crashes, hangs, lease
// renewals. Chips only -- the explanation is one click away in a <details>, so a clean run shows
// nothing and a weak one is noticed without a wall of text.
export function RunSignalsStrip({ signals, bg, targets }) {
  const chips = runSignalChips(signals, bg, targets);
  if (!chips.length) return null;
  const worst = chips.some((c) => c.tone === "bad") ? "bad" : chips.some((c) => c.tone === "warn") ? "warn" : "info";
  return html`
    <details class=${`rsig rsig-${worst}`}>
      <summary>
        <span class="rsig-lbl">this run</span>
        ${chips.map((c) => html`<span key=${c.key} class=${`rsig-chip rsig-${c.tone}`}
          title=${(c.detail || []).join("\n")}>${c.label}</span>`)}
        <span class="rsig-more">details</span>
      </summary>
      <ul class="rsig-detail">
        ${chips.map((c) => (c.detail || []).map((d, i) => html`<li key=${`${c.key}-${i}`} class=${`rsig-${c.tone}`}>${d}</li>`))}
      </ul>
    </details>`;
}

// Engine readiness on THIS host (GET /doctor = `lykos doctor`): which engines can run before the
// operator spends a 20-minute budget finding out. Compact: one summary line, the missing engines
// as chips, the full table behind a toggle.
const _TIER_ORDER = ["required", "recommended", "optional"];
export function DoctorPanel({ doctor, onRefresh, compact }) {
  if (!doctor) return null;
  const tools = doctor.tools || [];
  const probing = doctor.state === "probing";
  if (!tools.length) {
    return html`<div class="card doctor"><div class="doctor-head">
      ${probing ? html`<${Spinner} label="Checking which engines work on this machine…" />`
        : html`<span>Engine check unavailable${doctor.error ? ` — ${doctor.error}` : ""}</span>`}
      ${!probing && onRefresh ? html`<button class="btn xsmall ghost" onClick=${onRefresh}>retry</button>` : null}</div></div>`;
  }
  const missing = tools.filter((t) => !t.present);
  const req = missing.filter((t) => t.tier === "required");
  const tone = req.length ? "bad" : missing.some((t) => t.tier === "recommended") ? "warn" : "ok";
  return html`
    <div class=${`card doctor doctor-${tone}`}>
      <div class="doctor-head">
        <span class="doctor-title">Engines on this machine</span>
        <span class=${`doctor-sum doctor-${tone}`}>${doctor.present}/${doctor.total} ready${req.length ? ` · ${req.length} REQUIRED missing` : ""}</span>
        ${probing ? html`<${Spinner} label="re-checking…" />` : null}
        <span class="doctor-acts">
          ${onRefresh && !probing ? html`<button class="btn xsmall ghost" title="probe every engine again" onClick=${onRefresh}>re-check</button>` : null}
        </span>
      </div>
      ${missing.length ? html`<div class="doctor-miss">
        ${missing.map((t) => html`<span key=${t.key} class=${`doctor-chip tier-${t.tier}`}
          title=${`${t.title}\nwithout it: ${t.without}\ninstall: ${t.install}`}>${t.title.replace(/\s*\(.*$/, "").replace(/\s+--.*$/, "")}</span>`)}
      </div>` : html`<div class="doctor-miss doctor-ok">every engine probed OK</div>`}
      ${!compact && doctor.toolchain ? html`<div class="doctor-tc">${doctor.toolchain}</div>` : null}
      <details class="doctor-more"><summary>every engine</summary>
      <table class="doctor-table"><tbody>
        ${_TIER_ORDER.flatMap((tier) => tools.filter((t) => t.tier === tier).map((t) => html`
          <tr key=${t.key} class=${t.present ? "dt-ok" : "dt-miss"}>
            <td class="dt-mark">${t.present ? "✓" : "✕"}</td>
            <td class="dt-name">${t.title}<span class="dt-tier">${tier}</span></td>
            <td class="dt-info">${t.present ? (t.found || "") : html`<span>${t.without}</span><br /><code>${t.install}</code>`}</td>
          </tr>`))}
      </tbody></table></details>
    </div>`;
}

// Self-test: lykos's own validation gates, from the GUI (were CLI-only). They check the TOOL, not
// a target, take minutes, and cannot be stopped once started -- the panel says so up front.
const _SELFTESTS = [
  { kind: "archgate", label: "Architecture gate", what: "every ISA still reaches its PoC level (lykos archgate)" },
  { kind: "realgate", label: "Real-program gate", what: "detect → PoC → attribution on real programs (lykos realgate)" },
  { kind: "eval", opts: { stage: "static" }, label: "Detection benchmark", what: "static detection precision/recall on the bundled corpus (lykos eval)" },
  { kind: "eval", opts: { stage: "dynamic" }, label: "Crash-reproduction benchmark", what: "fuzzing reproduces the corpus's crashes (lykos eval --stage dynamic)" },
];
export function SelftestPanel({ st, history, onStart, onHistory }) {
  const running = !!(st && st.running);
  const res = st && st.result;
  const tone = res ? (res.verdict === "PASS" ? "ok" : res.verdict === "SKIP" ? "warn" : "bad") : "";
  return html`
    <details class="card selftest">
      <summary class="doctor-title">Self-test — check this lykos build</summary>
      <div class="cat-intro">These validate the tool itself, not a target. Each takes minutes and runs to completion once started; one at a time.</div>
      <div class="diff-bar">
        ${_SELFTESTS.map((t, i) => html`<button class="btn small" key=${i} title=${t.what} disabled=${running}
          onClick=${() => onStart(t.kind, t.opts || {})}>${t.label}</button>`)}
        ${onHistory ? html`<button class="btn small ghost" style="margin-left:auto" onClick=${onHistory}
          title="the recorded detection-quality history (lykos dashboard)">Benchmark history</button>` : null}
      </div>
      ${st && st.state === "running" ? html`<${Spinner} label=${`Running ${st.kind}${st.options && st.options.stage ? ` (${st.options.stage})` : ""}…`} />` : null}
      ${st && st.error ? html`<div class="banner err">${st.kind} self-test failed: ${st.error}</div>` : null}
      ${res ? html`<div class=${`diff-verify ${tone === "ok" ? "dv-fixed" : tone === "bad" ? "dv-vuln" : ""}`}>
        ${st.kind}: ${res.verdict} — ${res.reason}</div>
        <pre class="selftest-out">${res.table}</pre>` : null}
      ${st && st.lines && st.lines.length && !res ? html`<pre class="selftest-out">${st.lines.slice(-20).join("\n")}</pre>` : null}
      ${history ? html`<div class="cat-intro">Benchmark history (${history.runs || 0} recorded run(s), ${history.path})${(history.regressions || []).length ? html` — <b>${history.regressions.length} series regressed</b>` : ""}</div>
        <pre class="selftest-out">${history.error || history.text || "no history recorded yet"}</pre>` : null}
    </details>`;
}

// Operator seed files (the CLI's `--seed`): real example inputs -- a config, a sample document, a
// known reproducer -- uploaded into the case and handed to the fuzzers. Without them a structured
// parser is rarely reached in a 20-minute budget.
export function SeedsField({ seeds, onAdd, onRemove, busy }) {
  const list = seeds || [];
  return html`
    <span class="seeds-field" title="Seed files: real example inputs (a config, a sample document, a known-crashing input) the fuzzers start from — the same as the CLI's --seed. Stored in this case, max 1 MiB each.">
      <label class=${`btn xsmall ghost seed-add${busy ? " busy" : ""}`}>${busy ? "uploading…" : "+ seeds"}
        <input type="file" multiple disabled=${busy} style="display:none" aria-label="add seed files"
          onChange=${(e) => { const fl = e.target.files; if (fl && fl.length) onAdd(fl); e.target.value = ""; }} /></label>
      ${list.map((s) => html`<span key=${s.sha256} class="seed-chip" title=${`${s.name} · ${s.size} bytes · ${s.sha256.slice(0, 12)}`}>
        ${s.name}<button type="button" class="seed-rm" aria-label=${`remove seed ${s.name}`}
          onClick=${() => onRemove(s.sha256)}>✕</button></span>`)}
    </span>`;
}

// Which build is serving the GUI (GET /version), so a stale air-gap disc is noticeable.
export function BuildFoot({ info }) {
  if (!info) return null;
  const bits = [];
  if (info.built) bits.push(`commit date ${String(info.built).slice(0, 10)}`);
  if (info.toolchain_built) bits.push(`toolchain ${String(info.toolchain_built).slice(0, 10)}`);
  const tip = [`version ${info.version || "?"}`, info.commit ? `commit ${info.commit}` : "no commit recorded",
    info.branch ? `branch ${info.branch}` : null, info.source ? `from ${info.source}` : null,
    info.code_mtime ? `newest source file ${info.code_mtime}` : null].filter(Boolean).join("\n");
  return html`<footer class="build-foot" title=${tip}>
    <span>${info.display || `lykos ${info.version || ""}`}</span>
    ${bits.length ? html`<span class="bf-sub">${bits.join(" · ")}</span>` : null}
    ${info.source === "none" ? html`<span class="bf-warn">no commit stamp — build unidentified</span>` : null}
  </footer>`;
}


// A pan/zoom canvas of a target's internal call graph. Nodes = functions (clickable → open) plus
// leaf nodes for external/PLT calls; edges = calls. Laid out in layers by BFS depth from main/entry.
// The demonstrated finding's function is highlighted so the exploit's home is visible at a glance.
const _cgClean = (n) => (n || "").replace(/^(sym\.imp\.|sym\.|imp\.)/, "").replace(/@.*/, "") || "?";
export function CallGraphCanvas({ functions, edges, onOpen, highlightAddr }) {
  const [view, setView] = useState({ tx: 0, ty: 0, k: 1 });
  const drag = useRef(null);
  const na = (a) => (a == null ? null : (typeof a === "string" ? parseInt(a, 16) : a));
  if (!functions || !edges) return html`<div class="wb-soon"><${Spinner} label="Loading call graph…" /></div>`;
  const fnByAddr = new Map((functions || []).map((f) => [na(f.addr), f]));
  const nodeMap = new Map();
  const E = [];
  const addFn = (f) => { const k = "f" + na(f.addr); if (!nodeMap.has(k)) nodeMap.set(k, { key: k, label: _cgClean(f.name) || fmtAddr(f.addr), kind: "fn", fn: f, addr: na(f.addr) }); return k; };
  const addExt = (nm) => { const k = "x" + nm; if (!nodeMap.has(k)) nodeMap.set(k, { key: k, label: _cgClean(nm), kind: "ext" }); return k; };
  for (const e of edges) {
    const sf = fnByAddr.get(na(e.src_addr));
    if (!sf) continue;
    const from = addFn(sf);
    const df = fnByAddr.get(na(e.dst_addr));
    const to = df ? addFn(df) : (e.dst_name ? addExt(e.dst_name) : null);
    if (to && to !== from) E.push([from, to]);
  }
  const nodes = [...nodeMap.values()];
  if (!nodes.length) return html`<div class="wb-soon">No call edges were recovered for this target.</div>`;
  const adj = new Map(nodes.map((n) => [n.key, []]));
  const indeg = new Map(nodes.map((n) => [n.key, 0]));
  for (const [a, b] of E) { adj.get(a).push(b); indeg.set(b, indeg.get(b) + 1); }
  let roots = nodes.filter((n) => n.kind === "fn" && /(^|\.)main$|entry/i.test(n.label)).map((n) => n.key);
  if (!roots.length) roots = nodes.filter((n) => indeg.get(n.key) === 0).map((n) => n.key);
  if (!roots.length) roots = [nodes[0].key];
  const depth = new Map(); const q = [...roots]; roots.forEach((r) => depth.set(r, 0));
  while (q.length) { const a = q.shift(); for (const b of adj.get(a) || []) if (!depth.has(b)) { depth.set(b, depth.get(a) + 1); q.push(b); } }
  let maxD = 0; depth.forEach((v) => { maxD = Math.max(maxD, v); });
  nodes.forEach((n) => { if (!depth.has(n.key)) depth.set(n.key, maxD + 1); });
  const layers = [];
  nodes.forEach((n) => { const d = depth.get(n.key); (layers[d] = layers[d] || []).push(n); });
  const COLW = 168, ROWH = 92, NW = 132, NH = 38, PAD = 30;
  const maxCols = Math.max(1, ...layers.map((l) => (l ? l.length : 0)));
  const pos = new Map();
  layers.forEach((layer, d) => { if (!layer) return; const off = (maxCols - layer.length) / 2; layer.forEach((n, i) => pos.set(n.key, { x: (off + i) * COLW + PAD, y: d * ROWH + PAD })); });
  const W = maxCols * COLW + PAD * 2, H = layers.length * ROWH + PAD * 2;
  const onWheel = (ev) => { ev.preventDefault(); const f = ev.deltaY < 0 ? 1.1 : 0.9; setView((v) => ({ ...v, k: Math.min(2.4, Math.max(0.3, v.k * f)) })); };
  const onDown = (ev) => { drag.current = { x: ev.clientX, y: ev.clientY, tx: view.tx, ty: view.ty }; };
  const onMove = (ev) => { if (!drag.current) return; setView((v) => ({ ...v, tx: drag.current.tx + (ev.clientX - drag.current.x), ty: drag.current.ty + (ev.clientY - drag.current.y) })); };
  const onUp = () => { drag.current = null; };
  return html`
    <div class="cgc">
      <div class="cgc-tools">
        <button class="btn xsmall ghost" onClick=${() => setView({ tx: 0, ty: 0, k: 1 })}>Reset view</button>
        <span class="cgc-hint">${nodes.length} nodes · drag to pan · scroll to zoom · click a function to open it</span>
      </div>
      <svg class="cgc-svg" width="100%" height="520" viewBox=${`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet" onWheel=${onWheel} onPointerDown=${onDown}
        onPointerMove=${onMove} onPointerUp=${onUp} onPointerLeave=${onUp}>
        <g transform=${`translate(${view.tx},${view.ty}) scale(${view.k})`}>
          ${E.map(([a, b], i) => { const p = pos.get(a), r = pos.get(b); if (!p || !r) return null;
            const x1 = p.x + NW / 2, y1 = p.y + NH, x2 = r.x + NW / 2, y2 = r.y, my = (y1 + y2) / 2;
            return html`<path key=${"e" + i} class="cg2-edge" d=${`M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`} />`; })}
          ${nodes.map((n) => { const p = pos.get(n.key); if (!p) return null;
            const hl = n.kind === "fn" && highlightAddr != null && n.addr === na(highlightAddr);
            return html`<g key=${n.key} class=${`cg2-node ${n.kind === "ext" ? "cg2-ext" : "cg2-fn"}${hl ? " cg2-hl" : ""}`}
                transform=${`translate(${p.x},${p.y})`} onClick=${() => { if (n.kind === "fn" && onOpen) onOpen(n.fn); }}>
              <rect width=${NW} height=${NH} rx="8"></rect>
              <text x=${NW / 2} y=${NH / 2 + 4} text-anchor="middle">${n.label.length > 17 ? n.label.slice(0, 16) + "…" : n.label}</text>
            </g>`; })}
        </g>
      </svg>
    </div>`;
}

// Severity -> CSS color token (matches the --crit..--info / sev-* palette used across the UI).
const SEVVAR = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const _sameSeg = (a, b) => a && b && a.severity === b.severity && a.cwe === b.cwe;

// Case Overview: at-a-glance INTERACTIVE analytics for the active target -- a severity donut, a
// top-CWE bar chart, the L0->L3 weaponization ladder, and a detector mix. Pure inline SVG (the
// project ships no chart lib), themed via the --crit..--info tokens. Clicking a severity arc or a
// CWE bar calls onFilter to narrow the findings list (click again to clear); hovering shows a
// native <title> tooltip. onFilter is optional, so this renders -- and tests -- with or without the
// interactive wiring.
// The engagement map (doc 49 Theme 2a): the analysis path recover -> detect -> search -> prove,
// each phase a clickable node that jumps to the tab where that phase's work lives. A reached phase
// is solid; an unreached one is muted and inert -- so the map shows honestly how far this run got.
export function EngagementMap({ phases, onNav }) {
  if (!phases || !phases.length) return null;
  return html`<div class="engmap">
    ${phases.map((p, i) => html`
      ${i ? html`<span class="engmap-arrow" key=${"a" + i}>▸</span>` : null}
      <div key=${p.label}
        class=${`engmap-node${p.reached ? " reached" : " muted"}${p.reached && p.nav ? " clk" : ""}`}
        onClick=${() => (p.reached && p.nav && onNav ? onNav(p.nav) : null)}
        title=${p.reached ? (p.nav ? `Go to ${p.nav}` : "") : "not reached in this run"}>
        <span class="engmap-lbl">${p.label}</span>
        <span class="engmap-sub">${p.detail}</span>
      </div>`)}
  </div>`;
}

export function CaseOverview({ findings, pocs, filter, onFilter }) {
  const fs = findings || [];
  if (!fs.length) return null;
  const total = fs.length;
  const sev = SEV_ORDER
    .map((s) => ({ key: s, count: fs.filter((f) => (f.severity || "").toLowerCase() === s).length }))
    .filter((d) => d.count);
  const cwes = histogram(fs, "cwe").slice(0, 6);
  const dets = histogram(fs, "detector");
  const lvl = maxPocLevel(pocs);
  const LADDER = ["Detected", "Crash", "Primitive", "Exploit"];       // L0 .. L3
  const pick = (seg) => onFilter && onFilter(_sameSeg(filter, seg) ? null : seg);

  // Donut: one stroked arc per severity, sized by share of findings.
  const R = 46, C = 58, SW = 16;
  let a0 = -Math.PI / 2;
  const pt = (ang) => [C + R * Math.cos(ang), C + R * Math.sin(ang)];
  const arcs = sev.map((d) => {
    const a1 = a0 + (d.count / total) * 2 * Math.PI;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const [x0, y0] = pt(a0);
    const [x1, y1] = pt(a1 - 1e-4);
    const on = !!(filter && filter.severity === d.key);
    const seg = { severity: d.key };
    const path = `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${R} ${R} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
    a0 = a1;
    return html`<path key=${d.key} d=${path} fill="none" stroke=${`var(--${SEVVAR[d.key]})`}
      stroke-width=${on ? SW + 4 : SW} stroke-linecap="butt"
      class=${`ov-arc${onFilter ? " clk" : ""}`} onClick=${() => pick(seg)}>
      <title>${d.count} ${d.key}${onFilter ? " — click to filter the list" : ""}</title></path>`;
  });

  const barMax = Math.max(1, ...cwes.map((c) => c.count));
  return html`<div class="ov" aria-label="case overview">
    ${filter ? html`<button class="ov-clear btn small ghost" onClick=${() => onFilter && onFilter(null)}>
      ✕ clear ${filter.severity || filter.cwe || filter.stageLabel || filter.stage} filter</button>` : null}
    <div class="ov-grid">
      <div class="ov-card">
        <div class="ov-h">Severity</div>
        <svg viewBox="0 0 116 116" class="ov-donut" role="img" aria-label="severity distribution">
          <circle cx=${C} cy=${C} r=${R} fill="none" stroke="var(--line)" stroke-width=${SW} opacity="0.25" />
          ${arcs}
          <text x=${C} y=${C - 2} text-anchor="middle" class="ov-donut-n">${total}</text>
          <text x=${C} y=${C + 13} text-anchor="middle" class="ov-donut-l">finding${total === 1 ? "" : "s"}</text>
        </svg>
        <div class="ov-legend">${sev.map((d) => html`<span key=${d.key} class=${`ov-leg${filter && filter.severity === d.key ? " on" : ""}`}
          onClick=${() => pick({ severity: d.key })}><i class=${`sev sev-${d.key}`}></i>${d.key} ${d.count}</span>`)}</div>
      </div>
      <div class="ov-card">
        <div class="ov-h">Top CWEs</div>
        <div class="ov-bars">${cwes.map((c) => html`<div key=${c.key}
          class=${`ov-bar${onFilter ? " clk" : ""}${filter && filter.cwe === c.key ? " on" : ""}`}
          onClick=${() => pick({ cwe: c.key })} title=${`${c.key}: ${c.count}${onFilter ? " — click to filter" : ""}`}>
          <span class="ov-bar-k">${c.key}</span>
          <span class="ov-bar-t"><span class="ov-bar-f" style=${`width:${Math.round((c.count / barMax) * 100)}%`}></span></span>
          <span class="ov-bar-n">${c.count}</span></div>`)}</div>
      </div>
      <div class="ov-card">
        <div class="ov-h">Weaponization</div>
        <div class="ov-ladder">${LADDER.map((name, i) => html`<div key=${name}
          class=${`ov-step${lvl >= i ? " reached" : ""}${lvl === i ? " top" : ""}`}
          title=${`L${i} ${name}${lvl >= i ? " — reached" : ""}`}>
          <span class="ov-step-n">L${i}</span><span class="ov-step-l">${name}</span></div>`)}</div>
        <div class="ov-det">${dets.map((d) => html`<span key=${d.key} class="ov-chip" title=${`${d.count} finding(s) via ${d.key}`}>${d.key} ·${d.count}</span>`)}</div>
      </div>
    </div>
  </div>`;
}


// One fuzz engine's per-attempt log: every execution, what was sent, how it ended. Filter by
// outcome / phase, page through, download the whole gzipped JSONL.
const _PHASES = ["seed", "mutate", "minimize", "reproduce", "confirm", "afl-seed", "afl-queue",
                 "afl-crash", "afl-hang"];

export function AttemptLogModal({ sha, engine, fetchPage, artifactUrl, onClose }) {
  const [filter, setFilter] = useState({ outcome: "", phase: "", errorsOnly: false, offset: 0 });
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const limit = 200;
  useEffect(() => {
    let live = true;
    setErr(null);
    fetchPage(sha, { ...filter, limit }).then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(e.message || String(e)); });
    return () => { live = false; };
  }, [sha, filter.outcome, filter.phase, filter.errorsOnly, filter.offset]);
  if (!sha) return null;
  const sm = (data && data.summary) || {};
  const set = (k, v) => setFilter((f) => ({ ...f, [k]: v, offset: k === "offset" ? v : 0 }));
  const rows = (data && data.rows) || [];
  const total = data ? data.total : 0;
  const matched = data ? data.matched : 0;
  const tops = Object.entries(sm.top_errors || {}).flatMap(([o, l]) => (l || []).slice(0, 2).map((t) => ({ o, ...t })));
  return html`
    <div class="modal-back" onClick=${onClose}>
      <div class="modal attempts" role="dialog" aria-modal="true" tabindex="-1"
        aria-label=${`Attempt log for ${engine}`} onClick=${(e) => e.stopPropagation()}>
        <div class="ev-head">
          <div>
            <div class="ev-title">Attempt log — ${_FH_ENGINE[engine] || engine}</div>
            <div class="ev-sub">${_fmtN(total)} attempts · verdict <b>${sm.verdict || "…"}</b>
              ${data && data.header && data.header.unit ? html` · coverage unit: ${data.header.unit}` : null}</div>
          </div>
          <span style="display:flex;gap:6px">
            <a class="btn xsmall" href=${artifactUrl(sha)} download=${`${engine}-attempts.jsonl.gz`}>⬇ full log</a>
            <button class="btn ghost small" onClick=${onClose}>✕ Close</button>
          </span>
        </div>
        ${sm.verdict_note ? html`<div class=${`att-verdict att-${sm.verdict}`}>${sm.verdict_note}</div>` : null}
        ${sm.counts ? html`<div class="att-bar"><${OutcomeBar} counts=${sm.counts} /></div>` : null}
        ${tops.length ? html`
          <div class="att-tops">
            <div class="ev-sec-h">Most common error output</div>
            ${tops.map((t) => html`<div class="att-top"><span class="att-o" style=${`color:${(OUTCOME_META[t.o] || {}).color}`}>${(OUTCOME_META[t.o] || {}).label || t.o}</span>
              <span class="att-n">×${_fmtN(t.count)}</span>${t.rc != null ? html`<code>rc ${t.rc}</code>` : null}
              <span class="att-msg">${t.msg || "(no stderr)"}</span></div>`)}
          </div>` : null}
        <div class="att-filters">
          <button class=${`chip${!filter.outcome && !filter.errorsOnly ? " on" : ""}`} onClick=${() => setFilter({ outcome: "", phase: filter.phase, errorsOnly: false, offset: 0 })}>all</button>
          <button class=${`chip${filter.errorsOnly ? " on" : ""}`} onClick=${() => setFilter({ outcome: "", phase: filter.phase, errorsOnly: true, offset: 0 })}>not clean</button>
          ${_OUTCOME_ORDER.map((o) => html`<button class=${`chip${filter.outcome === o ? " on" : ""}`}
            onClick=${() => setFilter({ outcome: o, phase: filter.phase, errorsOnly: false, offset: 0 })}>
            <i style=${`background:${OUTCOME_META[o].color}`}></i>${OUTCOME_META[o].label}${sm.counts && sm.counts[o] != null ? ` ${_fmtN(sm.counts[o])}` : ""}</button>`)}
          <select class="att-phase" value=${filter.phase} onChange=${(e) => set("phase", e.target.value)}>
            <option value="">every phase</option>
            ${_PHASES.map((p) => html`<option value=${p}>${p}</option>`)}
          </select>
        </div>
        ${err ? html`<div class="att-verdict att-erroring">${err}</div>` : null}
        <div class="att-table-wrap">
          <table class="att-table">
            <thead><tr><th>#</th><th>t</th><th>phase</th><th>outcome</th><th>rc / sig</th><th>ms</th><th>len</th><th>new</th><th>input (first bytes)</th><th>stderr / note</th></tr></thead>
            <tbody>
              ${rows.map((r) => html`<tr key=${r.i}>
                <td class="num">${r.i}</td><td class="num">${r.t != null ? Number(r.t).toFixed(2) : ""}</td>
                <td>${r.ph}</td>
                <td><span class="att-o" style=${`color:${(OUTCOME_META[r.o] || {}).color || "var(--muted)"}`}>${(OUTCOME_META[r.o] || {}).label || r.o}</span>${r.kept ? html` <span class="att-kept" title="joined the corpus">kept</span>` : null}</td>
                <td><code>${r.sig || (r.rc == null ? "" : r.rc)}</code></td>
                <td class="num">${r.ms != null ? r.ms : ""}</td><td class="num">${r.len}</td>
                <td class="num">${r.new || ""}</td>
                <td><code class="att-hex" title=${`sha256 ${r.in}…${r.argv ? `\nflags: ${r.argv.join(" ")}` : ""}`}>${r.head}</code></td>
                <td class="att-msg">${r.err || r.note || ""}</td>
              </tr>`)}
            </tbody>
          </table>
          ${data && !rows.length ? html`<div class="att-empty">No attempts match this filter.</div>` : null}
        </div>
        <div class="att-pager">
          <span>${matched ? `${_fmtN(filter.offset + 1)}–${_fmtN(filter.offset + rows.length)} of ${_fmtN(matched)}` : ""}</span>
          <button class="btn xsmall ghost" disabled=${filter.offset === 0} onClick=${() => set("offset", Math.max(0, filter.offset - limit))}>‹ prev</button>
          <button class="btn xsmall ghost" disabled=${filter.offset + rows.length >= matched} onClick=${() => set("offset", filter.offset + limit)}>next ›</button>
        </div>
      </div>
    </div>`;
}

// Every attempt log in the case (older runs too), newest first.
export function AttemptLogsList({ logs, onOpen }) {
  if (!Array.isArray(logs) || !logs.length) return null;
  return html`
    <details class="card att-list">
      <summary class="sysmap-head" style="cursor:pointer">Fuzz attempt logs <span class="tab-n">${logs.length}</span></summary>
      <div class="sysmap-sub">One log per fuzz engine per run: every execution, what was sent and how it ended.</div>
      ${logs.map((l) => html`
        <div key=${l.sha256} class="att-list-row">
          <span style="flex:0 0 150px">${_FH_ENGINE[l.engine] || l.engine}</span>
          <span style="flex:0 0 90px" class="num">${_fmtN(l.attempts)} attempts</span>
          <span style="flex:0 0 160px"><${OutcomeBar} counts=${l.counts} compact=${true} /></span>
          <span style="flex:1;opacity:.75;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=${l.verdict_note || ""}>${l.verdict}${l.verdict_note ? ` — ${l.verdict_note}` : ""}</span>
          <button class="btn xsmall ghost" onClick=${() => onOpen(l.sha256, l.engine)}>open</button>
        </div>`)}
    </details>`;
}
