// Presentational components. No fetching, no orchestration -- they render what app.js hands
// them. Keeping them pure is what makes the workbench maintainable: the old GUI was one
// 160 KB file where markup, state, and network calls were braided together.

import { h } from "preact";
import { useState, useRef, useEffect } from "preact/hooks";
import htm from "htm";
import {
  STATE_LABEL, STATE_GLOSS, isDemonstrated, fmtBytes, shortHash, runTone, stageLabel,
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
const _PLAN_ICON = { done: "✓", error: "✕", skipped: "–", cancelled: "■" };
// A COMPACT progress summary -- deliberately not a stage list (the Run log already is one). It
// gives what the log does not: overall progress at a glance, the step running right now, and the
// shape of what is still ahead (the dot strip, each dot a stage; hover for its name + detail).
export function PipelinePlan({ plan, targetName, target, targets }) {
  if (!plan || !plan.length) return null;
  const active = plan.filter((p) => p.state !== "skipped");
  const done = active.filter((p) => p.state === "done").length;
  const total = active.length || plan.length;
  const running = plan.find((p) => p.state === "running");
  const errored = plan.find((p) => p.state === "error");
  const pct = Math.round((100 * done) / Math.max(1, total));
  return html`
    <div class="plan card compact">
      <div class="plan-head">
        <span>Pipeline${target && targets > 1 ? ` · target ${target}/${targets}` : ""}${
          targetName ? html` · <span class="mono">${targetName}</span>` : null}</span>
        <span class="plan-count">${done}/${total}</span>
      </div>
      <div class="plan-bar"><div class=${`plan-fill${errored ? " err" : ""}`} style=${`width:${Math.max(3, pct)}%`}></div></div>
      <div class="plan-now">
        ${running ? html`<${Spinner} label=${running.label + (running.detail ? ` — ${running.detail}` : "")} />`
          : errored ? html`<span class="plan-nowerr">✕ ${errored.label}${errored.detail ? ` — ${errored.detail}` : " failed"}</span>`
          : html`<span class="plan-nowok">✓ all ${total} steps complete</span>`}
      </div>
      <div class="plan-dots">
        ${plan.map((p) => html`<span class=${`plan-dot dot-${p.state}`} key=${p.stage}
          title=${p.label + (p.detail ? ` — ${p.detail}` : "")}></span>`)}
      </div>
    </div>`;
}

// The upload surface. A drop target AND a click-to-pick, because the whole design goal is the
// fewest clicks: drag a binary onto the page and Autopilot can start on the next click. Accepts
// several files at once -- multiple binaries in one case unlock the cross-binary analyses.
export function DropZone({ onFiles, busy, compact }) {
  const take = (fl) => { if (fl && fl.length) onFiles(fl); };
  const onDrop = (e) => { e.preventDefault(); if (!busy) take(e.dataTransfer && e.dataTransfer.files); };
  const onPick = (e) => { take(e.target.files); e.target.value = ""; };
  return html`
    <label class=${`dropzone${busy ? " busy" : ""}${compact ? " compact" : ""}`}
           onDragOver=${(e) => e.preventDefault()} onDrop=${onDrop}>
      <input type="file" multiple hidden onChange=${onPick} disabled=${busy} />
      <div class="dz-inner">
        <div class="dz-icon">⇪</div>
        <div class="dz-title">${compact ? "Add more binaries to this case" : "Drop one or more binaries or firmware images here"}</div>
        <div class="dz-sub">${compact ? "several binaries unlock IPC modelling and cross-binary taint" : "or click to choose files — analysis starts on the next click"}</div>
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
    const icon = e.status === "running" ? html`<span class="st-run"></span>`
      : e.status === "error" ? html`<span class="st-ico st-bad">✕</span>`
      : html`<span class="st-ico st-ok">✓</span>`;
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
export function FindingCard({ finding, pocs, reportUrl, artifactUrl, onViewCode, mitigations, onInspect }) {
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
    <div class=${`card finding${demo ? " demo" : ""}`}>
      <div class="find-top">
        <${SevDot} severity=${finding.severity} />
        <div class="find-id">
          <div class="find-title">${finding.title || finding.detector || finding.cwe}</div>
          <div class="find-meta">
            <span class="cwe cwe-info" title=${cweTip(finding)}>${finding.cwe}</span>
            ${finding.detector ? html`<span class="det">via ${finding.detector}</span>` : null}
            ${site ? html`<span class="at">at <code>${site}</code></span>` : null}
            ${finding.group_count > 1 ? html`<span class="sites">${finding.group_count} occurrences</span>` : (finding.site_count ? html`<span class="sites">${finding.site_count} site${finding.site_count === 1 ? "" : "s"}${finding.proven_sites ? ` · ${finding.proven_sites} proven` : ""}</span>` : null)}
          </div>
        </div>
        <${Badge} state=${finding.state} />
      </div>
      <div class="find-gloss">${STATE_GLOSS[finding.state] || ""}</div>

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
        ${finding.function_addr && onViewCode
          ? html`<button class="btn small ghost" onClick=${() => onViewCode(finding)}>⟨⟩ View code</button>` : null}
        ${onInspect ? html`<button class="btn small ghost" onClick=${() => inspect(null)}>🔍 Inspect evidence</button>` : null}
        ${finding.verification ? html`<${VerifyBadge} v=${finding.verification} />` : null}
      </div>
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
export function EvidenceModal({ finding, pocs, artifactUrl, onViewCode, onClose, focus }) {
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
      <div class="modal evidence" onClick=${(e) => e.stopPropagation()}>
        <div class="ev-head">
          <div>
            <div class="ev-title"><${SevDot} severity=${finding.severity} /> ${finding.title || finding.cwe}</div>
            <div class="ev-sub"><span class="cwe cwe-info" title=${cweTip(finding)}>${finding.cwe}</span>
              ${finding.cwe_name ? html`<span class="cwe-name">${finding.cwe_name}</span>` : null}
              ${finding.detector ? html`<span class="det">via ${finding.detector}</span>` : null}
              ${site ? html`<span class="at">at <code>${site}</code></span>` : null}
              <${Badge} state=${finding.state} /></div>
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
          ${finding.function_addr && onViewCode ? html`<button class="btn small ghost" onClick=${() => { onClose(); onViewCode(finding); }}>⟨⟩ View code at ${site || "site"}</button>` : null}
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
      <div class="modal funcs" onClick=${(e) => e.stopPropagation()}>
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
      <div class="modal code" onClick=${(e) => e.stopPropagation()}>
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
  return html`
    <div class="card sysmap">
      <div class="sysmap-head">Case components — cross-binary analysis</div>
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
    </div>`;
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
        <div class="vv-mini-ladder" title="how far the exploit chain got">
          ${[1, 2, 3].map((n) => html`${n > 1 ? html`<span class=${`vd-arrow${v.level >= n ? " filled" : ""}`}>▸</span>` : null}<span class=${`vd-rung${v.level >= n ? " filled" : ""}`} key=${n}>L${n}</span>`)}
        </div>
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
export function DiffPanel({ targets, findings, onVerify, verify }) {
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
        ${onVerify ? html`<button class="btn small primary" style="margin-left:auto"
          disabled=${verify && verify.running} onClick=${() => onVerify(a, b)}>
          ${verify && verify.running ? "Verifying…" : "Verify fix — re-run A's PoCs on B"}</button>` : null}
      </div>
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

export function CrashesPanel({ crashes, artifactUrl }) {
  if (!crashes) return html`<div class="wb-soon"><${Spinner} label="Loading crashes…" /></div>`;
  const c = (crashes || []).filter((x) => x.crashed);
  if (!c.length) return html`<div class="wb-soon">No reproduced crashes for this target.</div>`;
  return html`
    <div class="fnp">
      <div class="fnp-hint">${c.length} reproduced crash${c.length === 1 ? "" : "es"}</div>
      <div class="crash-list">
        ${c.map((x, i) => html`
          <div class="crash-row" key=${i}>
            <span class="crash-sig">${x.signal || "crash"}</span>
            <span class="crash-pc">${x.fault_pc || ""}</span>
            <span class="crash-mode">${x.input_mode || "stdin"}${x.argv && x.argv.length ? " · " + x.argv.join(" ") : ""}${x.isolation ? " · " + x.isolation : ""}</span>
            ${x.input_sha ? html`<a class="btn small ghost" href=${artifactUrl(x.input_sha)} download>⬇ input</a>` : html`<span></span>`}
          </div>`)}
      </div>
    </div>`;
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
