// Presentational components. No fetching, no orchestration -- they render what app.js hands
// them. Keeping them pure is what makes the workbench maintainable: the old GUI was one
// 160 KB file where markup, state, and network calls were braided together.

import { h } from "preact";
import htm from "htm";
import {
  STATE_LABEL, STATE_GLOSS, isDemonstrated, fmtBytes, shortHash, runTone, stageLabel,
} from "./util.js";

const html = htm.bind(h);
export { html };

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

export function TargetSummary({ target, advice, index }) {
  if (!target) return null;
  const d = target.details || {};
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
export function FindingCard({ finding, pocs, reportUrl, artifactUrl, onViewCode, mitigations }) {
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
            <span class="cwe">${finding.cwe}</span>
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
        <div class=${`exploit-rating ${RATING_CLASS[exp.rating] || "exp-mid"}`}>
          <span class="er-badge">${exp.rating ? exp.rating.replace(/_/g, " ") : "assessed"}${exp.score != null ? ` · ${exp.score}/100` : ""}</span>
          ${exp.why || exp.text ? html`<span class="er-why">${exp.why || exp.text}</span>` : null}
        </div>` : null}

      ${(rootCause || howFound.length || other.length || legacySteps) ? html`
        <div class="exploit">
          <div class="exploit-head">How it can be exploited</div>
          <ol class="exploit-trail">
            ${rootCause ? html`<li><span class="et-k">Mechanism</span> ${rootCause}</li>` : null}
            ${howFound.map((h) => html`<li><span class="et-k">Reached</span> ${h}</li>`)}
            ${other.map((o) => html`<li><span class="et-k">Evidence</span> ${o}</li>`)}
            ${legacySteps ? (Array.isArray(legacySteps) ? legacySteps : String(legacySteps).split("\n")).filter(Boolean).map((s) => html`<li>${typeof s === "string" ? s : (s.text || "")}</li>`) : null}
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
export function CoveragePanel({ coverage, targets }) {
  const rows = Object.entries(coverage || {});
  if (!rows.length) return null;
  const nameOf = (id) => ((targets || []).find((t) => t.id === id) || {}).filename || id.slice(0, 8);
  return html`
    <div class="card cov">
      <div class="cov-head">Fuzzing coverage</div>
      <div class="cov-sub">How much of each binary's recovered code the search actually exercised.</div>
      ${rows.map(([tid, c]) => html`
        <div class="cov-row" key=${tid}>
          <span class="cov-name">${nameOf(tid)}</span>
          <div class="cov-bar"><div class=${`cov-fill cov-${covTone(c.pct)}`} style=${`width:${c.pct != null ? Math.max(2, Math.min(100, c.pct)) : 0}%`}></div></div>
          <span class="cov-val">${c.pct != null ? `${c.pct}%` : "—"} <span class="cov-detail">${c.kind === "edge" ? `${c.edges || "?"} edges` : `${c.hit}/${c.known} blocks`}</span></span>
        </div>`)}
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
