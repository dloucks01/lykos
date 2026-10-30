// The finding detail pane: full analysis for one finding, every state. PoC deliverable, the attack
// FLOW (how the payload reaches the effect), status, exploitability, and the evidence trail as a
// flowing report (no cards/bubbles).
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { PocDeliverable, ConfirmationLadder } from "./poc.js";
import { Disasm, StackFrame, XRefs } from "./code.js";
import { fetchFunctionAt } from "./store.js";

// classify a leaked 64-bit word by its address range -> what it is + what it gives the attacker.
function classifyWord(w) {
  let v; try { v = BigInt(w); } catch (e) { return null; }
  if (v === 0n) return { t: "null", c: "null", s: "" };
  const bytes = []; let t = v;
  for (let i = 0; i < 8; i++) { bytes.push(Number(t & 0xffn)); t >>= 8n; }
  const nz = bytes.filter((b) => b !== 0);
  if (nz.length && nz.every((b) => b >= 0x20 && b < 0x7f)) {
    const s = bytes.filter((b) => b).map((b) => String.fromCharCode(b)).join("");
    return { t: "echoed input / ASCII", c: "ascii", s: `"${s}" — your own bytes, not a useful leak` };
  }
  if (v >= 0x7fffff000000n && v < 0x800000000000n)
    return { t: "stack pointer", c: "stk", s: "leaks the stack layout — defeats stack ASLR" };
  if (v >= 0x7f0000000000n && v < 0x7fffff000000n)
    return { t: "library pointer (libc / ld)", c: "lib", s: "compute the libc base from it → ret2libc / one-gadget" };
  if (v >= 0x555500000000n && v < 0x565600000000n)
    return { t: "PIE code pointer", c: "code", s: "a PIE image address — defeats PIE/ASLR for the binary" };
  if (v >= 0x400000n && v < 0x500000n)
    return { t: "code pointer (no-PIE image)", c: "code", s: "an image / code-segment address" };
  if (v >= 0x1000n && v < 0x400000n)
    return { t: "heap / low pointer", c: "heap", s: "a heap or low-mapping address" };
  return { t: "data word", c: "data", s: "" };
}

function Disclosure({ finding }) {
  const seen = new Set(), words = [];
  for (const e of finding.evidence || []) {
    if (!["effects", "injection", "disclosure", "dynamic", "leak"].includes(e.channel)) continue;
    for (const m of (e.detail || "").match(/0x[0-9a-fA-F]{6,}/g) || []) {
      if (!seen.has(m)) { seen.add(m); words.push(m); }
    }
  }
  const rows = words.map((w) => ({ w, ...classifyWord(w) })).filter((r) => r.t);
  const useful = rows.filter((r) => ["stk", "lib", "code"].includes(r.c)).length;
  if (rows.length < 2 || !useful) return null;   // only show for a real multi-word leak
  return html`<div class="sect"><div class="sect-h">Disclosed memory</div>
    <div class="dsc-sum">This leak discloses <b>${rows.length}</b> live memory words;
      <b>${useful}</b> are address pointers that defeat the mitigations the control bugs need.</div>
    <div class="disc">
      <div class="drow dhead"><span>#</span><span>leaked value</span><span>what it is</span><span>significance</span></div>
      ${rows.map((r, i) => html`<div class=${"drow dc-" + r.c}>
        <span class="didx">${i}</span><span class="dval mono">${r.w}</span>
        <span class="dcls">${r.t}</span><span class="dsig">${r.s}</span></div>`)}
    </div>
  </div>`;
}

const CH_LABEL = {
  "root-cause": "Root cause", exploitability: "Exploitability", dataflow: "Dataflow",
  recipe: "Exploitation recipe", "recipe-input": "Computed input", "recipe-plan": "Write plan",
  "recipe-assumptions": "Assumptions", "recipe-ceiling": "Ceiling", dynamic: "Reached / how found",
  effects: "Effects", poc: "Proof", detonation: "Detonation", chain: "Primitive chain",
};
const IN_POC = new Set(["soundness", "reproduce", "poc-input", "customize",
                        "exploit-script", "builder-usage", "effects", "poc"]);

// render text with `inline code` spans
function ic(text) {
  return (text || "").split(/(`[^`]+`)/).map((p) =>
    (p.startsWith("`") && p.endsWith("`")) ? html`<code class="ic">${p.slice(1, -1)}</code>` : p);
}

function BuilderUsage({ detail }) {
  const grab = (re) => { const m = detail.match(re); return m ? m[1].trim() : ""; };
  const whatIs = grab(/WHAT IT IS —\s*([\s\S]*?)(?=\nWORKFLOW —|\nON SOURCE —|$)/);
  const flow = grab(/WORKFLOW —\s*([\s\S]*?)(?=\nON SOURCE —|$)/)
    .split("\n").filter((l) => /^\d+\./.test(l.trim())).map((l) => l.trim().replace(/^\d+\.\s*/, ""));
  const onSrc = grab(/ON SOURCE —\s*([\s\S]*?)$/);
  return html`<div class="usage">
    ${whatIs ? html`<div class="u-part"><div class="u-k">What it is</div><div>${ic(whatIs)}</div></div>` : null}
    ${flow.length ? html`<div class="u-part"><div class="u-k">Workflow</div>
      <ol class="u-steps">${flow.map((s) => html`<li>${ic(s)}</li>`)}</ol></div>` : null}
    ${onSrc ? html`<div class="u-part"><div class="u-k">On source</div><div>${ic(onSrc)}</div></div>` : null}
  </div>`;
}

// "Customize / retarget this PoC": how the builder works + the knobs + the editable script.
function Customize({ finding }) {
  const usage = (finding.evidence || []).find((e) => e.channel === "builder-usage");
  const guide = (finding.evidence || []).find((e) => e.channel === "customize");
  const script = (finding.evidence || []).find((e) => e.channel === "exploit-script");
  if (!usage && !guide && !script) return null;
  let head = "", knobs = [];
  if (guide) {
    const lines = guide.detail.split("\n");
    knobs = lines.filter((l) => l.trim().startsWith("- ")).map((l) => l.trim().slice(2));
    head = lines.filter((l) => !l.trim().startsWith("- ")).join(" ").trim();
  }
  const dl = script ? "data:text/x-python;charset=utf-8," + encodeURIComponent(script.detail) : null;
  const knob = (t) => {
    const i = t.indexOf("—");
    return i < 0 ? html`<li>${ic(t)}</li>`
      : html`<li><b class="knob-k">${t.slice(0, i).trim()}</b> — ${ic(t.slice(i + 1).trim())}</li>`;
  };
  return html`<div class="sect"><div class="sect-h">Customize / retarget this PoC</div>
    ${usage ? html`<${BuilderUsage} detail=${usage.detail} />` : null}
    ${head ? html`<div class="blk"><div class="blk-h">How to retarget it</div>
      <div class="why">${ic(head)}</div>
      ${knobs.length ? html`<ul class="knobs">${knobs.map(knob)}</ul>` : null}</div>` : null}
    ${script ? html`<div class="blk"><div class="blk-h">Editable exploit builder
      <a class="dl-link" href=${dl} download="poc.py">⬇ poc.py</a></div>
      <pre class="script">${script.detail}</pre></div>` : null}
  </div>`;
}

// Evidence as a flowing report: a label, then the text — spaced, not boxed.
function Evidence({ finding }) {
  const rest = (finding.evidence || []).filter((e) => e && e.detail && !IN_POC.has(e.channel));
  if (!rest.length) return null;
  return html`<div class="sect"><div class="sect-h">Evidence trail</div>
    <div class="ev-flow">${rest.map((e) => html`<div class="ev-item">
      <div class="ev-lbl">${CH_LABEL[e.channel] || e.channel}</div>
      <div class="ev-txt">${e.detail}</div></div>`)}</div></div>`;
}

const bestPoc = (pocs, fid) => {
  const m = (pocs || []).filter((p) => p.finding_id === fid);
  const r = (p) => (p.provenance === "detonated" || p.verified ? 2 : p.provenance === "constructed" ? 1 : 0);
  return m.slice().sort((a, b) => r(b) - r(a))[0];
};

// The attack flow: deliver -> reach the sink -> the primitive -> the effect. Derived from the
// finding's own fields; the effect node is marked demonstrated/potential by the PoC provenance.
function AttackFlow({ finding, advice, pocs }) {
  const x = finding.exploitability || {};
  const poc = bestPoc(pocs, finding.id);
  const det = poc && (poc.provenance === "detonated" || poc.verified);
  const input = (advice && advice.input_mode) || "input";
  const site = finding.title || finding.cwe_name || "the vulnerable site";
  const prim = x.class_primitive;
  const effect = poc && poc.signal ? poc.signal
    : /control|hijack|rce|code exec/i.test(finding.title || "") ? "control-flow hijack"
    : finding.cwe_name || "the finding effect";
  const nodes = [
    { k: "deliver", t: "Deliver", d: `attacker-controlled ${input}`, edge: poc ? "the payload" : "an input" },
    { k: "reach", t: "Reach", d: site, edge: prim ? "gives" : "triggers" },
  ];
  if (prim) nodes.push({ k: "prim", t: "Primitive", d: prim, edge: det ? "drives" : "would drive" });
  nodes.push({ k: det ? "effect-on" : "effect-off", t: "Effect", d: effect, edge: null });
  return html`<div class="flow">
    ${nodes.map((n, i) => html`
      <div class=${"fnode fn-" + n.k}>
        <span class="fstep">${i + 1}</span>
        <div><div class="ftitle">${n.t}</div><div class="ftext">${n.d}</div></div>
      </div>
      ${n.edge ? html`<div class="fedge"><span class="farrow">↓</span> ${n.edge}</div>` : null}`)}
    ${!det ? html`<div class="fnote muted">the Effect is not demonstrated here — see Status for what would close it</div>` : null}
  </div>`;
}

function Related({ related }) {
  if (!related || !related.length) return null;
  return html`<div class="sect"><div class="sect-h">Related findings · ${related.length}</div>
    <div class="rel-note muted">Other detectors' views of this same issue (same function / shape), merged here:</div>
    <div class="rel">${related.map((r) => html`<div class="rel-i">
      <span class=${"rel-cwe"}>${r.cwe || ""}</span>
      <span class="rel-t">${r.title || r.detector}</span>
      <span class=${"rel-st st-" + (r.state || "candidate")}>${r.state || "candidate"}</span>
      <span class="rel-d muted">${r.detector}</span></div>`)}</div>
  </div>`;
}

export function DetailPane({ finding, pocs, advice, related }) {
  const [fn, setFn] = useState(null);
  const faddr = finding && finding.function_addr;
  useEffect(() => {
    let on = true; setFn(null);
    if (faddr != null) fetchFunctionAt(faddr).then((d) => { if (on) setFn(d); });
    return () => { on = false; };
  }, [faddr]);
  if (!finding) return html`<div class="pane-pad muted">Select a finding.</div>`;
  const a = finding.analysis || {};
  const x = finding.exploitability || {};
  const miw = x.mitigations_in_way || [];
  const site = finding.site_addr;
  const hasCode = fn && (fn.ir || fn.decompiled);
  return html`<div class="detail">
    <div class="d-head">
      <span class=${"sev " + (finding.severity || "info")}>${finding.severity}</span>
      <span class="d-cwe">${finding.cwe || ""}</span>
      <span class="d-cwename">${finding.cwe_name || ""}</span>
    </div>
    <div class="d-title">${finding.title || finding.detector}</div>
    ${finding.cwe_desc ? html`<div class="cwe-desc">${finding.cwe_desc}</div>` : null}
    <${ConfirmationLadder} state=${finding.state} />

    <div class="sect"><div class="sect-h">Proof of concept</div>
      <${PocDeliverable} finding=${finding} pocs=${pocs} /></div>

    <div class="sect"><div class="sect-h">Attack flow</div>
      <${AttackFlow} finding=${finding} advice=${advice} pocs=${pocs} /></div>

    <${Disclosure} finding=${finding} />

    ${hasCode ? html`<div class="sect"><div class="sect-h">
        Code — <span class="mono">${fn.name || ""}</span> ${fn.addr ? html`<span class="muted">@ ${fn.addr}</span>` : null}</div>
      <${Disasm} ir=${fn.ir} siteAddr=${site} signature=${fn.signature} source=${fn.decompiled || null} /></div>` : null}

    ${(fn && fn.frame) ? html`<div class="sect"><div class="sect-h">Memory layout — stack frame</div>
      <${StackFrame} frame=${fn.frame} /></div>` : null}

    ${(a.why_state || a.to_promote) ? html`<div class="sect"><div class="sect-h">Status</div>
      ${a.why_state ? html`<div class="why">${a.why_state}</div>` : null}
      ${a.to_promote ? html`<div class="promote"><span class="pr-k">To advance</span> ${a.to_promote}</div>` : null}
    </div>` : null}

    ${(x.class_primitive || miw.length) ? html`<div class="sect"><div class="sect-h">Exploitability</div>
      ${x.class_primitive ? html`<div class="prim mono">${x.class_primitive}</div>` : null}
      ${miw.length ? html`<div class="miw-h">mitigations in the way</div>
        <ul class="miw">${miw.map((m) => html`<li>${m}</li>`)}</ul>` : null}
    </div>` : null}

    <${Customize} finding=${finding} />

    ${(fn && (fn.callees || fn.callers)) ? html`<div class="sect"><div class="sect-h">Cross-references</div>
      <${XRefs} callers=${fn.callers} callees=${fn.callees} /></div>` : null}

    <${Evidence} finding=${finding} />

    <${Related} related=${related} />

    <div class="meta">
      <span>detector <b>${finding.detector}</b></span>
      <span>stage ${finding.stage_label || finding.stage || "—"}</span>
      <span>confidence ${finding.confidence != null ? Math.round(finding.confidence * 100) + "%" : "—"}</span>
      ${finding.site_count ? html`<span>${finding.proven_sites || 0}/${finding.site_count} sites proven</span>` : null}
    </div>
  </div>`;
}
