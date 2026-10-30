// The finding detail pane: full analysis for one finding, every state. PoC deliverable, the attack
// FLOW (how the payload reaches the effect), status, exploitability, and the evidence trail as a
// flowing report (no cards/bubbles).
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { PocDeliverable, ConfirmationLadder } from "./poc.js";
import { Disasm, StackFrame, XRefs } from "./code.js";
import { fetchFunctionAt } from "./store.js";

const CH_LABEL = {
  "root-cause": "Root cause", exploitability: "Exploitability", dataflow: "Dataflow",
  recipe: "Exploitation recipe", "recipe-input": "Computed input", "recipe-plan": "Write plan",
  "recipe-assumptions": "Assumptions", "recipe-ceiling": "Ceiling", dynamic: "Reached / how found",
  effects: "Effects", poc: "Proof", detonation: "Detonation", chain: "Primitive chain",
};
const IN_POC = new Set(["soundness", "reproduce", "poc-input"]);

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

export function DetailPane({ finding, pocs, advice }) {
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

    ${(fn && (fn.callees || fn.callers)) ? html`<div class="sect"><div class="sect-h">Cross-references</div>
      <${XRefs} callers=${fn.callers} callees=${fn.callees} /></div>` : null}

    <${Evidence} finding=${finding} />

    <div class="meta">
      <span>detector <b>${finding.detector}</b></span>
      <span>stage ${finding.stage_label || finding.stage || "—"}</span>
      <span>confidence ${finding.confidence != null ? Math.round(finding.confidence * 100) + "%" : "—"}</span>
      ${finding.site_count ? html`<span>${finding.proven_sites || 0}/${finding.site_count} sites proven</span>` : null}
    </div>
  </div>`;
}
