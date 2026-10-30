// The finding detail pane: the full analysis for one finding, every state. PoC deliverable, status +
// what would advance it, exploitability + mitigations in the way, and the evidence trail as cards.
import { html } from "./html.js";
import { PocDeliverable, ConfirmationLadder } from "./poc.js";

const CH_LABEL = {
  "root-cause": "Root cause", exploitability: "Exploitability", dataflow: "Dataflow",
  recipe: "Exploitation recipe", "recipe-input": "Computed input", "recipe-plan": "Write plan",
  "recipe-assumptions": "Assumptions", "recipe-ceiling": "Ceiling", dynamic: "Reached / how found",
  effects: "Effects", poc: "Proof", detonation: "Detonation", chain: "Primitive chain",
};
const IN_POC = new Set(["soundness", "reproduce", "poc-input"]);

function Evidence({ finding }) {
  const rest = (finding.evidence || []).filter((e) => e && e.detail && !IN_POC.has(e.channel));
  if (!rest.length) return null;
  return html`<div class="sect"><div class="sect-h">Evidence trail</div>
    <div class="ev-cards">${rest.map((e) => html`<div class="ev-card">
      <div class="ev-ch">${CH_LABEL[e.channel] || e.channel}</div>
      <div class="ev-d">${e.detail}</div></div>`)}</div></div>`;
}

export function DetailPane({ finding, pocs }) {
  if (!finding) return html`<div class="pane-pad muted">Select a finding.</div>`;
  const a = finding.analysis || {};
  const x = finding.exploitability || {};
  const miw = x.mitigations_in_way || [];
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

    ${(a.why_state || a.to_promote) ? html`<div class="sect"><div class="sect-h">Status</div>
      ${a.why_state ? html`<div class="why">${a.why_state}</div>` : null}
      ${a.to_promote ? html`<div class="promote"><span class="pr-k">To advance</span> ${a.to_promote}</div>` : null}
    </div>` : null}

    ${(x.class_primitive || miw.length) ? html`<div class="sect"><div class="sect-h">Exploitability</div>
      ${x.class_primitive ? html`<div class="prim mono">${x.class_primitive}</div>` : null}
      ${miw.length ? html`<div class="miw-h">mitigations in the way</div>
        <ul class="miw">${miw.map((m) => html`<li>${m}</li>`)}</ul>` : null}
    </div>` : null}

    <${Evidence} finding=${finding} />

    <div class="meta">
      <span>detector <b>${finding.detector}</b></span>
      <span>stage ${finding.stage_label || finding.stage || "—"}</span>
      <span>confidence ${finding.confidence != null ? Math.round(finding.confidence * 100) + "%" : "—"}</span>
      ${finding.site_count ? html`<span>${finding.proven_sites || 0}/${finding.site_count} sites proven</span>` : null}
    </div>
  </div>`;
}
