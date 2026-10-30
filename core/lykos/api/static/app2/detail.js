// The rich detail pane + target header. Shows EVERYTHING the analysis found for the selected
// finding, regardless of PoC state: the PoC deliverable (or honest status), why it sits at its
// rung and what would advance it, the exploitability/mitigation picture, and the full evidence
// trail (the recipe, dataflow, root-cause…). A corroborated/candidate finding is NOT a dead end —
// it hands the analyst everything we have.
import { html } from "./html.js";
import { PocDeliverable, ConfirmationLadder } from "./poc.js";

function fmtBytes(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

const MIT = ["nx", "pie", "relro", "bind_now", "canary", "fortify", "seccomp"];
const MIT_LABEL = { nx: "NX", pie: "PIE", relro: "RELRO", bind_now: "BIND_NOW",
                    canary: "Canary", fortify: "FORTIFY", seccomp: "seccomp" };

export function Mitigations({ m }) {
  if (!m) return null;
  return html`<div class="mits">${MIT.map((k) => {
    const v = m[k]; if (v == null) return null;
    const on = v === "on" || v === "full" || v === true;
    const part = v === "partial";
    return html`<span class=${"mit " + (on ? "on" : part ? "part" : "off")} title=${k}>
      ${MIT_LABEL[k]} <b>${typeof v === "boolean" ? (v ? "on" : "off") : v}</b></span>`;
  })}</div>`;
}

export function TargetHeader({ target }) {
  if (!target) return null;
  const t = target;
  return html`<div class="thead">
    <div class="trow">
      <span class="tname">${t.filename}</span>
      <span class="muted">${[t.file_type, `${t.arch}/${t.bits}`, t.linking,
        t.stripped ? "stripped" : "with symbols", fmtBytes(t.size)].filter(Boolean).join(" · ")}</span>
    </div>
    <${Mitigations} m=${t.mitigations} />
  </div>`;
}

const CH_LABEL = {
  "root-cause": "Root cause", exploitability: "Exploitability", dataflow: "Dataflow",
  recipe: "Exploitation recipe", "recipe-input": "Computed input", "recipe-plan": "Write plan",
  "recipe-assumptions": "Assumptions", "recipe-ceiling": "Ceiling", dynamic: "Reached / how found",
  effects: "Effects", poc: "Proof", detonation: "Detonation",
};
// these are already rendered inside the PoC deliverable, so the trail skips them.
const IN_POC = new Set(["soundness", "reproduce", "poc-input"]);

function EvidenceTrail({ finding }) {
  const rest = (finding.evidence || []).filter((e) => e && e.detail && !IN_POC.has(e.channel));
  if (!rest.length) return null;
  return html`<div class="sect"><div class="sect-h">Evidence trail</div>
    ${rest.map((e) => html`<div class="ev">
      <div class="ev-ch">${CH_LABEL[e.channel] || e.channel}</div>
      <pre class="ev-d">${e.detail}</pre></div>`)}
  </div>`;
}

export function DetailPane({ finding, pocs }) {
  if (!finding) return html`<div class="detail empty muted">Select a finding to see its full analysis.</div>`;
  const a = finding.analysis || {};
  const x = finding.exploitability || {};
  const miw = x.mitigations_in_way || [];
  return html`<div class="detail">
    <div class="d-head">
      <span class=${"sev " + (finding.severity || "info")}>${finding.severity}</span>
      <span class="cwe">${finding.cwe || ""}</span>
      <span class="cwe-name">${finding.cwe_name || ""}</span>
    </div>
    <div class="d-title">${finding.title || finding.detector}</div>
    <${ConfirmationLadder} state=${finding.state} />
    ${finding.cwe_desc ? html`<div class="cwe-desc">${finding.cwe_desc}</div>` : null}

    <div class="sect"><div class="sect-h">Proof of concept</div>
      <${PocDeliverable} finding=${finding} pocs=${pocs} /></div>

    ${(a.why_state || a.to_promote) ? html`<div class="sect"><div class="sect-h">Status & what would advance it</div>
      ${a.why_state ? html`<div class="why">${a.why_state}</div>` : null}
      ${a.to_promote ? html`<div class="promote"><b>To advance →</b> ${a.to_promote}</div>` : null}
    </div>` : null}

    ${(x.class_primitive || miw.length) ? html`<div class="sect"><div class="sect-h">Exploitability</div>
      ${x.class_primitive ? html`<div class="prim mono">${x.class_primitive}</div>` : null}
      ${miw.length ? html`<div class="miw-h muted">mitigations in the way:</div>
        <ul class="miw">${miw.map((m) => html`<li>${m}</li>`)}</ul>` : null}
    </div>` : null}

    <${EvidenceTrail} finding=${finding} />

    <div class="meta muted">
      detector <b>${finding.detector}</b> · stage ${finding.stage_label || finding.stage || "—"}
      · confidence ${finding.confidence != null ? Math.round(finding.confidence * 100) + "%" : "—"}
      ${finding.site_count ? ` · ${finding.proven_sites || 0}/${finding.site_count} sites proven` : ""}
    </div>
  </div>`;
}
