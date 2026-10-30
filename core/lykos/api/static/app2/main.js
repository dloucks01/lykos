// New workbench shell (doc 59 ground-up rebuild). Step 1+2: load a case, pick a target, and render
// findings with the new PoC-centric spine. Analysis/run/coverage tabs are re-ported in later steps.
import { h, render } from "preact";
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { store, subscribe, loadCases, selectCase, selectTarget } from "./store.js";
import { PocDeliverable, ConfirmationLadder } from "./poc.js";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATE_RANK = { "poc-backed": 0, confirmed: 1, corroborated: 2, candidate: 3 };

function Finding({ finding, pocs }) {
  const [open, setOpen] = useState(finding.state === "poc-backed" || finding.state === "confirmed");
  return html`<div class=${"fcard s-" + (finding.state || "candidate")}>
    <div class="fc-head" onClick=${() => setOpen(!open)}>
      <span class=${"sev " + (finding.severity || "info")}>${finding.severity || "info"}</span>
      <span class="cwe">${finding.cwe || ""}</span>
      <span class="ftitle">${finding.title || finding.detector || "finding"}</span>
      <span class="state">${finding.state || "candidate"}</span>
    </div>
    ${open ? html`<div class="fc-body">
      <${ConfirmationLadder} state=${finding.state} />
      <${PocDeliverable} finding=${finding} pocs=${pocs} />
    </div>` : null}
  </div>`;
}

function App() {
  const [, force] = useState(0);
  useEffect(() => { const u = subscribe(() => force((n) => n + 1)); loadCases(); return u; }, []);
  const s = store;
  const findings = s.findings.slice().sort((a, b) =>
    (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9) ||
    (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  const demonstrated = findings.filter((f) => f.state === "poc-backed" || f.state === "confirmed").length;
  return html`<div class="wb">
    <header class="top">
      <div class="brand">lykos <span class="muted">· PoC workbench</span></div>
      <select onChange=${(e) => selectCase(e.target.value)}>
        ${s.cases.map((c) => html`<option value=${c.id} selected=${c.id === s.caseId}>${c.name || c.id.slice(0,8)}</option>`)}
      </select>
      <select onChange=${(e) => selectTarget(e.target.value)}>
        ${s.targets.map((t) => html`<option value=${t.id} selected=${t.id === s.targetId}>${t.filename || t.id.slice(0,8)}</option>`)}
      </select>
    </header>
    ${s.error ? html`<div class="err">${s.error}</div>` : null}
    <main>
      <div class="summary">${findings.length} findings · <b>${demonstrated}</b> with a PoC/confirmed</div>
      ${s.loading ? html`<div class="muted">loading…</div>` :
        findings.length ? findings.map((f) => html`<${Finding} finding=${f} pocs=${s.pocs} />`)
                        : html`<div class="muted">no findings for this target</div>`}
    </main>
  </div>`;
}

render(h(App), document.getElementById("root"));
