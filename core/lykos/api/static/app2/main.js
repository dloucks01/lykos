// New workbench shell (doc 59). Master-detail: a dense, scannable findings list (left) and a rich
// detail pane (right) that shows the full analysis for the selected finding — PoC deliverable,
// status + what would advance it, exploitability, and the complete evidence trail. A persistent
// target header carries the mitigation picture. Analysis/run/coverage tabs re-ported in later steps.
import { h, render } from "preact";
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { store, subscribe, loadCases, selectCase, selectTarget, selectFinding } from "./store.js";
import { DetailPane, TargetHeader } from "./detail.js";
import { ProvBadge } from "./poc.js";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATE_RANK = { "poc-backed": 0, confirmed: 1, corroborated: 2, candidate: 3 };

function bestPoc(pocs, fid) {
  const mine = (pocs || []).filter((p) => p.finding_id === fid);
  const rank = (p) => (p.provenance === "detonated" || p.verified ? 2 : p.provenance === "constructed" ? 1 : 0);
  return mine.slice().sort((a, b) => rank(b) - rank(a))[0];
}

function Row({ f, pocs, sel, onClick }) {
  const p = bestPoc(pocs, f.id);
  return html`<div class=${"row" + (sel ? " sel" : "")} onClick=${onClick}>
    <span class=${"dot " + (f.severity || "info")} title=${f.severity}></span>
    <span class="r-cwe">${f.cwe || ""}</span>
    <span class=${"r-state s-" + (f.state || "candidate")}>${f.state || "candidate"}</span>
    <span class="r-poc">${p && p.input_sha
      ? html`<span class="plvl">${String(p.level).replace(/^L?/, "L")}</span>
             <${ProvBadge} provenance=${p.provenance} verified=${p.verified} />`
      : html`<span class="muted">—</span>`}</span>
    <span class="r-title">${f.title || f.detector}</span>
  </div>`;
}

function App() {
  const [, force] = useState(0);
  useEffect(() => { const u = subscribe(() => force((n) => n + 1)); loadCases(); return u; }, []);
  const s = store;
  const findings = s.findings.slice().sort((a, b) =>
    (STATE_RANK[a.state] ?? 9) - (STATE_RANK[b.state] ?? 9) ||
    (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  const sel = findings.find((f) => f.id === s.selectedId) || findings[0];
  const demo = findings.filter((f) => f.state === "poc-backed" || f.state === "confirmed").length;
  const withPoc = findings.filter((f) => bestPoc(s.pocs, f.id)?.input_sha).length;
  return html`<div class="wb">
    <header class="top">
      <div class="brand">lykos <span class="muted">· PoC workbench</span></div>
      <select title="case" onChange=${(e) => selectCase(e.target.value)}>
        ${s.cases.map((c) => html`<option value=${c.id} selected=${c.id === s.caseId}>${c.name || c.id.slice(0, 8)}</option>`)}
      </select>
      <select title="target" onChange=${(e) => selectTarget(e.target.value)}>
        ${s.targets.map((t) => html`<option value=${t.id} selected=${t.id === s.targetId}>${t.filename || t.id.slice(0, 8)}</option>`)}
      </select>
      <${TargetHeader} target=${s.target} />
    </header>
    ${s.error ? html`<div class="err">${s.error}</div>` : null}
    <div class="body">
      <div class="list">
        <div class="list-h">
          <b>${findings.length}</b> findings · <b>${demo}</b> confirmed · <b>${withPoc}</b> with a PoC payload
        </div>
        ${s.loading ? html`<div class="muted pad">loading…</div>`
          : findings.length ? findings.map((f) => html`<${Row} f=${f} pocs=${s.pocs}
              sel=${sel && f.id === sel.id} onClick=${() => selectFinding(f.id)} />`)
          : html`<div class="muted pad">no findings for this target</div>`}
      </div>
      <div class="pane"><${DetailPane} finding=${sel} pocs=${s.pocs} /></div>
    </div>
  </div>`;
}

render(h(App), document.getElementById("root"));
