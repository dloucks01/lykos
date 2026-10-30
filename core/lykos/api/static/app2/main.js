// Workbench shell (doc 59). Top bar (case/target + Binary/Finding view) · filterable findings list ·
// right pane showing the binary overview or the selected finding's full detail.
import { h, render } from "preact";
import { useState, useEffect } from "preact/hooks";
import { html } from "./html.js";
import { store, subscribe, loadCases, selectCase, selectTarget, selectFinding, setView, setFilter } from "./store.js";
import { DetailPane } from "./detail.js";
import { BinaryOverview } from "./binary.js";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATE_RANK = { "poc-backed": 0, confirmed: 1, corroborated: 2, candidate: 3 };
const FILTERS = [["all", "All"], ["poc", "With PoC"], ["confirmed", "Confirmed"],
                 ["corroborated", "Corroborated"], ["candidate", "Candidate"]];

function bestPoc(pocs, fid) {
  const m = (pocs || []).filter((p) => p.finding_id === fid);
  const r = (p) => (p.provenance === "detonated" || p.verified ? 2 : p.provenance === "constructed" ? 1 : 0);
  return m.slice().sort((a, b) => r(b) - r(a))[0];
}

const LVL = { L3: 3, L2: 2, L1: 1 };
// Rank a finding for "which is the representative of its cluster": a real PoC first (level),
// then state, then severity.
function findingScore(f, pocs) {
  const p = bestPoc(pocs, f.id);
  const lvl = p && p.input_sha ? (LVL[String(p.level).replace(/^L?/, "L")] || 0) : 0;
  const det = p && (p.provenance === "detonated" || p.verified) ? 1 : 0;
  return [lvl, det, 3 - (STATE_RANK[f.state] ?? 9), 4 - (SEV_RANK[f.severity] ?? 9)];
}
// Cluster key: findings in the same FUNCTION are one issue; siteless ones cluster by CWE+title
// shape (addresses stripped) so identical crashes/leaks collapse. Grouping only — nothing is hidden.
function clusterKey(f) {
  if (f.function_addr) return "fn:" + f.function_addr;
  const t = (f.title || f.detector || "").replace(/0x[0-9a-fA-F]+/g, "").replace(/\s+/g, " ").trim().slice(0, 48);
  return "t:" + (f.cwe || "") + ":" + t;
}
function cluster(findings, pocs) {
  const groups = new Map();
  for (const f of findings) {
    const k = clusterKey(f);
    (groups.get(k) || groups.set(k, []).get(k)).push(f);
  }
  const cmp = (a, b) => { const x = findingScore(a, pocs), y = findingScore(b, pocs);
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return y[i] - x[i]; return 0; };
  return [...groups.values()].map((g) => { g.sort(cmp); return { rep: g[0], members: g.slice(1) }; });
}

function Row({ f, pocs, sel, onClick, members = 0 }) {
  const p = bestPoc(pocs, f.id);
  const det = p && (p.provenance === "detonated" || p.verified);
  const hasPoc = p && p.input_sha;
  return html`<div class=${"row sev-" + (f.severity || "info") + (sel ? " sel" : "")} onClick=${onClick}>
    <span class="dot" title=${f.severity}></span>
    <div class="row-l">
      <div class="row-title">${f.title || f.detector}</div>
      <div class="row-sub">
        <span class="row-cwe">${f.cwe || ""}</span>
        <span class="row-sep">·</span>
        <span class=${"row-state st-" + (f.state || "candidate")}>${f.state || "candidate"}</span>
        ${members ? html`<span class="row-sep">·</span>
          <span class="row-rel" title=${members + " related finding(s) merged into this issue"}>+${members} related</span>` : null}
      </div>
    </div>
    ${hasPoc
      ? html`<span class=${"pbadge " + (det ? "det" : "con")} title=${det ? "detonated — oracle fired" : "constructed — sound"}>
          ${String(p.level).replace(/^L?/, "L")}</span>`
      : html`<span class="pbadge none">—</span>`}
  </div>`;
}

function App() {
  const [, force] = useState(0);
  useEffect(() => { const u = subscribe(() => force((n) => n + 1)); loadCases(); return u; }, []);
  const s = store;
  const findings = s.findings;
  // cluster into issues, rank clusters by their representative
  const clusters = cluster(findings, s.pocs).sort((a, b) => {
    const x = findingScore(a.rep, s.pocs), y = findingScore(b.rep, s.pocs);
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return y[i] - x[i]; return 0;
  });
  const f = s.filter;
  const match = (x) => f === "all" ? true
    : f === "poc" ? !!(bestPoc(s.pocs, x.id) && bestPoc(s.pocs, x.id).input_sha)
    : f === "confirmed" ? (x.state === "confirmed" || x.state === "poc-backed")
    : x.state === f;
  const shown = clusters.filter((c) => match(c.rep));
  const selC = clusters.find((c) => c.rep.id === s.selectedId)
    || clusters.find((c) => c.members.some((m) => m.id === s.selectedId));
  const sel = selC ? selC.rep : null;
  const confirmed = findings.filter((x) => x.state === "poc-backed" || x.state === "confirmed").length;
  const withPoc = findings.filter((x) => bestPoc(s.pocs, x.id) && bestPoc(s.pocs, x.id).input_sha).length;
  return html`<div class="wb">
    <header class="top">
      <div class="brand">lykos</div>
      <select class="sel" title="case" onChange=${(e) => selectCase(e.target.value)}>
        ${s.cases.map((c) => html`<option value=${c.id} selected=${c.id === s.caseId}>${c.name || c.id.slice(0, 8)}</option>`)}
      </select>
      <select class="sel" title="target" onChange=${(e) => selectTarget(e.target.value)}>
        ${s.targets.map((t) => html`<option value=${t.id} selected=${t.id === s.targetId}>${t.filename || t.id.slice(0, 8)}</option>`)}
      </select>
      <div class="spacer"></div>
      <div class="tabs">
        <button class=${"tab" + (s.view === "overview" ? " on" : "")} onClick=${() => setView("overview")}>Binary</button>
        <button class=${"tab" + (s.view === "finding" ? " on" : "")} onClick=${() => setView("finding")} disabled=${!sel}>Finding</button>
      </div>
    </header>
    ${s.error ? html`<div class="err">${s.error}</div>` : null}
    <div class="body">
      <aside class="list">
        <div class="filters">${FILTERS.map(([k, l]) =>
          html`<button class=${"fb" + (f === k ? " on" : "")} onClick=${() => setFilter(k)}>${l}</button>`)}</div>
        <div class="list-sum"><b>${shown.length}</b> issues · ${findings.length} findings · ${confirmed} confirmed · ${withPoc} with PoC</div>
        <div class="rows">${s.loading ? html`<div class="pane-pad muted">loading…</div>`
          : shown.length ? shown.map((c) => html`<${Row} f=${c.rep} pocs=${s.pocs} members=${c.members.length}
              sel=${sel && c.rep.id === sel.id} onClick=${() => selectFinding(c.rep.id)} />`)
          : html`<div class="pane-pad muted">no findings match</div>`}</div>
      </aside>
      <section class="pane">
        ${s.view === "finding" && sel
          ? html`<${DetailPane} finding=${sel} pocs=${s.pocs} advice=${s.advice} related=${selC ? selC.members : []} />`
          : html`<${BinaryOverview} target=${s.target} advice=${s.advice} findings=${findings} pocs=${s.pocs} />`}
      </section>
    </div>
  </div>`;
}

render(h(App), document.getElementById("root"));
