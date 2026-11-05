// Proof screen: every finding of the case laid out by what is PROVEN. Three lanes --
//   proven (a PoC ran), real but no PoC yet (with what it takes), unverified leads --
// and a finding detail view: its PoCs + downloads, the evidence trail, why it is in this state,
// what would promote it, the mitigations in the way, and a hop to the code at its site.
import { useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { backlogFor, bestLevel, isNoise, laneOf, pocsOf, rankFindings } from "./data.js";

const SEGS = [["all", "All"], ["proven", "Proven"], ["needs", "Needs a PoC"], ["lead", "Leads"]];

function LevelBadge({ level, constructed }) {
  if (!level) return null;
  const strong = level === "L3";
  const style = strong ? "background:var(--blue);color:#0B1220;border-color:var(--blue)"
    : "background:var(--blue-soft);color:var(--blue-tx);border-color:var(--blue-edge)";
  return html`<span class="lvl" style=${style}>${level}${constructed ? " · constructed" : ""}</span>`;
}

function Meta({ f, showTarget }) {
  return html`<span class="mono dim" style="font-size:11.5px">
    ${[f.cwe, f.severity, showTarget ? f.target_name : null, f.site_addr ? "@ " + f.site_addr : null].filter(Boolean).join(" · ")}</span>`;
}

function ProvenCard({ f, pocs, open, showTarget }) {
  const best = pocs.find((p) => p.verified || p.provenance === "detonated");
  const why = f.analysis && f.analysis.why_state;
  return html`<button class="card proven" onClick=${() => open(f.id)}>
    <div class="row-c"><${LevelBadge} level=${bestLevel(pocs)} /><${Meta} f=${f} showTarget=${showTarget} /></div>
    <div class="card-t">${f.title}</div>
    ${why ? html`<div class="card-b">${why}</div>` : null}
    <div class="row-c" style="flex-wrap:wrap">
      ${best ? html`<span class="chip on">${best.provenance === "detonated" || best.verified ? "PoC ran" : "constructed"}${best.signal ? " · " + best.signal : ""}</span>` : null}
      ${f.stage_label ? html`<span class="chip">found by ${f.stage_label}</span>` : null}
      ${f.site_count > 1 ? html`<span class="chip">${f.site_count} sites</span>` : null}
    </div>
  </button>`;
}

function NeedsCard({ f, pocs, backlog, open, showTarget }) {
  const a = f.analysis || {};
  const bl = backlogFor(f, backlog);
  const next = (bl && bl.missing_technique) || a.to_promote;
  return html`<button class="card" onClick=${() => open(f.id)}>
    <div class="row-c"><span class="lvl amber">${f.state}</span><${Meta} f=${f} showTarget=${showTarget} />
      ${pocs.length ? html`<${LevelBadge} level=${"L" + (String(pocs[0].level || "").replace(/^L/, "") || "?")} constructed=${true} />` : null}</div>
    <div class="card-t">${f.title}</div>
    ${a.why_state ? html`<div class="card-b">${a.why_state}</div>` : null}
    ${next ? html`<div class="next"><b>${bl ? "Technique to build next" : "To promote it"}:</b> ${next}</div>` : null}
  </button>`;
}

function LeadRow({ f, open, showTarget }) {
  return html`<button class="lead" onClick=${() => open(f.id)}>
    <span class="mono dim" style="flex:none;width:72px;font-size:11.5px">${f.cwe || "—"}</span>
    <span style="flex:1 1 auto;min-width:0;display:flex;flex-direction:column;text-align:left">
      <span style=${isNoise(f) ? "color:var(--tx3)" : ""}>${f.title}</span>
      <span class="dim" style="font-size:11.5px">${[f.stage_label || f.detector, showTarget ? f.target_name : null, isNoise(f) ? "flagged as noise" : null].filter(Boolean).join(" · ")}</span>
    </span>
    <span class="dim" style="font-size:12px">${f.severity}</span>
  </button>`;
}

export function ProofScreen({ data, targetId, open, focusTarget }) {
  const [seg, setSeg] = useState("all");
  const [hideNoise, setHideNoise] = useState(true);
  const { findings, pocs, backlog } = data;
  const scoped = useMemo(() => rankFindings(findings.filter((f) => !targetId || f.target_id === targetId), pocs),
    [findings, pocs, targetId]);
  const lanes = useMemo(() => {
    const out = { proven: [], needs: [], lead: [] };
    for (const f of scoped) out[laneOf(f, pocsOf(f, pocs))].push(f);
    return out;
  }, [scoped, pocs]);
  const leads = hideNoise ? lanes.lead.filter((f) => !isNoise(f)) : lanes.lead;
  const showTarget = !targetId && data.targets.length > 1;
  const tgt = data.targets.find((t) => t.id === targetId);
  const show = (k) => seg === "all" || seg === k;
  return html`
    <div style="display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:12px">
      <div style="display:flex;flex-direction:column;gap:3px">
        <h1>${lanes.proven.length} proven · ${lanes.needs.length} need a PoC · ${lanes.lead.length} leads</h1>
        <span class="muted" style="font-size:13px">${tgt ? html`<span class="mono">${tgt.filename}</span> · ` : "All targets · "}
          ranked by what is proven; leads are never shown as proof.</span>
      </div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <select value=${targetId || ""} onChange=${(e) => focusTarget(e.target.value || null)}>
          <option value="">All targets</option>
          ${data.targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
        </select>
        <div class="seg" role="group" aria-label="Show">
          ${SEGS.map(([k, l]) => html`<button class=${seg === k ? "on" : ""} onClick=${() => setSeg(k)}>${l}</button>`)}
        </div>
      </div>
    </div>
    ${data.loading ? html`<div class="panel empty">Loading findings…</div>`
      : !scoped.length ? html`<div class="panel empty">No findings yet. Start an analysis on the Run screen.</div>`
      : html`<div class="lanes">
        ${show("proven") ? html`<section class="lane">
          <div class="lane-h blue"><span class="dot live"></span>PROVEN — A POC RAN</div>
          ${lanes.proven.length ? lanes.proven.map((f) => html`<${ProvenCard} f=${f} pocs=${pocsOf(f, pocs)} open=${open} showTarget=${showTarget} />`)
            : html`<div class="panel empty" style="padding:22px">Nothing proven yet.</div>`}
        </section>` : null}
        ${show("needs") ? html`<section class="lane">
          <div class="lane-h amber"><span class="dot" style="background:var(--amber)"></span>REAL, NO POC YET — WHAT IT TAKES</div>
          ${lanes.needs.length ? lanes.needs.map((f) => html`<${NeedsCard} f=${f} pocs=${pocsOf(f, pocs)} backlog=${backlog} open=${open} showTarget=${showTarget} />`)
            : html`<div class="panel empty" style="padding:22px">None.</div>`}
        </section>` : null}
        ${show("lead") ? html`<section class="lane">
          <div class="lane-h"><span class="dot" style="background:transparent;border:1px solid var(--tx3)"></span>LEADS — NOT VERIFIED
            <label style="margin-left:auto;font-weight:400;letter-spacing:0;font-size:11.5px;display:flex;gap:5px;align-items:center">
              <input type="checkbox" checked=${hideNoise} onChange=${(e) => setHideNoise(e.target.checked)} />hide noise</label></div>
          <div class="panel" style="overflow:hidden">
            ${leads.length ? leads.map((f) => html`<${LeadRow} f=${f} open=${open} showTarget=${showTarget} />`)
              : html`<div class="empty" style="padding:22px">None.</div>`}
          </div>
        </section>` : null}
      </div>`}`;
}

function fmtTime(t) { return t ? new Date(t * 1000).toLocaleString() : ""; }

export function FindingDetail({ data, findingId, back, toCode }) {
  const f = data.findings.find((x) => x.id === findingId);
  if (!f) return html`<div class="panel empty">Finding not found. <button class="btn sm" onClick=${back}>Back</button></div>`;
  const pocs = pocsOf(f, data.pocs);
  const a = f.analysis || {};
  const ex = f.exploitability || {};
  const bl = backlogFor(f, data.backlog);
  const lane = laneOf(f, pocs);
  return html`
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <button class="btn sm" onClick=${back}>← Proof board</button>
      <span class="mono dim" style="font-size:12px">${f.target_name || ""}</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:6px">
      <div class="row-c"><${LevelBadge} level=${bestLevel(pocs)} />
        <span class=${"lvl" + (lane === "needs" ? " amber" : "")}>${f.state}</span>
        <${Meta} f=${f} /></div>
      <h1 style="font-size:20px">${f.title}</h1>
      ${f.cwe_name ? html`<span class="muted" style="font-size:13px">${f.cwe} — ${f.cwe_name}</span>` : null}
    </div>
    <div class="detail">
      <div style="flex:999 1 520px;min-width:0;display:flex;flex-direction:column;gap:14px">
        <section class="panel pad">
          <h2>Why it is ${f.state}</h2>
          <p class="card-b" style="margin:6px 0 0">${a.why_state || "—"}</p>
          ${a.to_promote ? html`<p class="next" style="margin-top:10px"><b>To promote it:</b> ${a.to_promote}</p>` : null}
          ${bl ? html`<p class="next" style="margin-top:10px"><b>Technique to build next:</b> ${bl.missing_technique}
            ${bl.reached ? html`<span class="dim"> (reached ${bl.reached}${bl.would_reach ? `, would reach ${bl.would_reach}` : ""})</span>` : null}</p>` : null}
        </section>
        <section class="panel" style="overflow:hidden">
          <div class="pad" style="padding-bottom:8px"><h2>Evidence trail</h2>
            <span class="dim" style="font-size:12px">${(f.evidence || []).length} entries · ${(a.signals || []).length} independent channels</span></div>
          ${(f.evidence || []).map((e) => html`<div class="ev">
            <span class="chip" style="flex:none">${e.channel}</span>
            <span style="min-width:0;word-break:break-word">${String(e.detail || "").slice(0, 900)}</span></div>`)}
        </section>
      </div>
      <aside style="flex:1 1 320px;min-width:0;display:flex;flex-direction:column;gap:14px">
        <section class="panel pad">
          <h2>PoCs</h2>
          ${pocs.length ? pocs.map((p) => html`<div class="poc">
            <div class="row-c"><${LevelBadge} level=${p.level ? "L" + String(p.level).replace(/^L/, "") : null} />
              <span class="chip ${p.verified || p.provenance === "detonated" ? "on" : ""}">${p.provenance || (p.verified ? "verified" : "unverified")}</span>
              <span class="dim" style="font-size:11px">${fmtTime(p.created_at)}</span></div>
            ${p.signal ? html`<div class="mono dim" style="font-size:11.5px">${p.signal}</div>` : null}
            <div class="row-c">
              ${p.input_sha ? html`<a class="btn sm" href=${"/artifacts/" + p.input_sha} download>Input</a>` : null}
              ${p.bundle_sha ? html`<a class="btn sm" href=${"/artifacts/" + p.bundle_sha} download>Bundle</a>` : null}
            </div></div>`)
            : html`<p class="muted" style="margin:6px 0 0;font-size:13px">No PoC for this finding.</p>`}
        </section>
        ${ex.class_primitive || (ex.mitigations_in_way || []).length ? html`<section class="panel pad">
          <h2>Exploitability</h2>
          ${ex.class_primitive ? html`<p class="card-b" style="margin:6px 0">${ex.class_primitive}</p>` : null}
          ${(ex.mitigations_in_way || []).length ? html`<div class="dim" style="font-size:11.5px;letter-spacing:.04em;margin-top:6px">MITIGATIONS IN THE WAY</div>
            <ul class="mit">${ex.mitigations_in_way.map((m) => html`<li>${m}</li>`)}</ul>` : null}
        </section>` : null}
        <section class="panel pad">
          <h2>Where</h2>
          <p class="mono" style="margin:6px 0;font-size:12.5px">${f.site_addr ? "site " + f.site_addr : "no site address"}${f.function_addr ? " · function " + f.function_addr : ""}</p>
          ${f.site_addr || f.function_addr ? html`<button class="btn sm" onClick=${() => toCode(f.target_id, f.site_addr || f.function_addr)}>View code</button>` : null}
          ${f.stage_label ? html`<p class="dim" style="margin:8px 0 0;font-size:12px">Found by ${f.stage_label} (${f.detector})</p>` : null}
        </section>
      </aside>
    </div>`;
}
