// Engagement screen: every target of the case and what is PROVEN on each, plus adding a target
// and starting an analysis (with the CLI's invocation options: argv template, input channel).
import { useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { bestLevel, laneOf, pocsOf, rankFindings } from "./data.js";

const LEVEL_TEXT = { L3: "working exploit", L2: "control primitive", L1: "crash" };

function summarize(data, t) {
  const fs = rankFindings(data.findings.filter((f) => f.target_id === t.id), data.pocs);
  const c = { proven: 0, needs: 0, lead: 0 };
  let top = null, topLevel = null;
  for (const f of fs) {
    const ps = pocsOf(f, data.pocs);
    const lane = laneOf(f, ps);
    c[lane]++;
    if (lane === "proven" && !top) { top = f; topLevel = bestLevel(ps) || "PoC"; }
  }
  return { c, top, topLevel };
}

function AddTarget({ caseId, onAdded }) {
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(null);
  const [err, setErr] = useState(null);
  const upload = async (files) => {
    setErr(null);
    for (const f of files) {
      setBusy(`uploading ${f.name}…`);
      try { await api.uploadTarget(caseId, f); } catch (e) { setErr(`${f.name}: ${e.message || e}`); }
    }
    setBusy(null);
    onAdded && onAdded();
  };
  return html`<section class=${"drop" + (over ? " over" : "")}
      onDragOver=${(e) => { e.preventDefault(); setOver(true); }} onDragLeave=${() => setOver(false)}
      onDrop=${(e) => { e.preventDefault(); setOver(false); upload([...e.dataTransfer.files]); }}>
    <h2>Add a target</h2>
    <span class="muted" style="font-size:13px">Drop a binary or firmware image here, or${" "}
      <label style="color:var(--blue);cursor:pointer">browse<input type="file" multiple hidden
        onChange=${(e) => upload([...e.target.files])} /></label>.</span>
    ${busy ? html`<span class="dim" style="font-size:12px">${busy}</span>` : null}
    ${err ? html`<span style="color:var(--amber-tx);font-size:12px">${err}</span>` : null}
  </section>`;
}

function StartPanel({ caseId, targets, onStarted }) {
  const [argv, setArgv] = useState("");
  const [mode, setMode] = useState("auto");
  const [budget, setBudget] = useState(600);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const start = async () => {
    setBusy(true); setErr(null);
    const overrides = {};
    if (argv.trim()) overrides.argv = argv.trim();
    if (mode !== "auto") overrides.input_mode = mode;
    try { await api.startBackground(caseId, targets.map((t) => t.id), budget, overrides); onStarted && onStarted(); }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <h2>Analyse ${targets.length === 1 ? "this target" : `all ${targets.length} targets`}</h2>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px">
      <label class="field">How it is invoked (@@ = the input)
        <input type="text" class="mono" placeholder="auto-detect, e.g. -c @@" value=${argv} onInput=${(e) => setArgv(e.target.value)} /></label>
      <label class="field">Input reaches it via
        <select value=${mode} onChange=${(e) => setMode(e.target.value)}>
          <option value="auto">auto-detect</option><option value="file">file</option>
          <option value="stdin">stdin</option><option value="arg">argument</option></select></label>
      <label class="field">Time budget
        <select value=${budget} onChange=${(e) => setBudget(+e.target.value)}>
          <option value="300">5 min</option><option value="600">10 min</option>
          <option value="1800">30 min</option><option value="7200">2 h</option></select></label>
    </div>
    <div class="row-c"><button class="btn primary" disabled=${busy || !targets.length} onClick=${start}>Start analysis</button>
      ${err ? html`<span style="color:var(--amber-tx);font-size:12px">${err}</span>` : null}</div>
  </section>`;
}

export function EngagementScreen({ cases, caseId, setCaseId, data, go, reloadCases, running }) {
  const [newName, setNewName] = useState("");
  const rows = useMemo(() => data.targets.map((t) => ({ t, ...summarize(data, t) })), [data]);
  const tot = rows.reduce((a, r) => ({ proven: a.proven + r.c.proven, needs: a.needs + r.c.needs, lead: a.lead + r.c.lead,
    hit: a.hit + (r.c.proven ? 1 : 0), l3: a.l3 + (r.topLevel === "L3" ? 1 : 0) }), { proven: 0, needs: 0, lead: 0, hit: 0, l3: 0 });
  const create = async () => {
    if (!newName.trim()) return;
    const c = await api.createCase(newName.trim());
    setNewName("");
    await reloadCases();
    if (c && c.id) setCaseId(c.id);
  };
  return html`
    <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
      <select value=${caseId || ""} onChange=${(e) => setCaseId(e.target.value)}>
        ${cases.map((c) => html`<option value=${c.id}>${c.name || c.id}</option>`)}
      </select>
      <input type="text" placeholder="new case name" value=${newName} onInput=${(e) => setNewName(e.target.value)}
             onKeyDown=${(e) => e.key === "Enter" && create()} />
      <button class="btn sm" onClick=${create} disabled=${!newName.trim()}>New case</button>
      ${running ? html`<button class="chip on" style="cursor:pointer" onClick=${() => go("run")}><span class="dot live"></span>analysis running — open Run</button>` : null}
    </div>
    <h1>${data.targets.length ? `${tot.hit} of ${data.targets.length} target${data.targets.length > 1 ? "s" : ""} ha${tot.hit === 1 ? "s" : "ve"} a proven vulnerability` : "No targets yet"}</h1>
    <div class="kpis">
      <div class="kpi blue"><b>${tot.proven}</b><span>proven, a PoC ran</span></div>
      <div class="kpi"><b>${tot.l3}</b><span>targets with a working exploit (L3)</span></div>
      <div class="kpi"><b>${tot.needs}</b><span>real, no PoC yet</span></div>
      <div class="kpi"><b>${tot.lead}</b><span>unverified leads</span></div>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:stretch">
      <div style="flex:1 1 300px"><${AddTarget} caseId=${caseId} onAdded=${data.reload} /></div>
      <div style="flex:2 1 420px">${data.targets.length ? html`<${StartPanel} caseId=${caseId} targets=${data.targets} onStarted=${() => go("run")} />` : null}</div>
    </div>
    ${rows.length ? html`<section class="panel" style="overflow:hidden">
      <div class="trow head"><span>TARGET</span><span>BEST PROOF</span><span>PROVEN</span><span>NEED POC</span><span>LEADS</span><span></span></div>
      ${rows.map(({ t, c, top, topLevel }) => html`<div class="trow">
        <span style="display:flex;flex-direction:column;min-width:0">
          <span class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.filename}</span>
          <span class="dim" style="font-size:11.5px">${[t.arch, t.linking, t.stripped ? "stripped" : null].filter(Boolean).join(" · ")}</span></span>
        <span style="display:flex;gap:9px;align-items:center;min-width:0">
          ${top ? html`<span class="lvl" style=${topLevel === "L3" ? "background:var(--blue);color:#0B1220;border-color:var(--blue)" : "background:var(--blue-soft);color:var(--blue-tx);border-color:var(--blue-edge)"}>${topLevel}</span>
            <button class="xref" style="color:var(--tx);font-family:var(--ui);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
              onClick=${() => go("finding", { findingId: top.id, targetId: t.id })} title=${top.title}>${LEVEL_TEXT[topLevel] ? LEVEL_TEXT[topLevel] + ": " : ""}${top.title}</button>`
            : html`<span class="dim" style="font-size:13px">nothing proven yet</span>`}
        </span>
        <span style="font-weight:600">${c.proven}</span><span>${c.needs}</span><span class="muted">${c.lead}</span>
        <span class="row-c" style="justify-content:flex-end;flex-wrap:wrap">
          <button class="btn sm" onClick=${() => go("proof", { targetId: t.id })}>Proof</button>
          <button class="btn sm" onClick=${() => go("code", { targetId: t.id })}>Code</button>
        </span>
      </div>`)}
    </section>` : null}`;
}
