// Engagement screen: every target of the case and what is PROVEN on each, plus adding a target
// and starting an analysis (with the CLI's invocation options: argv template, input channel).
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api } from "../app/api.js";
import { folderArchive, isFolderPick } from "../app/archive.js";
import { BUDGET_OPTIONS, bestLevel, getJSON, isNoise, laneOf, pocsOf, rankFindings, startSettings, triageOf } from "./data.js";
import { Lazy, useModule } from "./lazy.js";

const LEVEL_TEXT = { L3: "working exploit", L2: "control primitive", L1: "crash" };
// The server's request-body ceiling (api/server.py _MAX_BODY). A bigger upload is refused on its
// Content-Length, which a browser reports as a bare network error -- so say it here, before sending.
const MAX_UPLOAD = 1 << 30;
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const STATES = ["candidate", "corroborated", "confirmed", "poc-backed"];

function fmtBytes(n) {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KiB`;
  return `${n} B`;
}

// Counted the way the Proof screen counts: attack-path rows are not findings, and what the tool
// itself disproved (noise, triage "false-positive") is not open work. Engagement used to count
// both, and its "126 real, no PoC yet" disagreed with Proof's 78 for the same case.
function summarize(data, t) {
  const fs = rankFindings(data.findings.filter((f) => f.target_id === t.id && f.detector !== "attack_path"), data.pocs);
  const c = { proven: 0, needs: 0, lead: 0, drivable: 0 };
  let top = null, topLevel = null;
  for (const f of fs) {
    const ps = pocsOf(f, data.pocs);
    const lane = laneOf(f, ps);
    const tri = triageOf(f);
    if (lane !== "proven" && (isNoise(f) || (tri && tri.kind === "false-positive"))) continue;
    c[lane]++;
    if (lane !== "proven" && tri && tri.kind === "drivable") c.drivable++;
    if (lane === "proven" && !top) { top = f; topLevel = bestLevel(ps) || "PoC"; }
  }
  return { c, top, topLevel };
}

// A dropped FOLDER arrives as one empty File: walk it with the entry API and hand back every file
// with its path relative to the dropped folder (what a folder PICK gives), so it packs into one
// source archive exactly like a picked folder. Plain dropped files pass through unchanged.
async function droppedFiles(dt) {
  const items = [...(dt.items || [])];
  const entries = items.map((it) => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null)).filter(Boolean);
  if (!entries.some((en) => en.isDirectory)) return [...(dt.files || [])];
  const out = [];
  const readAll = (reader) => new Promise((res, rej) => {
    const acc = [];
    const step = () => reader.readEntries((batch) => (batch.length ? (acc.push(...batch), step()) : res(acc)), rej);
    step();
  });
  const walk = async (en, prefix) => {
    if (en.isFile) {
      const f = await new Promise((res, rej) => en.file(res, rej));
      out.push({ name: f.name, size: f.size, webkitRelativePath: prefix + f.name, arrayBuffer: () => f.arrayBuffer() });
    } else if (en.isDirectory) {
      for (const child of await readAll(en.createReader())) await walk(child, prefix + en.name + "/");
    }
  };
  for (const en of entries) await walk(en, "");
  return out;
}

// POST one file to the case. The name is percent-encoded (a header value is Latin-1 only, so a
// name like `测试.bin` made fetch throw) and the server is told so (api/endpoints.py x_filename).
async function uploadOne(caseId, file) {
  const res = await fetch(`/cases/${caseId}/targets`, {
    method: "POST", body: file,
    headers: { "Content-Type": "application/octet-stream",
               "X-Filename": encodeURIComponent((file && file.name) || "upload.bin"),
               "X-Filename-Encoding": "uri" },
  });
  const text = await res.text();
  let d = null;
  try { d = text ? JSON.parse(text) : null; } catch (_e) { d = { error: text }; }
  if (!res.ok) throw new Error((d && (d.error || d.message)) || `${res.status} ${res.statusText}`);
  return d;
}

// version-control metadata is never part of the source the analysis needs, and it is often most
// of a checkout's bytes
const SKIP_PATH = /(^|\/)(\.git|\.hg|\.svn)\//;

function AddTarget({ caseId, onAdded }) {
  const [over, setOver] = useState(false);
  // A FOLDER picker needs the webkitdirectory ATTRIBUTE. Preact sets it as a DOM property, and
  // an empty-string value read as false -- the picker opened as a plain file chooser and a
  // folder could not be selected. Set the attributes on the element itself.
  const dirInput = useRef(null);
  useEffect(() => {
    const el = dirInput.current;
    if (el) { el.setAttribute("webkitdirectory", ""); el.setAttribute("directory", ""); }
  }, []);
  const [busy, setBusy] = useState(null);
  const [errs, setErrs] = useState([]);
  const [done, setDone] = useState(null);
  const upload = async (fileList) => {
    if (busy) return;                                  // one batch at a time
    setErrs([]); setDone(null);
    let files = [...(fileList || [])];
    const problems = [];
    if (isFolderPick(files)) {
      // a FOLDER pick (a source tree) is packed into one archive client-side and ingested as a
      // source project, as the previous workbench did
      const kept = files.filter((f) => !SKIP_PATH.test(f.webkitRelativePath || ""));
      const skipped = files.length - kept.length;
      const total = kept.reduce((a, f) => a + (f.size || 0), 0);
      if (!kept.length) { setErrs(["the folder is empty (nothing to upload)"]); return; }
      if (total > MAX_UPLOAD) {
        setErrs([`the folder holds ${fmtBytes(total)}; the server takes at most ${fmtBytes(MAX_UPLOAD)} per upload — pick the source directory itself, without build output`]);
        return;
      }
      setBusy(`packing ${kept.length.toLocaleString()} files (${fmtBytes(total)}) into a source archive…${skipped ? ` · ${skipped.toLocaleString()} version-control files left out` : ""}`);
      try { files = [await folderArchive(kept)]; }
      catch (e) { setBusy(null); setErrs([`could not pack the folder: ${e.message || e}`]); return; }
    }
    if (!files.length) { setErrs(["nothing to upload (an empty folder, or no file was picked)"]); return; }
    let ok = 0;
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (f.size > MAX_UPLOAD) { problems.push(`${f.name}: ${fmtBytes(f.size)} is over the ${fmtBytes(MAX_UPLOAD)} upload limit`); continue; }
      setBusy(`uploading ${files.length > 1 ? `${i + 1} of ${files.length}: ` : ""}${f.name} (${fmtBytes(f.size || 0)})…`);
      try { await uploadOne(caseId, f); ok++; } catch (e) { problems.push(`${f.name}: ${e.message || e}`); }
    }
    setBusy(null);
    setErrs(problems);
    if (ok) setDone(`${ok} target${ok === 1 ? "" : "s"} added`);
    if (ok && onAdded) onAdded();
  };
  // copy the FileList, then clear the input: picking the same file again (after a failed upload)
  // must fire `change` again
  const onPick = (e) => { const fl = [...(e.target.files || [])]; e.target.value = ""; upload(fl); };
  const onDrop = async (e) => {
    e.preventDefault(); setOver(false);
    if (busy) return;
    let files;
    setBusy("reading the dropped files…");
    try { files = await droppedFiles(e.dataTransfer); }
    catch (err) { setBusy(null); setErrs([`could not read what was dropped: ${err.message || err}`]); return; }
    setBusy(null);
    upload(files);
  };
  return html`<section class=${"drop" + (over ? " over" : "")} aria-busy=${!!busy}
      onDragOver=${(e) => { e.preventDefault(); setOver(true); }} onDragLeave=${() => setOver(false)}
      onDrop=${onDrop}>
    <h2>Add a target</h2>
    <span class="muted" style="font-size:13px">Drop a binary or firmware image here, or${" "}
      <label style="color:var(--blue);cursor:pointer">browse files<input type="file" multiple hidden disabled=${!!busy}
        onChange=${onPick} /></label>, or pick a${" "}
      <label style="color:var(--blue);cursor:pointer">source folder<input type="file" multiple hidden disabled=${!!busy}
        ref=${dirInput} onChange=${onPick} /></label>.${" "}
      <span class="dim">Up to ${fmtBytes(MAX_UPLOAD)} per upload.</span></span>
    ${busy ? html`<span class="dim" style="font-size:12px" role="status">${busy}</span>` : null}
    ${done && !busy ? html`<span class="dim" style="font-size:12px" role="status">${done}</span>` : null}
    ${errs.map((x) => html`<span style="color:var(--amber-tx);font-size:12px" role="alert">${x}</span>`)}
  </section>`;
}

function StartPanel({ caseId, targets, onStarted, running }) {
  const [argv, setArgv] = useState("");
  const [mode, setMode] = useState("auto");
  const [budget, setBudget] = useState(600);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [more, setMore] = useState(false);
  const [opts, setOpts] = useState({});
  // targets left OUT of this run (default: none, so a newly added target is included)
  const [excluded, setExcluded] = useState(() => new Set());
  const mod = useModule("./results.js");
  useEffect(() => { if (mod && mod.loadRunOptions) setOpts(mod.loadRunOptions()); }, [mod]);
  const chosen = targets.filter((t) => !excluded.has(t.id));
  const toggle = (id, on) => setExcluded((o) => { const n = new Set(o); if (on) n.delete(id); else n.add(id); return n; });
  const start = async () => {
    if (!chosen.length) return;
    setBusy(true); setErr(null);
    try {
      // The invocation is THIS panel's two fields, never one remembered from another screen or
      // case (the hidden saved argv used to be sent along with a blank field here).
      const [ov, converge, skip] = await startSettings(mod, { ...opts, invArgv: "", invMode: "auto" }, caseId);
      const overrides = { ...ov };
      delete overrides.argv; delete overrides.input_mode;
      if (argv.trim()) overrides.argv = argv.trim();
      if (mode !== "auto") overrides.input_mode = mode;
      await api.startBackground(caseId, chosen.map((t) => t.id), budget, overrides, converge, skip);
      onStarted && onStarted();
    }
    catch (e) { setErr(String(e.message || e)); }
    setBusy(false);
  };
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <h2>Analyse ${targets.length === 1 ? "this target" : chosen.length === targets.length ? `all ${targets.length} targets` : `${chosen.length} of ${targets.length} targets`}</h2>
    ${targets.length > 1 ? html`<fieldset class="tpick" aria-label="Targets to analyse">
      ${targets.map((t) => html`<label class="tpick-i" title=${t.filename}>
        <input type="checkbox" checked=${!excluded.has(t.id)} onChange=${(e) => toggle(t.id, e.target.checked)} />
        <span class="mono">${t.filename || t.id}</span></label>`)}
      ${excluded.size ? html`<button class="xref" onClick=${() => setExcluded(new Set())}>all</button>` : null}
    </fieldset>` : null}
    ${excluded.size ? html`<span class="dim" style="font-size:12px">Only the ticked targets are analysed; the unticked ones are
      left out of this run.</span>` : null}
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px">
      <label class="field">How it is invoked (@@ = the input)
        <input type="text" class="mono" placeholder="auto-detect, e.g. -c @@" value=${argv} onInput=${(e) => setArgv(e.target.value)} /></label>
      <label class="field">Input reaches it via
        <select value=${mode} onChange=${(e) => setMode(e.target.value)}>
          <option value="auto">auto-detect</option><option value="file">file</option>
          <option value="stdin">stdin</option><option value="arg">argument</option>
          <option value="env">environment variable</option></select></label>
      <label class="field">Time budget
        <select value=${budget} onChange=${(e) => setBudget(+e.target.value)}>
          ${BUDGET_OPTIONS.map((o) => html`<option value=${o.secs}>${o.label}</option>`)}</select></label>
    </div>
    ${more ? html`<${Lazy} path="./results.js" name="RunOptions" props=${{ value: opts, onChange: setOpts, caseId, hideInvocation: true }}
      fallback=${html`<span class="dim">More options are not available.</span>`} />` : null}
    <div class="row-c" style="flex-wrap:wrap"><button class="btn primary" disabled=${busy || running || !chosen.length} onClick=${start}
        title=${running ? "an analysis is already running in this case" : ""}>${busy ? "Starting…" : "Start analysis"}</button>
      <button class="btn sm" onClick=${() => setMore(!more)} aria-expanded=${more}>${more ? "Fewer options ▴" : "More options ▾"}</button>
      ${running ? html`<span class="dim" style="font-size:12px">An analysis is running — stop it on the Run screen to start another.</span>` : null}
      ${err ? html`<span style="color:var(--amber-tx);font-size:12px" role="alert">${err}</span>` : null}</div>
  </section>`;
}

// The engagement report (GET /cases/{id}/report) with the CLI's filters: --min-severity,
// --min-state, --states (`lykos report`), and the portable case archive (export / import).
function ExportPanel({ caseId, reloadCases, setCaseId }) {
  const fmts = [["html", "HTML report"], ["pdf", "PDF report"], ["sarif", "SARIF"], ["json", "JSON"]];
  const [minSev, setMinSev] = useState("");
  const [minState, setMinState] = useState("candidate");
  const [states, setStates] = useState(() => new Set());
  const q = (f) => {
    const p = new URLSearchParams({ format: f });
    if (minSev) p.set("min_severity", minSev);
    if (minState && minState !== "candidate") p.set("min_state", minState);
    if (states.size) p.set("states", STATES.filter((s) => states.has(s)).join(","));
    return `/cases/${caseId}/report?${p}`;
  };
  const flip = (s, on) => setStates((o) => { const n = new Set(o); if (on) n.add(s); else n.delete(s); return n; });
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <h2>Report & export</h2>
    <span class="muted" style="font-size:13px">The engagement report, generated offline from this case.</span>
    <div class="row-c" style="flex-wrap:wrap;gap:12px">
      <label class="field">Lowest severity
        <select value=${minSev} onChange=${(e) => setMinSev(e.target.value)}>
          <option value="">any</option>${SEVERITIES.map((s) => html`<option value=${s}>${s}</option>`)}</select></label>
      <label class="field">Lowest state
        <select value=${minState} onChange=${(e) => setMinState(e.target.value)}>
          ${STATES.map((s) => html`<option value=${s}>${s}${s === "candidate" ? " (everything)" : ""}</option>`)}</select></label>
      <fieldset class="field rep-states"><legend>Only these states <span class="dim">(none = no restriction)</span></legend>
        <span class="row-c" style="flex-wrap:wrap;gap:10px">${STATES.map((s) => html`<label class="row-c" style="gap:5px">
          <input type="checkbox" checked=${states.has(s)} onChange=${(e) => flip(s, e.target.checked)} />${s}</label>`)}</span></fieldset>
    </div>
    <div class="row-c" style="flex-wrap:wrap">
      ${fmts.map(([f, l]) => html`<a class="btn sm" href=${q(f)} target="_blank" rel="noopener">${l}</a>`)}
      <a class="btn sm" href=${`/cases/${caseId}/export`} download>Case archive</a>
      <${ImportCase} reloadCases=${reloadCases} setCaseId=${setCaseId} />
    </div>
  </section>`;
}

// POST /import: merge a case archive (.tar.gz from "Case archive" / another lykos) into this store.
function ImportCase({ reloadCases, setCaseId }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const run = async (f) => {
    setMsg(null);
    if (f.size > MAX_UPLOAD) { setMsg({ bad: true, text: `${f.name}: ${fmtBytes(f.size)} is over the ${fmtBytes(MAX_UPLOAD)} upload limit` }); return; }
    setBusy(true);
    try {
      const res = await fetch("/import", { method: "POST", body: f, headers: { "Content-Type": "application/octet-stream" } });
      const text = await res.text();
      let d = null;
      try { d = text ? JSON.parse(text) : null; } catch (_e) { d = { error: text }; }
      if (!res.ok) throw new Error((d && d.error) || `${res.status} ${res.statusText}`);
      const ids = (d && d.cases) || [];
      setMsg({ text: `imported ${ids.length} case${ids.length === 1 ? "" : "s"}` });
      if (reloadCases) await reloadCases();
      if (ids.length === 1 && setCaseId) setCaseId(ids[0]);
    } catch (e) { setMsg({ bad: true, text: `could not import ${f.name}: ${e.message || e}` }); }
    setBusy(false);
  };
  return html`<label class=${"btn sm" + (busy ? " busy" : "")} style="display:inline-flex;align-items:center"
      title="merge a case archive (.tar.gz exported from lykos) into this server">
    ${busy ? "importing…" : "Import case archive"}
    <input type="file" accept=".gz,.tgz,application/gzip" hidden disabled=${busy}
      onChange=${(e) => { const f = e.target.files && e.target.files[0]; e.target.value = ""; if (f) run(f); }} /></label>
    ${msg ? html`<span style=${`font-size:12px;${msg.bad ? "color:var(--amber-tx)" : ""}`} class=${msg.bad ? "" : "dim"} role="status">${msg.text}</span>` : null}`;
}

function DeleteTarget({ t, onDeleted }) {
  const [arm, setArm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const del = async () => {
    setBusy(true); setErr(null);
    try { await api.deleteTarget(t.id); setArm(false); onDeleted && onDeleted(); }
    catch (e) { setErr(`could not remove: ${e.message || e}`); }
    setBusy(false);
  };
  const errEl = err ? html`<span style="color:var(--amber-tx);font-size:12px" role="alert">${err}</span>` : null;
  if (!arm) return html`<button class="btn sm" title="remove this target and its results from the case"
    onClick=${() => { setArm(true); setTimeout(() => setArm(false), 5000); }}>Remove</button>${errEl}`;
  return html`<button class="btn sm" style="border-color:#7A3B2E;color:#FFB4A6" disabled=${busy}
    onClick=${del}>${busy ? "Removing…" : "Confirm remove"}</button>${errEl}`;
}

function SystemMap({ caseId, targets }) {
  const [m, setM] = useState(null);
  useEffect(() => {
    if (!caseId || targets.length < 2) { setM(null); return undefined; }
    let live = true;
    getJSON(`/cases/${caseId}/systemmap`).then((x) => { if (live) setM(x); }).catch(() => { if (live) setM(null); });
    return () => { live = false; };
  }, [caseId, targets.length]);
  if (!m || !(m.edges || []).length) return null;
  const name = Object.fromEntries((m.nodes || []).map((n) => [n.id, n.filename || n.id]));
  return html`<section class="panel" style="overflow:hidden">
    <div class="pad" style="padding-bottom:6px"><h2>How the targets connect</h2>
      <span class="dim" style="font-size:12px">${m.edges.length} link(s) between ${m.nodes.length} targets — loads, execs, IPC, shared files</span></div>
    ${m.edges.map((e) => html`<div class="ev">
      <span class="mono" style="flex:1 1 40%;min-width:0">${name[e.src] || name[e.source] || e.src || e.source}</span>
      <span class="chip">${e.kind || e.type || e.label || "→"}</span>
      <span class="mono" style="flex:1 1 40%;min-width:0">${name[e.dst] || name[e.target] || e.dst || e.target}</span></div>`)}
  </section>`;
}

export function EngagementScreen({ cases, caseId, setCaseId, data, go, reloadCases, running }) {
  const [newName, setNewName] = useState("");
  const [cerr, setCerr] = useState(null);
  // the targets that hold the results first (a source build's owner, not its empty siblings)
  const rows = useMemo(() => data.targets.map((t) => ({ t, ...summarize(data, t) }))
    .sort((a, b) => (b.c.proven - a.c.proven) || ((b.c.needs + b.c.lead) - (a.c.needs + a.c.lead))), [data]);
  const tot = rows.reduce((a, r) => ({ proven: a.proven + r.c.proven, needs: a.needs + r.c.needs, lead: a.lead + r.c.lead,
    drivable: a.drivable + r.c.drivable, hit: a.hit + (r.c.proven ? 1 : 0), l3: a.l3 + (r.topLevel === "L3" ? 1 : 0) }),
  { proven: 0, needs: 0, lead: 0, drivable: 0, hit: 0, l3: 0 });
  const create = async () => {
    if (!newName.trim()) return;
    setCerr(null);
    try {
      const c = await api.createCase(newName.trim());
      setNewName("");
      await reloadCases();
      if (c && c.id) setCaseId(c.id);
    } catch (e) { setCerr(`could not create the case: ${e.message || e}`); }
  };
  const heading = !caseId ? "Create or pick a case"
    : data.loading && !data.targets.length ? "Loading the case…"
    : data.error && !data.targets.length ? "The case could not be loaded"
    : data.targets.length ? `${tot.hit} of ${data.targets.length} target${data.targets.length > 1 ? "s" : ""} ha${tot.hit === 1 ? "s" : "ve"} a proven vulnerability`
    : "No targets yet";
  return html`
    <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
      ${cases.length ? html`<select value=${caseId || ""} onChange=${(e) => setCaseId(e.target.value)} aria-label="Case">
        ${caseId ? null : html`<option value="">pick a case…</option>`}
        ${cases.map((c) => html`<option value=${c.id}>${c.name || c.id}</option>`)}
      </select>` : null}
      <input type="text" placeholder="new case name" value=${newName} onInput=${(e) => setNewName(e.target.value)}
             onKeyDown=${(e) => e.key === "Enter" && create()} aria-label="New case name" />
      <button class="btn sm" onClick=${create} disabled=${!newName.trim()}>New case</button>
      ${running ? html`<button class="chip on" style="cursor:pointer" onClick=${() => go("run")}><span class="dot live"></span>analysis running — open Run</button>` : null}
      ${cerr ? html`<span style="color:var(--amber-tx);font-size:12px" role="alert">${cerr}</span>` : null}
    </div>
    <h1>${heading}</h1>
    ${caseId && data.error ? html`<div class="panel pad" style="color:var(--amber-tx);font-size:13px" role="alert">Could not read this case: ${data.error}
      ${" "}<button class="btn sm" onClick=${data.reload}>Retry</button></div>` : null}
    ${caseId ? html`<div class="kpis">
      <div class="kpi blue"><b>${tot.proven}</b><span>proven, a PoC ran</span></div>
      <div class="kpi"><b>${tot.l3}</b><span>targets with a working exploit (L3)</span></div>
      <div class="kpi"><b>${tot.needs}</b><span>confirmed / corroborated, no PoC yet${tot.drivable ? ` · ${tot.drivable} drivable` : ""}</span></div>
      <div class="kpi"><b>${tot.lead}</b><span>unverified leads</span></div>
    </div>` : null}
    ${caseId ? html`<div style="display:flex;flex-wrap:wrap;gap:14px;align-items:stretch">
      <div style="flex:1 1 300px"><${AddTarget} caseId=${caseId} onAdded=${data.reload} /></div>
      <div style="flex:2 1 420px">${data.targets.length ? html`<${StartPanel} caseId=${caseId} targets=${data.targets} running=${running} onStarted=${() => go("run")} />` : null}</div>
    </div>` : html`<div class="dim" style="font-size:13px">Name a case above to start — targets are added to a case.</div>`}
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
        <span style="font-weight:600" data-l="proven">${c.proven}</span><span data-l="need PoC">${c.needs}</span><span class="muted" data-l="leads">${c.lead}</span>
        <span class="row-c" style="justify-content:flex-end;flex-wrap:wrap">
          <button class="btn sm" onClick=${() => go("proof", { targetId: t.id })}>Proof</button>
          <button class="btn sm" onClick=${() => go("code", { targetId: t.id })}>Code</button>
          <${DeleteTarget} t=${t} onDeleted=${data.reload} />
        </span>
      </div>`)}
    </section>` : null}
    <${SystemMap} caseId=${caseId} targets=${data.targets} />
    ${caseId ? html`<${ExportPanel} caseId=${caseId} reloadCases=${reloadCases} setCaseId=${setCaseId} />`
      : html`<section class="panel pad row-c" style="flex-wrap:wrap"><span class="muted" style="font-size:13px">Have a case archive from another lykos?</span>
        <${ImportCase} reloadCases=${reloadCases} setCaseId=${setCaseId} /></section>`}`;
}
