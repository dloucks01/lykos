// Proof screen, LIST view: every finding as one row that says plainly WHAT it is and WHERE it is.
//   what  -- a plain-language statement of the defect (from its CWE), qualified by how sure we are
//   where -- target · function · address, with a link straight to the code
//   proof -- what was demonstrated (PoC level, replay) or measured (the resolver's verdict)
// A row expands to show the instructions at the site, who calls the function, and the first
// evidence lines. Grouping: by status, by location (function), or by bug class.
import { useEffect, useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { bestLevel, functionAt, getJSON, hexToInt, pocsOf } from "./data.js";

// What each class of defect IS, in one plain sentence (the CWE name is the fallback).
const WHAT = {
  "CWE-125": "Reads memory past the end of a buffer",
  "CWE-126": "Reads past the end of a buffer",
  "CWE-787": "Writes memory past the end of a buffer",
  "CWE-122": "Overflows a heap buffer",
  "CWE-121": "Overflows a stack buffer",
  "CWE-120": "Copies data into a buffer without checking that it fits",
  "CWE-129": "Uses an index taken from the input without checking its range",
  "CWE-190": "An arithmetic result can wrap around (integer overflow)",
  "CWE-191": "An arithmetic result can wrap below zero (integer underflow)",
  "CWE-476": "Dereferences a NULL pointer",
  "CWE-416": "Uses memory after it has been freed",
  "CWE-415": "Frees the same memory twice",
  "CWE-763": "Frees a pointer that was not returned by the allocator",
  "CWE-134": "Passes a format string that may not be constant",
  "CWE-78": "Runs a command built from data",
  "CWE-22": "Opens or writes a file path that may come from input",
  "CWE-789": "Allocates a size that may come from the input",
  "CWE-770": "Allocates without a limit",
  "CWE-822": "Calls through a function pointer that may be corrupted",
  "CWE-94": "Control flow may follow a pointer derived from data",
  "CWE-457": "Reads memory that was never initialised",
  "CWE-369": "Divides by a value that can be zero",
  "CWE-835": "Can loop forever on some inputs",
  "CWE-400": "Can exhaust a resource (memory / CPU)",
  "CWE-377": "Creates a temporary file insecurely",
  "CWE-252": "Ignores a return value that signals failure",
  "CWE-617": "Can hit an assertion from input",
  "CWE-732": "Creates files with overly broad permissions",
};
// How sure lykos is, as the word in front of the sentence -- from the EVIDENCE, never the lane
// alone: an advisory API warning that picked up corroborating signals is still only "possible".
const ADVISORY = new Set(["dangerous_api", "windows_dangerous_imports"]);
function certainty(f, lane) {
  if (lane === "proven") return "Demonstrated";
  if (ADVISORY.has(f.detector)) return "Possible";
  if (f.state === "confirmed") return "Confirmed";
  if (f.state === "corroborated") return "Likely";
  return "Possible";
}

const fnCache = new Map();          // targetId -> Promise<functions[]>
const detCache = new Map();         // functionId -> Promise<function detail>
function functionsOf(tid) {
  if (!fnCache.has(tid)) {
    fnCache.set(tid, getJSON(`/targets/${tid}/functions`)
      .then((r) => (Array.isArray(r) ? r : Object.values(r || {}).find(Array.isArray) || [])).catch(() => []));
  }
  return fnCache.get(tid);
}
function detailOf(fid) {
  if (!detCache.has(fid)) detCache.set(fid, getJSON(`/functions/${fid}`).catch(() => null));
  return detCache.get(fid);
}
const parse = (v) => { if (v && typeof v === "object") return v; try { return JSON.parse(v); } catch (_e) { return null; } };

function where(f, fns) {
  const addr = f.site_addr || f.function_addr;
  let fn = addr ? functionAt(fns, addr) : null;
  if (!fn) {
    const m = /\b(fcn\.[0-9a-f]+|sub_[0-9a-f]+|FUN_[0-9a-f]+)\b/i.exec(f.title || "");
    if (m) fn = fns.find((x) => x.name === m[1]) || null;
  }
  return { fn, addr: f.site_addr || (fn ? fn.addr : f.function_addr) || null };
}

function resolveVerdict(f) {
  const ev = (f.evidence || []).filter((e) => e && e.channel === "resolve");
  const m = ev.length ? /^\[([a-z-]+)\]\s*(.*)$/s.exec(ev[ev.length - 1].detail || "") : null;
  return m ? { kind: m[1], detail: m[2] } : null;
}
const VERDICT = {
  "fired": "fired at its site", "reached-did-not-fire": "reached — no fault yet",
  "function-entered-site-cold": "function runs, site never reached", "not-reached": "not reached by any input",
  "not-reached-no-static-path": "no call path from the program", "unmapped": "not measured", "untested": "not measured",
};

function ProofCell({ f, lane, pocs }) {
  const lvl = bestLevel(pocs);
  const ran = pocs.find((p) => p.verified || p.provenance === "detonated");
  const rv = resolveVerdict(f);
  return html`<div class="fl-proof">
    ${lane === "proven"
      ? html`<span class="fl-status proven">${lvl || "PoC"} · proven</span>`
      : lane === "needs" ? html`<span class="fl-status needs">${f.state}</span>`
      : html`<span class="fl-status fl-lead">lead</span>`}
    <span class="dim" style="font-size:12px" title=${rv ? rv.detail : ""}>
      ${ran ? `PoC ran${ran.signal ? " · " + ran.signal : ""}` : rv ? VERDICT[rv.kind] || rv.kind : "not yet measured"}</span>
  </div>`;
}

function Row({ u, lane, pocsBy, fns, tname, showTarget, open, toCode }) {
  const f = u.rep;
  const [exp, setExp] = useState(false);
  const pocs = pocsOf(f, pocsBy);
  const w = where(f, fns);
  const what = WHAT[f.cwe] || f.cwe_name || f.title;
  return html`<div class=${"fl-row" + (exp ? " open" : "")}>
    <button class="fl-main" onClick=${() => setExp(!exp)} aria-expanded=${exp}>
      <span class="fl-sev" data-sev=${f.severity} title=${f.severity}></span>
      <span class="fl-what">
        <span class="fl-w1"><b>${certainty(f, lane)}:</b> ${what}</span>
        <span class="fl-w2">${f.title}${u.members.length ? html` <span class="dim">· +${u.members.length} related</span>` : null}</span>
      </span>
      <span class="fl-where mono">
        <span>${w.fn ? w.fn.name : "—"}</span>
        <span class="dim">${w.addr || ""}${showTarget ? ` · ${tname}` : ""}</span>
      </span>
      <${ProofCell} f=${f} lane=${lane} pocs=${pocs} />
      <span class="fl-chev" aria-hidden="true">${exp ? "▾" : "▸"}</span>
    </button>
    ${exp ? html`<${Expanded} f=${f} w=${w} fns=${fns} open=${open} toCode=${toCode} />` : null}
  </div>`;
}

function Expanded({ f, w, fns, open, toCode }) {
  const [d, setD] = useState(null);
  useEffect(() => { if (w.fn) detailOf(w.fn.id).then(setD); }, [w.fn && w.fn.id]);
  const site = hexToInt(f.site_addr);
  const lines = useMemo(() => {
    const ir = parse(d && d.ir);
    const flat = ((ir && ir.blocks) || []).flatMap((b) => b.instructions || []);
    if (!flat.length) return [];
    let i = site != null ? flat.findIndex((x) => hexToInt(x.addr) === site) : 0;
    if (i < 0) i = 0;
    return flat.slice(Math.max(0, i - 5), i + 6).map((x) => ({ ...x, hit: hexToInt(x.addr) === site }));
  }, [d, site]);
  const callers = useMemo(() => {
    const cs = parse(d && d.callers) || [];
    const names = [...new Set(cs.map((e) => (functionAt(fns, e.src_addr) || {}).name || e.src_addr))];
    return names.slice(0, 6);
  }, [d, fns]);
  const ev = (f.evidence || []).filter((e) => !["triage", "grounding-map"].includes(e.channel)).slice(0, 4);
  const rv = resolveVerdict(f);
  return html`<div class="fl-exp">
    <div class="fl-code">
      <div class="dim fl-label">${w.fn ? `IN ${w.fn.name}` : "CODE"}${callers.length ? ` · called from ${callers.join(", ")}` : ""}</div>
      ${lines.length ? html`<pre class="mono">${lines.map((x) => html`<div class=${x.hit ? "hit" : ""}><span class="a">${x.addr}</span>  ${x.text}</div>`)}</pre>`
        : html`<div class="dim" style="font-size:12.5px">${w.fn ? "Loading the instructions…" : "No recovered function for this finding."}</div>`}
    </div>
    <div class="fl-ev">
      ${rv ? html`<div><span class="chip">${VERDICT[rv.kind] || rv.kind}</span> <span class="card-b">${rv.detail}</span></div>` : null}
      ${ev.map((e) => html`<div class="fl-evl"><span class="chip" style="flex:none">${e.channel}</span><span>${String(e.detail || "").slice(0, 320)}</span></div>`)}
      <div class="row-c" style="flex-wrap:wrap;margin-top:6px">
        <button class="btn sm primary" onClick=${() => open(f.id)}>Full detail</button>
        ${w.addr && toCode ? html`<button class="btn sm" onClick=${() => toCode(f.target_id, w.addr)}>View code</button>` : null}
      </div>
    </div>
  </div>`;
}

const GROUPS = [["status", "Status"], ["location", "Location"], ["class", "Bug class"]];

export function FindingsList({ units, laneById, data, open, toCode, showTarget }) {
  const [groupBy, setGroupBy] = useState(() => { try { return localStorage.getItem("lykos.next.proofGroup") || "status"; } catch (_e) { return "status"; } });
  const [fnsBy, setFnsBy] = useState({});
  useEffect(() => { try { localStorage.setItem("lykos.next.proofGroup", groupBy); } catch (_e) { /* no storage */ } }, [groupBy]);
  useEffect(() => {
    let live = true;
    const tids = [...new Set(units.map((u) => u.rep.target_id))];
    Promise.all(tids.map((t) => functionsOf(t).then((fs) => [t, fs]))).then((pairs) => { if (live) setFnsBy(Object.fromEntries(pairs)); });
    return () => { live = false; };
  }, [units.length]);
  const tname = (tid) => (data.targets.find((t) => t.id === tid) || {}).filename || tid;
  const groups = useMemo(() => {
    const g = new Map();
    const key = (u) => {
      const f = u.rep;
      if (groupBy === "status") return ["proven", "needs", "lead"].indexOf(laneById.get(f.id)) + "|" + ({ proven: "Proven — a PoC ran", needs: "Real, no PoC yet", lead: "Leads — not verified" })[laneById.get(f.id)];
      if (groupBy === "class") return (WHAT[f.cwe] ? "1" : "2") + "|" + (WHAT[f.cwe] || f.cwe_name || f.cwe || "other") + (f.cwe ? ` (${f.cwe})` : "");
      const w = where(f, fnsBy[f.target_id] || []);
      return "1|" + (w.fn ? w.fn.name : "no recovered function") + (showTarget ? ` · ${tname(f.target_id)}` : "");
    };
    for (const u of units) { const k = key(u); if (!g.has(k)) g.set(k, []); g.get(k).push(u); }
    return [...g.entries()].sort((a, b) => (groupBy === "location" ? b[1].length - a[1].length : 0) || a[0].localeCompare(b[0]))
      .map(([k, us]) => ({ title: k.split("|").slice(1).join("|"), us }));
  }, [units, groupBy, fnsBy]);
  return html`<div class="fl">
    <div class="row-c" style="justify-content:space-between;flex-wrap:wrap">
      <span class="dim" style="font-size:12.5px">Each row: what the defect is · where it is · what is proven. Click a row for the code at the site.</span>
      <label class="muted" style="font-size:12.5px;display:flex;gap:6px;align-items:center">Group by
        <select value=${groupBy} onChange=${(e) => setGroupBy(e.target.value)}>${GROUPS.map(([v, l]) => html`<option value=${v}>${l}</option>`)}</select></label>
    </div>
    ${groups.map((g) => html`<section class="panel fl-group">
      <div class="fl-gh"><span>${g.title}</span><span class="dim">${g.us.length}</span></div>
      <div class="fl-head dim"><span></span><span>WHAT</span><span>WHERE</span><span>PROOF</span><span></span></div>
      ${g.us.map((u) => html`<${Row} key=${u.rep.id} u=${u} lane=${laneById.get(u.rep.id)} pocsBy=${data.pocs}
        fns=${fnsBy[u.rep.target_id] || []} tname=${tname(u.rep.target_id)} showTarget=${showTarget} open=${open} toCode=${toCode} />`)}
    </section>`)}
  </div>`;
}
