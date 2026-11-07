// Proof screen, LIST view: every finding as one row that says plainly WHAT it is and WHERE it is.
//   what  -- a plain-language statement of the defect (from its CWE), qualified by how sure we are
//   where -- target · function · address (binary) or file:line · function (source), with a link to the code
//   proof -- what was demonstrated (PoC level, replay) or measured (the resolver's verdict)
// A row expands to show the instructions (or the source lines) at the site, who calls the
// function, and the first evidence lines. Grouping: by status, by location, or by bug class.
import { useEffect, useMemo, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { bestLevel, functionAt, getJSON, hexToInt, pocsOf, proofNav, srcLocOf, srcText, triageOf } from "./data.js";

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
export function certainty(f, lane) {
  if (lane === "proven") return "Demonstrated";
  if (ADVISORY.has(f.detector)) return "Possible";
  if (f.state === "confirmed") return "Confirmed";
  if (f.state === "corroborated") return "Likely";
  return "Possible";
}
// The lane names, worded as certainty() words a row: nothing in "needs" has executed, so it is
// confirmed / corroborated, not "real".
export const LANE_TITLE = { proven: "Proven — a PoC ran", needs: "Confirmed or corroborated — no PoC yet", lead: "Leads — not verified" };

// The finding-triage disposition, as a chip: [label, tooltip lead, class]
export const DISP = {
  drivable: ["drivable", "reachable + attacker-tainted — on the PoC worklist", "on"],
  "needs-technique": ["needs a technique", "no reachability verdict yet / a technique is missing", ""],
  "off-surface": ["off-surface", "not on the attacker-reachable surface", ""],
  "false-positive": ["tool: false positive", "the tool's own triage disproved it", "pf-cur-false_positive"],
  untainted: ["untainted", "reachable, but no attacker-controlled data reaches the sink", ""],
};
export const dispLabel = (k) => (DISP[k] ? DISP[k][0] : k);
export function DispChip({ f }) {
  const t = triageOf(f);
  if (!t) return null;
  const [label, tip, cls] = DISP[t.kind] || [t.kind, "", ""];
  return html`<span class=${"chip" + (cls ? " " + cls : "")} title=${`tool triage: ${tip}${t.detail ? " — " + t.detail : ""}`}>${label}</span>`;
}

const ranP = (p) => p.verified || p.provenance === "detonated";
const conLevel = (pocs) => {
  const c = pocs.filter((p) => !ranP(p)).map((p) => +((String(p.level || "").match(/\d/) || [0])[0])).sort((a, b) => b - a)[0];
  return c ? "L" + c : null;
};

// Functions per target. Kept for the session, but an empty or failed answer is NOT kept: early
// in a run the list is still empty, and caching that hid every function until a page reload.
const fnCache = new Map();          // targetId -> Promise<functions[]>
const detCache = new Map();         // functionId -> Promise<function detail>
export function functionsOf(tid) {
  if (!fnCache.has(tid)) {
    fnCache.set(tid, getJSON(`/targets/${tid}/functions`)
      .then((r) => (Array.isArray(r) ? r : Object.values(r || {}).find(Array.isArray) || []))
      .then((fs) => { if (!fs.length) fnCache.delete(tid); return fs; })
      .catch(() => { fnCache.delete(tid); return []; }));
  }
  return fnCache.get(tid);
}
// The target's functions (null while loading), shared with the list's cache.
export function useFunctions(tid) {
  const [fs, setFs] = useState(null);
  useEffect(() => {
    let live = true;
    setFs(null);
    if (tid) functionsOf(tid).then((x) => { if (live) setFs(x); });
    return () => { live = false; };
  }, [tid]);
  return fs;
}
function detailOf(fid) {
  if (!detCache.has(fid)) {
    detCache.set(fid, getJSON(`/functions/${fid}`).catch(() => { detCache.delete(fid); return null; }));
  }
  return detCache.get(fid);
}
const parse = (v) => { if (v && typeof v === "object") return v; try { return JSON.parse(v); } catch (_e) { return null; } };

// The source lines around a finding's site. The server resolves the finding's own site first
// (GET /targets/{tid}/source-file?finding=); a finding whose site only the evidence prose names
// falls back to the path:line read here. Failures are not cached.
const srcCache = new Map();
function sourceWindow(tid, f, src, context) {
  const k = `${tid}|${f.id}|${context}`;
  if (!srcCache.has(k)) {
    const q = (s) => fetch(`/targets/${tid}/source-file?${s}&context=${context}`)
      .then(async (r) => { const d = await r.json().catch(() => ({})); return r.ok ? d : { error: d.error || `HTTP ${r.status}`, candidates: d.candidates }; });
    const p = q(`finding=${encodeURIComponent(f.id)}`)
      .then((d) => (d.error && src && src.line ? q(`path=${encodeURIComponent(src.path)}&line=${src.line}`) : d))
      .then((d) => { if (d.error) srcCache.delete(k); return d; })
      .catch((e) => { srcCache.delete(k); return { error: String(e.message || e) }; });
    srcCache.set(k, p);
  }
  return srcCache.get(k);
}
export function SourceWindow({ tid, f, src, context = 6, toCode }) {
  const [st, setSt] = useState(null);
  useEffect(() => {
    let live = true;
    setSt(null);
    sourceWindow(tid, f, src, context).then((d) => { if (live) setSt(d); });
    return () => { live = false; };
  }, [tid, f.id, context]);
  if (!st) return html`<div class="dim" style="font-size:12.5px">Reading the source…</div>`;
  if (st.error) {
    return html`<div class="dim" style="font-size:12.5px">Source not available${src ? ` for ${srcText(src)}` : ""}: ${st.error}${(st.candidates || []).length ? ` (matches: ${st.candidates.slice(0, 4).join(", ")})` : ""}</div>`;
  }
  const lines = st.lines || [];
  return html`<div>
    <div class="row-c" style="flex-wrap:wrap;gap:6px;margin-bottom:4px">
      <span class="mono dim" style="font-size:12px">${st.path}:${st.line}${st.total ? ` · ${st.total} lines` : ""}</span>
      ${toCode ? html`<button class="pf-mini" onClick=${() => toCode(tid, null, `${st.path}:${st.line}`)}>View source</button>` : null}
    </div>
    <pre class="mono fl-src">${lines.map((t, i) => {
      const n = (st.start || 1) + i;
      return html`<div class=${n === st.line ? "hit" : ""}><span class="a">${n}</span>  ${t}</div>`;
    })}</pre></div>`;
}

// Where a finding is: its recovered function (binary), its address, or its source location.
export function where(f, fns) {
  const addr = f.site_addr || f.function_addr;
  let fn = addr ? functionAt(fns, addr) : null;
  if (!fn) {
    const m = /\b(fcn\.[0-9a-f]+|sub_[0-9a-f]+|FUN_[0-9a-f]+)\b/i.exec(f.title || "");
    if (m) fn = fns.find((x) => x.name === m[1]) || null;
  }
  const src = addr || fn ? null : srcLocOf(f);
  return { fn, addr: f.site_addr || (fn ? fn.addr : f.function_addr) || null, src };
}
const whereText = (w) => (w.fn ? w.fn.name : w.src ? (w.src.fn ? w.src.fn + "()" : w.src.path.split("/").pop()) : null);

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
  const ran = pocs.find(ranP);
  const con = lane === "proven" ? null : conLevel(pocs);
  const rv = resolveVerdict(f);
  return html`<div class="fl-proof">
    <span class="row-c" style="gap:4px;flex-wrap:wrap">
      ${lane === "proven"
        ? html`<span class="fl-status proven">${lvl || "PoC"} · proven</span>`
        : lane === "needs" ? html`<span class="fl-status needs">${f.state}</span>`
        : html`<span class="fl-status fl-lead">lead</span>`}
      ${con ? html`<span class="lvl pf-lvl-con" title="a PoC was constructed at this level by analysis — not executed">${con} · constructed</span>` : null}
      <${DispChip} f=${f} />
    </span>
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
    <button class="fl-main" data-fid=${f.id} onClick=${() => setExp(!exp)} aria-expanded=${exp ? "true" : "false"}>
      <span class="fl-sev" data-sev=${f.severity} aria-hidden="true"></span>
      <span class="fl-what">
        <span class="fl-w1"><b>${certainty(f, lane)}:</b> ${what}</span>
        <span class="fl-w2"><span class=${"fl-sevtx sev-" + (f.severity || "none")}>${f.severity || "no severity"}</span> · ${f.title}${u.members.length ? html` <span class="dim">· +${u.members.length} related</span>` : null}</span>
      </span>
      <span class="fl-where mono">
        <span>${whereText(w) || "—"}</span>
        <span class="dim">${w.addr || srcText(w.src)}${showTarget ? ` · ${tname}` : ""}</span>
      </span>
      <${ProofCell} f=${f} lane=${lane} pocs=${pocs} />
      <span class="fl-chev" aria-hidden="true">${exp ? "▾" : "▸"}</span>
    </button>
    ${exp ? html`<${Expanded} f=${f} w=${w} fns=${fns} open=${open} toCode=${toCode} />` : null}
  </div>`;
}

function Expanded({ f, w, fns, open, toCode }) {
  const [d, setD] = useState(undefined);      // undefined = loading, null = no detail
  const fid = w.fn && w.fn.id;
  useEffect(() => {
    let live = true;
    setD(undefined);
    if (fid) detailOf(fid).then((x) => { if (live) setD(x); });
    return () => { live = false; };
  }, [fid]);
  const site = hexToInt(f.site_addr);
  const { lines, missed } = useMemo(() => {
    const ir = parse(d && d.ir);
    const flat = ((ir && ir.blocks) || []).flatMap((b) => b.instructions || []);
    if (!flat.length) return { lines: [], missed: false };
    let i = site != null ? flat.findIndex((x) => hexToInt(x.addr) === site) : 0;
    const miss = site != null && i < 0;
    if (i < 0) i = 0;
    return { lines: flat.slice(Math.max(0, i - 5), i + 6).map((x) => ({ ...x, hit: hexToInt(x.addr) === site })), missed: miss };
  }, [d, site]);
  const callers = useMemo(() => {
    const cs = parse(d && d.callers) || [];
    const names = [...new Set(cs.map((e) => (functionAt(fns, e.src_addr) || {}).name || e.src_addr))];
    return names.slice(0, 6);
  }, [d, fns]);
  const ev = (f.evidence || []).filter((e) => !["triage", "grounding-map"].includes(e.channel)).slice(0, 4);
  const rv = resolveVerdict(f);
  const tri = triageOf(f);
  return html`<div class="fl-exp">
    <div class="fl-code">
      <div class="dim fl-label">${w.fn ? `IN ${w.fn.name}` : w.src ? `SOURCE${w.src.fn ? ` · IN ${w.src.fn}()` : ""}` : "CODE"}${callers.length ? ` · called from ${callers.join(", ")}` : ""}</div>
      ${w.fn ? (lines.length ? html`
          ${missed ? html`<div class="dim" style="font-size:12px;margin-bottom:4px">The site ${f.site_addr} is not among the recovered instructions — showing the start of the function.</div>` : null}
          <pre class="mono">${lines.map((x) => html`<div class=${x.hit ? "hit" : ""}><span class="a">${x.addr}</span>  ${x.text}</div>`)}</pre>`
          : html`<div class="dim" style="font-size:12.5px">${d === undefined ? "Loading the instructions…" : "No recovered instructions for this function."}</div>`)
        : w.src ? html`<${SourceWindow} tid=${f.target_id} f=${f} src=${w.src} toCode=${toCode} />`
        : html`<div class="dim" style="font-size:12.5px">No recovered function or source site for this finding.</div>`}
    </div>
    <div class="fl-ev">
      ${tri ? html`<div><${DispChip} f=${f} /> <span class="card-b">${tri.detail}</span></div>` : null}
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
const PAGE = 100;

// Rows are rendered PAGE at a time per group: a 500-finding group is one click away, not 500
// live rows re-rendering on every keystroke.
export function FindingsList({ units, laneById, data, open, toCode, showTarget }) {
  const [groupBy, setGroupBy] = useState(() => { try { return localStorage.getItem("lykos.next.proofGroup") || "status"; } catch (_e) { return "status"; } });
  const [fnsBy, setFnsBy] = useState({});
  const [lim, setLim] = useState({});
  useEffect(() => { try { localStorage.setItem("lykos.next.proofGroup", groupBy); } catch (_e) { /* no storage */ } }, [groupBy]);
  const tidKey = [...new Set(units.map((u) => u.rep.target_id))].sort().join(",");
  useEffect(() => {
    let live = true;
    const tids = tidKey ? tidKey.split(",") : [];
    Promise.all(tids.map((t) => functionsOf(t).then((fs) => [t, fs]))).then((pairs) => { if (live) setFnsBy(Object.fromEntries(pairs)); });
    return () => { live = false; };
  }, [tidKey]);
  const tname = (tid) => (data.targets.find((t) => t.id === tid) || {}).filename || tid;
  const groups = useMemo(() => {
    const g = new Map();
    const key = (u) => {
      const f = u.rep;
      if (groupBy === "status") { const l = laneById.get(f.id); return ["proven", "needs", "lead"].indexOf(l) + "|" + LANE_TITLE[l]; }
      if (groupBy === "class") return (WHAT[f.cwe] ? "1" : "2") + "|" + (WHAT[f.cwe] || f.cwe_name || f.cwe || "other") + (f.cwe ? ` (${f.cwe})` : "");
      const w = where(f, fnsBy[f.target_id] || []);
      const loc = w.fn ? w.fn.name : w.src ? w.src.path : null;
      return (loc ? "1|" : "2|") + (loc || "no recovered function or source site") + (showTarget ? ` · ${tname(f.target_id)}` : "");
    };
    for (const u of units) { const k = key(u); if (!g.has(k)) g.set(k, []); g.get(k).push(u); }
    return [...g.entries()].sort((a, b) => (groupBy === "location" ? b[1].length - a[1].length : 0) || a[0].localeCompare(b[0]))
      .map(([k, us]) => ({ k, title: k.split("|").slice(1).join("|"), us }));
  }, [units, groupBy, fnsBy, laneById, showTarget]);
  // the detail view's previous / next follow exactly this order
  useEffect(() => { proofNav.order = groups.flatMap((g) => g.us.flatMap((u) => [u.rep.id, ...u.members.map((m) => m.id)])); }, [groups]);
  return html`<div class="fl">
    <div class="row-c" style="justify-content:space-between;flex-wrap:wrap">
      <span class="dim" style="font-size:12.5px">Each row: what the defect is · where it is · what is proven. Click a row for the code at the site · j / k move between rows.</span>
      <label class="muted" style="font-size:12.5px;display:flex;gap:6px;align-items:center">Group by
        <select value=${groupBy} onChange=${(e) => setGroupBy(e.target.value)}>${GROUPS.map(([v, l]) => html`<option value=${v}>${l}</option>`)}</select></label>
    </div>
    ${groups.map((g) => {
      const n = lim[g.k] || PAGE;
      const rest = g.us.length - n;
      return html`<section class="panel fl-group" key=${g.k}>
        <div class="fl-gh"><span>${g.title}</span><span class="dim">${g.us.length}</span></div>
        <div class="fl-head dim"><span></span><span>WHAT</span><span>WHERE</span><span>PROOF</span><span></span></div>
        ${g.us.slice(0, n).map((u) => html`<${Row} key=${u.rep.id} u=${u} lane=${laneById.get(u.rep.id)} pocsBy=${data.pocs}
          fns=${fnsBy[u.rep.target_id] || []} tname=${tname(u.rep.target_id)} showTarget=${showTarget} open=${open} toCode=${toCode} />`)}
        ${rest > 0 ? html`<div class="fl-more">
          <button class="pf-mini" onClick=${() => setLim((o) => ({ ...o, [g.k]: n + PAGE }))}>Show ${Math.min(PAGE, rest)} more</button>
          <button class="pf-mini" onClick=${() => setLim((o) => ({ ...o, [g.k]: g.us.length }))}>Show all ${g.us.length}</button>
          <span class="dim">${rest} not shown</span></div>` : null}
      </section>`;
    })}
  </div>`;
}
