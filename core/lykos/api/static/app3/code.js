// Code screen: everything lykos recovered about a target's code, one sub-view per question --
//   Functions  the function list (findings first, virtualized for 10k+), a function's disassembly
//              with every finding site marked, its stack frame, callers/callees (by name, across
//              binaries too), decompiled C when the decompiler produced real code
//   Call graph the selected function's neighbourhood, N hops up and down, pannable / zoomable
//   Strings    every recovered string, with the functions that reference it
//   Target     identity, mitigations posture, sections, imports, what to do next (advice), what
//              lykos can and cannot do here and why (capabilities), and the invocation helper
//   Source     the uploaded source tree (or the compiled single file), finding lines marked
//   Scans      operator scans: variant hunt, weggli, CodeQL, hypothesis hunt, differential test
//   Diff       two builds compared: findings fixed / new, patch-diff leads, PoC re-run
//   Classes    heap / taint / known-CVE findings (when the target has any)
// Every number on it comes from the server; nothing is invented when a field is absent.
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { html } from "../app2/html.js";
import { api, waitForRun } from "../app/api.js";
import { getJSON, hexToInt, isNoise } from "./data.js";

const asList = (r) => (Array.isArray(r) ? r : (r && Object.values(r).find(Array.isArray)) || []);
const parseMaybe = (v) => {
  if (Array.isArray(v) || (v && typeof v === "object")) return v;
  try { return JSON.parse(v); } catch (_e) { return null; }
};
const hx = (n) => (n == null ? "" : (n < 0 ? "-0x" + (-n).toString(16) : "0x" + n.toString(16)));
const errText = (e) => String((e && e.message) || e);
function fmtBytes(n) {
  if (n == null || !isFinite(n)) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
function fmtDur(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}
const bare = (n) => (n || "").replace(/^(sym\.imp\.|sym\.|imp\.|_+)/, "").replace(/@.*$/, "");
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
// Is the decompiled text real code, or a tool's "install me" placeholder / empty stub?
const usableDecompile = (s) => !!s && s.trim().length >= 24 && !/you need to install|r2pm|not available|no decompiler/i.test(s);
// A PLT / import thunk: rizin types it `sym.imp.X` (it has one block, so `blocks` alone missed all 29
// of gif2rgb's).
const isStub = (f) => !f.blocks || /\bsym\.imp\./.test(f.signature || "") || /^(sym\.)?imp\./.test(f.name || "");
const live = (fs) => (fs || []).filter((f) => !isNoise(f));

// A GET whose error body matters (an ambiguous source path answers 404 with its candidates).
async function fetchJSON(path) {
  const r = await fetch(path);
  let body = null;
  try { body = await r.json(); } catch (_e) { body = null; }
  return { ok: r.ok, status: r.status, body };
}

// Per-target lists that outlive a screen mount: finding -> code -> finding re-fetched a multi-MB
// function list every time. An EMPTY or failed answer is not kept (disassembly may still be running).
const FN_CACHE = new Map(), EDGE_CACHE = new Map(), SRC_CACHE = new Map();
function cached(map, key, fetcher, keep = (v) => asList(v).length > 0) {
  let p = map.get(key);
  if (!p) {
    p = fetcher();
    map.set(key, p);
    p.then((v) => { if (!keep(v)) map.delete(key); }, () => map.delete(key));
  }
  return p;
}
const loadFuncs = (tid) => cached(FN_CACHE, tid, () => getJSON(`/targets/${tid}/functions`).then(asList));
const loadCallgraph = (tid) => cached(EDGE_CACHE, tid, () => api.callgraph(tid).then(asList));
// The target's source: the uploaded tree (source-tree), else the single compiled file (/source).
const loadSource = (tid) => cached(SRC_CACHE, tid, async () => {
  const t = await fetchJSON(`/targets/${tid}/source-tree`).catch(() => null);
  if (t && t.ok && t.body && t.body.source && (t.body.files || []).length) {
    return { kind: "tree", files: t.body.files, truncated: !!t.body.truncated };
  }
  const r = await api.targetSource(tid).catch(() => null);
  if (r && typeof r.source === "string") {
    return { kind: "single", files: [r.filename || "source"], text: r.source, compiler: r.compiler, sanitizers: r.sanitizers };
  }
  return null;
}, (v) => !!v);
// Function detail, a few kept: arrowing back and forth through the list re-fetched each one.
const FN_DETAIL = new Map();
function keepDetail(id, d) {
  FN_DETAIL.set(id, d);
  if (FN_DETAIL.size > 24) FN_DETAIL.delete(FN_DETAIL.keys().next().value);
}

// A per-viewer convenience (last sub-view, last graph depth). Never state that must persist.
function useLocal(key, init) {
  const [v, setV] = useState(() => {
    try { const x = localStorage.getItem(key); return x == null ? init : JSON.parse(x); } catch (_e) { return init; }
  });
  const set = (x) => { setV(x); try { localStorage.setItem(key, JSON.stringify(x)); } catch (_e) { /* private window */ } };
  return [v, set];
}

// Address -> function, by binary search over sorted starts (a 10k-function target with a
// 5k-instruction listing needs this to stay fast).
function makeIndex(funcs) {
  const arr = [];
  for (const f of funcs) { const a = hexToInt(f.addr); if (a != null) arr.push([a, f]); }
  arr.sort((x, y) => x[0] - y[0]);
  const starts = new Map(arr.map(([a, f]) => [a, f]));
  const at = (addr) => {
    const a = hexToInt(addr);
    if (a == null || !arr.length) return null;
    let lo = 0, hi = arr.length - 1, best = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (arr[m][0] <= a) { best = m; lo = m + 1; } else hi = m - 1; }
    for (let i = best; i >= 0 && i > best - 8; i--) {
      const [s, f] = arr[i];
      if (a < s + Math.max(1, +f.size || 0)) return f;
    }
    return null;
  };
  return { starts, at, byId: new Map(funcs.map((f) => [f.id, f])), byName: new Map(funcs.map((f) => [f.name, f])) };
}

// The function a finding sits in: its site, its function address, else the function its title /
// evidence names (uc_symbolic files "... in fcn.00004b16()" with no address at all).
const FN_REF = /\b(fcn\.[0-9a-fA-F]{4,}|sub_[0-9a-fA-F]{4,})\b/;
function fnOfFinding(f, index) {
  const fn = index.at(f.site_addr || f.function_addr) || index.at(f.function_addr);
  if (fn) return fn;
  for (const s of [f.title, ...(f.evidence || []).map((e) => e && e.detail)]) {
    const m = FN_REF.exec(String(s || ""));
    if (!m) continue;
    const g = index.byName.get(m[1]) || index.starts.get(parseInt(m[1].replace(/^(fcn\.|sub_)/, ""), 16));
    if (g) return g;
  }
  return null;
}

// A source finding's site, read as the server's dedup.parse_loc does: `path:line` on a site
// channel, else a `path: fn()` site (file, no line), else any `path:line` it carries.
const SRC_LOC = /([\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|hxx|cs|go|rs|py|java|js|ts)):(\d+)/;
const FN_SITE = /^\s*([\w./+-]+\.(?:c|h|cc|cpp|cxx|hpp|hh)):\s*([A-Za-z_]\w*)\(\)/;
const SITE_CH = new Set(["source", "recipe-source", "guard-gap", "alloc-overflow", "sibling-guard", "dop-target",
  "oob-write", "cpg", "source-sink", "int-overflow", "uaf", "assert-guard"]);
function srcSiteOf(f) {
  let fnFile = null;
  for (const e of f.evidence || []) {
    if (!e || !SITE_CH.has(e.channel)) continue;
    const d = String(e.detail || "");
    const m = SRC_LOC.exec(d);
    if (m) return { path: m[1], line: +m[2] };
    const mf = FN_SITE.exec(d);
    if (mf && !fnFile) fnFile = mf[1];
  }
  if (fnFile) return { path: fnFile, line: null };
  const rest = [f.dedup_key, ...(f.evidence || []).filter((e) => e && e.channel !== "triage").map((e) => e.detail), f.title];
  for (const c of rest) {
    const m = SRC_LOC.exec(String(c || ""));
    if (m) return { path: m[1], line: +m[2] };
  }
  return null;
}
// Tree-relative resolution, the same order as the server's source_tree.resolve: exact, the longest
// suffix of a longer (build-dir / absolute) path, else a basename that names exactly one file.
function treeIndex(files) {
  const set = new Set(files), byBase = new Map();
  for (const p of files) { const b = p.slice(p.lastIndexOf("/") + 1); if (!byBase.has(b)) byBase.set(b, []); byBase.get(b).push(p); }
  const resolve = (path) => {
    const p = String(path || "").replace(/\\/g, "/").replace(/^\/+/, "").replace(/^(\.\/)+/, "");
    if (!p) return { rel: null, cands: [] };
    if (set.has(p)) return { rel: p, cands: [] };
    const parts = p.split("/");
    for (let i = 1; i < parts.length; i++) { const s = parts.slice(i).join("/"); if (set.has(s)) return { rel: s, cands: [] }; }
    const c = byBase.get(parts[parts.length - 1]) || [];
    return c.length === 1 ? { rel: c[0], cands: [] } : { rel: null, cands: c };
  };
  return { set, resolve };
}
// "tree/relative/path.c:LINE" (or a bare path) -> {path, line}
function parseSrcRef(s) {
  if (!s) return null;
  const m = /^(.*?):(\d+)$/.exec(String(s));
  return m ? { path: m[1], line: +m[2] } : { path: String(s), line: null };
}

// A quote-aware split of an argv string ("-c @@", `--name "a b"`), for the invocation helper.
function shellSplit(s) {
  const out = []; let cur = "", q = null, any = false;
  for (const ch of String(s || "")) {
    if (q) { if (ch === q) q = null; else cur += ch; continue; }
    if (ch === "'" || ch === '"') { q = ch; any = true; continue; }
    if (/\s/.test(ch)) { if (cur || any) { out.push(cur); cur = ""; any = false; } continue; }
    cur += ch;
  }
  if (cur || any) out.push(cur);
  return out;
}
const shellJoin = (argv) => (argv || []).map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, "'\\''")}'`)).join(" ");
function b64utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// Operator-launched stages (scans, diffs, harness). A stage that declines returns no output record
// and says why in its `<stage>.done` event only; read that event (by run id, paging forward from
// the cursor taken before the run started -- a busy autopilot pushes it out of any fixed tail) so
// the operator sees the reason, not an empty result. No `.done` event: the run's last progress line.
async function eventCursor(caseId) {
  try { const t = asList(await api.eventsTail(caseId, 1)); return t.length ? t[t.length - 1].id : 0; } catch (_e) { return null; }
}
async function stageVerdict(caseId, runId, cursor) {
  if (!caseId) return null;
  let done = null, prog = null;
  const scan = (evs) => {
    for (const x of evs) {
      if (x.run_id !== runId) continue;
      if (/\.done$/.test(x.type || "") && x.type !== "job.done" && x.payload) done = x.payload;
      else if (x.type === "job.progress" && x.payload && x.payload.msg) prog = x.payload.msg;
    }
  };
  try {
    if (cursor != null) {
      let after = cursor;
      for (let i = 0; i < 80; i++) {                       // 500 a page: up to 40k events
        const evs = asList(await api.events(caseId, after));
        scan(evs);
        if (evs.length < 500) break;
        after = evs[evs.length - 1].id;
      }
    } else {
      scan(asList(await api.eventsTail(caseId, 2000)));
    }
  } catch (_e) { /* best effort: the Run console has it */ }
  return done || (prog ? { note: prog } : null);
}

// Runs live in a module store per case, not in the screen: opening a finding unmounts the Code
// screen, and a scan's status and result vanished while its poll kept running.
const STAGE_RUNS = new Map();
function stageStore(caseId) {
  let s = STAGE_RUNS.get(caseId);
  if (!s) { s = { runs: {}, subs: new Set() }; STAGE_RUNS.set(caseId, s); }
  return s;
}
function useStageRuns(caseId, onDone) {
  const st = stageStore(caseId || "");
  const [, bump] = useState(0);
  const doneRef = useRef(onDone);
  doneRef.current = onDone;
  useEffect(() => {
    const f = () => bump((x) => x + 1);
    st.subs.add(f);
    return () => { st.subs.delete(f); };
  }, [st]);
  const notify = () => st.subs.forEach((f) => f());
  const patch = (k, p) => { st.runs = { ...st.runs, [k]: { ...(st.runs[k] || {}), ...p } }; notify(); };
  const start = async (kind, stage, opts, meta = {}) => {
    st.runs = { ...st.runs, [kind]: { running: true, stage, started: Date.now(), meta } };
    notify();
    try {
      const cursor = await eventCursor(caseId);
      const r = await api.createRun(stage, opts);
      patch(kind, { runId: r.run_id, fromCache: !!r.from_cache });
      // polled until the run ends: the stage bounds itself, and Cancel is offered meanwhile
      const done = await waitForRun(r.run_id, { onTick: (run) => patch(kind, { run }), timeoutMs: 12 * 3600 * 1000 });
      const out = await api.runOutput(r.run_id).catch(() => null);
      if (done.status !== "done") throw new Error(done.error || `the run ended ${done.status}`);
      let data = out ? out.output : null;
      if (!data || (typeof data === "object" && !Array.isArray(data) && !Object.keys(data).length)) {
        data = (await stageVerdict(caseId, r.run_id, cursor)) || data;
      }
      patch(kind, { running: false, run: done, data, ended: Date.now() });
      if (doneRef.current) doneRef.current();
    } catch (e) {
      patch(kind, { running: false, error: errText(e), ended: Date.now() });
    }
  };
  const cancel = (kind) => {
    const id = st.runs[kind] && st.runs[kind].runId;
    if (id) api.cancelRun(id).catch(() => {});
  };
  return { runs: st.runs, start, cancel };
}

function RunStatus({ st, what, cancel }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!st || !st.running) return undefined;
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, [st && st.running]);
  if (!st) return null;
  if (st.running) {
    const status = (st.run && st.run.status) || "starting";
    return html`<div class="cx-runst" role="status">
      <span class="dot live"></span><span>${what} — ${status} · ${fmtDur(Date.now() - st.started)}</span>
      ${st.runId ? html`<button class="btn sm" onClick=${cancel}>Cancel</button>` : null}</div>`;
  }
  if (st.error) return html`<div class="cx-note warn">${what} did not finish: ${st.error}</div>`;
  return html`<div class="cx-runst done"><span class="dot"></span>${what} finished in ${fmtDur((st.ended || Date.now()) - st.started)}${st.fromCache ? " (cached result)" : ""}</div>`;
}

// A fixed-row-height virtual list: only the rows in view (plus a margin) are rendered, so a
// 10k-function or 50k-string list scrolls as fast as a 50-row one. `center` puts the selected
// row mid-view (a source site), `selKey` re-scrolls to an unchanged index (the same chip twice).
function VList({ items, rowH = 28, maxH = 640, render, selIdx = -1, selKey = null, center = false, onKeyDown, label,
  cls = "", role, activeId }) {
  const box = useRef(null);
  const [top, setTop] = useState(0);
  const [h, setH] = useState(maxH);
  const n = items.length;
  useEffect(() => {
    const el = box.current;
    if (!el) return undefined;
    const upd = () => setH(el.clientHeight || maxH);
    upd();
    if (typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(upd); ro.observe(el);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    const el = box.current;
    if (!el || selIdx < 0 || selIdx >= n) return;
    const y = selIdx * rowH;
    if (center) el.scrollTop = Math.max(0, y - el.clientHeight / 2 + rowH / 2);
    else if (y < el.scrollTop) el.scrollTop = y;
    else if (y + rowH > el.scrollTop + el.clientHeight) el.scrollTop = y + rowH - el.clientHeight;
  }, [selIdx, selKey, selIdx < n]);
  useEffect(() => { if (box.current && top > n * rowH) { box.current.scrollTop = 0; setTop(0); } }, [n]);
  const first = Math.max(0, Math.floor(top / rowH) - 12);
  const last = Math.min(n, Math.ceil((top + h) / rowH) + 12);
  const rows = [];
  for (let i = first; i < last; i++) rows.push(render(items[i], i));
  return html`<div class=${"cx-vlist " + cls} ref=${box} aria-label=${label} role=${role} aria-activedescendant=${activeId}
      tabindex=${onKeyDown ? "0" : undefined} onKeyDown=${onKeyDown}
      style=${`max-height:${maxH}px;height:${Math.min(maxH, n * rowH + 2)}px`}
      onScroll=${(e) => setTop(e.currentTarget.scrollTop)}>
    <div style=${`height:${n * rowH}px;position:relative`}>
      <div class="cx-vrows" style=${`position:absolute;left:0;right:0;top:${first * rowH}px`}>${rows}</div>
    </div></div>`;
}

const Empty = ({ children }) => html`<div class="panel empty">${children}</div>`;
function KV({ k, v, mono, title }) {
  if (v == null || v === "") return null;
  return html`<div class="cx-kv"><span class="k">${k}</span><span class=${"v" + (mono ? " mono" : "")} title=${title}>${v}</span></div>`;
}
function Copy({ text, label = "copy", what }) {
  const [ok, setOk] = useState(false);
  const go = () => {
    try {
      const t = typeof text === "function" ? text() : text;
      navigator.clipboard.writeText(t).then(() => { setOk(true); setTimeout(() => setOk(false), 1200); }, () => {});
    } catch (_e) { /* no clipboard in this context */ }
  };
  return html`<button class="cx-copy" onClick=${go} aria-label=${what ? `copy ${what}` : "copy"} title=${what ? `copy ${what}` : "copy"}>${ok ? "copied" : label}</button>`;
}

const VIEWS = [
  ["functions", "Functions"], ["graph", "Call graph"], ["strings", "Strings"], ["target", "Target"],
  ["source", "Source"], ["scans", "Scans"], ["diff", "Diff"], ["classes", "Classes"],
];
const HEAP_DET = new Set(["heap_trace", "heap_check"]);
const TAINT_DET = new Set(["tainted_deref", "cross_taint", "dynamic_taint"]);
const isHeap = (f) => HEAP_DET.has(f.detector) || /CWE-(122|415|416)\b/.test(f.cwe || "");
const isTaint = (f) => TAINT_DET.has(f.detector);
const isCve = (f) => f.detector === "cve_scan" || /^CVE-/i.test(f.cwe || "");

// Props: focusAddr / focusSrc ("path.c:LINE") open a site; onLocate({addr} | {src}), when given,
// is told where the operator now is so the route can carry it (reload / Back / a shared link).
export function CodeScreen({ data, targetId, focusTarget, focusAddr, focusSrc = null, openFinding, onLocate = null,
  initialView = null }) {
  // no target asked for: the one with the most (non-noise) findings, pinned once the case loaded --
  // FreeRDP opened on a 0-function harness when it took the first in the list
  const pinned = useRef(null);
  const bestTid = useMemo(() => {
    if (!data.targets.length) return null;
    if (pinned.current && data.targets.some((t) => t.id === pinned.current)) return pinned.current;
    if (data.loading) return null;
    const n = new Map();
    for (const f of data.findings) if (!isNoise(f)) n.set(f.target_id, (n.get(f.target_id) || 0) + 1);
    let best = data.targets[0].id, bn = -1;
    for (const t of data.targets) { const c = n.get(t.id) || 0; if (c > bn) { best = t.id; bn = c; } }
    pinned.current = best;
    return best;
  }, [data.targets, data.findings, data.loading]);
  const tid = targetId || bestTid;
  const target = data.targets.find((t) => t.id === tid) || null;
  const caseId = (target && target.case_id) || (data.targets[0] && data.targets[0].case_id) || null;
  const [view, setView] = useLocal("lykos.code.view", initialView || "functions");
  const [pick, setPick] = useState({ tid: null, v: null });   // a sub-view the operator chose here
  // the function list belongs to the target it was loaded for: a cross-binary jump used to be
  // resolved against the PREVIOUS target's list in the commit where the target changed
  const [fst, setFst] = useState({ tid: null, v: null });
  const funcs = fst.tid === tid ? fst.v : null;          // null = loading
  const [sel, setSel] = useState(null);                  // function id
  const [detail, setDetail] = useState(null);
  const [focus, setFocus] = useState(focusAddr || null);
  const [focusMiss, setFocusMiss] = useState(null);      // a requested address no function holds
  const [edgesSt, setEdgesSt] = useState({ tid: null, v: null });   // call graph, lazily
  const [strsSt, setStrsSt] = useState({ tid: null, v: null });     // {items,total,complete,loading,error}
  const strsRef = useRef(strsSt);
  const edgesRef = useRef(edgesSt);
  const edges = edgesSt.tid === tid ? edgesSt.v : null;
  const strs = strsSt.tid === tid ? strsSt.v : null;
  const setStrsFor = (t, v) => { strsRef.current = { tid: t, v }; setStrsSt(strsRef.current); };
  const [srcSt, setSrcSt] = useState({ tid: null, v: undefined });  // undefined = not known yet, null = none
  const source = srcSt.tid === tid ? srcSt.v : undefined;
  const [srcFocus, setSrcFocus] = useState(null);       // {path, line, n}
  const [sysmap, setSysmap] = useState(null);
  const [jumpErr, setJumpErr] = useState(null);
  const pending = useRef(null);                          // a cross-binary jump waiting for its target
  const located = useRef({ addr: focusAddr || null, src: focusSrc || null });
  const stage = useStageRuns(caseId, () => data.reload && data.reload());

  useEffect(() => {
    if (!tid) return undefined;
    let stop = false;
    setDetail(null); setSel(null); setFocusMiss(null);
    loadFuncs(tid).then((l) => { if (!stop) setFst({ tid, v: l }); }).catch(() => { if (!stop) setFst({ tid, v: [] }); });
    loadSource(tid).then((s) => { if (!stop) setSrcSt({ tid, v: s }); }).catch(() => { if (!stop) setSrcSt({ tid, v: null }); });
    return () => { stop = true; };
  }, [tid]);
  useEffect(() => {
    if (!caseId || data.targets.length < 2) { setSysmap(null); return; }
    api.systemmap(caseId).then(setSysmap).catch(() => setSysmap(null));
  }, [caseId, data.targets.length]);

  const fl = funcs || [];
  const index = useMemo(() => makeIndex(fl), [funcs]);
  const findings = useMemo(() => data.findings.filter((f) => f.target_id === tid), [data.findings, tid]);
  const byFunc = useMemo(() => {
    const m = new Map();
    for (const f of findings) {
      const fn = fnOfFinding(f, index);
      if (!fn) continue;
      if (!m.has(fn.id)) m.set(fn.id, []);
      m.get(fn.id).push(f);
    }
    return m;
  }, [findings, index]);
  const nLiveFns = useMemo(() => [...byFunc.values()].filter((fs) => live(fs).length).length, [byFunc]);

  const loadEdges = () => {
    const c = edgesRef.current;
    if (!tid || (c.tid === tid && c.v && !c.v.error)) return;
    const t = tid;
    edgesRef.current = { tid: t, v: "loading" }; setEdgesSt(edgesRef.current);
    const done = (v) => { if (edgesRef.current.tid === t) { edgesRef.current = { tid: t, v }; setEdgesSt(edgesRef.current); } };
    loadCallgraph(t).then(done, (e) => done({ error: errText(e) }));
  };
  // Strings come in 5000-row pages (the server's cap); `all` keeps paging until every one is in.
  const loadStrings = async (all) => {
    if (!tid) return;
    const t = tid;
    const cur = strsRef.current.tid === t ? strsRef.current.v : null;
    if (cur && (cur.loading || cur.complete || (!all && cur.items.length))) return;
    let items = cur ? cur.items.slice() : [], total = cur ? cur.total : null;
    setStrsFor(t, { items, total, complete: false, loading: true, error: null });
    try {
      for (;;) {
        const r = await api.strings(t, { limit: 5000, offset: items.length });
        if (strsRef.current.tid !== t) return;                     // the target changed meanwhile
        const got = (r && r.items) || asList(r);
        items = items.concat(got);
        total = r && r.total != null ? r.total : items.length;
        const more = all && got.length > 0 && items.length < total && items.length < 200000;
        setStrsFor(t, { items, total, complete: items.length >= total, loading: more, error: null });
        if (!more) break;
      }
    } catch (e) {
      if (strsRef.current.tid === t) setStrsFor(t, { items, total, complete: false, loading: false, error: errText(e) });
    }
  };

  // a requested address (from a finding / the route): open the function containing it -- unless it
  // is the address this screen itself just reported (the route echoing a selection back)
  useEffect(() => {
    if (!focusAddr || !funcs) return;
    if (located.current.addr === focusAddr && sel) return;
    located.current = { ...located.current, addr: focusAddr };
    const fn = index.at(focusAddr);
    if (fn) { setSel(fn.id); setFocus(focusAddr); setFocusMiss(null); setView("functions"); setPick({ tid, v: "functions" }); }
    else setFocusMiss(focusAddr);
  }, [focusAddr, funcs]);
  // a requested source site: open the Source view at that file and line
  useEffect(() => {
    if (!focusSrc) return;
    if (located.current.src === focusSrc && srcFocus) return;
    located.current = { ...located.current, src: focusSrc };
    const r = parseSrcRef(focusSrc);
    if (r) { setSrcFocus({ ...r, n: Date.now() }); setView("source"); setPick({ tid, v: "source" }); }
  }, [focusSrc, tid]);
  // a cross-binary jump lands once the other target's functions are in
  useEffect(() => {
    const p = pending.current;
    if (!p || !funcs || p.tid !== tid) return;
    pending.current = null;
    const fn = (p.fnId && index.byId.get(p.fnId)) || (p.addr && index.at(p.addr));
    if (fn) { setSel(fn.id); setFocus(p.addr || null); setView("functions"); }
    else setJumpErr("The jump target is not among this binary's recovered functions.");
  }, [funcs, tid]);
  // the function's detail, debounced (holding ↓ through the list fetched every row) and kept
  useEffect(() => {
    if (!sel) return undefined;
    const hit = FN_DETAIL.get(sel);
    if (hit) { setDetail(hit); return undefined; }
    let stop = false;
    setDetail(null);
    const t = setTimeout(() => {
      api.getFunction(sel).then((d) => { keepDetail(sel, d); if (!stop) setDetail(d); })
        .catch(() => { if (!stop) setDetail({ id: sel, error: true }); });
    }, 120);
    return () => { stop = true; clearTimeout(t); };
  }, [sel]);
  useEffect(() => { if (sel) loadStrings(true); }, [sel]);  // string annotations in the listing
  // tell the route where the operator is (only what changed, so the echo above is recognised)
  const selFn = sel ? index.byId.get(sel) : null;
  useEffect(() => {
    if (!onLocate || !selFn) return;
    const addr = focus || selFn.addr;
    if (located.current.addr === addr) return;
    located.current = { ...located.current, addr };
    onLocate({ addr });
  }, [sel, focus, !!selFn]);
  const locateSrc = (path, line) => {
    const src = line ? `${path}:${line}` : path;
    if (!onLocate || located.current.src === src) return;
    located.current = { ...located.current, src };
    onLocate({ src });
  };

  const goAddr = (addr) => {
    const fn = index.at(addr);
    if (fn) { setSel(fn.id); setFocus(addr); setFocusMiss(null); setView("functions"); }
    else setFocusMiss(addr);
  };
  const openFn = (id, addr = null) => { setSel(id); setFocus(addr); setView("functions"); };
  const jumpTarget = (otherTid, { fnId, addr }) => {
    setJumpErr(null);
    if (otherTid === tid) { if (fnId) openFn(fnId, addr); else goAddr(addr); return; }
    pending.current = { tid: otherTid, fnId, addr };
    focusTarget(otherTid);
  };
  // Cross-binary: an import here that another component of the case exports
  const resolveImport = async (name) => {
    setJumpErr(null);
    const want = bare(name);
    const e = ((sysmap && sysmap.edges) || []).find((x) => x.src === tid
      && (x.symbols || (x.symbol ? [x.symbol] : [])).some((s) => bare(s) === want));
    if (!e) return;
    try {
      const fns = await loadFuncs(e.dst);
      const m = fns.find((f) => bare(f.name) === want && !isStub(f)) || fns.find((f) => bare(f.name) === want);
      if (!m) { setJumpErr(`${want} is exported by another component, but no function of that name was recovered there.`); return; }
      jumpTarget(e.dst, { fnId: m.id });
    } catch (err) { setJumpErr(errText(err)); }
  };
  const followCaller = async (xc) => {
    setJumpErr(null);
    try {
      const cg = await loadCallgraph(xc.targetId);
      const edge = cg.find((x) => bare(x.dst_name) === xc.symbol);
      const idx = makeIndex(await loadFuncs(xc.targetId));
      const caller = edge ? idx.at(edge.src_addr) : null;
      if (!caller) { setJumpErr(`Could not locate the function in ${xc.filename} that calls ${xc.symbol}.`); return; }
      jumpTarget(xc.targetId, { fnId: caller.id, addr: edge.site_addr });
    } catch (err) { setJumpErr(errText(err)); }
  };

  // instruction address -> the string it references, from the strings' own xrefs (rizin prints
  // `lea rcx, str.GIFVER`, never the string's address, so keying on operands annotated 1 line)
  const strByIns = useMemo(() => {
    if (!strs || !strs.items.length) return null;
    const m = new Map();
    for (const s of strs.items) for (const x of (Array.isArray(s.xrefs) ? s.xrefs : [])) {
      const a = hexToInt(typeof x === "object" && x ? (x.from || x.addr || x.src_addr || x.site_addr) : x);
      if (a != null && !m.has(a)) m.set(a, s.value);
    }
    return m.size ? m : null;
  }, [strs]);
  const classes = useMemo(() => ({ heap: findings.filter(isHeap), taint: findings.filter(isTaint), cve: findings.filter(isCve) }), [findings]);
  const nClasses = classes.heap.length + classes.taint.length + classes.cve.length;
  const patchLeads = findings.filter((f) => f.detector === "patch_diff");
  const avail = { source: !!source, classes: nClasses > 0 };
  const views = VIEWS.filter(([k]) => avail[k] !== false);
  // a source project with no recovered functions opens on its source, unless the operator chose
  const preferSrc = !!source && funcs != null && !funcs.length && pick.tid !== tid;
  const want = preferSrc && (view === "functions" || view === "graph" || view === "strings") ? "source" : view;
  const cur = views.some(([k]) => k === want) ? want : "functions";
  const choose = (k) => { setView(k); setPick({ tid, v: k }); };
  useEffect(() => { if (cur === "graph") loadEdges(); if (cur === "strings") loadStrings(false); }, [cur, tid]);

  if (!tid) {
    return html`<h1>Code</h1><${Empty}>${data.loading ? "Loading the case…" : "No target in this case yet."}</${Empty}>`;
  }

  let body;
  if (cur === "functions") {
    body = html`<${FunctionsView} funcs=${funcs} index=${index} byFunc=${byFunc} sel=${sel} detail=${detail && detail.id === sel ? detail : null}
      focus=${focus} setSel=${(id) => { setSel(id); setFocus(null); }} goAddr=${goAddr} setFocus=${setFocus} openFinding=${openFinding}
      target=${target} targets=${data.targets} strByIns=${strByIns} sysmap=${sysmap}
      resolveImport=${resolveImport} followCaller=${followCaller} hasSource=${!!source} openSource=${() => choose("source")}
      openGraph=${() => choose("graph")} stage=${stage} tid=${tid} findings=${findings} />`;
  } else if (cur === "graph") {
    body = html`<${CallGraphView} funcs=${funcs} edges=${edges} index=${index} byFunc=${byFunc} sel=${sel}
      openFn=${openFn} retry=${loadEdges} key=${tid} />`;
  } else if (cur === "strings") {
    body = html`<${StringsView} strs=${strs} loadAll=${() => loadStrings(true)} index=${index} goAddr=${goAddr}
      funcsLoaded=${!!funcs} />`;
  } else if (cur === "target") {
    body = html`<${TargetView} target=${target} caseId=${caseId} nFuncs=${funcs ? funcs.length : null} key=${tid} />`;
  } else if (cur === "source") {
    body = html`<${SourceView} tid=${tid} source=${source} findings=${findings} openFinding=${openFinding}
      focus=${srcFocus} locate=${locateSrc} key=${tid} />`;
  } else if (cur === "scans") {
    body = html`<${ScansView} targets=${data.targets} tid=${tid} caseId=${caseId} stage=${stage} findings=${findings}
      allFindings=${data.findings} hasSource=${!!source} />`;
  } else if (cur === "diff") {
    body = html`<${DiffView} targets=${data.targets} tid=${tid} findings=${data.findings} stage=${stage}
      patchLeads=${patchLeads} index=${index} openFn=${openFn} openFinding=${openFinding} />`;
  } else {
    body = html`<${ClassesView} classes=${classes} index=${index} openFn=${openFn} openFinding=${openFinding} />`;
  }

  const counts = funcs == null ? "loading functions…"
    : !funcs.length && source && source.kind === "tree" ? `${plural(source.files.length, "source file")} · ${plural(live(findings).length, "finding")}`
    : `${plural(funcs.length, "function")} · ${nLiveFns} with findings`;
  return html`
    <div class="cx-head">
      <h1>Code</h1>
      <select value=${tid || ""} aria-label="Target" onChange=${(e) => focusTarget(e.target.value)}>
        ${data.targets.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}
      </select>
      <span class="dim" style="font-size:12px">${counts}</span>
    </div>
    <div class="seg cx-nav" role="tablist" aria-label="Code views">
      ${views.map(([k, l]) => html`<button role="tab" aria-selected=${cur === k} class=${cur === k ? "on" : ""}
        onClick=${() => choose(k)}>${l}${k === "classes" ? html` <span class="dim">${nClasses}</span>`
          : k === "diff" && patchLeads.length ? html` <span class="dim">${patchLeads.length}</span>` : null}</button>`)}
    </div>
    ${jumpErr ? html`<div class="cx-note warn">${jumpErr} <button class="xref" onClick=${() => setJumpErr(null)}>dismiss</button></div>` : null}
    ${focusMiss && cur === "functions" ? html`<div class="cx-note warn"><span class="mono">${focusMiss}</span> is not inside any recovered function of this target${funcs && !funcs.length ? " (no functions were recovered)" : ""}. <button class="xref" onClick=${() => setFocusMiss(null)}>dismiss</button></div>` : null}
    ${body}`;
}

// ── Functions ────────────────────────────────────────────────────────────────────────────
const SORTS = [["findings", "Findings first"], ["addr", "Address"], ["size", "Size"], ["name", "Name"]];
const HEXQ = /^(0x)?[0-9a-f]{3,16}$/i;
function FunctionsView(p) {
  const { funcs, index, byFunc, sel, detail, setSel, goAddr, stage, tid } = p;
  const [q, setQ] = useState("");
  const [only, setOnly] = useState(false);
  const [stubs, setStubs] = useState(true);
  const [sort, setSort] = useLocal("lykos.code.sort", "findings");
  const nLive = (id) => live(byFunc.get(id)).length;
  const shown = useMemo(() => {
    const qq = q.trim().toLowerCase();
    const xs = (funcs || []).filter((f) => (!only || nLive(f.id)) && (stubs || !isStub(f))
      && (!qq || (f.name || "").toLowerCase().includes(qq) || (f.addr || "").toLowerCase().includes(qq)));
    const a = (f) => hexToInt(f.addr) || 0;
    const cmp = {
      findings: (x, y) => (nLive(y.id) - nLive(x.id)) || ((+y.size || 0) - (+x.size || 0)),
      addr: (x, y) => a(x) - a(y),
      size: (x, y) => (+y.size || 0) - (+x.size || 0),
      name: (x, y) => (x.name || "").localeCompare(y.name || ""),
    }[sort] || (() => 0);
    return xs.sort(cmp);
  }, [funcs, q, only, stubs, sort, byFunc]);
  // an address typed into the filter: the function that CONTAINS it (substring matching found
  // nothing for an address inside a function)
  const qt = q.trim();
  const addrHit = HEXQ.test(qt) && funcs ? index.at(qt.startsWith("0x") || qt.startsWith("0X") ? qt : "0x" + qt) : null;
  const selIdx = shown.findIndex((f) => f.id === sel);
  const onKey = (e) => {
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 }[e.key];
    if (step == null && e.key !== "Home" && e.key !== "End") return;
    e.preventDefault();
    if (!shown.length) return;
    const i = e.key === "Home" ? 0 : e.key === "End" ? shown.length - 1
      : Math.min(shown.length - 1, Math.max(0, (selIdx < 0 ? -1 : selIdx) + step));
    setSel(shown[i].id);
  };
  const h = stage.runs.harness;
  return html`
    <div class="code">
      <section class="panel flist">
        <div class="pad" style="display:flex;flex-direction:column;gap:8px;padding-bottom:10px">
          <input type="text" placeholder="filter by name, or go to an address" aria-label="Filter functions or go to an address" value=${q}
            onInput=${(e) => setQ(e.target.value)}
            onKeyDown=${(e) => { if (e.key === "Enter" && addrHit) goAddr(qt.toLowerCase().startsWith("0x") ? qt : "0x" + qt); }} />
          ${addrHit ? html`<button class="xref cx-goto" onClick=${() => goAddr(qt.toLowerCase().startsWith("0x") ? qt : "0x" + qt)}>
            ↵ go to ${qt.toLowerCase().startsWith("0x") ? qt : "0x" + qt} in ${addrHit.name}</button>` : null}
          <div class="row-c" style="flex-wrap:wrap;gap:6px 12px">
            <label class="cx-chk"><input type="checkbox" checked=${only} onChange=${(e) => setOnly(e.target.checked)} />with findings</label>
            <label class="cx-chk" title="import / PLT thunks and empty functions"><input type="checkbox" checked=${stubs} onChange=${(e) => setStubs(e.target.checked)} />import stubs</label>
            <select value=${sort} aria-label="Sort functions" onChange=${(e) => setSort(e.target.value)} style="padding:3px 6px;font-size:12px">
              ${SORTS.map(([k, l]) => html`<option value=${k}>${l}</option>`)}</select>
          </div>
          <span class="dim" style="font-size:11.5px">${funcs == null ? "loading…" : `${shown.length} of ${funcs.length}`} · ↑↓ PgUp PgDn to move</span>
        </div>
        ${funcs == null ? html`<div class="dim pad">Loading functions…</div>`
          : !funcs.length ? html`<div class="dim pad" style="font-size:12.5px">No functions were recovered for this target — the disassemble stage has not run on it, or recovered nothing.${p.hasSource ? html` <button class="xref" onClick=${p.openSource}>Read its source</button>` : null}</div>`
          : !shown.length ? html`<div class="dim pad" style="font-size:12.5px">No function matches.</div>`
          : html`<${VList} items=${shown} rowH=${30} maxH=${620} selIdx=${selIdx} onKeyDown=${onKey} label="Functions"
              role="listbox" activeId=${sel ? "cx-fn-" + sel : undefined}
              render=${(f) => {
                const all = byFunc.get(f.id) || [], n = live(all).length;
                return html`<button key=${f.id} id=${"cx-fn-" + f.id} role="option" aria-selected=${sel === f.id ? "true" : "false"}
                  class=${"fitem cx-frow" + (sel === f.id ? " on" : "") + (isStub(f) ? " stub" : "")}
                  tabindex="-1" onClick=${() => setSel(f.id)} title=${f.signature || f.name}>
                <span class="nm">${f.name || f.addr}</span>
                ${n ? html`<span class="lvl amber cx-n">${n}</span>`
                  : all.length ? html`<span class="cx-n dim" title="only findings flagged as noise">${all.length}</span>` : null}
                <span class="dim">${f.addr}</span></button>`;
              }} />`}
        <div class="pad cx-harness">
          <button class="btn sm" disabled=${!tid || (h && h.running)}
            title="Rank this binary's functions and fuzz the most promising ones directly under the emulator (constant-guided inputs, an unbounded-allocation oracle, stateful sequences). Operator-initiated, bounded; not part of a normal run. x86-64, after disassembly."
            onClick=${() => stage.start("harness", "harness", { targetId: tid, params: {} })}>
            Deep function fuzzing</button>
          <${RunStatus} st=${h} what="Deep function fuzzing" cancel=${() => stage.cancel("harness")} />
          ${h && !h.running && !h.error ? html`<div class="dim" style="font-size:12px">${(() => {
            const r = h.data || {};
            const n = p.findings.filter((f) => f.detector === "harness").length;
            if (r.supported === false) return `declined — ${r.note || "not applicable to this target"}`;
            if (n) return `${plural(n, "function-level finding")} on this target`;
            if (r.note) return r.note;
            return `0 faults${r.functions != null ? ` — ${plural(r.functions, "function")} driven` : ""}`;
          })()}</div>` : null}
        </div>
      </section>
      <div class="fview">
        ${!sel ? html`<${Empty}>Pick a function. ${byFunc.size ? "Functions with findings are listed first." : ""}</${Empty}>`
          : !detail ? html`<${Empty}>Loading…</${Empty}>`
          : detail.error ? html`<${Empty}>Could not load this function.</${Empty}>`
          : html`<${FunctionView} ...${p} key=${detail.id} fn=${detail} findings=${byFunc.get(sel) || []} index=${index} />`}
      </div>
    </div>`;
}

const BRANCH = /^\s*(call|jmp|j[a-z]{1,4}|bl?x?|bl?r|b\.[a-z]{2}|b[a-z]{2,3}|jalr?|cbn?z|tbn?z)\b/i;
const CAP = 6000;

function FunctionView({ fn, findings, focus, goAddr, setFocus, openFinding, index, target, targets, strByIns, sysmap,
  resolveImport, followCaller, openGraph, tid }) {
  const dec = usableDecompile(fn.decompiled);
  const frame = parseMaybe(fn.frame) || null;
  const hasFrame = !!(frame && ((frame.vars && frame.vars.length) || (frame.params && frame.params.length) || frame.frame_size));
  const [tab, setTab] = useState("asm");
  const box = useRef(null);
  const ir = parseMaybe(fn.ir) || {};
  const blocks = ir.blocks || [];
  const callers = parseMaybe(fn.callers) || [];
  const callees = parseMaybe(fn.callees) || [];
  const nIns = blocks.reduce((n, b) => n + (b.instructions || []).length, 0);
  const sites = useMemo(() => {
    const m = new Map();
    for (const f of findings) { const a = hexToInt(f.site_addr); if (a != null) { if (!m.has(a)) m.set(a, []); m.get(a).push(f); } }
    return m;
  }, [findings]);
  // the instruction holding the focused address (a typed / reported address may fall mid-instruction)
  const focusInt = useMemo(() => {
    const f = hexToInt(focus);
    if (f == null) return null;
    let best = null;
    for (const b of blocks) for (const i of b.instructions || []) { const a = hexToInt(i.addr); if (a != null && a <= f && (best == null || a > best)) best = a; }
    return best != null && f - best < 16 ? best : f;
  }, [fn.id, focus]);
  // where the listing must reach: the focused instruction, else the first finding site. Beyond
  // the CAP-instruction first render it was never drawn, so nothing was highlighted.
  const needIdx = useMemo(() => {
    let k = 0, firstSite = -1;
    for (const b of blocks) for (const i of b.instructions || []) {
      const a = hexToInt(i.addr);
      if (focusInt != null && a === focusInt) return k;
      if (firstSite < 0 && sites.has(a)) firstSite = k;
      k++;
    }
    return firstSite;
  }, [fn.id, focusInt, sites]);
  const [all, setAll] = useState(needIdx >= CAP);
  useEffect(() => { if (needIdx >= CAP) setAll(true); }, [needIdx]);
  // scroll the LISTING only (scrollIntoView also scrolled the page, pushing the header and xrefs away)
  useEffect(() => {
    if (tab !== "asm") return;
    const c = box.current;
    const el = c && (c.querySelector(".ins.focus") || c.querySelector(".ins.site"));
    if (!el) return;
    c.scrollTop += el.getBoundingClientRect().top - c.getBoundingClientRect().top - c.clientHeight / 2;
  }, [fn.id, focus, tab, all]);
  useEffect(() => { if (focusInt != null) setTab("asm"); }, [focus]);
  const uniq = (xs, k) => [...new Map(xs.map((x) => [x[k], x])).values()];
  const ups = uniq(callers, "src_addr");
  const downsU = uniq(callees.map((e) => ({ ...e, _k: e.dst_addr || e.dst_name })), "_k");
  const nameAt = (a) => { const f = index.starts.get(hexToInt(a)) || index.at(a); return f ? f.name : null; };
  const multi = targets.length > 1 && sysmap && (sysmap.edges || []).length;
  const exportedBy = (name) => {
    if (!multi) return null;
    const want = bare(name);
    const e = sysmap.edges.find((x) => x.src === tid && (x.symbols || (x.symbol ? [x.symbol] : [])).some((s) => bare(s) === want));
    return e ? (targets.find((t) => t.id === e.dst) || {}).filename || "another component" : null;
  };
  const xbin = useMemo(() => {
    if (!multi) return [];
    const want = bare(fn.name);
    return sysmap.edges.filter((e) => e.dst === tid && (e.symbols || (e.symbol ? [e.symbol] : [])).some((s) => bare(s) === want))
      .map((e) => ({ targetId: e.src, filename: (targets.find((t) => t.id === e.src) || {}).filename || "other", symbol: want }));
  }, [fn.id, sysmap, tid, targets]);

  // Operands that name a function become links. A non-branch operand links only when it is
  // EXACTLY a function start (`lea rdi, [0x8d9a]` -> main): `[rbp-0x2054]` and `cmp eax, 0x7fff`
  // used to link into whatever function happened to span that number.
  const renderText = (text, selfStart) => {
    const parts = [];
    let last = 0, m;
    const branch = BRANCH.test(text);
    const re = /\b(0x[0-9a-fA-F]{3,}|fcn\.[0-9a-fA-F]{4,}|sub_[0-9a-fA-F]{4,})\b/g;
    while ((m = re.exec(text))) {
      const tok = m[1];
      if (/[-+]\s*$/.test(text.slice(Math.max(0, m.index - 3), m.index))) continue;     // a displacement
      const a = tok.startsWith("0x") ? parseInt(tok, 16) : parseInt(tok.replace(/^(fcn\.|sub_)/, ""), 16);
      const f = index.starts.get(a) || (branch ? index.at(a) : null);
      if (!f) continue;
      parts.push(text.slice(last, m.index));
      const local = hexToInt(f.addr) === selfStart;
      parts.push(html`<button class="xref cx-op" title=${local ? "jump within this function" : `open ${f.name}`}
        onClick=${() => goAddr(a)}>${tok}</button>`);
      last = m.index + tok.length;
    }
    parts.push(text.slice(last));
    return parts;
  };
  const selfStart = hexToInt(fn.addr);
  const listingText = () => blocks.map((b) => `${b.addr}:\n` + (b.instructions || []).map((i) => `  ${i.addr}  ${i.text || ""}`).join("\n")).join("\n");
  // a chip scrolls to its site in the listing; "open" opens the finding
  const toSite = (f) => {
    if (f.site_addr && hexToInt(f.site_addr) != null) { setTab("asm"); setFocus(f.site_addr); } else openFinding(f.id);
  };
  let shownIns = 0;

  return html`
    <section class="panel pad" style="display:flex;flex-direction:column;gap:6px">
      <div class="row-c" style="flex-wrap:wrap"><h2 class="mono" style="word-break:break-all">${fn.name}</h2>
        <${Copy} text=${fn.name} what="function name" />
        <span class="mono dim" style="font-size:12px">${[fn.addr, fn.size != null ? `${fn.size} bytes` : null,
          fn.blocks != null ? plural(fn.blocks, "block") : null, nIns ? plural(nIns, "instruction") : null].filter(Boolean).join(" · ")}</span>
        <${Copy} text=${fn.addr} what="address" />
        <span style="flex:1 1 auto"></span>
        <button class="btn sm" onClick=${openGraph}>Show in call graph</button></div>
      ${fn.signature ? html`<span class="mono muted" style="font-size:12px;word-break:break-word">${fn.signature}</span>` : null}
      ${findings.length ? html`<div class="row-c" style="flex-wrap:wrap;margin-top:4px">
        ${findings.map((f) => html`<span class=${"cx-fchipw" + (isNoise(f) ? " noise" : "")}>
          <button class="chip cx-fchip" onClick=${() => toSite(f)}
            title=${(f.site_addr ? "show the site in the listing — " : "") + (f.title || "") + (isNoise(f) ? " (flagged as noise)" : "")}>
            ${f.cwe} · ${f.state} @ ${f.site_addr || "fn"}</button>
          <button class="xref cx-fopen" onClick=${() => openFinding(f.id)} aria-label=${`open finding: ${f.title || f.cwe}`}>open</button></span>`)}</div>` : null}
    </section>
    <div class="row-c" style="flex-wrap:wrap;align-items:flex-start">
      <section class="panel pad cx-xr">
        <div class="cx-lbl">CALLED FROM (${ups.length})</div>
        ${!ups.length ? html`<div class="dim" style="font-size:12px">no recovered caller — an entry point, or reached indirectly</div>` : null}
        ${ups.slice(0, 40).map((e) => html`<div class="cx-xrow"><button class="xref" onClick=${() => goAddr(e.site_addr || e.src_addr)}
            title="open the caller at its call site">${nameAt(e.src_addr) || e.src_addr}</button>
          <span class="mono dim" style="font-size:11px">at ${e.site_addr}</span></div>`)}
        ${ups.length > 40 ? html`<div class="dim" style="font-size:11.5px">+${ups.length - 40} more — see the call graph</div>` : null}
        ${xbin.length ? html`<div class="cx-lbl" style="margin-top:8px">REACHED FROM ANOTHER BINARY</div>
          ${xbin.map((xc) => html`<div><button class="xref" onClick=${() => followCaller(xc)}
            title=${`follow ${xc.symbol} back into ${xc.filename}`}>${xc.filename} → ${xc.symbol}()</button></div>`)}` : null}
      </section>
      <section class="panel pad cx-xr">
        <div class="cx-lbl">CALLS (${downsU.length})</div>
        ${!downsU.length ? html`<div class="dim" style="font-size:12px">leaf — calls nothing recovered</div>` : null}
        ${downsU.slice(0, 50).map((e) => {
          // an import resolves to its 6-byte PLT thunk, which is not where it is defined: offer the
          // component that exports it instead (it never was offered while the thunk counted as internal)
          const internal = !e.external && e.dst_addr && index.at(e.dst_addr);
          const xb = !internal && e.dst_name ? exportedBy(e.dst_name) : null;
          return html`<div class="cx-xrow">
            ${internal ? html`<button class="xref" onClick=${() => goAddr(e.dst_addr)}>${e.dst_name || nameAt(e.dst_addr) || e.dst_addr}</button>`
              : xb ? html`<button class="xref" onClick=${() => resolveImport(e.dst_name)} title=${`defined in ${xb}`}>${e.dst_name}</button>`
              : html`<span class="mono muted" style="font-size:12px">${e.dst_name || e.dst_addr || "indirect"}</span>`}
            ${e.external ? html`<span class="dim" style="font-size:11px">import${xb ? ` · in ${xb}` : ""}</span>` : null}
            ${e.site_addr ? html`<button class="xref dim" style="font-size:11px;color:var(--tx3)" onClick=${() => goAddr(e.site_addr)}>at ${e.site_addr}</button>` : null}</div>`;
        })}
        ${downsU.length > 50 ? html`<div class="dim" style="font-size:11.5px">+${downsU.length - 50} more — see the call graph</div>` : null}
      </section>
    </div>
    <div class="row-c" style="flex-wrap:wrap">
      <div class="seg" role="tablist" aria-label="Function view">
        <button role="tab" aria-selected=${tab === "asm"} class=${tab === "asm" ? "on" : ""} onClick=${() => setTab("asm")}>Disassembly</button>
        <button role="tab" aria-selected=${tab === "src"} class=${tab === "src" ? "on" : ""} onClick=${() => setTab("src")} disabled=${!dec}
          title=${dec ? "" : "the decompiler produced no usable C for this function"}>Decompiled</button>
        <button role="tab" aria-selected=${tab === "frame"} class=${tab === "frame" ? "on" : ""} onClick=${() => setTab("frame")} disabled=${!hasFrame}
          title=${hasFrame ? "" : "no stack frame was recovered for this function"}>Stack frame</button>
      </div>
      <span style="flex:1 1 auto"></span>
      ${tab === "asm" && blocks.length ? html`<${Copy} text=${listingText} label="copy listing" what="the disassembly listing" />` : null}
      ${tab === "src" && dec ? html`<${Copy} text=${fn.decompiled} label="copy C" what="the decompiled C" />` : null}
    </div>
    ${tab === "src" && dec ? html`<pre class="asm" style="padding:12px 14px;margin:0;white-space:pre-wrap">${fn.decompiled}</pre>`
      : tab === "frame" && hasFrame ? html`<${StackFrame} frame=${frame} />`
      : html`<div class="asm" ref=${box}>
        ${blocks.length ? blocks.map((b) => {
          if (!all && shownIns >= CAP) return null;
          return html`<div>
          <div class="bb">${b.addr}:${b.succ && b.succ.length ? html`<span class="cx-succ"> → ${b.succ.join(", ")}</span>` : null}</div>
          ${(b.instructions || []).map((i) => {
            if (!all && shownIns >= CAP) return null;
            shownIns++;
            const a = hexToInt(i.addr);
            const fs = sites.get(a);
            const allNoise = fs && fs.every(isNoise);
            const note = strByIns ? strByIns.get(a) : null;
            const cls = "ins" + (fs ? " site" + (allNoise ? " noise" : "") : "") + (focusInt != null && a === focusInt ? " focus" : "");
            return html`<div class=${cls}><span class="a">${i.addr}</span><span class="cx-t">${renderText(String(i.text || ""), selfStart)}${note != null ? html`<span class="cx-str"> ; "${note.length > 60 ? note.slice(0, 59) + "…" : note}"</span>` : null}</span>
              ${fs ? html`<button class="xref cx-site" onClick=${() => openFinding(fs[0].id)} title=${fs.map((f) => f.title).join("\n")}>◂ ${fs[0].cwe} ${fs[0].state}${fs.length > 1 ? ` +${fs.length - 1}` : ""}</button>` : null}</div>`;
          })}</div>`;
        }) : html`<div class="dim" style="padding:12px 14px">No instruction listing recovered for this function.</div>`}
        ${!all && nIns > CAP ? html`<div style="padding:8px 14px"><button class="btn sm" onClick=${() => setAll(true)}>
          Show all ${nIns} instructions (${nIns - CAP} more)</button></div>` : null}
      </div>`}`;
}

// The recovered stack frame as a memory diagram, highest offset first. Offsets are shown in the
// decompiler's own frame coordinates exactly as recovered (rizin numbers from the frame pointer,
// Ghidra from the return slot -- `coords` / ret_offset say which); no return-address distance
// is claimed here, because that conversion is the PoC engine's job and it checks it.
function StackFrame({ frame }) {
  const vars = (frame.vars || []).slice().sort((a, b) => (b.offset || 0) - (a.offset || 0));
  const params = frame.params || [];
  const maxSz = Math.max(8, ...vars.map((v) => +v.size || 0));
  const rows = [];
  for (let i = 0; i < vars.length; i++) {
    const v = vars[i];
    rows.push({ v });
    const nx = vars[i + 1];
    if (nx && v.offset != null && nx.offset != null && nx.size != null) {
      const gap = v.offset - (nx.offset + nx.size);
      if (gap > 0) rows.push({ gap, at: nx.offset + nx.size });
    }
  }
  const nbuf = vars.filter((v) => v.is_buffer).length;
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <div class="row-c" style="flex-wrap:wrap;gap:6px 16px">
      <${KV} k="frame size" v=${frame.frame_size != null ? `${frame.frame_size} B` : null} />
      <${KV} k="locals" v=${frame.local_size != null ? `${frame.local_size} B` : null} />
      <${KV} k="params" v=${frame.param_size ? `${frame.param_size} B` : null} />
      <${KV} k="ret_offset" v=${frame.ret_offset != null ? String(frame.ret_offset) : null} mono=${true} />
      <${KV} k="offsets from" v=${frame.coords === "fp" ? "frame pointer" : frame.coords || null} />
      ${nbuf ? html`<span class="chip cx-amb">${plural(nbuf, "buffer")}</span>` : null}
    </div>
    <div class="cx-stack" role="table" aria-label="Stack frame">
      <div class="cx-srow head" role="row"><span>offset</span><span>name</span><span>type</span><span>size</span><span></span></div>
      ${rows.map((r) => r.gap ? html`<div class="cx-srow gap" role="row"><span class="mono">${hx(r.at)}</span>
          <span class="dim">— ${r.gap} B unaccounted —</span><span></span><span class="mono dim">${r.gap}</span><span></span></div>`
        : html`<div class=${"cx-srow" + (r.v.is_buffer ? " buf" : "")} role="row">
          <span class="mono">${hx(r.v.offset)}</span>
          <span class="mono" style="word-break:break-all">${r.v.name}</span>
          <span class="mono dim">${r.v.type || ""}</span>
          <span class="mono">${r.v.size != null ? r.v.size : "?"}</span>
          <span class="cx-bar"><i style=${`width:${Math.max(3, Math.round(100 * (+r.v.size || 0) / maxSz))}%`}></i>
            ${r.v.is_buffer ? html`<b>${r.v.buffer_inferred ? "buffer (inferred)" : "buffer"}${r.v.offset < 0 ? ` · ${-r.v.offset} B below offset 0` : ""}</b>` : null}</span>
        </div>`)}
      ${!vars.length ? html`<div class="dim" style="padding:6px 0;font-size:12.5px">No stack variables recovered.</div>` : null}
    </div>
    ${params.length ? html`<div><div class="cx-lbl">PARAMETERS</div>
      ${params.map((x) => html`<div class="mono" style="font-size:12px">${x.name || "?"}${x.type ? `: ${x.type}` : ""}${x.reg ? ` (${x.reg})` : ""}${x.offset != null ? ` @ ${hx(x.offset)}` : ""}</div>`)}</div>` : null}
  </section>`;
}

// ── Call graph ───────────────────────────────────────────────────────────────────────────
const NODE_W = 150, NODE_H = 34, COL_W = 172, ROW_H = 74, PER_ROW = 10, CAP_NODES = 140;

function buildGraph(edges, index) {
  const out = new Map(), inn = new Map(), ext = new Map();
  const add = (m, a, b) => { let s = m.get(a); if (!s) { s = new Set(); m.set(a, s); } s.add(b); };
  for (const e of edges) {
    const s = index.starts.get(hexToInt(e.src_addr)) || index.at(e.src_addr);
    if (!s) continue;
    let dk = null;
    // an import is an import node, not its PLT thunk (every one resolved to the thunk, so the
    // "imports" toggle did nothing and libc calls ate the node budget)
    if (e.external) {
      const nm = e.dst_name || e.dst_addr;
      if (nm) { dk = "x:" + nm; ext.set(dk, bare(String(nm))); }
    } else if (e.dst_addr != null) {
      const d = index.starts.get(hexToInt(e.dst_addr)) || index.at(e.dst_addr);
      if (d) dk = d.id;
    }
    if (!dk && e.dst_name) { dk = "x:" + e.dst_name; ext.set(dk, e.dst_name); }
    if (!dk || dk === s.id) continue;
    add(out, s.id, dk);
    add(inn, dk, s.id);
  }
  return { out, inn, ext };
}

function neighbourhood(g, center, hops, showExt) {
  const layer = new Map([[center, 0]]);
  let cut = 0;
  const walk = (adj, sign, budget) => {
    let q = [center], used = 0;
    for (let d = 1; d <= hops && q.length; d++) {
      const next = [];
      for (const n of q) {
        for (const m of adj.get(n) || []) {
          if (layer.has(m)) continue;
          if (m.startsWith("x:") && !showExt) continue;
          if (used >= budget) { cut++; continue; }
          layer.set(m, sign * d); used++;
          if (!m.startsWith("x:")) next.push(m);
        }
      }
      q = next;
    }
    return used;
  };
  const upUsed = walk(g.inn, -1, Math.floor(CAP_NODES * 0.45));
  walk(g.out, 1, CAP_NODES - 1 - upUsed);
  const E = [];
  for (const [n] of layer) for (const m of g.out.get(n) || []) if (layer.has(m)) E.push([n, m]);
  return { layer, E, cut };
}

function layout(layerMap, E) {
  const byLayer = new Map();
  for (const [n, d] of layerMap) { if (!byLayer.has(d)) byLayer.set(d, []); byLayer.get(d).push(n); }
  const pred = new Map(), succ = new Map();
  for (const [a, b] of E) {
    if (!pred.has(b)) pred.set(b, []); pred.get(b).push(a);
    if (!succ.has(a)) succ.set(a, []); succ.get(a).push(b);
  }
  const x = new Map();
  const place = (d, order) => {
    const k = Math.min(order.length, PER_ROW);
    order.forEach((n, i) => x.set(n, ((i % PER_ROW) - (k - 1) / 2) * COL_W));
    byLayer.set(d, order);
  };
  const bary = (n, nbr) => {
    const xs = (nbr.get(n) || []).map((m) => x.get(m)).filter((v) => v != null);
    return xs.length ? xs.reduce((s, v) => s + v, 0) / xs.length : 0;
  };
  place(0, byLayer.get(0) || []);
  const ds = [...byLayer.keys()];
  for (const d of ds.filter((v) => v > 0).sort((a, b) => a - b)) place(d, byLayer.get(d).slice().sort((a, b) => bary(a, pred) - bary(b, pred)));
  for (const d of ds.filter((v) => v < 0).sort((a, b) => b - a)) place(d, byLayer.get(d).slice().sort((a, b) => bary(a, succ) - bary(b, succ)));
  const pos = new Map();
  let y = 0;
  for (const d of [...byLayer.keys()].sort((a, b) => a - b)) {
    const ns = byLayer.get(d);
    ns.forEach((n, i) => pos.set(n, { x: x.get(n), y: y + Math.floor(i / PER_ROW) * ROW_H, d }));
    y += Math.ceil(ns.length / PER_ROW) * ROW_H + 26;
  }
  return pos;
}

function CallGraphView({ funcs, edges, index, byFunc, sel, openFn, retry }) {
  const [hops, setHops] = useLocal("lykos.code.hops", 2);
  const [showExt, setShowExt] = useLocal("lykos.code.imports", false);
  const [clickMode, setClickMode] = useLocal("lykos.code.click", "open");
  const [center, setCenter] = useState(sel);
  const [q, setQ] = useState("");
  const [hover, setHover] = useState(null);
  const [tf, setTf] = useState({ x: 0, y: 0, k: 1 });
  const svg = useRef(null);
  const drag = useRef(null);
  useEffect(() => { if (sel) setCenter(sel); }, [sel]);
  const ready = Array.isArray(edges) && funcs;
  const g = useMemo(() => (ready ? buildGraph(edges, index) : null), [edges, index]);
  const fallback = useMemo(() => {
    if (!funcs || !funcs.length) return null;
    let best = null, bn = 0;
    for (const [id, fs] of byFunc) { const n = live(fs).length; if (n > bn) { best = id; bn = n; } }
    if (best) return best;
    const m = funcs.find((f) => /^(sym\.)?main$|^entry0?$/.test(f.name || ""));
    return (m || funcs.slice().sort((a, b) => (+b.size || 0) - (+a.size || 0))[0]).id;
  }, [funcs, byFunc]);
  const c = (center && index.byId.has(center)) ? center : fallback;
  const hood = useMemo(() => (g && c ? neighbourhood(g, c, hops, showExt) : null), [g, c, hops, showExt]);
  const pos = useMemo(() => (hood ? layout(hood.layer, hood.E) : null), [hood]);

  // all=true (the Fit button): everything in view at any zoom. Automatic: everything if that stays
  // legible, else a readable zoom centred on the focused function.
  const fit = (all = false) => {
    const el = svg.current;
    if (!el || !pos || !pos.size) return;
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    for (const p of pos.values()) { x0 = Math.min(x0, p.x - NODE_W / 2); x1 = Math.max(x1, p.x + NODE_W / 2); y0 = Math.min(y0, p.y); y1 = Math.max(y1, p.y + NODE_H); }
    const w = el.clientWidth || 800, h = el.clientHeight || 540, pad = 40;
    const kf = Math.min(1.2, Math.min((w - pad) / (x1 - x0 || 1), (h - pad) / (y1 - y0 || 1)));
    if (all || kf >= 0.62) {
      const k = Math.max(0.1, kf);
      setTf({ k, x: w / 2 - k * (x0 + x1) / 2, y: h / 2 - k * (y0 + y1) / 2 });
      return;
    }
    const k = 0.75, cp = pos.get(c) || { x: 0, y: 0 };
    setTf({ k, x: w / 2 - k * cp.x, y: h * 0.38 - k * (cp.y + NODE_H / 2) });
  };
  useEffect(() => { fit(); }, [pos]);

  if (edges && edges.error) {
    return html`<${Empty}>Could not load the call graph: ${edges.error} <button class="btn sm" onClick=${retry}>Retry</button></${Empty}>`;
  }
  if (edges === "loading" || edges == null || funcs == null) return html`<${Empty}>Loading the call graph…</${Empty}>`;
  if (!edges.length) return html`<${Empty}>No call edges were recovered for this target (the disassemble stage has not run, or found no calls).</${Empty}>`;
  if (!c) return html`<${Empty}>No functions to draw.</${Empty}>`;

  const zoomAt = (f, cx, cy) => setTf((t) => {
    const k = Math.min(3, Math.max(0.12, t.k * f));
    const r = k / t.k;
    return { k, x: cx - (cx - t.x) * r, y: cy - (cy - t.y) * r };
  });
  const onWheel = (e) => {
    e.preventDefault();
    const r = svg.current.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
  };
  const onDown = (e) => { if (e.button !== 0) return; drag.current = { x: e.clientX, y: e.clientY, tx: tf.x, ty: tf.y, moved: false }; };
  const onMove = (e) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.x, dy = e.clientY - d.y;
    if (!d.moved && Math.abs(dx) + Math.abs(dy) > 4) d.moved = true;
    if (d.moved) setTf((t) => ({ ...t, x: d.tx + dx, y: d.ty + dy }));
  };
  const onUp = () => { const d = drag.current; drag.current = null; if (d && d.moved) drag.moved = Date.now(); };
  const onKey = (e) => {
    const step = 60;
    const k = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[e.key];
    if (k && e.target === svg.current) { e.preventDefault(); setTf((t) => ({ ...t, x: t.x + k[0], y: t.y + k[1] })); return; }
    const el = svg.current;
    if (e.key === "+" || e.key === "=") zoomAt(1.2, el.clientWidth / 2, el.clientHeight / 2);
    else if (e.key === "-") zoomAt(1 / 1.2, el.clientWidth / 2, el.clientHeight / 2);
    else if (e.key === "0") fit(true);
  };
  const activate = (id) => {
    if (drag.moved && Date.now() - drag.moved < 250) return;
    if (id.startsWith("x:")) return;
    if (clickMode === "center") setCenter(id); else openFn(id);
  };
  const label = (id) => (id.startsWith("x:") ? g.ext.get(id) : ((index.byId.get(id) || {}).name || id));
  const cf = index.byId.get(c);
  const ups = (g.inn.get(c) || new Set()).size, downs = (g.out.get(c) || new Set()).size;
  const qq = q.trim().toLowerCase();
  const matches = qq ? funcs.filter((f) => (f.name || "").toLowerCase().includes(qq) || (f.addr || "").includes(qq)).slice(0, 8) : [];
  const hl = hover ? new Set([hover, ...(g.out.get(hover) || []), ...(g.inn.get(hover) || [])]) : null;

  return html`
    <section class="panel pad cx-gbar">
      <div class="row-c" style="flex-wrap:wrap;gap:8px 14px">
        <span>Centred on <b class="mono">${cf ? cf.name : c}</b>
          <span class="dim" style="font-size:12px"> · ${ups} caller${ups === 1 ? "" : "s"} · ${downs} callee${downs === 1 ? "" : "s"}</span></span>
        <span style="flex:1 1 auto"></span>
        <div class="seg" role="group" aria-label="Depth">
          ${[1, 2, 3].map((n) => html`<button class=${hops === n ? "on" : ""} onClick=${() => setHops(n)} aria-label=${`${n} hop${n > 1 ? "s" : ""}`}>${n} hop${n > 1 ? "s" : ""}</button>`)}</div>
        <div class="seg" role="group" aria-label="Click a node to">
          <button class=${clickMode === "open" ? "on" : ""} onClick=${() => setClickMode("open")}>Click opens code</button>
          <button class=${clickMode === "center" ? "on" : ""} onClick=${() => setClickMode("center")}>Click re-centres</button></div>
        <label class="cx-chk"><input type="checkbox" checked=${showExt} onChange=${(e) => setShowExt(e.target.checked)} />imports</label>
      </div>
      <div class="row-c" style="flex-wrap:wrap;gap:8px;margin-top:8px;position:relative">
        <input type="text" placeholder="centre on another function…" aria-label="Centre on function" value=${q}
          onInput=${(e) => setQ(e.target.value)} style="flex:1 1 220px;max-width:360px" />
        ${matches.map((f) => html`<button class="chip cx-pick" onClick=${() => { setCenter(f.id); setQ(""); }}>${f.name}</button>`)}
        <span style="flex:1 1 auto"></span>
        <button class="btn sm" onClick=${() => zoomAt(1.2, svg.current.clientWidth / 2, svg.current.clientHeight / 2)} aria-label="Zoom in">+</button>
        <button class="btn sm" onClick=${() => zoomAt(1 / 1.2, svg.current.clientWidth / 2, svg.current.clientHeight / 2)} aria-label="Zoom out">−</button>
        <button class="btn sm" onClick=${() => fit(true)} title="fit the whole neighbourhood (0)">Fit all</button>
        ${cf ? html`<button class="btn sm" onClick=${() => openFn(c)}>Open code</button>` : null}
      </div>
    </section>
    <div class="cx-graph">
      <svg ref=${svg} tabindex="0" role="application" aria-label="Call graph — arrows pan, + and − zoom, 0 fits, Tab moves between functions"
        onWheel=${onWheel} onPointerDown=${onDown} onPointerMove=${onMove} onPointerUp=${onUp} onPointerLeave=${onUp} onKeyDown=${onKey}>
        <defs><marker id="cx-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" class="cx-arrhead"></path></marker></defs>
        <g transform=${`translate(${tf.x},${tf.y}) scale(${tf.k})`}>
          ${hood.E.map(([a, b]) => {
            const p = pos.get(a), r = pos.get(b);
            if (!p || !r) return null;
            const down = r.y > p.y;
            const x1 = p.x, y1 = down ? p.y + NODE_H : p.y, x2 = r.x, y2 = down ? r.y : r.y + NODE_H;
            const my = (y1 + y2) / 2;
            const on = hl && (a === hover || b === hover);
            return html`<path class=${"cx-edge" + (on ? " on" : "") + (hl && !on ? " fade" : "")} marker-end="url(#cx-arr)"
              d=${`M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`}></path>`;
          })}
          ${[...pos.entries()].map(([id, p]) => {
            const ext = id.startsWith("x:");
            const fs = ext ? null : live(byFunc.get(id));
            const hot = fs && fs.length;
            const nm = label(id) || "";
            const cls = "cx-node" + (id === c ? " center" : "") + (hot ? " hot" : "") + (ext ? " ext" : "") + (hl && !hl.has(id) ? " fade" : "");
            return html`<g key=${id} class=${cls} transform=${`translate(${p.x - NODE_W / 2},${p.y})`}
                tabindex=${ext ? undefined : "0"} role=${ext ? undefined : "button"}
                aria-label=${`${nm}${hot ? `, ${plural(fs.length, "finding")}` : ""}${p.d < 0 ? ", caller" : p.d > 0 ? ", callee" : ", centre"}`}
                onClick=${() => activate(id)} onKeyDown=${(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(id); } }}
                onPointerEnter=${() => setHover(id)} onPointerLeave=${() => setHover(null)} onFocus=${() => setHover(id)} onBlur=${() => setHover(null)}>
              <rect width=${NODE_W} height=${NODE_H} rx="8"></rect>
              <text x=${NODE_W / 2} y=${NODE_H / 2 + 4} text-anchor="middle">${nm.length > 19 ? nm.slice(0, 18) + "…" : nm}</text>
              ${hot ? html`<g transform=${`translate(${NODE_W - 9},-7)`}><circle r="9" class="cx-badge"></circle>
                <text y="3.5" text-anchor="middle" class="cx-badge-t">${fs.length}</text></g>` : null}
              <title>${nm}${ext ? " (import)" : ""}${hot ? ` — ${plural(fs.length, "finding")}` : ""}</title>
            </g>`;
          })}
        </g>
      </svg>
      <div class="cx-legend">
        <span><i class="center"></i>centre</span><span><i class="hot"></i>has findings</span>
        <span><i></i>function</span>${showExt ? html`<span><i class="ext"></i>import</span>` : null}
        <span class="dim">callers above, callees below · ${pos.size} nodes${hood.cut ? ` · ${hood.cut} more beyond the ${CAP_NODES}-node cap` : ""} · drag to pan, scroll to zoom</span>
      </div>
    </div>`;
}

// ── Strings ──────────────────────────────────────────────────────────────────────────────
function StringsView({ strs, loadAll, index, goAddr, funcsLoaded }) {
  const [q, setQ] = useState("");
  const [refd, setRefd] = useState(false);
  const qq = q.trim().toLowerCase();
  // re-checked when a page finishes too: a filter typed while the first page loaded never loaded the rest
  useEffect(() => { if ((qq || refd) && strs && !strs.complete && !strs.loading && !strs.error) loadAll(); },
    [qq, refd, strs && strs.loading, strs && strs.complete]);
  const rows = useMemo(() => {
    const xs = (strs && strs.items) || [];
    return xs.filter((s) => (!qq || (s.value || "").toLowerCase().includes(qq) || (s.addr || "").toLowerCase().includes(qq))
      && (!refd || (Array.isArray(s.xrefs) && s.xrefs.length)));
  }, [strs, qq, refd]);
  if (!strs || (strs.loading && !strs.items.length)) return html`<${Empty}>Loading strings…</${Empty}>`;
  if (strs.error && !strs.items.length) return html`<${Empty}>Could not load strings: ${strs.error}</${Empty}>`;
  if (!strs.items.length) return html`<${Empty}>No strings were recovered for this target.</${Empty}>`;
  const anyX = strs.items.some((s) => Array.isArray(s.xrefs) && s.xrefs.length);
  const xrefOf = (x) => (typeof x === "object" && x ? (x.from || x.addr || x.src_addr || x.site_addr) : x);
  return html`<section class="panel" style="overflow:hidden">
    <div class="pad row-c" style="flex-wrap:wrap;gap:8px 14px;padding-bottom:10px">
      <input type="text" placeholder="filter strings" aria-label="Filter strings" value=${q} onInput=${(e) => setQ(e.target.value)} style="flex:1 1 240px;max-width:420px" />
      ${anyX ? html`<label class="cx-chk"><input type="checkbox" checked=${refd} onChange=${(e) => setRefd(e.target.checked)} />referenced by code</label>` : null}
      <span class="dim" style="font-size:12px">${qq || refd ? `${rows.length} ${rows.length === 1 ? "match" : "matches"} · ` : ""}${strs.items.length}${strs.total != null && strs.total !== strs.items.length ? ` of ${strs.total}` : ""} loaded</span>
      ${!strs.complete ? html`<button class="btn sm" disabled=${strs.loading} onClick=${loadAll}>${strs.loading ? "Loading…" : `Load all ${strs.total}`}</button>` : null}
    </div>
    ${(qq || refd) && !strs.complete ? html`<div class="cx-note" style="margin:0 16px 10px">${strs.loading ? "Filtering the strings loaded so far; the rest are loading." : `Filtering the ${strs.items.length} strings loaded so far${strs.error ? ` (loading the rest failed: ${strs.error})` : ""}.`}</div>` : null}
    ${!anyX ? html`<div class="dim" style="font-size:12px;padding:0 16px 8px">No code references were recorded for these strings (the xref pass did not run or did not finish), so they are not linked to functions.</div>` : null}
    <div class="cx-strhead"><span>address</span><span>value</span><span>referenced from</span></div>
    <${VList} items=${rows} rowH=${30} maxH=${600} label="Strings" render=${(s, i) => {
      const xs = Array.isArray(s.xrefs) ? s.xrefs.map(xrefOf).filter(Boolean) : [];
      return html`<div class="cx-strrow" key=${i}>
        <span class="mono dim">${s.addr}</span>
        <span class="mono cx-sval" title=${s.value}>${s.value}</span>
        <span class="cx-sx">${xs.slice(0, 3).map((a) => {
          const f = funcsLoaded ? index.at(a) : null;
          return f ? html`<button class="xref" onClick=${() => goAddr(a)} title=${`${f.name} at ${a}`}>${f.name}</button>`
            : html`<span class="mono dim">${a}</span>`;
        })}${xs.length > 3 ? html`<span class="dim">+${xs.length - 3}</span>` : null}</span></div>`;
    }} />
  </section>`;
}

// ── Target ───────────────────────────────────────────────────────────────────────────────
const MITS = [
  ["nx", "NX / DEP", "no exec stack / heap"], ["pie", "PIE / ASLR", "address randomization"],
  ["relro", "RELRO", "GOT write-protection"], ["bind_now", "BIND_NOW", "eager GOT binding"],
  ["canary", "Stack canary", "stack-overflow guard"], ["fortify", "FORTIFY", "libc bounds checks"],
  ["seccomp", "seccomp", "syscall filter"],
];
const DANGEROUS = new Set(["strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "memmove",
  "alloca", "system", "popen", "execve", "execl", "execlp", "execvp", "exec", "fscanf", "printf", "fprintf", "snprintf",
  "read", "recv", "fread", "getenv", "strncpy", "strncat"]);
// the libc variants name the same API: __isoc23_sscanf, __printf_chk, __memcpy_chk
const apiName = (s) => bare(s).replace(/^isoc\d+_/, "").replace(/^_+/, "").replace(/_chk$/, "");
// "unknown" is NOT absent: it rendered amber "favours exploitation" (libwinpr's pie:"unknown")
const posture = (v) => {
  const s = String(v).toLowerCase();
  if (v === true || s === "on" || s === "full" || s === "yes" || s === "enabled") return "on";
  if (s === "partial") return "part";
  if (v === false || s === "off" || s === "none" || s === "no" || s === "disabled") return "off";
  return "unk";
};
const POSTURE_TITLE = { off: "absent — favours exploitation", part: "partial", on: "present", unk: "not determined" };

function TargetView({ target, caseId, nFuncs }) {
  const [details, setDetails] = useState(undefined);
  const [advice, setAdvice] = useState(undefined);
  const [caps, setCaps] = useState(undefined);
  const tid = target && target.id;
  useEffect(() => {
    if (!tid) return undefined;
    let stop = false;
    api.advice(tid).then((a) => !stop && setAdvice(a)).catch(() => !stop && setAdvice(null));
    api.capabilities(tid).then((c) => !stop && setCaps(c)).catch(() => !stop && setCaps(null));
    (async () => {
      try {
        const runs = asList(await api.listRuns(caseId));
        const r = runs.find((x) => x.target_id === tid && x.stage === "ingest_triage" && x.status === "done");
        const out = r ? await api.runOutput(r.id) : null;
        if (!stop) setDetails((out && out.output) || null);
      } catch (_e) { if (!stop) setDetails(null); }
    })();
    return () => { stop = true; };
  }, [tid]);
  if (!target) return html`<${Empty}>No target selected.</${Empty}>`;
  const t = target, d = details || {};
  const m = parseMaybe(t.mitigations) || {};
  const elf = (d.format_details && d.format_details.elf) || {};
  const imp = d.imports || {};
  const syms = imp.symbols || [];
  const dang = syms.filter((s) => DANGEROUS.has(apiName(s)));
  const ent = d.entropy && typeof d.entropy === "object" ? d.entropy : null;
  const sections = Array.isArray(d.sections) ? d.sections.filter((s) => s.name || s.size) : [];
  const exportsN = d.exports_count != null ? d.exports_count : (d.exports && d.exports.count);
  return html`
    <div class="cx-grid">
      <section class="panel pad">
        <div class="row-c" style="flex-wrap:wrap"><h2 class="mono" style="word-break:break-all">${t.filename}</h2><${Copy} text=${t.filename} what="file name" /></div>
        <div class="muted" style="font-size:12.5px;margin:2px 0 10px">${d.detected || [String(t.file_type || "").toUpperCase(), t.arch, t.bits ? `${t.bits}-bit` : null, t.endianness, t.linking, t.stripped ? "stripped" : "with symbols"].filter(Boolean).join(" · ")}</div>
        <${KV} k="Type" v=${t.file_type} />
        <${KV} k="Arch" v=${[t.arch, t.bits ? `${t.bits}-bit` : null, t.endianness].filter(Boolean).join(" ")} />
        <${KV} k="Linking" v=${t.linking} />
        <${KV} k="Stripped" v=${t.stripped == null ? null : t.stripped ? "yes" : "no"} />
        <${KV} k="Size" v=${t.size != null ? `${fmtBytes(t.size)} (${t.size.toLocaleString()} bytes)` : null} />
        <${KV} k="Entry" v=${d.entry_point || (elf.entry != null ? hx(elf.entry) : null)} mono=${true} />
        <${KV} k="Interpreter" v=${d.interpreter || elf.interpreter} mono=${true} />
        <${KV} k="ELF type" v=${elf.type} />
        <${KV} k="Toolchain" v=${t.toolchain_hint || d.toolchain_hint} />
        <${KV} k="Entropy" v=${ent && ent.overall != null ? `${ent.overall}${ent.packed_hint ? ` — packed?${ent.packer ? ` (${ent.packer})` : ""}` : ""}`
          : t.entropy != null ? String(t.entropy) : null} />
        <${KV} k="Functions" v=${nFuncs != null ? String(nFuncs) : null} />
        <${KV} k="Imports" v=${imp.functions_count != null ? `${imp.functions_count}${(imp.libraries || []).length ? ` from ${imp.libraries.join(", ")}` : ""}` : null} />
        <${KV} k="Exports" v=${exportsN != null ? String(exportsN) : null} />
        <${KV} k="Dependencies" v=${t.deps && t.deps.length ? t.deps.join(", ") : null} mono=${true} />
        ${ent && ent.reasons && ent.reasons.length ? html`<div class="dim" style="font-size:12px">${ent.reasons.join("; ")}</div>` : null}
        <div class="cx-hashes">
          ${[["SHA-256", t.sha256], ["SHA-1", t.sha1], ["MD5", t.md5]].filter(([, v]) => v).map(([k, v]) => html`
            <div class="cx-hash"><span class="k">${k}</span><code title=${v}>${v}</code><${Copy} text=${v} what=${k} /></div>`)}
        </div>
        ${details === undefined ? html`<div class="dim" style="font-size:12px;margin-top:6px">loading the triage record…</div>`
          : details === null ? html`<div class="dim" style="font-size:12px;margin-top:6px">No triage record for this target (sections and imports come from it).</div>` : null}
        ${d.parse_errors && d.parse_errors.length ? html`<div class="cx-note warn">Parse errors: ${d.parse_errors.join("; ")}</div>` : null}
      </section>
      <section class="panel pad">
        <h2>Mitigations</h2>
        <div class="dim" style="font-size:12px;margin:2px 0 10px">Amber = absent, which favours exploitation. Dashed = not determined.</div>
        ${Object.keys(m).length ? html`<div class="cx-posture">${MITS.filter(([k]) => m[k] != null).map(([k, l, desc]) => {
          const p = posture(m[k]);
          return html`<div class=${"cx-pm " + p} title=${POSTURE_TITLE[p]}>
            <div class="row-c" style="justify-content:space-between"><b>${l}</b><span class="mono">${typeof m[k] === "boolean" ? (m[k] ? "on" : "off") : m[k]}</span></div>
            <span class="dim">${desc}</span></div>`;
        })}
          ${Object.keys(m).filter((k) => !MITS.some(([x]) => x === k)).map((k) => html`<div class=${"cx-pm " + posture(m[k])} title=${POSTURE_TITLE[posture(m[k])]}>
            <div class="row-c" style="justify-content:space-between"><b>${k}</b><span class="mono">${String(m[k])}</span></div></div>`)}
        </div>` : html`<div class="dim">No mitigation posture was recorded for this target.</div>`}
        ${dang.length ? html`<div style="margin-top:14px"><div class="cx-lbl">DANGEROUS IMPORTS</div>
          <div class="row-c" style="flex-wrap:wrap;gap:6px;margin-top:4px">${dang.map((s) => html`<code class="chip cx-amb">${s}</code>`)}</div></div>` : null}
        ${syms.length ? html`<details style="margin-top:12px"><summary class="muted" style="cursor:pointer;font-size:12.5px">All ${syms.length} imported symbols</summary>
          <div class="cx-syms mono">${syms.join("  ")}</div></details>` : null}
      </section>
    </div>
    ${sections.length ? html`<section class="panel" style="overflow:hidden">
      <div class="pad" style="padding-bottom:6px"><h2>Sections <span class="dim" style="font-weight:400;font-size:12.5px">${sections.length}</span></h2></div>
      <div class="cx-table" role="table">
        <div class="cx-tr head" role="row"><span>name</span><span>perms</span><span>size</span><span>entropy</span></div>
        ${sections.map((s) => html`<div class=${"cx-tr" + (/w/.test(s.perms || "") && /x/.test(s.perms || "") ? " warn" : "")} role="row">
          <span class="mono">${s.name || "(unnamed)"}</span><span class="mono">${s.perms || ""}</span>
          <span class="mono">${s.size != null ? s.size.toLocaleString() : ""}</span>
          <span class="mono">${s.entropy != null ? s.entropy : "—"}${s.entropy != null ? html`<i class="cx-ebar" style=${`width:${Math.round(s.entropy / 8 * 60)}px`}></i>` : null}</span></div>`)}
      </div></section>` : null}
    <${AdvicePanel} advice=${advice} />
    <${InvocationHelper} tid=${tid} advice=${advice} />
    <${CapabilitiesPanel} caps=${caps} />`;
}


function AdvicePanel({ advice }) {
  if (advice === undefined) return html`<section class="panel pad dim">Loading advice…</section>`;
  if (!advice) return html`<section class="panel pad dim">No advice for this target.</section>`;
  const a = advice;
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:8px">
    <h2>What to do next</h2>
    ${a.headline ? html`<div class="cx-headline">${a.headline}</div>` : null}
    <div class="cx-kvs">
      <${KV} k="Input" v=${a.input_mode || (a.input_unknown ? "unknown" : null)} />
      <${KV} k="Shape" v=${a.shape} />
      <${KV} k="Backend" v=${a.backend} mono=${true} />
      <${KV} k="File parser" v=${a.file_parser == null ? null : a.file_parser ? "yes" : "no"} />
      <${KV} k="AFL++ usable" v=${a.afl_usable == null ? null : a.afl_usable ? "yes" : "no"} />
      <${KV} k="Analysable" v=${a.analysable == null ? null : a.analysable ? "yes" : "no"} />
    </div>
    ${a.backend_why ? html`<div class="muted" style="font-size:12.5px">${a.backend_why}</div>` : null}
    ${(a.checks || []).length ? html`<div><div class="cx-lbl">CHECKS</div>
      ${a.checks.map((c) => html`<div class="cx-check"><span class=${c.ok ? "ok" : "no"} aria-label=${c.ok ? "ok" : "not met"}>${c.ok ? "✓" : "✗"}</span><span>${c.text}</span></div>`)}</div>` : null}
    ${(a.plan || []).length ? html`<div><div class="cx-lbl">PLAN</div>
      ${a.plan.map((s, i) => html`<div class="cx-plan"><span class="mono dim">${i + 1}</span>
        <span class="mono">${s.stage}</span>
        <span class="muted" style="flex:1 1 220px">${s.why}</span>
        ${s.done ? html`<span class="chip on">ran</span>` : s.ready === false ? html`<span class="chip">not ready</span>` : html`<span class="chip">ready</span>`}</div>`)}</div>` : null}
  </section>`;
}

function InvocationHelper({ tid, advice }) {
  const inv = advice && advice.invocation;
  const seed = (inv && inv.proposed_argv) || (advice && advice.invocation_hint) || null;
  const [argv, setArgv] = useState("");
  const [touched, setTouched] = useState(false);
  const [sample, setSample] = useState("");
  const [tmo, setTmo] = useState("15");
  const [busy, setBusy] = useState(null);
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  useEffect(() => { if (!touched && seed) setArgv(shellJoin(seed)); }, [advice]);
  const go = async (verify) => {
    setBusy(verify ? "verify" : "detect"); setErr(null);
    try {
      const body = { verify };
      if (verify) {
        const a = shellSplit(argv);
        if (a.length) body.argv = a;
        const n = Number(tmo);
        if (n > 0) body.timeout = n;
        if (sample) body.sample_b64 = b64utf8(sample);
      }
      setRes(await api.invocation(tid, body));
    } catch (e) { setErr(errText(e)); }
    setBusy(null);
  };
  const flags = (res && res.flags) || (inv && inv.flags) || [];
  const info = res || inv || null;
  const v = res && res.verified;
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
    <div class="row-c" style="flex-wrap:wrap"><h2>Invocation</h2>
      <span class="dim" style="font-size:12.5px">how the target is run — read off its own usage text, then checked by running it in the sandbox</span></div>
    ${info ? html`<div class="cx-kvs">
      <${KV} k="Usage" v=${info.usage} mono=${true} />
      <${KV} k="Confidence" v=${info.confidence} />
      <${KV} k="Read from" v=${(info.sources || []).join(", ")} />
      <${KV} k="Subcommand" v=${info.subcommand} mono=${true} />
      <${KV} k="Proposed" v=${info.proposed_argv ? (info.proposed_argv.length ? shellJoin(info.proposed_argv) : "(no arguments)") : null} mono=${true} />
    </div>` : null}
    ${flags.length ? html`<details><summary class="muted" style="cursor:pointer;font-size:12.5px">${plural(flags.length, "option")} recognised</summary>
      <div class="cx-flags">${flags.map((f) => html`<span class="mono" title=${f.kind || ""}>${f.flag}${f.takes_value ? ` <${f.placeholder || f.name || "value"}>` : ""}${f.default != null ? html`<span class="dim"> = ${f.default}</span>` : null}</span>`)}</div></details>` : null}
    <label class="field">argv (use @@ where the input file goes)
      <input type="text" class="mono" value=${argv} placeholder="e.g. -c @@" onInput=${(e) => { setArgv(e.target.value); setTouched(true); }} /></label>
    <div class="row-c" style="flex-wrap:wrap;align-items:flex-end;gap:10px">
      <label class="field" style="flex:1 1 260px">sample input for @@ (optional text)
        <textarea class="cx-ta mono" rows="2" value=${sample} onInput=${(e) => setSample(e.target.value)} placeholder="the server uses a tiny default sample when blank"></textarea></label>
      <label class="field" style="width:110px">timeout (s)
        <input type="number" min="1" max="120" value=${tmo} onInput=${(e) => setTmo(e.target.value)} /></label>
    </div>
    <div class="row-c" style="flex-wrap:wrap">
      <button class="btn sm" disabled=${!!busy} onClick=${() => go(false)}>${busy === "detect" ? "Detecting…" : "Detect from strings"}</button>
      <button class="btn primary sm" disabled=${!!busy} onClick=${() => go(true)}
        title="runs the target in the sandbox, with no arguments and with this argv, and compares">${busy === "verify" ? "Running the target…" : "Verify by running"}</button>
      ${res && res.proposed_argv && shellJoin(res.proposed_argv) !== argv ? html`<button class="btn sm" onClick=${() => { setArgv(shellJoin(res.proposed_argv)); setTouched(true); }}>Use proposed argv</button>` : null}
    </div>
    ${err ? html`<div class="cx-note warn">${err}</div>` : null}
    ${v ? html`<div class=${"cx-verdict " + (v.accepted ? "ok" : "no")}>
      <b>${v.accepted ? "Accepted" : "Refused"}</b> — ${v.why}
      <div class="mono" style="font-size:12px;margin-top:4px">argv: ${v.argv && v.argv.length ? shellJoin(v.argv) : "(none)"}</div>
      ${v.target_says ? html`<div class="mono dim" style="font-size:12px">with no arguments the target says: ${v.target_says}</div>` : null}
      ${v.bare_rejected != null ? html`<div class="dim" style="font-size:12px">no-argument run ${v.bare_rejected ? "was refused" : "was not refused"}</div>` : null}
    </div>` : null}
    <div class="dim" style="font-size:12px">To make an analysis use this invocation, set it when starting the analysis (the Run screen); this helper only proposes and checks.</div>
  </section>`;
}

function CapabilitiesPanel({ caps }) {
  if (caps === undefined) return html`<section class="panel pad dim">Loading capabilities…</section>`;
  if (!caps) return html`<section class="panel pad dim">Capabilities could not be read for this target.</section>`;
  const groups = caps.groups || [];
  const st = caps.stages || {};
  const all = groups.flatMap((g) => st[g.key] || []);
  const un = all.filter((s) => s.available === false);
  return html`<section class="panel pad" style="display:flex;flex-direction:column;gap:12px">
    <div class="row-c" style="flex-wrap:wrap"><h2>What lykos can do here</h2>
      <span class="dim" style="font-size:12.5px">${all.filter((s) => s.done).length} of ${all.length} capabilities have run on this target</span></div>
    ${un.length ? html`<div class="cx-unavail">
      <b>${un.length} not applicable to this target</b>
      ${un.map((s) => html`<div class="cx-un"><span class="mono">${s.label || s.stage}</span><span>${s.why || "not applicable"}</span></div>`)}
    </div>` : html`<div class="dim" style="font-size:12.5px">Every capability applies to this target.</div>`}
    ${groups.map((g) => html`<div>
      <div class="cx-lbl">${String(g.label || g.key).toUpperCase()} <span style="text-transform:none;letter-spacing:0;font-weight:400">— ${g.why}</span></div>
      <div class="cx-caps">${(st[g.key] || []).map((s) => html`<div class=${"cx-cap" + (s.available === false ? " no" : "") + (s.done ? " done" : "")}
          title=${s.available === false ? s.why || "" : s.purpose || ""}>
        <div class="row-c" style="justify-content:space-between;gap:6px"><b>${s.label || s.stage}</b>
          ${s.available === false ? html`<span class="chip cx-amb">n/a</span>` : s.done ? html`<span class="chip on">ran</span>`
            : s.planned != null ? html`<span class="chip">recommended</span>` : null}</div>
        <span class="dim">${s.available === false ? s.why : s.purpose}</span>
        <span class="mono dim" style="font-size:10.5px">${s.stage}</span></div>`)}</div></div>`)}
  </section>`;
}

// ── Source ───────────────────────────────────────────────────────────────────────────────
// A tree file is read in 801-line windows (the server's max context is 400 either side of a line).
const SRC_CHUNK = 400, SRC_MAX_LINES = 60000;
const FILE_CACHE = new Map();     // tid \0 path -> {lines, total, complete, capped}
const SITE_CACHE = new Map();     // tid \0 finding id -> {path, line} | false: the server's own site_of
function useSourceFile(tid, source, path) {
  const key = `${tid}\0${path}`;
  const [st, setSt] = useState(null);
  useEffect(() => {
    if (!path || !source) { setSt(null); return undefined; }
    if (source.kind === "single") {
      const lines = String(source.text || "").split("\n");
      setSt({ lines, total: lines.length, complete: true });
      return undefined;
    }
    const hit = FILE_CACHE.get(key);
    if (hit) { setSt(hit); return undefined; }
    let stop = false;
    (async () => {
      let lines = [], total = null;
      setSt({ lines, total, complete: false, loading: true });
      try {
        for (let guard = 0; guard < 200; guard++) {
          const from = lines.length + 1;
          const want = total == null ? from + SRC_CHUNK : Math.min(total, from + SRC_CHUNK);
          const r = await fetchJSON(`/targets/${tid}/source-file?path=${encodeURIComponent(path)}&line=${want}&context=${SRC_CHUNK}`);
          if (stop) return;
          if (!r.ok || !r.body) throw new Error((r.body && r.body.error) || `HTTP ${r.status}`);
          total = r.body.total;
          const got = r.body.lines || [];
          const off = from - (r.body.start || 1);
          if (off < 0 || off >= got.length) break;               // nothing past what is in
          lines = lines.concat(got.slice(off));
          if (lines.length >= total || lines.length >= SRC_MAX_LINES) break;
          setSt({ lines, total, complete: false, loading: true });
        }
        if (stop) return;
        const v = { lines, total: total == null ? lines.length : total, complete: true,
                    capped: total != null && lines.length < total };
        FILE_CACHE.set(key, v);
        if (FILE_CACHE.size > 40) FILE_CACHE.delete(FILE_CACHE.keys().next().value);
        setSt(v);
      } catch (e) {
        if (!stop) setSt({ lines, total, complete: false, loading: false, error: errText(e) });
      }
    })();
    return () => { stop = true; };
  }, [key, source]);
  return st;
}

function SourceView({ tid, source, findings, openFinding, focus, locate }) {
  const files = (source && source.files) || [];
  const tix = useMemo(() => treeIndex(files), [source]);
  const [tick, setTick] = useState(0);                 // server-resolved sites arrived
  // every finding with a source site, placed in a tree file when it names one unambiguously; the
  // server's own resolution (?finding=) wins once asked
  const locs = useMemo(() => findings.map((f) => {
    const srv = SITE_CACHE.get(`${tid}\0${f.id}`);
    if (srv) return { f, rel: srv.path, line: srv.line, cands: [], server: true };
    const site = srcSiteOf(f);
    if (!site) return null;
    const r = tix.resolve(site.path);
    return { f, rel: r.rel, line: site.line, cands: r.cands, path: site.path, asked: srv === false };
  }).filter(Boolean), [findings, tix, tick, tid]);
  const byFile = useMemo(() => {
    const m = new Map();
    for (const l of locs) if (l.rel && l.line) { if (!m.has(l.rel)) m.set(l.rel, []); m.get(l.rel).push(l); }
    return m;
  }, [locs]);
  const unplaced = locs.filter((l) => !l.rel && !l.cands.length);
  const noSite = findings.length - locs.length;
  const [cur, setCur] = useState(null);
  const [jump, setJump] = useState({ idx: -1, n: 0 });
  const [ambig, setAmbig] = useState(null);           // {path, line, cands}: a focus naming several files
  const [fq, setFq] = useState("");
  const [onlyF, setOnlyF] = useState(null);           // null = "with findings" when there are any
  const [q, setQ] = useState("");
  const [hit, setHit] = useState(-1);
  const open = (rel, line = null) => {
    setCur(rel); setAmbig(null); setHit(-1);
    setJump({ idx: line ? line - 1 : -1, n: Date.now() });
    locate(rel, line);
  };
  // a requested site (the route / a finding): resolve it in the tree
  useEffect(() => {
    if (!focus || !files.length) return;
    const r = tix.resolve(focus.path);
    if (r.rel) { setCur(r.rel); setAmbig(null); setJump({ idx: focus.line ? focus.line - 1 : -1, n: focus.n }); }
    else setAmbig({ path: focus.path, line: focus.line, cands: r.cands });
  }, [focus && focus.n, source]);
  // nothing asked for: the file with the most findings
  useEffect(() => {
    if (cur || focus || !files.length) return;
    let best = null, bn = 0;
    for (const [p, ls] of byFile) { const n = live(ls.map((l) => l.f)).length || ls.length * 0.001; if (n > bn) { best = p; bn = n; } }
    const first = byFile.size && best ? best : (files.find((p) => /^readme(\.|$)/i.test(p)) || files[0]);
    setCur(first);
    const ls = byFile.get(first);
    if (ls && ls.length) setJump({ idx: Math.min(...ls.map((l) => l.line)) - 1, n: Date.now() });
  }, [source, byFile.size]);
  // a site the client cannot place in THIS file (an ambiguous basename, a `file: fn()` site with no
  // line): ask the server, which resolves it exactly as the confirm stages do
  useEffect(() => {
    if (!cur || !source || source.kind !== "tree") return undefined;
    const want = locs.filter((l) => !l.server && !l.asked && ((l.rel === cur && !l.line) || (!l.rel && l.cands.includes(cur))))
      .slice(0, 60);
    if (!want.length) return undefined;
    let stop = false;
    (async () => {
      const q2 = want.slice();
      const worker = async () => {
        while (q2.length && !stop) {
          const l = q2.shift();
          const k = `${tid}\0${l.f.id}`;
          if (SITE_CACHE.has(k)) continue;
          try {
            const r = await fetchJSON(`/targets/${tid}/source-file?finding=${encodeURIComponent(l.f.id)}&context=0`);
            SITE_CACHE.set(k, r.ok && r.body && r.body.path ? { path: r.body.path, line: r.body.line || r.body.start || null } : false);
          } catch (_e) { SITE_CACHE.set(k, false); }
        }
      };
      await Promise.all([worker(), worker(), worker(), worker()]);
      if (!stop) setTick((x) => x + 1);
    })();
    return () => { stop = true; };
  }, [cur, source, locs]);

  const fileSt = useSourceFile(tid, source, cur);
  const lines = (fileSt && fileSt.lines) || [];
  const marks = useMemo(() => {
    const m = new Map();
    for (const l of byFile.get(cur) || []) { if (!m.has(l.line)) m.set(l.line, []); m.get(l.line).push(l.f); }
    return m;
  }, [byFile, cur]);
  const markLines = useMemo(() => [...marks.keys()].sort((a, b) => a - b), [marks]);
  const qq = q.trim().toLowerCase();
  const hits = useMemo(() => (qq ? lines.map((l, i) => (l.toLowerCase().includes(qq) ? i : -1)).filter((i) => i >= 0) : []), [lines, qq]);
  const showOnly = onlyF == null ? byFile.size > 0 : onlyF;
  const shownFiles = useMemo(() => {
    const ff = fq.trim().toLowerCase();
    const xs = files.filter((p) => (!showOnly || byFile.has(p)) && (!ff || p.toLowerCase().includes(ff)));
    return showOnly ? xs.sort((a, b) => (byFile.get(b).length - byFile.get(a).length) || a.localeCompare(b)) : xs;
  }, [files, fq, showOnly, byFile]);

  if (source === undefined) return html`<${Empty}>Loading the source…</${Empty}>`;
  if (!files.length) return html`<${Empty}>No source is recorded for this target.</${Empty}>`;
  const nextHit = (dir) => {
    if (!hits.length) return;
    const k = hit < 0 ? (dir > 0 ? 0 : hits.length - 1) : (hit + dir + hits.length) % hits.length;
    setHit(k); setJump({ idx: hits[k], n: Date.now() });
  };
  const nextMark = (dir) => {
    if (!markLines.length) return;
    const at = jump.idx + 1;
    const ln = dir > 0 ? (markLines.find((x) => x > at) || markLines[0])
      : ([...markLines].reverse().find((x) => x < at) || markLines[markLines.length - 1]);
    setJump({ idx: ln - 1, n: Date.now() }); locate(cur, ln);
  };
  const selIdx = files.length ? shownFiles.indexOf(cur) : -1;
  const onKey = (e) => {
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 }[e.key];
    if (step == null || !shownFiles.length) return;
    e.preventDefault();
    open(shownFiles[Math.min(shownFiles.length - 1, Math.max(0, (selIdx < 0 ? -1 : selIdx) + step))]);
  };
  const line1 = jump.idx >= 0 ? jump.idx + 1 : null;
  return html`
    <div class="code">
      <section class="panel flist">
        <div class="pad" style="display:flex;flex-direction:column;gap:6px;padding-bottom:8px">
          <div class="cx-lbl">FILES (${files.length}${source.truncated ? "+, list truncated" : ""})</div>
          <input type="text" placeholder="filter files" aria-label="Filter files" value=${fq} onInput=${(e) => setFq(e.target.value)} />
          ${byFile.size ? html`<label class="cx-chk"><input type="checkbox" checked=${showOnly} onChange=${(e) => setOnlyF(e.target.checked)} />with findings (${byFile.size} files)</label>` : null}
          <span class="dim" style="font-size:11.5px">${shownFiles.length} shown · ↑↓ to move</span>
        </div>
        ${!shownFiles.length ? html`<div class="dim pad" style="font-size:12.5px">No file matches.</div>`
          : html`<${VList} items=${shownFiles} rowH=${28} maxH=${620} selIdx=${selIdx} onKeyDown=${onKey} label="Source files"
            role="listbox" activeId=${selIdx >= 0 ? "cx-sf-" + selIdx : undefined}
            render=${(p, i) => {
              const ls = byFile.get(p), n = ls ? live(ls.map((l) => l.f)).length : 0;
              const cut = p.lastIndexOf("/");
              return html`<button key=${p} id=${"cx-sf-" + i} role="option" aria-selected=${p === cur ? "true" : "false"}
                  class=${"fitem cx-frow" + (p === cur ? " on" : "")} tabindex="-1" onClick=${() => open(p)} title=${p}>
                <span class="nm">${p.slice(cut + 1)}${cut >= 0 ? html`<span class="dim">${"  " + p.slice(0, cut)}</span>` : null}</span>
                ${n ? html`<span class="lvl amber cx-n">${n}</span>` : ls ? html`<span class="cx-n dim">${ls.length}</span>` : null}</button>`;
            }} />`}
        <div class="pad dim" style="font-size:12px">
          ${[source.compiler ? `compiled with ${source.compiler}` : null, source.sanitizers ? `sanitizers: ${source.sanitizers}` : null,
            noSite ? `${plural(noSite, "finding")} on this target name no source location` : null].filter(Boolean).join(" · ")}
        </div>
      </section>
      <div class="fview">
        ${ambig ? html`<div class="cx-note warn">${ambig.path} names ${ambig.cands.length ? `${ambig.cands.length} files in the tree — pick one:` : "no file in the source tree."}
          ${ambig.cands.slice(0, 20).map((c) => html` <button class="xref" onClick=${() => open(c, ambig.line)}>${c}</button>`)}</div>` : null}
        ${!cur ? html`<${Empty}>Pick a file.</${Empty}>` : html`
        <section class="panel pad row-c" style="flex-wrap:wrap;gap:8px 12px">
          <h2 class="mono" style="word-break:break-all">${cur}</h2>
          <${Copy} text=${line1 ? `${cur}:${line1}` : cur} what=${line1 ? "path:line" : "path"} />
          <span class="dim" style="font-size:12px">${fileSt && fileSt.total != null ? plural(fileSt.total, "line") : ""}${fileSt && fileSt.loading ? ` · loading ${lines.length}…` : ""}${fileSt && fileSt.capped ? ` · first ${lines.length} shown` : ""}${marks.size ? ` · ${plural(marks.size, "finding line")}` : ""}</span>
          <span style="flex:1 1 auto"></span>
          ${markLines.length ? html`<button class="btn sm" onClick=${() => nextMark(-1)} aria-label="previous finding line">◂ finding</button>
            <button class="btn sm" onClick=${() => nextMark(1)} aria-label="next finding line">finding ▸</button>` : null}
          <input type="text" placeholder="find in file" aria-label="Find in file" value=${q} style="width:180px"
            onInput=${(e) => { setQ(e.target.value); setHit(-1); }} onKeyDown=${(e) => { if (e.key === "Enter") nextHit(e.shiftKey ? -1 : 1); }} />
          ${qq ? html`<span class="dim" style="font-size:12px">${hits.length ? `${hit + 1 || 0}/${hits.length}` : "no match"}</span>
            <button class="btn sm" onClick=${() => nextHit(-1)} aria-label="previous match">↑</button>
            <button class="btn sm" onClick=${() => nextHit(1)} aria-label="next match">↓</button>` : null}
        </section>
        ${fileSt && fileSt.error ? html`<div class="cx-note warn">Could not read ${cur}: ${fileSt.error}</div>` : null}
        ${markLines.length ? html`<div class="row-c" style="flex-wrap:wrap;gap:6px">${markLines.map((ln) => marks.get(ln).map((f) => html`
          <span class=${"cx-fchipw" + (isNoise(f) ? " noise" : "")}>
            <button class="chip cx-fchip" onClick=${() => { setJump({ idx: ln - 1, n: Date.now() }); locate(cur, ln); }}
              title=${"show the line — " + (f.title || "")}>line ${ln} · ${f.cwe} · ${f.state}</button>
            <button class="xref cx-fopen" onClick=${() => openFinding(f.id)} aria-label=${`open finding: ${f.title || f.cwe}`}>open</button></span>`))}</div>` : null}
        ${fileSt && !lines.length && fileSt.loading ? html`<${Empty}>Loading ${cur}…</${Empty}>`
          : html`<${SrcLines} lines=${lines} marks=${marks} jump=${jump} hits=${hits} qq=${qq} openFinding=${openFinding} />`}`}
        ${unplaced.length ? html`<section class="panel pad"><div class="cx-lbl">FINDINGS WHOSE FILE IS NOT IN THE TREE (${unplaced.length})</div>
          <div class="dim" style="font-size:12px;margin-bottom:6px">These name a file the uploaded tree does not hold (a generated or build-directory file).</div>
          ${unplaced.slice(0, 60).map(({ f, path, line }) => html`<div><button class="xref" onClick=${() => openFinding(f.id)}>${path}${line ? `:${line}` : ""}</button>
            <span class="dim" style="font-size:12px"> ${f.cwe} · ${f.title}</span></div>`)}
          ${unplaced.length > 60 ? html`<div class="dim" style="font-size:12px">+${unplaced.length - 60} more</div>` : null}</section>` : null}
      </div>
    </div>`;
}

function SrcLines({ lines, marks, jump, hits, qq, openFinding }) {
  const ROW = 20;
  const hitSet = useMemo(() => new Set(hits), [hits]);
  return html`<${VList} items=${lines} rowH=${ROW} maxH=${640} selIdx=${jump.idx} selKey=${jump.n} center=${true} label="Source" cls="asm cx-src" render=${(l, i) => {
    const fs = marks.get(i + 1);
    const cls = "cx-sl" + (fs ? " site" + (fs.every(isNoise) ? " noise" : "") : "") + (i === jump.idx ? " focus" : "") + (qq && hitSet.has(i) ? " hit" : "");
    return html`<div class=${cls} key=${i}><span class="n">${i + 1}</span><span class="t">${l || " "}</span>
      ${fs ? html`<button class="xref cx-site" onClick=${() => openFinding(fs[0].id)} title=${fs.map((f) => f.title).join("\n")}>◂ ${fs[0].cwe} ${fs[0].state}${fs.length > 1 ? ` +${fs.length - 1}` : ""}</button>` : null}</div>`;
  }} />`;
}

// ── Scans ────────────────────────────────────────────────────────────────────────────────
function ScansView({ targets, tid, caseId, stage, hasSource, allFindings }) {
  const ts = targets;
  const [seeds, setSeeds] = useState([]);
  useEffect(() => { if (caseId) api.seeds(caseId).then((r) => setSeeds((r && r.seeds) || [])).catch(() => setSeeds([])); }, [caseId]);
  const [ref, setRef] = useState(tid);
  const [fn, setFn] = useState("");
  const [thr, setThr] = useState("0.9");
  const [src, setSrc] = useState(tid);
  const [cpp, setCpp] = useState(false);
  const [cq, setCq] = useState(tid);
  const [hy, setHy] = useState(tid);
  const [hyMode, setHyMode] = useState("");
  const [hySize, setHySize] = useState("300");
  const [hyMem, setHyMem] = useState("8192");
  const [hyBudget, setHyBudget] = useState("150");
  const [picked, setPicked] = useState(() => ts.slice(0, 2).map((t) => t.id));
  const [mode, setMode] = useState("stdin");
  const [compare, setCompare] = useState("status");
  const [iters, setIters] = useState("2000");
  const [useSeeds, setUseSeeds] = useState(true);
  // the selects follow the screen's target when it changes (they kept the previous one)
  useEffect(() => { setRef(tid); setSrc(tid); setCq(tid); setHy(tid); }, [tid]);
  const opt = (t) => html`<option value=${t.id}>${t.filename}</option>`;
  const R = stage.runs;
  const run = (kind, st, opts, meta) => stage.start(kind, st, opts, meta);
  const toggle = (id) => setPicked((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  const num = (v, d) => { const n = Number(v); return Number.isFinite(n) && v !== "" ? n : d; };
  const nCodeql = (t) => (allFindings || []).filter((f) => f.target_id === t && f.detector === "codeql").length;
  return html`
    <section class="panel pad cx-scan">
      <h2>Variant hunt</h2>
      <div class="muted cx-sub">Find a known-vulnerable function from one build in every other target of the case (N-day). Matches are candidates.</div>
      <div class="cx-form">
        <label class="field">reference build<select value=${ref} onChange=${(e) => setRef(e.target.value)}>${ts.map(opt)}</select></label>
        <label class="field" style="flex:2 1 220px">vulnerable function<input type="text" class="mono" placeholder="e.g. parse_header" value=${fn} onInput=${(e) => setFn(e.target.value)} /></label>
        <label class="field" style="width:120px">similarity ≥<input type="number" min="0" max="1" step="0.05" value=${thr} onInput=${(e) => setThr(e.target.value)} /></label>
        <button class="btn primary sm" disabled=${!fn.trim() || ts.length < 2 || (R.variant && R.variant.running)}
          title=${ts.length < 2 ? "add the other builds to this case first" : "scan every other target in the case"}
          onClick=${() => run("variant", "variant_scan", { targetId: ref, params: { function: fn.trim(), threshold: num(thr, 0.9) } })}>Hunt variants</button>
      </div>
      ${ts.length < 2 ? html`<div class="dim" style="font-size:12px">Needs at least two targets in the case — the reference and the builds to search.</div>` : null}
      <${RunStatus} st=${R.variant} what="Variant hunt" cancel=${() => stage.cancel("variant")} />
      <${ScanResult} kind="variant" st=${R.variant} />
    </section>
    <section class="panel pad cx-scan">
      <h2>Source patterns</h2>
      <div class="muted cx-sub">Run the weggli vulnerability-pattern pack over a target's uploaded source. Matches are filed as candidate findings.</div>
      <div class="cx-form">
        <label class="field">target<select value=${src} onChange=${(e) => setSrc(e.target.value)}>${ts.map(opt)}</select></label>
        <label class="cx-chk" style="align-self:center"><input type="checkbox" checked=${cpp} onChange=${(e) => setCpp(e.target.checked)} />C++</label>
        <button class="btn primary sm" disabled=${!src || (R.weggli && R.weggli.running)} onClick=${() => run("weggli", "weggli_scan", { targetId: src, params: { cpp } })}>Scan source</button>
      </div>
      ${!hasSource && src === tid ? html`<div class="dim" style="font-size:12px">This target has no source recorded; the scan will say so if there is nothing to read.</div>` : null}
      <${RunStatus} st=${R.weggli} what="Source-pattern scan" cancel=${() => stage.cancel("weggli")} />
      <${ScanResult} kind="weggli" st=${R.weggli} />
    </section>
    <section class="panel pad cx-scan">
      <h2>Deep CodeQL pass</h2>
      <div class="muted cx-sub">Build a CodeQL database of the target's source project and run the C/C++ security query suite (the CLI's on-demand codeql stage). Results are filed as findings; it declines on a binary with no source project.</div>
      <div class="cx-form">
        <label class="field">target<select value=${cq} onChange=${(e) => setCq(e.target.value)}>${ts.map(opt)}</select></label>
        <button class="btn primary sm" disabled=${!cq || (R.codeql && R.codeql.running)}
          onClick=${() => run("codeql", "codeql", { targetId: cq }, { before: nCodeql(cq), tid: cq })}>Run CodeQL</button>
      </div>
      <${RunStatus} st=${R.codeql} what="CodeQL pass" cancel=${() => stage.cancel("codeql")} />
      ${R.codeql && !R.codeql.running && !R.codeql.error ? html`<div class="cx-note">${(() => {
        const st = R.codeql, r = st.data || {}, t = (st.meta && st.meta.tid) || cq;
        const n = nCodeql(t), before = st.meta && st.meta.before != null ? st.meta.before : null;
        const said = r.note || (r.metrics && (r.metrics.codeql || null));
        return `${said ? said + " — " : ""}${plural(n, "CodeQL finding")} on this target${before != null && n > before ? ` (${n - before} new)` : ""}${n ? " — see Proof" : ""}.`;
      })()}</div>` : null}
    </section>
    <section class="panel pad cx-scan">
      <h2>Hypothesis hunt</h2>
      <div class="muted cx-sub">Propose a defect predicate per suspicious site, solve it symbolically (angr), and keep only the inputs that replay and fault at that site. ELF executables; bounded by the budget.</div>
      <div class="cx-form">
        <label class="field">target<select value=${hy} onChange=${(e) => setHy(e.target.value)}>${ts.map(opt)}</select></label>
        <label class="field" style="width:130px">input via<select value=${hyMode} onChange=${(e) => setHyMode(e.target.value)}>
          <option value="">auto</option><option value="file">file</option><option value="stdin">stdin</option><option value="arg">argument</option></select></label>
        <label class="field" style="width:120px">input size (B)<input type="number" min="1" max="65536" value=${hySize} onInput=${(e) => setHySize(e.target.value)} /></label>
        <label class="field" style="width:120px">memory (MB)<input type="number" min="512" max="65536" value=${hyMem} onInput=${(e) => setHyMem(e.target.value)} /></label>
        <label class="field" style="width:110px">budget (s)<input type="number" min="30" max="7200" value=${hyBudget} onInput=${(e) => setHyBudget(e.target.value)} /></label>
        <button class="btn primary sm" disabled=${!hy || (R.hypo && R.hypo.running)}
          onClick=${() => run("hypo", "hypo_hunt", { targetId: hy, params: {
            input_size: num(hySize, 300), mem_mb: num(hyMem, 8192), budget: num(hyBudget, 150),
            ...(hyMode ? { input_mode: hyMode } : {}) } })}>Hunt</button>
      </div>
      <${RunStatus} st=${R.hypo} what="Hypothesis hunt" cancel=${() => stage.cancel("hypo")} />
      <${ScanResult} kind="hypo" st=${R.hypo} />
    </section>
    <section class="panel pad cx-scan">
      <h2>Differential test</h2>
      <div class="muted cx-sub">Feed the same inputs to two or more implementations of the same thing and report where they disagree.</div>
      <div class="row-c" style="flex-wrap:wrap;gap:6px 14px">${ts.map((t) => html`<label class="cx-chk"><input type="checkbox" checked=${picked.includes(t.id)} onChange=${() => toggle(t.id)} /><span class="mono">${t.filename}</span></label>`)}</div>
      <div class="cx-form">
        <label class="field">input via<select value=${mode} onChange=${(e) => setMode(e.target.value)}>
          <option value="stdin">stdin</option><option value="file">file</option><option value="arg">argument</option></select></label>
        <label class="field">compare<select value=${compare} onChange=${(e) => setCompare(e.target.value)}>
          <option value="status">accept / reject / crash</option><option value="output">also the output bytes</option></select></label>
        <label class="field" style="width:120px">inputs<input type="number" min="1" max="100000" value=${iters} onInput=${(e) => setIters(e.target.value)} /></label>
        ${seeds.length ? html`<label class="cx-chk" style="align-self:center"><input type="checkbox" checked=${useSeeds} onChange=${(e) => setUseSeeds(e.target.checked)} />seed with the ${plural(seeds.length, "uploaded seed")}</label>` : null}
        <button class="btn primary sm" disabled=${picked.length < 2 || (R.diff && R.diff.running)} title=${picked.length < 2 ? "pick at least two implementations" : ""}
          onClick=${() => run("diff", "diff_test", { caseId, params: { target_ids: picked, mode, compare, iterations: Number(iters) || 2000,
            ...(useSeeds && seeds.length ? { seed_shas: seeds.map((x) => x.sha256) } : {}) } })}>Compare</button>
      </div>
      ${ts.length < 2 ? html`<div class="dim" style="font-size:12px">Needs at least two targets in the case.</div>` : null}
      <${RunStatus} st=${R.diff} what="Differential test" cancel=${() => stage.cancel("diff")} />
      <${ScanResult} kind="diff" st=${R.diff} />
    </section>`;
}

function ScanResult({ kind, st }) {
  if (!st || st.running || st.error) return null;
  const r = st.data;
  if (!r || (typeof r === "object" && !Object.keys(r).length)) return html`<div class="cx-note">The stage returned no result record — its reason is on the Run console.</div>`;
  if (r.applicable === false || r.supported === false) return html`<div class="cx-note">${r.note || "Not applicable here."}</div>`;
  if (kind === "variant") {
    const res = r.results || [];
    return html`<div class="cx-res">
      <div class="muted">${r.function} from ${r.reference} — ${r.matched} of ${plural(res.length, "target")} match.${r.note ? " " + r.note : ""}</div>
      ${res.map((x) => html`<div class="cx-rrow">
        ${!x.scanned ? html`<span class="chip">not scanned</span> <span class="mono">${x.filename}</span> <span class="dim">${x.note}</span>`
          : (x.hits || []).length ? html`<span class="chip cx-amb">match</span> <span class="mono">${x.filename}</span> — <span class="mono">${x.hits[0].name || "(unnamed)"} @ ${x.hits[0].addr}</span>, similarity ${x.hits[0].similarity}${x.hits.length > 1 ? ` (+${x.hits.length - 1} more)` : ""}`
          : html`<span class="chip">no match</span> <span class="mono">${x.filename}</span> <span class="dim">(${x.functions} functions)</span>`}</div>`)}
    </div>`;
  }
  if (kind === "weggli") {
    const fs = r.findings || [];
    return html`<div class="cx-res">
      <div class="muted">${plural(fs.length, "pattern")} matched over ${r.queries_run} queries${fs.length ? " — filed as candidate findings (see Proof)" : ""}.${r.note ? " " + r.note : ""}</div>
      ${fs.map((f) => html`<div class="cx-rrow" title=${f.why}><span class="chip">${f.severity}</span> <span class="mono">${f.cwe}</span> ${f.name} ×${f.count}:${" "}<span class="mono dim">${(f.files || []).slice(0, 4).join(", ")}${(f.files || []).length > 4 ? ` (+${f.files.length - 4} more)` : ""}</span></div>`)}
    </div>`;
  }
  if (kind === "hypo") {
    if (r.proposed == null) return html`<div class="cx-note">${r.note || "The hunt finished; its record is on the Run console."}</div>`;
    const kinds = Object.entries(r.by_kind || {}).sort((a, b) => b[1] - a[1]);
    return html`<div class="cx-res">
      <div class=${"cx-verdict " + (r.confirmed ? "ok" : "")}><b>${r.confirmed || 0} ${r.confirmed === 1 ? "hypothesis" : "hypotheses"} confirmed</b> — ${r.proposed} proposed, ${r.solved} solved (${r.mode || "auto"} input, ${r.budget_s} s).${r.note ? " " + r.note : ""}</div>
      ${kinds.length ? html`<div class="dim">${kinds.map(([k, n]) => `${k} ×${n}`).join(" · ")}</div>` : null}
      ${r.error ? html`<div class="cx-note warn">${r.error}</div>` : null}
    </div>`;
  }
  const ds = r.discrepancies || [], inc = Object.entries(r.inconclusive || {});
  return html`<div class="cx-res">
    <div class=${"cx-verdict " + (r.compared ? (ds.length ? "no" : "ok") : "")}>${r.execs} input(s), ${r.delta_diversity} distinct behaviour combination(s), ${plural(ds.length, "disagreement")}.${r.note ? " " + r.note : ""}</div>
    ${inc.length ? html`<div class="dim">Inconclusive runs (never started or timed out — not counted): ${inc.map(([n, c]) => `${n} ×${c}`).join(", ")}</div>` : null}
    ${ds.slice(0, 40).map((x) => html`<div class="cx-rrow"><b>${x.kind}</b> on <code class="mono">${String(x.input).slice(0, 48)}${String(x.input).length > 48 ? "…" : ""}</code> —${" "}<span class="mono dim">${Object.entries(x.partitions || {}).map(([o, names]) => `[${o}] ${names.join(", ")}`).join("  ")}</span></div>`)}
    ${ds.length > 40 ? html`<div class="dim">+${ds.length - 40} more disagreements</div>` : null}
  </div>`;
}

// ── Diff ─────────────────────────────────────────────────────────────────────────────────
// A finding's identity across two builds: CWE + its title with the build-specific parts (addresses,
// fcn./sub_ names, a trailing parenthetical) normalized. Cutting the title at the first "-" or ":"
// made every "Out-of-bounds ..." one key, and a Map kept one finding per key.
const diffKey = (f) => `${f.cwe || "?"}::${String(f.title || "").replace(/\s*\([^()]*\)\s*$/, "")
  .replace(/\b(?:0x[0-9a-f]+|fcn\.[0-9a-f]+|sub_[0-9a-f]+)\b/gi, "#").replace(/\s+/g, " ").trim().toLowerCase()}`;
function groupBy(fs, key) {
  const m = new Map();
  for (const f of fs) { const k = key(f); if (!m.has(k)) m.set(k, []); m.get(k).push(f); }
  return m;
}
function diffRowVerdict(r) {
  if (r.error) return "skipped (" + r.error + ")";
  if (r.method) {
    const how = r.method === "breakpoint" ? `${r.win || "win"} reached` : `win output "${r.marker || "marker"}"`;
    return r.reproduced ? `win reproduces — ${how}` : "fixed — win no longer reproduces";
  }
  return r.reproduced ? "still faults (" + (r.signal || "crash") + ")" : "no fault";
}
function patchMap(f) {
  for (const e of f.evidence || []) {
    if (e && e.channel === "patch-diff-map") { const m = parseMaybe(e.detail); if (m) return m; }
  }
  return null;
}

function DiffView({ targets, tid, findings, stage, patchLeads, index, openFn, openFinding }) {
  const ts = targets;
  const other = ts.find((t) => t.id !== tid);
  const [a, setA] = useState(other ? other.id : tid);
  const [b, setB] = useState(tid);
  const [maxLeads, setMaxLeads] = useState("12");
  const name = (id) => (ts.find((x) => x.id === id) || {}).filename || id;
  // A = the vulnerable baseline (its PoCs are replayed), B = the patched candidate. Same-key
  // findings pair up one to one; the surplus on a side is what was fixed / what is new.
  const rows = useMemo(() => {
    const ga = groupBy(findings.filter((f) => f.target_id === a && !isNoise(f)), diffKey);
    const gb = groupBy(findings.filter((f) => f.target_id === b && !isNoise(f)), diffKey);
    const out = [];
    for (const [k, xs] of ga) {
      const ys = gb.get(k) || [];
      xs.forEach((f, i) => out.push(i < ys.length ? { d: "same", f, g: ys[i], a: f.state, b: ys[i].state } : { d: "fixed", f, a: f.state, b: null }));
    }
    for (const [k, ys] of gb) {
      const n = (ga.get(k) || []).length;
      ys.slice(n).forEach((f) => out.push({ d: "new", f, a: null, b: f.state }));
    }
    const o = { fixed: 0, new: 1, same: 2 };
    return out.sort((x, y) => o[x.d] - o[y.d]);
  }, [findings, a, b]);
  const R = stage.runs;
  const pd = R.patch, pv = R.pocdiff;
  const same = a === b;
  const nF = rows.filter((r) => r.d === "fixed").length, nN = rows.filter((r) => r.d === "new").length;
  return html`
    ${patchLeads.length ? html`<section class="panel pad">
      <h2>Patch-diff leads on this target <span class="dim" style="font-weight:400;font-size:12.5px">${patchLeads.length}</span></h2>
      <div class="muted cx-sub">Functions whose body changed against a baseline build — where a security fix, and the bug it fixes, usually lives. Leads, not proven weaknesses.</div>
      <div class="cx-table" role="table">
        <div class="cx-tr pd head" role="row"><span>function</span><span>likely</span><span>blocks</span><span>insns</span><span>new callees</span></div>
        ${patchLeads.map((f) => {
          const m = patchMap(f) || {};
          const fn = index.at(f.function_addr);
          return html`<div class="cx-tr pd" role="row">
            <span>${fn ? html`<button class="xref" onClick=${() => openFn(fn.id, f.function_addr)}>${m.name || fn.name}</button>` : html`<span class="mono">${m.name || f.function_addr}</span>`}
              <button class="xref" style="margin-left:8px;color:var(--tx3)" onClick=${() => openFinding(f.id)}>finding</button></span>
            <span class="mono">${m.exploit_class || ""}${m.likely_cwe || f.cwe ? ` · ${m.likely_cwe || f.cwe}` : ""}</span>
            <span class="mono">${m.blocks ? m.blocks.join(" → ") : ""}</span>
            <span class="mono">${m.insns ? m.insns.join(" → ") : ""}</span>
            <span class="mono dim">${(m.new_callees || []).join(", ")}</span></div>`;
        })}
      </div></section>` : null}
    <section class="panel pad" style="display:flex;flex-direction:column;gap:10px">
      <h2>Compare two builds</h2>
      ${ts.length < 2 ? html`<div class="muted" style="font-size:13px">Add a second build of this program to the case to compare — lykos diffs the findings,
          localizes the functions that changed (patch-diff) and, when a version has a working PoC, re-runs it against the other to confirm a fix.</div>` : html`
      <div class="cx-form">
        <label class="field">A — vulnerable (baseline, its PoCs are replayed)<select value=${a} onChange=${(e) => setA(e.target.value)}>${ts.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}</select></label>
        <span class="dim" style="align-self:center">→</span>
        <label class="field">B — patched (candidate)<select value=${b} onChange=${(e) => setB(e.target.value)}>${ts.map((t) => html`<option value=${t.id}>${t.filename}</option>`)}</select></label>
        <label class="field" style="width:110px" title="at most this many changed functions are filed as leads, highest-ranked first">max leads<input type="number" min="1" max="500" value=${maxLeads} onInput=${(e) => setMaxLeads(e.target.value)} /></label>
        <button class="btn sm" disabled=${same || (pd && pd.running)}
          title="localize the functions whose body changed between A and B, and file them as leads on B that the search then steers at (N-day)"
          onClick=${() => stage.start("patch", "patch_diff", { targetId: b, params: { baseline_target_id: a, max_leads: Math.max(1, Number(maxLeads) || 12) } }, { a, b })}>Find changed functions</button>
        <button class="btn primary sm" disabled=${same || (pv && pv.running)}
          onClick=${() => stage.start("pocdiff", "poc_diff", { targetId: b, params: { baseline_target_id: a } }, { a, b })}>Verify fix — re-run A's PoCs on B</button>
      </div>
      ${same ? html`<div class="dim" style="font-size:12px">Pick two different builds.</div>` : null}
      <${RunStatus} st=${pd} what="Patch-diff" cancel=${() => stage.cancel("patch")} />
      ${pd && !pd.running && !pd.error ? html`<div class="cx-note">${(() => {
        const r = pd.data || {};
        const pair = pd.meta ? `${name(pd.meta.a)} → ${name(pd.meta.b)}: ` : "";
        if (r.applicable === false) return pair + (r.note || "not applicable");
        if (!Object.keys(r).length) return pair + "the stage returned no result record — its reason is on the Run console.";
        if ((r.leads || 0) > 0) return `${pair}${plural(r.leads, "changed function")} localized as leads (listed above); the search now steers at them.`;
        if ((r.changed || 0) > 0) return `${pair}${plural(r.changed, "function")} changed, but none carried a usable address to steer at.`;
        return `${pair}no changed functions between these builds (or one side is not disassembled yet).`;
      })()}</div>` : null}
      <${RunStatus} st=${pv} what="Fix verification" cancel=${() => stage.cancel("pocdiff")} />
      ${pv && !pv.running && !pv.error ? (() => {
        const r = pv.data || {};
        const A = pv.meta ? name(pv.meta.a) : "A", B = pv.meta ? name(pv.meta.b) : "B";
        if (r.applicable === false || !Object.keys(r).length) return html`<div class="cx-note">${r.note || "Nothing to verify."}</div>`;
        return html`<div class=${"cx-verdict " + (r.fixed ? "ok" : "no")}>
          ${r.fixed ? `Fixed — none of ${A}'s ${r.checked} PoC input(s) reproduce against ${B}`
            : `Still vulnerable — ${r.reproduced}/${r.checked} PoC input(s) still reproduce against ${B}`}
          ${(r.results || []).map((x) => html`<div class="mono" style="font-size:12px">${x.level} · ${x.cwe || "input"} — ${diffRowVerdict(x)}</div>`)}</div>`;
      })() : null}
      ${!same ? html`<div class="row-c" style="gap:12px;font-size:12.5px">
        <span class="chip on">${nF} fixed</span><span class="chip cx-amb">${nN} new</span><span class="dim">${rows.length - nF - nN} unchanged · noise excluded</span></div>
      ${rows.length ? html`<div class="cx-table" role="table">
        <div class="cx-tr df head" role="row"><span>Δ</span><span>CWE</span><span>finding</span><span title="A — vulnerable">${name(a)}</span><span title="B — patched">${name(b)}</span></div>
        ${rows.map((r) => html`<div class=${"cx-tr df " + r.d} role="row">
          <span><span class=${"chip" + (r.d === "fixed" ? " on" : r.d === "new" ? " cx-amb" : "")}>${r.d}</span></span>
          <span class="mono">${(r.f.cwe || "").replace(/^CWE-/, "")}</span>
          <span><button class="xref" style="font-family:inherit;font-size:13px;color:var(--tx)" onClick=${() => openFinding((r.d === "new" || !r.g ? r.f : r.g).id)}>${(r.f.title || "").replace(/\s*\(.*$/, "")}</button></span>
          <span class="mono dim">${r.a || "—"}</span><span class="mono dim">${r.b || "—"}</span></div>`)}
      </div>` : html`<div class="dim">Neither build has findings yet.</div>`}` : null}`}
    </section>`;
}

// ── Classes (heap / taint / CVE) ─────────────────────────────────────────────────────────
function ClassesView({ classes, index, openFn, openFinding }) {
  const groups = [
    ["heap", "Heap", "Heap primitives found by tracing the target's allocator — the seeds for tcache poisoning and arbitrary write."],
    ["taint", "Taint", "Attacker-controlled data flows: values from untrusted input that reach a dangerous sink or a computed pointer."],
    ["cve", "Known CVEs", "Known-CVE matches from fingerprinting this binary's components against the offline vulnerability database."],
  ].filter(([k]) => classes[k].length);
  if (!groups.length) return html`<${Empty}>No heap, taint or known-CVE findings on this target.</${Empty}>`;
  return groups.map(([k, l, why]) => html`<section class="panel" style="overflow:hidden">
    <div class="pad" style="padding-bottom:8px"><h2>${l} <span class="dim" style="font-weight:400;font-size:12.5px">${classes[k].length}</span></h2>
      <div class="muted cx-sub">${why}</div></div>
    ${classes[k].map((f) => {
      const fn = fnOfFinding(f, index);
      return html`<div class=${"lead" + (isNoise(f) ? " cx-noise" : "")} style="cursor:default">
        <span class="mono dim" style="flex:none;width:86px;font-size:11.5px">${f.cwe || "—"}</span>
        <span style="flex:1 1 auto;min-width:0;display:flex;flex-direction:column;text-align:left">
          <button class="xref" style="font:inherit;font-size:13.5px;color:var(--tx)" onClick=${() => openFinding(f.id)}>${f.title}</button>
          <span class="dim" style="font-size:11.5px">${[f.state, f.stage_label || f.detector, f.severity, isNoise(f) ? "flagged as noise" : null].filter(Boolean).join(" · ")}</span></span>
        ${fn ? html`<button class="btn sm" onClick=${() => openFn(fn.id, f.site_addr || null)}>Code</button>` : null}
      </div>`;
    })}</section>`);
}
