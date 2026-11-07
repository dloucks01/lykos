// Case data for the Proof / Engagement / Code screens: one loader, the helpers that classify a
// finding (proven / needs a PoC / lead) and pick its best PoC. Read-only; the server is the truth.
import { useEffect, useState } from "preact/hooks";
import { api } from "../app/api.js";

const list = (r, key) => (Array.isArray(r) ? r : (r && (r[key] || Object.values(r).find(Array.isArray))) || []);

export async function getJSON(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

const EMPTY = { targets: [], findings: [], pocs: {}, backlog: null, loading: false, error: null, forCase: null };

// {targets, findings, pocs: {targetId: [...]}, backlog, loading, error, reload}
export function useCaseData(caseId, refreshKey = 0) {
  const [st, setSt] = useState({ targets: [], findings: [], pocs: {}, backlog: null, loading: true, error: null });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!caseId) return undefined;
    let stop = false;
    (async () => {
      try {
        const targets = list(await api.listTargets(caseId), "targets");
        const [findings, backlog, ...pl] = await Promise.all([
          getJSON(`/cases/${caseId}/findings`).then((r) => list(r, "findings")),
          getJSON(`/cases/${caseId}/backlog`).catch(() => null),
          ...targets.map((t) => getJSON(`/targets/${t.id}/pocs`).then((r) => list(r, "pocs")).catch(() => [])),
        ]);
        const pocs = {};
        targets.forEach((t, i) => { pocs[t.id] = pl[i]; });
        if (!stop) setSt({ targets, findings, pocs, backlog, loading: false, error: null, forCase: caseId });
      } catch (e) {
        if (!stop) setSt((o) => ({ ...(o.forCase === caseId ? o : EMPTY), loading: false,
                                   error: String(e.message || e), forCase: caseId }));
      }
    })();
    return () => { stop = true; };
  }, [caseId, tick, refreshKey]);
  // Data belongs to the case it was loaded for: on a case switch (or a failed load of an
  // unknown case) the previous case's targets/findings must not be shown under the new name.
  const cur = st.forCase === caseId ? st : { ...EMPTY, loading: !!caseId };
  return { ...cur, reload: () => setTick((x) => x + 1) };
}

export const LEVEL = { L3: 3, L2: 2, L1: 1 };
const lvl = (p) => LEVEL[String(p.level || "").replace(/^L?/, "L")] || 0;
const ran = (p) => p.verified || p.provenance === "detonated";

// The PoCs of a finding, best first: a PoC that RAN outranks a constructed one; then level.
export function pocsOf(finding, pocsByTarget) {
  const all = (pocsByTarget[finding.target_id] || []).filter((p) => p.finding_id === finding.id);
  return all.sort((a, b) => (ran(b) - ran(a)) || (lvl(b) - lvl(a)));
}

// proven: a PoC ran (or the finding is poc-backed); needs: real but no PoC yet; lead: unverified
export function laneOf(finding, pocs) {
  if (finding.state === "poc-backed" || pocs.some(ran)) return "proven";
  if (finding.state === "confirmed" || finding.state === "corroborated") return "needs";
  return "lead";
}

export function bestLevel(pocs) {
  const p = pocs.find(ran);
  return p ? `L${lvl(p)}` : null;
}

const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const STATE = { "poc-backed": 0, confirmed: 1, corroborated: 2, candidate: 3 };
// Best-first. The sort key is computed once per finding (pocsOf filters + sorts; calling it from
// the comparator made a 500-finding rank O(n log n) PoC scans).
// within a proof level and state, the tool's own triage orders the work: what is reachable and
// attacker-tainted first, what is off the attack surface last
const DISP_RANK = { drivable: 0, "needs-technique": 1, untainted: 2, "off-surface": 3, "false-positive": 4 };
export function rankFindings(fs, pocsByTarget) {
  const key = new Map(fs.map((f) => {
    const r = pocsOf(f, pocsByTarget).find(ran);
    const t = triageOf(f);
    return [f, [r ? lvl(r) : 0, STATE[f.state] ?? 9, t ? (DISP_RANK[t.kind] ?? 2) : 2, SEV[f.severity] ?? 9]];
  }));
  return fs.slice().sort((a, b) => {
    const x = key.get(a), y = key.get(b);
    return (y[0] - x[0]) || (x[1] - y[1]) || (x[2] - y[2]) || (x[3] - y[3]);
  });
}

// The backlog entry (technique to build next) for a finding. The dedup key is the identity both
// sides share; CWE + title alone matched e.g. every "Non-literal size arithmetic into realloc()"
// finding to ONE entry's technique (44 of 46 matches wrong on FreeRDP). Title/site is only the
// fallback for an entry that carries no key.
export function backlogFor(finding, backlog) {
  const es = (backlog && backlog.entries) || [];
  if (finding.dedup_key) {
    const hit = es.find((e) => e.dedup_key === finding.dedup_key);
    if (hit) return hit;
  }
  return es.find((e) => !e.dedup_key && e.cwe === finding.cwe
    && (e.title === finding.title || (e.site && e.site === finding.site_addr))) || null;
}

// The finding-triage stage's resolved disposition (evidence channel "triage": "<kind>: why").
// drivable = reachable + attacker-tainted (the PoC worklist); false-positive = the tool disproved it.
export function triageOf(f) {
  const ev = f.evidence || [];
  for (let i = ev.length - 1; i >= 0; i--) {
    const e = ev[i];
    if (!e || e.channel !== "triage") continue;
    const m = /^([a-z][a-z-]*):\s*(.*)$/s.exec(String(e.detail || ""));
    return m ? { kind: m[1], detail: m[2] } : null;
  }
  return null;
}

// A source finding's location. Source findings carry no address: the site lives in the
// per-site detail ("audin_main.c:251"), the dedup key, the title, or the evidence prose.
// Paths are tree-relative or bare basenames -- never a server path.
export const SRC_LOC = /([\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|cs|go|rs|py|java|js|ts)):(\d+)/;
// the line-less form some source detectors write: "path/file.c: fn() <what>" (the server's
// source-file?finding= resolves its exact line)
const SRC_FILE_FN = /([\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|cs|go|rs|py|java|js|ts)):\s+([A-Za-z_]\w*)\(\)/;
export function srcLocOf(f) {
  const ev = (f.evidence || []).filter((e) => e && e.channel !== "triage").map((e) => String(e.detail || ""));
  const cands = [...(f.sites || []).map((s) => s && s.detail), f.dedup_key, f.title, ...ev];
  for (const c of cands) {
    const m = SRC_LOC.exec(String(c || ""));
    if (!m) continue;
    // the enclosing function, as the source detectors write it: "... in fn()" or "file:N: fn() ..."
    let fn = null;
    const tail = m[1].split("/").pop() + ":" + m[2];
    for (const d of ev) {
      if (!d.includes(tail)) continue;
      const g = /\bin ([A-Za-z_]\w*)\(\)/.exec(d) || /:\d+:\s*([A-Za-z_]\w*)\(\)/.exec(d);
      if (g) { fn = g[1]; break; }
    }
    return { path: m[1], line: +m[2], fn };
  }
  for (const d of ev) {
    const m = SRC_FILE_FN.exec(d);
    if (m) return { path: m[1], line: null, fn: m[2] };
  }
  return null;
}
// "path:line", or the path alone when only the file + function are known
export const srcText = (src) => (src ? (src.line ? `${src.path}:${src.line}` : src.path) : "");

// Proof-screen state that outlives the screen: the filters (kept across open-a-finding and Back)
// and the order the findings were last shown in (the detail view's previous / next).
export const proofNav = { caseId: null, ui: {}, order: [] };

export const isNoise = (f) => !!(f.verification && f.verification.noise) || (f.curation && f.curation.hidden);

export function hexToInt(a) {
  if (a == null) return null;
  const n = typeof a === "number" ? a : parseInt(String(a), 16);
  return Number.isFinite(n) ? n : null;
}

// The function containing `addr` (functions: [{addr, size, ...}]) or null: the containing
// function with the highest start. A binary search over the sorted starts, built once per list
// (a linear scan per row cost 500 rows x 30k functions on every keystroke).
const FN_INDEX = new WeakMap();
function fnIndex(functions) {
  let ix = FN_INDEX.get(functions);
  if (!ix) {
    ix = [];
    for (const f of functions) { const s = hexToInt(f.addr); if (s != null) ix.push([s, f]); }
    ix.sort((x, y) => x[0] - y[0]);
    FN_INDEX.set(functions, ix);
  }
  return ix;
}
export function functionAt(functions, addr) {
  const a = hexToInt(addr);
  if (a == null || !functions || !functions.length) return null;
  const ix = fnIndex(functions);
  let lo = 0, hi = ix.length - 1, at = -1;
  while (lo <= hi) { const m = (lo + hi) >> 1; if (ix[m][0] <= a) { at = m; lo = m + 1; } else hi = m - 1; }
  for (let i = at; i >= 0 && i > at - 64; i--) {
    const [s, f] = ix[i];
    if (a < s + Math.max(1, +f.size || 0)) return f;
  }
  return null;
}

// The start arguments for api.startBackground after the budget: [overrides, converge, skipStages],
// from the run-options module (results.js) when it loaded. Seeds default to ALL of the case's
// seeds, as the previous workbench did -- the server uses none when seed_shas is absent.
export async function startSettings(mod, opts, caseId) {
  if (!mod || !mod.buildRunSettings) return [{}, !!(opts && opts.converge), []];
  let seeds = null;
  try { const r = await api.seeds(caseId); seeds = Array.isArray(r) ? r : (r && (r.seeds || Object.values(r).find(Array.isArray))) || []; }
  catch (_e) { seeds = null; }
  if (mod.saveRunOptions) mod.saveRunOptions(opts);
  const st = mod.buildRunSettings(opts, seeds);
  return [st.overrides || {}, !!(opts && opts.converge), st.skipStages || []];
}

// Run time budgets offered when starting a run: 5, 10, 15 (the CLI default) minutes, then every
// 10 minutes up to 2 hours.
// The value is seconds (what the autopilot API takes); the label reads as minutes / hours.
export const BUDGET_OPTIONS = [5, 10, 15, ...Array.from({ length: 11 }, (_, i) => (i + 2) * 10)].map((m) => ({
  secs: m * 60,
  label: m < 60 ? `${m} min` : (m % 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m / 60} h`),
}));
