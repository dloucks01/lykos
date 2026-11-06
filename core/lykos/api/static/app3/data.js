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
        if (!stop) setSt({ targets, findings, pocs, backlog, loading: false, error: null });
      } catch (e) {
        if (!stop) setSt((o) => ({ ...o, loading: false, error: String(e.message || e) }));
      }
    })();
    return () => { stop = true; };
  }, [caseId, tick, refreshKey]);
  return { ...st, reload: () => setTick((x) => x + 1) };
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
export function rankFindings(fs, pocsByTarget) {
  return fs.slice().sort((a, b) => {
    const pa = pocsOf(a, pocsByTarget), pb = pocsOf(b, pocsByTarget);
    const la = pa.find(ran) ? lvl(pa.find(ran)) : 0, lb = pb.find(ran) ? lvl(pb.find(ran)) : 0;
    return (lb - la) || ((STATE[a.state] ?? 9) - (STATE[b.state] ?? 9)) || ((SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9));
  });
}

// The backlog entry (technique to build next) for a finding, matched on CWE + title or site.
export function backlogFor(finding, backlog) {
  const es = (backlog && backlog.entries) || [];
  return es.find((e) => e.cwe === finding.cwe && (e.title === finding.title || (e.site && e.site === finding.site_addr))) || null;
}

export const isNoise = (f) => !!(f.verification && f.verification.noise) || (f.curation && f.curation.hidden);

export function hexToInt(a) {
  if (a == null) return null;
  const n = typeof a === "number" ? a : parseInt(String(a), 16);
  return Number.isFinite(n) ? n : null;
}

// The function containing `addr` (functions: [{addr, size, ...}]) or null
export function functionAt(functions, addr) {
  const a = hexToInt(addr);
  if (a == null) return null;
  let best = null;
  for (const f of functions) {
    const s = hexToInt(f.addr), z = +f.size || 0;
    if (s != null && s <= a && a < s + Math.max(1, z) && (!best || s > hexToInt(best.addr))) best = f;
  }
  return best;
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

// Run time budgets offered when starting a run: 5 minutes, then every 10 minutes up to 2 hours.
// The value is seconds (what the autopilot API takes); the label reads as minutes / hours.
export const BUDGET_OPTIONS = [5, ...Array.from({ length: 12 }, (_, i) => (i + 1) * 10)].map((m) => ({
  secs: m * 60,
  label: m < 60 ? `${m} min` : (m % 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m / 60} h`),
}));
