// Thin state layer over the (unchanged) api.js parity client: load a case, its targets, and the
// per-target findings + pocs the spine renders. No framework state magic -- a plain object + a
// subscribe callback the shell re-renders on.
import { api } from "../app/api.js";

export const store = {
  cases: [], caseId: null, targets: [], targetId: null,
  target: null,                 // full target detail (mitigations, arch, hashes…)
  advice: null,                 // invocation shape, decompiled count, headline
  findings: [], pocs: [], selectedId: null,
  view: "overview",             // "overview" (binary) | "finding"
  filter: "all",                // findings filter
  loading: false, error: null,
  _subs: new Set(),
};

export function setView(v) { store.view = v; emit(); }
export function setFilter(f) { store.filter = f; emit(); }

export function selectFinding(id) { store.selectedId = id; store.view = "finding"; emit(); }

export function subscribe(fn) { store._subs.add(fn); return () => store._subs.delete(fn); }
function emit() { for (const fn of store._subs) fn(); }

export async function loadCases() {
  try {
    const cases = await api.listCases();
    store.cases = Array.isArray(cases) ? cases : (cases.cases || []);
    if (!store.caseId && store.cases[0]) await selectCase(store.cases[0].id);
    else emit();
  } catch (e) { store.error = String(e); emit(); }
}

export async function selectCase(caseId) {
  store.caseId = caseId; store.targets = []; store.targetId = null;
  store.findings = []; store.pocs = []; emit();
  try {
    const targets = await api.listTargets(caseId);
    store.targets = Array.isArray(targets) ? targets : (targets.targets || []);
    if (store.targets[0]) await selectTarget(store.targets[0].id);
    else emit();
  } catch (e) { store.error = String(e); emit(); }
}

export async function selectTarget(targetId) {
  store.targetId = targetId; store.loading = true; store.error = null;
  store.target = null; store.advice = null; store.selectedId = null; store.view = "overview"; emit();
  try {
    const [target, advice, findings, pocs] = await Promise.all([
      api.getTarget(targetId).catch(() => null),
      api.advice(targetId).catch(() => null),
      api.targetFindings(targetId).catch(() => []),
      api.pocs(targetId).catch(() => []),
    ]);
    store.target = target;
    store.advice = advice;
    store.findings = Array.isArray(findings) ? findings : (findings.findings || []);
    store.pocs = Array.isArray(pocs) ? pocs : (pocs.pocs || []);
    store.selectedId = store.findings[0] ? store.findings[0].id : null;
  } catch (e) { store.error = String(e); }
  store.loading = false; emit();
}

export function artifactUrl(sha) { return `/artifacts/${sha}`; }

// Fetch raw artifact bytes (a PoC payload) for the hexdump, cached by sha.
const _bytesCache = new Map();
export async function fetchBytes(sha) {
  if (!sha) return null;
  if (_bytesCache.has(sha)) return _bytesCache.get(sha);
  try {
    const r = await fetch(artifactUrl(sha));
    if (!r.ok) return null;
    const b = new Uint8Array(await r.arrayBuffer());
    _bytesCache.set(sha, b);
    return b;
  } catch (e) { return null; }
}
