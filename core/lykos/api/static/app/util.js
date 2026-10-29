// Shared vocabulary and formatting. The ranking rules here are the whole point of the
// results-first UI: a demonstrated defect outranks a guessed one, always, and the list is
// sorted by that truth, not by discovery order.

// A finding's confidence ladder, best first. `poc-backed` means a reproducer ran and the
// signal fired; `candidate` means one detector flagged a pattern and nothing corroborated it.
export const STATE_ORDER = ["poc-backed", "confirmed", "corroborated", "candidate"];
export const STATE_RANK = Object.fromEntries(STATE_ORDER.map((s, i) => [s, i]));

export const STATE_LABEL = {
  "poc-backed": "PoC-backed",
  confirmed: "Confirmed",
  corroborated: "Corroborated",
  candidate: "Candidate",
};

// A short elapsed string ("3s", "2m14s", "1h03m") for a pipeline stage's duration. Used so the
// plan panel can show how long each stage has run -- a running stage with a growing elapsed is
// visibly alive, and a finished stage shows what it cost, so a hang is never mistaken for work.
export function fmtElapsed(sec) {
  if (sec == null || !isFinite(sec) || sec < 0) return "";
  const s = Math.round(sec);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), r = s % 60;
  if (m < 60) return `${m}m${String(r).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  return `${h}h${String(m % 60).padStart(2, "0")}m`;
}

// Plain-language gloss shown under the badge so a reader who is not steeped in the pipeline
// knows what the state actually claims.
export const STATE_GLOSS = {
  "poc-backed": "A reproducer ran and the fault fired. This is real.",
  confirmed: "Multiple independent channels agree on this defect.",
  corroborated: "A second signal supports the initial detection.",
  candidate: "One detector flagged a pattern. Not yet demonstrated.",
};

export const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
export const SEV_RANK = Object.fromEntries(SEV_ORDER.map((s, i) => [s, i]));

// Rank findings: demonstrated before guessed, then severity, then more evidence.
export function rankFindings(findings) {
  return [...findings].sort((a, b) => {
    const sa = STATE_RANK[a.state] ?? 99, sb = STATE_RANK[b.state] ?? 99;
    if (sa !== sb) return sa - sb;
    const va = SEV_RANK[(a.severity || "").toLowerCase()] ?? 99;
    const vb = SEV_RANK[(b.severity || "").toLowerCase()] ?? 99;
    if (va !== vb) return va - vb;
    return (b.proven_sites || 0) - (a.proven_sites || 0) || (b.site_count || 0) - (a.site_count || 0);
  });
}

export function isDemonstrated(f) {
  return f.state === "poc-backed" || f.state === "confirmed";
}

// Collapse near-duplicate findings so a target that crashed at forty addresses reads as one
// defect with forty sites, not forty cards. A demonstrated-with-its-own-PoC finding (poc-backed)
// is ALWAYS kept on its own -- it has a distinct reproducer worth seeing. Everything else is
// grouped by (cwe, state, detector): the first is the representative and carries a `group_count`
// and a summed `site_count`, the rest fold in. Order is preserved (callers rank first).
// Signal + located-ness of a crash finding, from its dedup_key "dynamic-crash:<SIG>[:<pc>]".
function crashKeyParts(f) {
  const k = f && f.dedup_key;
  if (typeof k !== "string" || !k.startsWith("dynamic-crash:")) return null;
  const rest = k.slice("dynamic-crash:".length).split(":");
  return { signal: rest[0], located: rest.length > 1 };
}

export function dedupeFindings(findings) {
  const list = findings || [];
  // A control-flow hijack faults at an attacker-controlled PC that the tracer can sometimes not
  // resolve, so ONE overflow shows up as both a LOCATED analysed finding
  // ("dynamic-crash:SIGSEGV:<pc>") and a bare UNLOCATED "Reproduced crash"
  // ("dynamic-crash:SIGSEGV"). They are the same defect -- drop the bare unlocated one when a
  // located, analysed (poc-backed / root-caused) finding of the same signal exists.
  const hasEffects = (f) => (f.evidence || []).some((e) => e && e.channel === "effects");
  const isHijack = (f) => /control-flow hijack|remote code execution/i.test(f.title || "")
    || (f.evidence || []).some((e) => e && e.channel === "effects" && /"kind"\s*:\s*"rce"/.test(e.detail || ""));
  // Signals whose defect is a CONTROL-FLOW HIJACK: the fault PC is attacker-controlled (and the
  // tracer sometimes cannot resolve it at all), so it is not a reliable discriminator -- every
  // other same-signal bare crash is the same overflow landing at a different PC. Collapse those
  // bare crashes into the analysed hijack finding. A non-hijack SIGSEGV (e.g. a NULL deref at a
  // fixed instruction) keeps its distinct fault PC and is never folded.
  const hijackSignals = new Set();
  for (const f of list) {
    const p = crashKeyParts(f);
    if (p && isHijack(f)) hijackSignals.add(p.signal);
  }
  // Memory-corruption CWEs: a stack/heap overflow reaches these. When the same overflow's
  // attacker-controlled fault lands at different PCs it is re-classified each time (return-address
  // control -> CWE-787/121, a corrupted saved RBP making `leave` fault -> "OOB read" CWE-125),
  // so one bug shows up as several poc-backed findings. If the signal has a hijack, fold all its
  // memory-corruption crash findings into the single strongest one. A NULL deref (CWE-476) or
  // arithmetic fault is NOT in this set and keeps its own finding.
  const MEMCORRUPT = new Set(["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125",
    "CWE-126", "CWE-127", "CWE-787", "CWE-415", "CWE-416"]);
  const score = (f) => (f.state === "poc-backed" ? 100 : f.state === "confirmed" ? 50 : 10)
    + (isHijack(f) ? 20 : 0) + (hasEffects(f) ? 5 : 0)
    + ({ critical: 4, high: 3, medium: 2, low: 1 }[f.severity] || 0);
  const bestByCorruptSig = new Map();     // signal -> the representative finding to keep
  for (const f of list) {
    const p = crashKeyParts(f);
    if (!p || !hijackSignals.has(p.signal) || !MEMCORRUPT.has(f.cwe)) continue;
    const cur = bestByCorruptSig.get(p.signal);
    if (!cur || score(f) > score(cur)) bestByCorruptSig.set(p.signal, f);
  }
  const kept = list.filter((f) => {
    const p = crashKeyParts(f);
    if (!p) return true;
    // a memory-corruption manifestation of a hijack overflow: fold the UNANALYSED ones into a
    // single representative, but NEVER drop a poc-backed finding -- it owns a distinct reproducer,
    // and two independent overflows that share a signal (each poc-backed) must both survive.
    // Hiding a real second defect is worse than showing a possibly-redundant card. The server
    // report does no folding, so dropping one here also disagreed with the report/API.
    if (hijackSignals.has(p.signal) && MEMCORRUPT.has(f.cwe)) {
      if (f.state === "poc-backed") return true;
      return bestByCorruptSig.get(p.signal) === f;
    }
    // a bare crash with no analysis of its own, on a hijack signal: drop it
    const bare = f && !hasEffects(f) && f.detector !== "root_cause";
    return !(bare && hijackSignals.has(p.signal));
  });

  const out = [];
  const byKey = new Map();
  for (const f of kept) {
    if (f.state === "poc-backed") { out.push(f); continue; }   // never merge a distinct PoC
    const key = `${f.cwe}|${f.state}|${f.detector || ""}`;
    const rep = byKey.get(key);
    if (!rep) {
      const clone = { ...f, group_count: 1, site_count: f.site_count || 1, group_ids: [f.id] };
      byKey.set(key, clone);
      out.push(clone);
    } else {
      rep.group_count += 1;
      rep.group_ids.push(f.id);   // so a curation of the CARD covers every finding folded into it
      rep.site_count = (rep.site_count || 1) + (f.site_count || 1);
      rep.proven_sites = (rep.proven_sites || 0) + (f.proven_sites || 0);
    }
  }
  return out;
}

// The PoCs to show on a finding's card. A PoC belongs to the finding it proves (finding_id).
// A PoC with no finding_id proved a crash not yet filed as its own finding; it is attached to
// the top demonstrated finding so the bundle is never orphaned, never duplicated on every card.
export function pocsForFinding(pocs, findingId, topDemoId) {
  return (pocs || []).filter(
    (p) => p.finding_id === findingId || (!p.finding_id && findingId === topDemoId));
}

export function fmtBytes(n) {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(1)} ${u[i]}`;
}

export function fmtTime(ts) {
  if (!ts) return "";
  const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
  if (isNaN(d)) return String(ts);
  return d.toLocaleString();
}

export function shortHash(h, n = 12) {
  if (!h) return "";
  return h.length > n ? `${h.slice(0, n)}…` : h;
}

// Run status → a small visual token. Terminal-good, terminal-bad, and in-flight.
export const RUN_TERMINAL_OK = new Set(["done", "skipped"]);
export const RUN_TERMINAL_BAD = new Set(["error", "failed", "cancelled", "canceled"]);
export function runTone(status) {
  if (RUN_TERMINAL_OK.has(status)) return "ok";
  if (RUN_TERMINAL_BAD.has(status)) return "bad";
  return "run";
}

// Human labels for the pipeline stages Autopilot drives, for the progress log.
export const STAGE_LABEL = {
  ingest_triage: "Triage",
  disassemble: "Disassemble",
  detect_cwe: "Static detectors",
  fuzz: "Fuzzing",
  coverage_fuzz: "Coverage-guided fuzzing",
  directed_fuzz: "Directed fuzzing",
  concolic: "Concolic execution",
  dynamic_run: "Dynamic run",
  root_cause: "Root-cause",
  build_poc: "Build PoC",
  poc_primitive: "PoC primitive",
  build_exploit: "Build exploit",
  cve_scan: "Known-CVE scan",
};

export function stageLabel(stage) {
  return STAGE_LABEL[stage] || (stage || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// Reconstruct the run-log rows for a REOPENED case from its run history. Reopening otherwise
// showed an empty log even though the analysis had run. One row per stage per target (the latest
// attempt, so repeated re-runs don't stack), ordered as they executed; the internal triage run
// is left out to match the live log. `targets` (optional) tags each row with its filename when a
// case holds more than one binary. Returns rows shaped like the live log's stage rows.
export function buildRunLog(runs, targets) {
  const ts = targets || [];
  const tname = Object.fromEntries(ts.map((t) => [t.id, t.filename]));
  const multi = ts.length > 1;
  const latest = {};
  for (const r of runs || []) {
    if (!r || !r.stage || r.stage === "ingest_triage") continue;
    const k = `${r.stage}:${r.target_id || ""}`;
    if (!latest[k] || (r.created_at || 0) >= (latest[k].created_at || 0)) latest[k] = r;
  }
  return Object.values(latest)
    .sort((a, b) => (a.created_at || 0) - (b.created_at || 0))
    .map((r) => ({
      kind: "stage", stage: r.stage,
      label: stageLabel(r.stage) + (multi && tname[r.target_id] ? ` · ${tname[r.target_id]}` : ""),
      status: (r.status === "running" || r.status === "queued") ? "running"
        : (r.status === "error" ? "error" : "done"),
      detail: r.status === "error" ? String(r.error || "").slice(0, 140) : undefined,
    }));
}

// ── Verdict derivation ────────────────────────────────────────────────────────────────────
// The verdict-first UI answers, per binary: what is the worst effect an attacker can DRIVE this
// binary to, is it proven, and how far did the exploit chain get? The helpers below derive that
// straight from the findings + PoCs + coverage app.js already holds -- no new API surface.

// Effect-kind severity: a worse end effect ranks higher, so "worst" is a max over this. The
// `effects` evidence channel carries a `kind` (rce/write/leak/dos/...); unknown kinds sit mid-pack.
const EFFECT_SEV = {
  rce: 6, "remote-code-execution": 6, "code-execution": 6, "arbitrary-code-execution": 6,
  "control-flow-hijack": 5, hijack: 5, "control-flow": 5,
  write: 4, "arbitrary-write": 4, "mem-write": 4, "memory-corruption": 4, "mem-corruption": 4,
  leak: 3, "info-leak": 3, "information-disclosure": 3, "oob-read": 3, disclosure: 3, read: 3,
  dos: 2, crash: 2, "denial-of-service": 2, hang: 2,
};
export function effectRank(kind) {
  const k = String(kind || "").toLowerCase();
  return EFFECT_SEV[k] != null ? EFFECT_SEV[k] : 1;
}

// The end-effects a finding carries: the `effects` evidence channel is a JSON list of
// {kind,title,status:'demonstrated'|'potential',proof}. Returns [] when absent or malformed.
export function effectsOf(finding) {
  const ev = Array.isArray(finding && finding.evidence) ? finding.evidence : [];
  const raw = (ev.find((e) => e && e.channel === "effects") || {}).detail;
  if (!raw) return [];
  try { const v = JSON.parse(raw); return Array.isArray(v) ? v : []; } catch { return []; }
}

// A PoC's exploitation level as a plain integer (L1/L2/L3 -> 1/2/3). 0 when unlevelled.
export function pocLevel(p) {
  if (!p || p.level == null) return 0;
  const n = parseInt(String(p.level).replace(/[^0-9]/g, ""), 10);
  return isNaN(n) ? 0 : n;
}

// The verdict for ONE target: its worst DEMONSTRATED effect (falling back to the worst POTENTIAL
// one, muted), the exploitation level the chain reached, whether a crash actually reproduced, and
// the proof artifacts to link when demonstrated. Derived from the case-wide findings/pocs/coverage.
export function verdictForTarget(target, findings, pocs, coverage) {
  const tid = target.id;
  const tFindings = (findings || []).filter((f) => f.target_id === tid);
  const findingIds = new Set(tFindings.map((f) => f.id));
  const demo = [], pot = [];
  for (const f of tFindings) {
    for (const e of effectsOf(f)) {
      const rec = { ...e, findingId: f.id };
      if (e.status === "demonstrated") demo.push(rec); else pot.push(rec);
    }
  }
  const worstOf = (list) => list.slice().sort((a, b) => effectRank(b.kind) - effectRank(a.kind))[0] || null;
  const worstDemo = worstOf(demo);
  const worstPot = worstOf(pot);
  const headline = worstDemo || worstPot || null;
  const status = worstDemo ? "demonstrated" : worstPot ? "potential" : "none";
  // A PoC belongs to a target through the finding it proves.
  const tPocs = (pocs || []).filter((p) => p.finding_id && findingIds.has(p.finding_id));
  // The level the chain REACHED counts verified PoCs only. A static recipe / unverified bundle
  // carries a level too (what it would reach), and counting it filled the L-ladder and printed
  // "L3" in the target rail for an exploit nothing had run -- the overstatement the reports
  // already refuse. The unverified best is kept apart as `candidateLevel`, shown as a candidate.
  const level = tPocs.filter((p) => p.verified).reduce((m, p) => Math.max(m, pocLevel(p)), 0);
  const candTop = tPocs.filter((p) => !p.verified).reduce((m, p) => Math.max(m, pocLevel(p)), 0);
  const candidateLevel = candTop > level ? candTop : 0;
  const bundlePoc = tPocs.find((p) => p.verified && p.bundle_sha) || tPocs.find((p) => p.bundle_sha) || null;
  const inputPoc = tPocs.find((p) => p.input_sha) || null;
  const crashed = tFindings.some((f) => f.state === "poc-backed") || !!worstDemo || !!inputPoc;
  const staticCount = tFindings.filter((f) => f.state !== "poc-backed").length;
  const cov = coverage && coverage[tid] && coverage[tid].pct != null ? coverage[tid].pct : null;
  return { target, headline, status, level, candidateLevel, crashed, staticCount, coverage: cov,
    bundlePoc, inputPoc };
}

// One verdict per target, in upload order. `index` is set (1-based) only for a multi-binary case,
// mirroring TargetSummary's numbering.
export function buildVerdicts(targets, findings, pocs, coverage) {
  const multi = (targets || []).length > 1;
  return (targets || []).map((t, i) => ({
    ...verdictForTarget(t, findings, pocs, coverage), index: multi ? i + 1 : null }));
}

// A live progress event's payload -> a short line under the running stage. Fuzzers report
// executions and crashes as they go; other stages report a percent and a message.
export function progressText(type, p) {
  if (!p) return "";
  if (/\.progress$/.test(type) && p.execs != null) {
    const bits = [`${Number(p.execs).toLocaleString()} execs`];
    if (p.crashes) bits.push(`${p.crashes} crash${p.crashes === 1 ? "" : "es"}`);
    if (p.corpus != null) bits.push(`corpus ${p.corpus}`);
    return bits.join(" · ");
  }
  if (type === "job.progress") {
    const pct = p.pct != null ? `${Math.round(p.pct)}% ` : "";
    return `${pct}${p.msg || ""}`.trim();
  }
  return "";
}

// --- Case Overview visualization helpers (pure; so the viz interactivity is unit-testable) ---

// Filter findings by a clicked overview segment or a cross-link. `viz` is null (no filter),
// {severity}, {cwe}, or {stage} (the provenance hop: a finding's "found by <stage>" chip, and the
// coverage ledger's class chips, narrow the list to one dimension). Returns the narrowed findings.
export function filterByViz(findings, viz) {
  if (!viz) return findings;
  if (viz.severity) return findings.filter((f) => (f.severity || "").toLowerCase() === viz.severity);
  if (viz.cwe) return findings.filter((f) => f.cwe === viz.cwe);
  if (viz.stage) return findings.filter((f) => f.stage === viz.stage);
  // Verification verdict (doc 49 spine): the prove-out shortlist / off-surface / noise triage, so
  // a verdict badge or the ledger's shortlist line filters the board to exactly those findings.
  if (viz.verdict) return findings.filter((f) => (f.verification || {}).verdict === viz.verdict);
  // Detector / impact level (the CaseOverview hub widgets): a detector chip, or a weaponization
  // ladder rung, filters the board. A finding's level is its verified PoC level, else L0.
  if (viz.detector) return findings.filter((f) => f.detector === viz.detector);
  if (viz.level) return findings.filter((f) => (f.poc_level || "L0") === viz.level);
  return findings;
}

// The weaponization ladder level reached (0..3) from a target's PoCs: L1 crash / L2 primitive /
// L3 exploit; 0 when only static findings exist. A verified PoC counts; its level is "L1".."L3".
export function maxPocLevel(pocs) {
  let lv = 0;
  for (const p of pocs || []) {
    if (!p || p.verified === false) continue;
    const m = /^L([0-3])$/.exec(p.level || "");
    if (m) lv = Math.max(lv, Number(m[1]));
  }
  return lv;
}

// Count findings into an ordered [{key,count}] histogram by a field (severity/cwe/detector),
// most-frequent first (ties keep input order). Used for the overview bars/donut.
export function histogram(findings, field) {
  const m = new Map();
  for (const f of findings || []) {
    const k = f[field] || "unknown";
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count);
}

// --- Operator curation (doc 47 P3) ---------------------------------------------------------
// The operator's verdict on a finding, carried by the server as `finding.curation` = {status,
// note, updated_at} (or null). It is the OPERATOR's judgement and is shown BESIDE the tool's state
// badge, never in place of it: marking a poc-backed finding a false positive does not lower the
// tool's L-level, and "true positive" is deliberately not called "confirmed" (the tool's two-source
// state). Labels, the list filter, and the per-status counts live here so they are unit-testable.
export const CURATION_STATUSES = ["false_positive", "true_positive", "needs_review"];
export const CURATION_LABEL = {
  false_positive: "False positive", true_positive: "True positive", needs_review: "Needs review",
};
export const CURATION_FILTERS = [
  ["hide_fp", "Hide false positives"], ["all", "All findings"], ["needs_review", "Needs review"],
  ["true_positive", "True positives"], ["false_positive", "False positives only"],
  ["uncurated", "Not yet triaged"],
];
export const curationStatus = (f) => (f && f.curation && f.curation.status) || null;

export function filterByCuration(findings, mode) {
  const list = findings || [];
  switch (mode) {
    case "all": return list;
    case "uncurated": return list.filter((f) => !curationStatus(f));
    case "false_positive": case "true_positive": case "needs_review":
      return list.filter((f) => curationStatus(f) === mode);
    case "hide_fp": default: return list.filter((f) => curationStatus(f) !== "false_positive");
  }
}

export function curationCounts(findings) {
  const c = { false_positive: 0, true_positive: 0, needs_review: 0, uncurated: 0 };
  for (const f of findings || []) {
    const s = curationStatus(f);
    if (s && s in c) c[s] += 1; else c.uncurated += 1;
  }
  return c;
}

// The function a finding lives in, from the target's recovered functions: an exact start-address
// match, else the function whose [addr, addr+size) range holds the address (a finding that only
// knows its fault / sink site). Addresses arrive as ints or hex strings; null when none contains it.
// Used to land a finding on its call-graph node and to open its code.
export function containingFunction(functions, addr) {
  const num = (x) => (x == null || x === "" ? null
    : typeof x === "number" ? x : (Number.isNaN(parseInt(x, 16)) ? null : parseInt(x, 16)));
  const a = num(addr);
  if (!functions || !functions.length || a == null) return null;
  let best = null;
  for (const f of functions) {
    const s = num(f.addr);
    if (s == null) continue;
    if (s === a) return f;
    if (f.size > 0 && s <= a && a < s + f.size && (!best || s > num(best.addr))) best = f;
  }
  return best;
}

// --- Run honesty signals (GET /cases/<id>/run-signals + the live background status) -------------
// Every way a run can be weaker than it looks, as compact chips for the run header: a target whose
// analysis ABORTED (failed, never quietly absent), a sandbox that ran rlimits-only, taint that saw
// only the ranked top-N of the reachable functions, a large binary recovered at a shallower tier,
// a crash list longer than the prove loop takes, inputs that hang the target (CWE-835), and leases
// renewed under DB write contention. Pure, so the honesty rules are unit-tested.

// The target ids whose analysis aborted: the server's signals (event log, survives a reopen) united
// with the live background status (in memory, appears the moment it happens).
export function failedTargets(signals, bg) {
  const out = new Map();
  for (const e of (signals && signals.target_errors) || []) {
    if (e && e.target_id && !out.has(e.target_id)) out.set(e.target_id, e);
  }
  for (const id of (signals && signals.failed_targets) || []) {
    if (id && !out.has(id)) out.set(id, { target_id: id });
  }
  for (const e of (bg && bg.target_errors) || []) {
    if (e && e.target_id && !out.has(e.target_id)) out.set(e.target_id, e);
  }
  return out;
}

const _ENGINE_NAME = { coverage: "coverage", net_fuzz: "network", env_fuzz: "env-var",
  fuzz: "black-box", directed: "directed", harness: "harness" };

export function runSignalChips(signals, bg, targets) {
  const sig = signals || {};
  const names = new Map((targets || []).map((t) => [t.id, t.filename]));
  const multi = (targets || []).length > 1;
  const nm = (id, fallback) => names.get(id) || fallback || (id ? String(id).slice(0, 8) : "target");
  const pre = (id, fb) => (multi ? `${nm(id, fb)}: ` : "");
  const chips = [];
  const failed = failedTargets(sig, bg);
  if (failed.size) {
    const list = [...failed.values()];
    chips.push({ key: "failed", tone: "bad",
      label: `✕ ${list.length} target${list.length === 1 ? "" : "s"} FAILED`,
      detail: list.map((e) => `${nm(e.target_id, e.filename)}: analysis aborted${e.stage ? ` in ${e.stage}` : ""}${e.error ? ` — ${e.error}` : ""}; its results are incomplete (the other targets were still analysed)`) });
  }
  const oc = sig.outcome || null;
  if (oc && oc.outcome === "error") {
    chips.push({ key: "run-error", tone: "bad", label: "✕ run errored",
      detail: [`the autopilot stopped with an error: ${oc.error || "no message"} — results are partial`] });
  }
  const iso = sig.isolation || [];
  if (iso.length) {
    const engines = [...new Set(iso.map((i) => _ENGINE_NAME[i.engine] || i.engine))];
    chips.push({ key: "iso", tone: "warn",
      label: `sandbox degraded: ${[...new Set(iso.map((i) => i.isolation))].join("/")} (${engines.join(", ")})`,
      detail: iso.map((i) => `${_ENGINE_NAME[i.engine] || i.engine}: ${i.isolation}${i.note ? ` — ${i.note}` : ""}`) });
  }
  for (const r of sig.recovery || []) {
    if (r.recovery_failed) {
      chips.push({ key: `rec-${r.target_id}`, tone: "bad", label: `${pre(r.target_id, r.filename)}recovery FAILED`,
        detail: [r.note || "the disassembler produced no program — every function-keyed detector saw nothing"] });
    } else {
      const n = (r.degradations || []).length;
      const fns = r.total_functions && r.functions != null && r.functions < r.total_functions
        ? `${r.functions}/${r.total_functions} functions` : null;
      chips.push({ key: `rec-${r.target_id}`, tone: "warn",
        label: `${pre(r.target_id, r.filename)}large binary: ${r.analysis_tier ? `tier ${r.analysis_tier}` : "partial recovery"}${fns ? ` · ${fns}` : ""}${n ? ` · ${n} degradation${n === 1 ? "" : "s"}` : ""}`,
        detail: (r.degradations && r.degradations.length ? r.degradations : [r.note || "recovery was partial"]) });
    }
  }
  for (const t of sig.taint || []) {
    const reach = (t.total != null && t.unreachable != null) ? t.total - t.unreachable : null;
    const loss = (t.skipped_reachable || 0) > 0;
    chips.push({ key: `taint-${t.target_id}`, tone: loss ? "warn" : "info",
      label: `${pre(t.target_id, t.filename)}taint: ${loss
        ? `analysed ${t.analyzed} of ${reach != null ? reach : (t.analyzed || 0) + t.skipped_reachable} reachable functions`
        : `ranked ${t.analyzed}/${t.total} functions, none reachable left out`}`,
      detail: [t.note || ""].filter(Boolean) });
  }
  for (const c of sig.crashes_capped || []) {
    chips.push({ key: `cap-${c.target_id}`, tone: "warn",
      label: `${pre(c.target_id, c.filename)}proving ${c.proving} of ${c.distinct} distinct crashes`,
      detail: [`the prove loop takes at most ${c.proving} distinct crashes; ${c.distinct - c.proving} were not worked on — that is not "not exploitable" (see the Crashes tab)`] });
  }
  const hangs = sig.hangs || [];
  if (hangs.length) {
    chips.push({ key: "hangs", tone: "warn",
      label: `${hangs.length} hang/DoS input${hangs.length === 1 ? "" : "s"} (CWE-835)`,
      detail: hangs.map((h) => `${multi ? `${nm(h.target_id, h.filename)}: ` : ""}input ${String(h.input_sha || "").slice(0, 12)} via ${h.mode || "?"} did not terminate${h.timeout ? ` within ${h.timeout}s` : ""} (${_ENGINE_NAME[h.engine] || h.engine})`) });
  }
  for (const e of sig.runtime_env || []) {
    if (e.applied) {
      const n = (e.supplied || []).length;
      chips.push({ key: `renv-${e.target_id}`, tone: (e.degraded || []).length ? "warn" : "info",
        label: `${pre(e.target_id, e.filename)}runtime env supplied (${n} item${n === 1 ? "" : "s"})`,
        detail: [`the target stops at a startup gate without these; lykos confirmed each one and supplied it inside the sandbox to every run`, ...(e.supplied || []), ...(e.degraded || []).map((d) => `not supplied: ${d}`)] });
    } else {
      chips.push({ key: `renv-${e.target_id}`, tone: "warn",
        label: `${pre(e.target_id, e.filename)}startup gate not opened`,
        detail: [e.note || "the target exits early on a missing resource and nothing supplied got it further", "every dynamic result for this target measured that early exit — set the invocation field (e.g. -c @@ with a config as the seed) and re-run", ...(e.degraded || []).map((d) => `not supplied: ${d}`)] });
    }
  }
  if (sig.lease_renewed && sig.lease_renewed.count) {
    chips.push({ key: "lease", tone: "info",
      label: `lease renewed ×${sig.lease_renewed.count}`,
      detail: ["the database was under write contention, so a working stage's heartbeat was late; its lease was renewed instead of the stage being killed — expect slower progress, not lost work"] });
  }
  return chips;
}

// The operator's run settings, as both autopilots take them. One builder, so the in-tab run and
// the server run cannot drift apart (the in-tab one used to drop the seeds and engine switches).
//   argv/input_mode -- how the binary is really run (argv: a shell string, @@ = the input file)
//   sysroot         -- the target's own libraries directory (QEMU_LD_PREFIX for afl-qemu/concolic)
//   deep_seed       -- synthesize parser-buffer seeds for daemon targets (candidate-tier)
//   seed_shas       -- operator seeds uploaded into the case (CLI --seed), resolved server-side
//   skipStages      -- engines switched off for this run (the server enforces an allowlist)
export function operatorSettings({ invArgv = "", invMode = "", sysroot = "", deepSeed = false,
  seeds = [], blackBox = true, covFuzz = true, dirFuzz = true, concolicOn = true,
  libfuzzerOn = true } = {}) {
  const overrides = {};
  if (invArgv.trim()) overrides.argv = invArgv.trim();
  if (invMode && invMode !== "auto") overrides.input_mode = invMode;
  if (sysroot.trim()) overrides.sysroot = sysroot.trim();
  if (deepSeed) overrides.deep_seed = true;
  if (seeds.length) overrides.seed_shas = seeds.map((x) => x.sha256);
  const skipStages = [];
  if (!blackBox) skipStages.push("fuzz");
  if (!covFuzz) skipStages.push("coverage_fuzz");
  if (!dirFuzz) skipStages.push("directed_fuzz");
  if (!concolicOn) skipStages.push("concolic");
  if (!libfuzzerOn) skipStages.push("libfuzzer");
  return { overrides, skipStages };
}
