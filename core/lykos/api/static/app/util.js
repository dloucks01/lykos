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
      const clone = { ...f, group_count: 1, site_count: f.site_count || 1 };
      byKey.set(key, clone);
      out.push(clone);
    } else {
      rep.group_count += 1;
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
  const level = tPocs.reduce((m, p) => Math.max(m, pocLevel(p)), 0);
  const bundlePoc = tPocs.find((p) => p.verified && p.bundle_sha) || tPocs.find((p) => p.bundle_sha) || null;
  const inputPoc = tPocs.find((p) => p.input_sha) || null;
  const crashed = tFindings.some((f) => f.state === "poc-backed") || !!worstDemo || !!inputPoc;
  const staticCount = tFindings.filter((f) => f.state !== "poc-backed").length;
  const cov = coverage && coverage[tid] && coverage[tid].pct != null ? coverage[tid].pct : null;
  return { target, headline, status, level, crashed, staticCount, coverage: cov,
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
