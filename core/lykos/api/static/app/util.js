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
    // a memory-corruption manifestation of a hijack overflow: keep only the representative
    if (hijackSignals.has(p.signal) && MEMCORRUPT.has(f.cwe)) {
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
