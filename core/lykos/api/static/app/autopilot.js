// Autopilot: one click, every applicable capability, demonstrable result.
//
// The user's goal is the fewest clicks between "here is a binary" and "here is a working
// proof-of-concept, or the exact steps to exploit it" -- and to go DEEP: exercise every
// analysis capability the target supports, not just the shortest path to one crash. The server
// already computes what is RECOMMENDED (GET /targets/<id>/advice) and what is POSSIBLE at all
// (GET /targets/<id>/capabilities). Autopilot runs the full applicable pipeline in a sensible
// order, threads a crashing input through the stages that need one, reports what each stage
// actually found (not just that it finished), and names the capabilities it skipped and why.

import { api, waitForRun } from "./api.js";
import { stageLabel } from "./util.js";

const DYNAMIC_BACKENDS = new Set([
  "fuzz", "coverage_fuzz", "directed_fuzz", "concolic", "dynamic_run", "firmware_carve",
]);

// The deep pipeline, in execution order. `needsCrash` stages only run once a crashing input
// exists (and are handed its sha); `wantSha` stages run regardless but analyse the crash when
// there is one. Everything is gated on the server's per-target availability, so an inapplicable
// stage (boundary fuzz on a lone ELF, firmware carve on an executable) is skipped with a reason
// rather than failing. `core` stages run even if the capability map does not list them.
const PIPELINE = [
  { stage: "disassemble", core: true, phase: "recover" },
  { stage: "detect_cwe", core: true, phase: "recover" },
  { stage: "cve_scan", phase: "recover" },
  { stage: "coverage_fuzz", isBackend: true, phase: "search" },
  { stage: "fuzz", isBackend: true, phase: "search" },
  // Dynamic evidence for static candidates WITHOUT needing a crash: run the target under GDB
  // with breakpoints on its dangerous sinks and record the concrete arguments.
  { stage: "debug_monitor", wantSha: true, phase: "search" },
  { stage: "heap_check", wantSha: true, phase: "search" },
  { stage: "directed_fuzz", phase: "search" },
  { stage: "boundary_fuzz", phase: "search" },              // IPC/protocol boundary, if any
  { stage: "firmware_rehost", phase: "search" },            // emulate a carved firmware image
  { stage: "concolic", isBackend: true, onlyIfNoCrash: true, phase: "search" },
  { stage: "root_cause", needsCrash: true, phase: "prove" },
  { stage: "build_poc", needsCrash: true, phase: "prove" },
  { stage: "poc_primitive", needsCrash: true, phase: "prove" },
  { stage: "build_exploit", needsCrash: true, phase: "prove" },
  { stage: "multi_debug", needsCrash: true, phase: "prove" },   // follow fork/exec, blame the child
  { stage: "behavior_trace", wantSha: true, phase: "enrich" },
  { stage: "dynamic_taint", wantSha: true, phase: "enrich" },
  { stage: "extract_secrets", phase: "enrich" },
  { stage: "synthesize_injection", phase: "enrich" },       // package a command/format injection
  { stage: "synthesize_secret", phase: "enrich" },          // package a recovered credential
  // synthesize_poc runs BEFORE the prove phase (handled explicitly below), not here: a crash it
  // synthesises has to feed root_cause/build_poc/build_exploit to reach L2/L3, and an enrich-phase
  // run happens after those have already passed.
];

export function newController() {
  return { cancelled: false, currentRunId: null };
}

export async function cancel(ctrl) {
  ctrl.cancelled = true;
  if (ctrl.currentRunId) {
    try { await api.cancelRun(ctrl.currentRunId); } catch { /* best effort */ }
  }
}

// A snapshot of the target's evidence, so a stage's effect can be reported as a delta.
async function snapshot(targetId) {
  const [fns, finds, dyn, pocs] = await Promise.all([
    api.functions(targetId).catch(() => []),
    api.targetFindings(targetId).catch(() => []),
    api.dynresults(targetId).catch(() => []),
    api.pocs(targetId).catch(() => []),
  ]);
  const crashes = (dyn || []).filter((d) => d.crashed);
  const levelRank = { L0: 0, L1: 1, L2: 2, L3: 3 };
  const topLevel = (pocs || []).filter((p) => p.verified)
    .reduce((m, p) => Math.max(m, levelRank[p.level] ?? -1), -1);
  return {
    functions: (fns || []).length,
    findings: (finds || []).length,
    demonstrated: (finds || []).filter((f) => f.state === "poc-backed" || f.state === "confirmed").length,
    crashes: crashes.length,
    crashSha: (crashes.find((d) => d.input_sha) || {}).input_sha || null,
    pocs: (pocs || []).length,
    verifiedPocs: (pocs || []).filter((p) => p.verified).length,
    topLevel,
  };
}

async function crashingResults(targetId) {
  try { return (await api.dynresults(targetId) || []).filter((d) => d.crashed); }
  catch { return []; }
}

async function firstCrashSha(targetId) {
  return ((await crashingResults(targetId)).find((d) => d.input_sha) || {}).input_sha || null;
}

// The DISTINCT crashes, one per unique fault. Two crashing inputs that fault with the same signal
// at the same address are the same bug -- deduped so the PoC ladder proves each bug once, not the
// same bug forty times. Returns [{input_sha, signal, fault_pc}], each carrying an input to work on.
async function distinctCrashes(targetId) {
  const rows = (await crashingResults(targetId)).filter((d) => d.input_sha);
  const byFault = new Map();
  for (const d of rows) {
    // A SIGABRT is bucketed by signal alone: its PC is in the abort/check machinery (glibc
    // malloc, a canary, ASan), not the defect, so one double-free is proved once, not 47 times.
    const key = d.signal === "SIGABRT" ? "SIGABRT" : `${d.signal || "?"}:${d.fault_pc || ""}`;
    if (!byFault.has(key)) byFault.set(key, { input_sha: d.input_sha, signal: d.signal, fault_pc: d.fault_pc });
  }
  return [...byFault.values()];
}

// How much of the target a fuzzing run actually exercised. Edge coverage (AFL's bitmap fill)
// or block coverage (blocks reached / recovered). A low number on a big binary is the signal
// that the fuzzer never got past an early gate -- the difference between "0 crashes, robust"
// and "0 crashes, barely ran".
export function coverageOf(output) {
  const c = output && output.coverage;
  if (!c) return null;
  // Block coverage is the honest "% of recovered code reached". AFL's bitmap percentage is a
  // fraction of a 64K edge map -- tiny in absolute terms for any small program -- so the edge
  // COUNT is the meaningful figure there, not the percentage; pct stays null so a block-coverage
  // reading (which has a real percentage) always wins when the UI keeps the best number.
  if (c.kind === "block" && c.blocks_known)
    return { kind: "block", pct: c.pct, hit: c.blocks_hit, known: c.blocks_known };
  if (c.kind === "edge" && (c.edges_found || c.bitmap_cvg_pct != null))
    return { kind: "edge", pct: null, edges: c.edges_found };
  return null;
}
function coverageStr(output) {
  const c = coverageOf(output);
  if (!c) return "";
  if (c.kind === "edge") return c.edges != null ? `${c.edges} edges covered` : "";
  return `${c.pct != null ? c.pct + "% " : ""}block coverage (${c.hit}/${c.known})`;
}

// One human line describing what a stage actually did, from its output artifact and the delta
// it produced. This is the "what is happening" the run log shows next to each step.
function describe(stage, before, after, output) {
  const dFind = after.findings - before.findings;
  const dCrash = after.crashes - before.crashes;
  const dPoc = after.verifiedPocs - before.verifiedPocs;
  const dLevel = after.topLevel - before.topLevel;   // did THIS stage raise the ladder?
  const o = output && typeof output === "object" ? output : null;
  switch (stage) {
    case "disassemble": {
      const n = (o && (o.function_count ?? (o.functions || []).length)) ?? after.functions;
      const strs = o && Array.isArray(o.strings) ? o.strings.length : null;
      return `${n} function${n === 1 ? "" : "s"} recovered${strs != null ? `, ${strs} strings` : ""}`;
    }
    case "detect_cwe":
      return dFind > 0 ? `${dFind} static finding${dFind === 1 ? "" : "s"}` : "no new static findings";
    case "cve_scan":
      return dFind > 0 ? `${dFind} known-CVE match${dFind === 1 ? "" : "es"}` : "no known-vulnerable components";
    case "coverage_fuzz": case "fuzz": case "directed_fuzz": {
      const crash = dCrash > 0 ? `${dCrash} new crashing input${dCrash === 1 ? "" : "s"}`
        : (after.crashes > 0 ? "no new crash" : "no crash");
      const cov = coverageStr(o);
      const execs = o && o.execs ? `${Math.round(o.execs).toLocaleString()} execs` : "";
      return [crash, cov, execs].filter(Boolean).join(" · ");
    }
    case "concolic": case "heap_check": case "dynamic_run":
      return dCrash > 0 ? `${dCrash} new crashing input${dCrash === 1 ? "" : "s"}`
        : (after.crashes > 0 ? "no new crash (already have one)" : "no crash");
    case "root_cause": {
      if (!o) return "root cause recorded";
      const cls = o.classification || {};
      const exp = o.exploitability || {};
      const bits = [o.signal, cls.cwe && `${cls.class || ""} (${cls.cwe})`.trim(),
        exp.rating && `${exp.rating}${exp.score != null ? ` ${exp.score}/100` : ""}`].filter(Boolean);
      return bits.join(" -> ") || "root cause recorded";
    }
    case "build_poc":
      return dPoc > 0 ? "verified reproducer (L1) built" : "no new reproducer";
    case "poc_primitive":
      return dLevel > 0 && after.topLevel >= 2 ? "instruction-pointer control confirmed (L2)" : "no IP-control primitive";
    case "build_exploit":
      return dLevel > 0 && after.topLevel >= 3 ? "control-flow redirect achieved (L3)" : "no L3 exploit (mitigations or non-trivial)";
    case "multi_debug":
      return dFind > 0 ? `fork/exec followed — fault blamed on a child (${dFind} finding${dFind === 1 ? "" : "s"})` : "no cross-process fault";
    case "debug_monitor":
      return dFind > 0 ? `${dFind} dangerous call${dFind === 1 ? "" : "s"} observed at runtime` : "no dangerous sink hit at runtime";
    case "boundary_fuzz":
      return dCrash > 0 ? `${dCrash} crash at the IPC/protocol boundary` : "no reachable IPC/protocol boundary";
    case "firmware_rehost":
      return dCrash > 0 || dFind > 0 ? "rehosted image executed" : "not a rehostable firmware image";
    case "behavior_trace":
      return "syscall/exec/network behaviour captured";
    case "dynamic_taint":
      return dFind > 0 ? `input reached a sink (${dFind} finding${dFind === 1 ? "" : "s"})` : "no input-to-sink flow observed";
    case "extract_secrets":
      return dFind > 0 ? `${dFind} compared-against value(s) recovered` : "no secrets recovered";
    case "synthesize_injection":
      return dPoc > 0 || dFind > 0 ? "injection PoC synthesised" : "no injectable sink";
    case "synthesize_secret":
      return dPoc > 0 || dFind > 0 ? "credential PoC packaged" : "no recovered secret to package";
    case "synthesize_poc":
      return dPoc > 0 ? "PoC synthesised from the stack frame" : "nothing to synthesise";
    default:
      return dFind > 0 ? `+${dFind} findings` : (dCrash > 0 ? `+${dCrash} crashes` : "done");
  }
}

// Run one stage to completion, reporting a start line and a done line carrying what it found.
// While a run is in flight, tail the case event stream for THIS run's live progress -- the
// fuzzers post execs/crashes/corpus every few hundred executions, stages post a percent and a
// message. Turns a 60-second spinner into a stage you can watch work. Stops when told to.
async function streamProgress(ctrl, emit, stage, caseId, runId, stopRef) {
  if (!caseId) return;
  let after = 0;
  try { const seed = await api.events(caseId, 0); after = seed.reduce((m, e) => Math.max(m, e.id), 0); }
  catch { return; }
  while (!stopRef.stopped && !ctrl.cancelled) {
    await new Promise((r) => setTimeout(r, 900));
    let evs;
    try { evs = await api.events(caseId, after); } catch { continue; }
    for (const ev of evs || []) {
      after = Math.max(after, ev.id);
      if (ev.run_id !== runId || !ev.payload) continue;
      if (/\.progress$/.test(ev.type) || ev.type === "job.progress")
        emit({ kind: "stage-progress", stage, runId, type: ev.type, payload: ev.payload });
      else if (ev.type === "job.exec")
        emit({ kind: "exec", id: ev.id, payload: ev.payload });
    }
  }
}

async function runStage(ctrl, emit, stage, { targetId, caseId, params } = {}) {
  if (ctrl.cancelled) return null;
  const label = stageLabel(stage);
  const before = await snapshot(targetId);
  emit({ kind: "stage-start", stage, label });
  let created;
  try {
    created = await api.createRun(stage, { targetId, params });
  } catch (e) {
    emit({ kind: "stage-error", stage, label, message: e.message });
    return null;
  }
  let run = { id: created.run_id, status: "done" };
  if (!created.from_cache) {
    ctrl.currentRunId = created.run_id;
    const stopRef = { stopped: false };
    const progress = streamProgress(ctrl, emit, stage, caseId, created.run_id, stopRef);
    try {
      run = await waitForRun(created.run_id);
    } catch (e) {
      ctrl.currentRunId = null;
      stopRef.stopped = true; await progress.catch(() => {});
      if (ctrl.cancelled) { emit({ kind: "cancelled", stage, label }); return null; }
      emit({ kind: "stage-error", stage, label, message: e.message });
      return null;
    }
    ctrl.currentRunId = null;
    stopRef.stopped = true; await progress.catch(() => {});
  }
  if (run.status !== "done" && run.status !== "skipped") {
    emit({ kind: "stage-error", stage, label, message: run.error || run.status });
    return run;
  }
  // What did it find? Read the stage's own output plus the evidence delta.
  let output = null;
  try { output = (await api.runOutput(created.run_id)).output; } catch { /* optional */ }
  const after = await snapshot(targetId);
  const cov = coverageOf(output);
  if (cov) {
    emit({ kind: "coverage", targetId, stage, coverage: cov });
    // Track the best block coverage so the orchestrator can close the loop: low coverage after
    // fuzzing means guarded paths were never reached, which is exactly concolic's job.
    if (cov.pct != null) ctrl.bestBlockPct = Math.max(ctrl.bestBlockPct || 0, cov.pct);
  }
  emit({ kind: "stage-done", stage, label, cached: !!created.from_cache,
         detail: describe(stage, before, after, output), run });
  return run;
}

// The full run. `emit` receives {kind, ...} progress objects; the UI turns them into a log and
// refreshes findings. Resolves with a summary when the pipeline is exhausted.
export async function runAutopilot(ctrl, emit, { targetId, caseId, silentDone = false }) {
  emit({ kind: "start", targetId });

  // What to do (advice) and what is possible at all (capabilities).
  let advice = null, caps = null;
  try { advice = await api.advice(targetId); emit({ kind: "advice", advice }); }
  catch (e) { emit({ kind: "info", message: `advice unavailable: ${e.message}` }); }
  try { caps = await api.capabilities(targetId); } catch { /* run the core anyway */ }

  // Flatten the capability map to available stages + the reasons the rest cannot run.
  const available = new Set();
  const unavailable = [];
  if (caps && caps.stages) {
    for (const group of Object.values(caps.stages)) {
      for (const s of group) {
        if (s.available) available.add(s.stage);
        else unavailable.push({ stage: s.stage, label: s.label, why: s.why });
      }
    }
  }
  const canRun = (stage, core) => (core || !caps) ? true : available.has(stage);

  // The recommended dynamic backend, and the command line read off the binary. Passed to every
  // dynamic stage so a target that needs `-c @@` is actually driven, not fuzzed on argv it
  // ignores. DEEP raises the search budget well above the stage defaults (3-4k execs / 30s):
  // "go deep" means spend more, so more paths and more distinct crashes surface.
  const DEEP = { max_execs: 12000, max_seconds: 60 };
  const backendEntry = advice && (advice.plan || []).find((p) => p.stage === advice.backend);
  const dynParams = { ...DEEP, ...((backendEntry && backendEntry.params) || {}) };
  if (advice && advice.input_mode && dynParams.input_mode == null) dynParams.input_mode = advice.input_mode;
  const chosenBackend = advice && DYNAMIC_BACKENDS.has(advice.backend) ? advice.backend
    : (available.has("coverage_fuzz") ? "coverage_fuzz" : "fuzz");

  const run = async (stage, params, core) => {
    if (ctrl.cancelled || !canRun(stage, core)) return;
    await runStage(ctrl, emit, stage, { targetId, caseId, params });
    emit({ kind: "refresh" });
  };
  const inMode = dynParams.input_mode;

  // ---- Phase 1: recover + search. Collect crashes; the search stages carry the big budget. ----
  let anyCrash = false;
  for (const step of PIPELINE.filter((s) => s.phase === "recover" || s.phase === "search")) {
    if (ctrl.cancelled) return finish(emit, "cancelled", unavailable, null, silentDone);
    if (step.isBackend && step.stage !== chosenBackend) continue;
    // Concolic is decided AFTER the loop, on the coverage the fuzzers achieved (the loop below).
    if (step.onlyIfNoCrash) continue;
    const p = DYNAMIC_BACKENDS.has(step.stage) ? { ...dynParams } : { input_mode: inMode };
    if (step.wantSha) { const s = await firstCrashSha(targetId); if (s) p.input_sha = s; }
    await run(step.stage, p, step.core);
    // One dynresults read, not a full 4-call snapshot, just to learn if a crash exists yet.
    if (!anyCrash) anyCrash = (await crashingResults(targetId)).length > 0;
  }

  // ---- Reinforcement: the capabilities feeding each other. The first search enriched the case
  //      corpus with crashing inputs, and detect_cwe flagged the dangerous sinks. A second
  //      directed pass exploits BOTH at once -- biased toward the known sinks, seeded from the
  //      crashes found so far -- to surface distinct faults the blind first pass missed. Only
  //      worth its cost once the first pass proved the target is crashable. ----
  if (anyCrash && canRun("directed_fuzz")) {
    const before = (await distinctCrashes(targetId)).length;
    emit({ kind: "info", message: "Reinforcement — re-fuzzing biased toward the flagged sinks and seeded by the crashes found so far." });
    await run("directed_fuzz", { ...dynParams, seed: (Number(dynParams.seed) || 1337) + 1 });
    const after = (await distinctCrashes(targetId)).length;
    if (after > before) emit({ kind: "info", message: `Reinforcement found ${after - before} more distinct crash${after - before === 1 ? "" : "es"}.` });
  }

  // ---- Closing the coverage loop: concolic execution runs when fuzzing left the binary
  //      under-covered (or found nothing at all). Where a coverage fuzzer stalls at a guarded
  //      branch -- a magic value, a length check -- concolic SOLVES for an input that takes it,
  //      reaching code the search never entered. The coverage we measured is what decides it. ----
  const cvg = ctrl.bestBlockPct;
  const lowCoverage = cvg != null && cvg < 60;
  if ((!anyCrash || lowCoverage) && chosenBackend !== "concolic" && canRun("concolic")) {
    if (lowCoverage && anyCrash) emit({ kind: "info", message: `Coverage reached ${cvg}% of blocks — running concolic to reach the paths fuzzing did not.` });
    await run("concolic", { ...dynParams });
    // Close the loop: re-fuzz seeded by concolic's solved inputs (directed_fuzz reuses them
    // automatically), so the search explores AROUND the branches concolic just unlocked.
    if (canRun("directed_fuzz")) {
      emit({ kind: "info", message: "Re-fuzzing from concolic's solved inputs to explore the newly-reached paths." });
      await run("directed_fuzz", { ...dynParams, ...DEEP, seed: (Number(dynParams.seed) || 1337) + 2 });
    }
  }

  // ---- Static-overflow synthesis: when the search produced NO crash, an unbounded stack
  //       overflow (gets(), scanf("%s"), a size-less strcpy) is the likeliest reason it is invisible
  //       to fuzzing -- the overflow needs a long, NEWLINE-FREE payload that blind mutation almost
  //       never generates, so the fuzzer reports full coverage and zero crashes on a binary whose
  //       bug is glaringly static. Derive the overflow straight from the recovered stack frame and
  //       sweep EVERY channel (no pinned input_mode: the guess ranks a file parser first, but the
  //       gets()/scanf() overflow is on stdin). Runs before the prove phase so a resulting L1 crash
  //       flows into root_cause -> build_poc -> build_exploit and reaches L2/L3. ----
  if (!(await crashingResults(targetId)).length && canRun("synthesize_poc")) {
    emit({ kind: "info", message: "No crash from the search — synthesising the overflow from the recovered stack frame (sweeping every input channel)." });
    await run("synthesize_poc", {});
  }

  // ---- Phase 2: prove EVERY distinct crash, not just the first. A confirmed crash with no PoC
  //       is a job half done -- each distinct fault (signal + faulting address) gets its own
  //       root-cause, reproducer and IP-control primitive, so every one becomes poc-backed. ----
  const crashes = await distinctCrashes(targetId);
  if (crashes.length) {
    emit({ kind: "info", message: `${crashes.length} distinct crash${crashes.length === 1 ? "" : "es"} — proving each.` });
    for (let i = 0; i < crashes.length; i++) {
      if (ctrl.cancelled) return finish(emit, "cancelled", unavailable, null, silentDone);
      const cr = crashes[i];
      emit({ kind: "info", message: `Crash ${i + 1} of ${crashes.length}: ${cr.signal}${cr.fault_pc ? ` @ ${cr.fault_pc}` : ""}` });
      const p = { input_mode: inMode, input_sha: cr.input_sha };
      await run("root_cause", p);
      await run("build_poc", p);
      await run("poc_primitive", p);
    }
    // Once per target: escalation and cross-process blame, on the most-promising crash.
    const rep = { input_mode: inMode, input_sha: crashes[0].input_sha };
    await run("build_exploit", rep);
    await run("multi_debug", rep);
  }

  // ---- Phase 3: enrich. Runtime evidence and PoC synthesis, using a representative crash. ----
  const repSha = crashes.length ? crashes[0].input_sha : null;
  for (const step of PIPELINE.filter((s) => s.phase === "enrich")) {
    if (ctrl.cancelled) return finish(emit, "cancelled", unavailable, null, silentDone);
    if (step.onlyIfNoCrash && crashes.length) continue;
    const p = { input_mode: inMode };
    if (step.wantSha && repSha) p.input_sha = repSha;
    await run(step.stage, p, step.core);
  }

  if (ctrl.cancelled) return finish(emit, "cancelled", unavailable, null, silentDone);

  // ---- False-positive review: a demonstrated finding is only trustworthy if its OWN input fires
  //      every time. Replay the PoCs' inputs (whose sha the UI maps back to the finding, so the
  //      verdict lands on the right card even when build_poc minimized the input to a new hash)
  //      AND any distinct crash not yet packaged as a PoC. A deterministic result confirms it, a
  //      flaky one is flagged rather than silently trusted. ----
  const reviewPocs = (await api.pocs(targetId).catch(() => [])).filter((p) => p.verified && p.input_sha);
  // Cap the review so a target with dozens of distinct faults cannot turn into hundreds of
  // sandbox runs; the PoC inputs (the demonstrated findings) come first and are never dropped.
  const reviewShas = [...new Set([...reviewPocs.map((p) => p.input_sha), ...crashes.map((c) => c.input_sha)])].slice(0, 12);
  if (reviewShas.length) {
    emit({ kind: "stage-start", stage: "verify", label: "Verifying findings" });
    let verified = 0;
    for (const sha of reviewShas) {
      if (ctrl.cancelled) break;
      try {
        const v = await api.replay(targetId, { input_sha: sha, times: 5 });
        if (v && v.runs) { emit({ kind: "verification", targetId, input_sha: sha, verification: v }); if (v.deterministic) verified++; }
      } catch { /* review is best-effort */ }
    }
    emit({ kind: "stage-done", stage: "verify", label: "Verifying findings",
           detail: `${verified}/${reviewShas.length} input${reviewShas.length === 1 ? "" : "s"} reproduced deterministically` });
    emit({ kind: "refresh" });
  }

  const final = await snapshot(targetId);
  const outcome = final.verifiedPocs > 0 ? "poc" : (final.crashes > 0 ? "crash" : "static");
  return finish(emit, outcome, unavailable, final, silentDone);
}

// Case-level capabilities: they analyse the RELATIONSHIPS between binaries, so they need a case
// with more than one target to mean anything (cross_taint with one binary has nothing to cross).
// `need` is the minimum target count. link_case and whole_system also run on a single target
// (they just find no cross-links), the cross-binary ones are skipped below that.
const CASE_PIPELINE = [
  { stage: "link_case", need: 1, label: "Link case" },
  { stage: "ipc_model", need: 2, label: "IPC model" },
  { stage: "cross_taint", need: 2, label: "Cross-binary taint" },
  { stage: "whole_system", need: 1, label: "Whole-system model" },
];

// Run one case-scoped stage (no target_id; the server routes on the case).
async function runCaseStage(ctrl, emit, stage, caseId, label) {
  if (ctrl.cancelled) return;
  emit({ kind: "stage-start", stage, label });
  const beforeN = await api.caseFindings(caseId).then((f) => (f || []).length).catch(() => 0);
  let created;
  try { created = await api.createRun(stage, { caseId }); }
  catch (e) { emit({ kind: "stage-error", stage, label, message: e.message }); return; }
  let run = { id: created.run_id, status: "done" };
  if (!created.from_cache) {
    ctrl.currentRunId = created.run_id;
    try { run = await waitForRun(created.run_id); }
    catch (e) { ctrl.currentRunId = null;
      if (ctrl.cancelled) { emit({ kind: "cancelled", stage, label }); return; }
      emit({ kind: "stage-error", stage, label, message: e.message }); return; }
    ctrl.currentRunId = null;
  }
  const afterN = await api.caseFindings(caseId).then((f) => (f || []).length).catch(() => 0);
  const d = afterN - beforeN;
  emit({ kind: "stage-done", stage, label, cached: !!created.from_cache,
         detail: d > 0 ? `${d} cross-binary finding${d === 1 ? "" : "s"}` : "no cross-binary defect", run });
}

// The whole run for a case: every target's deep pipeline, then the case-level analyses that
// look across binaries. This is what "complete every capability" means -- a single upload runs
// the target pipeline; several uploads additionally get IPC modelling and cross-binary taint.
export async function runAutopilotCase(ctrl, emit, { targetIds, caseId }) {
  const ids = targetIds || [];
  const perTarget = [];
  for (let i = 0; i < ids.length; i++) {
    if (ctrl.cancelled) return finish(emit, "cancelled", []);
    if (ids.length > 1) emit({ kind: "info", message: `Target ${i + 1} of ${ids.length}` });
    perTarget.push(await runAutopilot(ctrl, emit, { targetId: ids[i], caseId, silentDone: true }));
  }
  // Case-level: cross-binary analysis over the whole case.
  if (!ctrl.cancelled && caseId && ids.length >= 1) {
    let ran = false;
    for (const step of CASE_PIPELINE) {
      if (ids.length < step.need) continue;
      if (!ran) { emit({ kind: "info", message: "Linking the case — cross-binary analysis." }); ran = true; }
      await runCaseStage(ctrl, emit, step.stage, caseId, step.label);
      emit({ kind: "refresh" });
    }
  }
  if (ctrl.cancelled) return finish(emit, "cancelled", []);
  // Outcome across all targets: best wins.
  const outcome = perTarget.some((r) => r && r.outcome === "poc") ? "poc"
    : perTarget.some((r) => r && r.outcome === "crash") ? "crash" : "static";
  emit({ kind: "done", outcome });
  return { outcome, perTarget };
}

function finish(emit, outcome, unavailable, final, silentDone) {
  // Name the capabilities that could not run here, and why -- so "deep" is honest about its
  // own gaps instead of silently doing less.
  if (unavailable && unavailable.length) {
    emit({ kind: "unavailable", items: unavailable });
  }
  if (!silentDone) emit({ kind: "done", outcome, final });
  return { outcome, final };
}
