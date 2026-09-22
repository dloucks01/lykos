// Exercise the new workbench's pure ESM logic under node, without a browser.
//
// These are the modules that decide behaviour, not appearance: how findings are RANKED (the
// whole "results-first" promise), the exact REST contract the client speaks, and the Autopilot
// LADDER that turns one click into a proof-of-concept. All three are importable without Preact,
// so a CommonJS harness loads them by file URL and drives them against a stubbed fetch. A
// regression here -- a candidate sorted above a demonstrated bug, a wrong URL, a ladder that
// skips the PoC stages on a crash -- is invisible to a grep and caught here.
const path = require("path");
const { pathToFileURL } = require("url");

const given = process.argv[2] || "core/lykos/api/static/index.html";
const appDir = path.join(path.dirname(given), "app");
const load = (name) => import(pathToFileURL(path.join(appDir, name)).href);

let pass = true;
const ck = (n, cond) => { pass = pass && !!cond; console.log(`${cond ? "PASS" : "FAIL"}  ${n}`); };

(async () => {
  // ---------- util.js: ranking is the product ----------
  const util = await load("util.js");
  const findings = [
    { id: "a", state: "candidate", severity: "critical", site_count: 9 },
    { id: "b", state: "poc-backed", severity: "low", proven_sites: 1 },
    { id: "c", state: "corroborated", severity: "high" },
    { id: "d", state: "confirmed", severity: "medium" },
  ];
  const ranked = util.rankFindings(findings).map((f) => f.id);
  ck("demonstrated outranks a higher-severity candidate",
    ranked.indexOf("b") < ranked.indexOf("a") && ranked.indexOf("d") < ranked.indexOf("a"));
  ck("state ladder orders poc-backed > confirmed > corroborated > candidate",
    ranked.join(",") === "b,d,c,a");
  ck("rankFindings does not mutate its input", findings[0].id === "a");
  ck("dedupeFindings collapses near-duplicate crashes but keeps each PoC-backed finding",
    (() => {
      const g = util.dedupeFindings([
        { id: "p", cwe: "CWE-119", state: "poc-backed", detector: "poc" },
        { id: "c1", cwe: "CWE-119", state: "confirmed", detector: "directed_fuzz", site_count: 1 },
        { id: "c2", cwe: "CWE-119", state: "confirmed", detector: "directed_fuzz", site_count: 1 },
        { id: "c3", cwe: "CWE-119", state: "confirmed", detector: "directed_fuzz", site_count: 1 },
        { id: "d", cwe: "CWE-120", state: "corroborated", detector: "dangerous_api" },
      ]);
      // poc-backed stays; the three confirmed crashes fold to one with group_count 3; other kept
      return g.length === 3 && g[0].id === "p"
        && g.some((f) => f.detector === "directed_fuzz" && f.group_count === 3)
        && g.some((f) => f.cwe === "CWE-120");
    })());
  ck("dedupeFindings folds a same-signal bare crash into a control-flow-hijack finding (either PC)",
    (() => {
      const rce = { id: "rce", cwe: "CWE-787", state: "poc-backed", detector: "primitive",
        title: "Remote code execution / control-flow hijack (demonstrated): L2 primitive",
        dedup_key: "dynamic-crash:SIGSEGV",
        evidence: [{ channel: "effects", detail: '[{"kind":"rce","status":"demonstrated"}]' }] };
      const bare = { id: "bare", cwe: "CWE-119", state: "confirmed", detector: "directed_fuzz",
        title: "Reproduced crash (SIGSEGV) under dynamic execution",
        dedup_key: "dynamic-crash:SIGSEGV:40117a" };     // same hijack, different (garbage) PC
      const g1 = util.dedupeFindings([rce, bare]);
      const g2 = util.dedupeFindings([bare, rce]);        // order-independent
      return g1.length === 1 && g1[0].id === "rce" && g2.length === 1 && g2[0].id === "rce";
    })());
  ck("dedupeFindings does NOT fold a bare crash into a non-hijack finding (fault PC is reliable)",
    (() => {
      const g = util.dedupeFindings([
        { id: "nd", cwe: "CWE-476", state: "poc-backed", detector: "primitive",
          title: "Denial of service (demonstrated): null-pointer-dereference",
          dedup_key: "dynamic-crash:SIGSEGV:401200",
          evidence: [{ channel: "effects", detail: '[{"kind":"dos","status":"demonstrated"}]' }] },
        { id: "other", cwe: "CWE-119", state: "confirmed", detector: "directed_fuzz",
          title: "Reproduced crash (SIGSEGV) under dynamic execution",
          dedup_key: "dynamic-crash:SIGSEGV:409999" },   // a genuinely distinct SIGSEGV -> kept
      ]);
      return g.length === 2 && g.some((f) => f.id === "other");
    })());
  ck("dedupeFindings collapses one overflow's many poc-backed manifestations, keeps a NULL deref",
    (() => {
      const hijackRce = (id, cwe, title) => ({ id, cwe, state: "poc-backed", detector: "primitive",
        title, dedup_key: `dynamic-crash:SIGSEGV:${id}`, severity: "critical",
        evidence: [{ channel: "effects", detail: '[{"kind":"rce","status":"potential"}]' }] });
      const g = util.dedupeFindings([
        hijackRce("a1", "CWE-121", "Remote code execution / control-flow hijack (potential): L2 primitive"),
        hijackRce("a2", "CWE-787", "Remote code execution / control-flow hijack (potential): L2 primitive"),
        // same overflow: corrupted RBP -> `leave` faults, misread as an OOB read (CWE-125)
        { id: "a3", cwe: "CWE-125", state: "poc-backed", detector: "primitive", severity: "high",
          title: "Information disclosure (memory leak) (potential): out-of-bounds-read",
          dedup_key: "dynamic-crash:SIGSEGV:401221",
          evidence: [{ channel: "effects", detail: '[{"kind":"info-disclosure","status":"potential"}]' }] },
        // a GENUINELY separate defect on the same signal: a NULL deref keeps its own finding
        { id: "nd", cwe: "CWE-476", state: "poc-backed", detector: "primitive", severity: "high",
          title: "Denial of service (demonstrated): null-pointer-dereference",
          dedup_key: "dynamic-crash:SIGSEGV:401300",
          evidence: [{ channel: "effects", detail: '[{"kind":"dos","status":"demonstrated"}]' }] },
      ]);
      const ids = g.map((f) => f.id);
      // the three overflow manifestations collapse to ONE (the critical CWE-121 hijack); NULL deref stays
      return g.length === 2 && ids.includes("nd")
        && g.some((f) => f.cwe === "CWE-121") && !ids.includes("a3");
    })());
  ck("isDemonstrated is true only for poc-backed/confirmed",
    util.isDemonstrated({ state: "poc-backed" }) && util.isDemonstrated({ state: "confirmed" })
    && !util.isDemonstrated({ state: "corroborated" }) && !util.isDemonstrated({ state: "candidate" }));
  ck("stageLabel names a known stage and humanizes an unknown one",
    util.stageLabel("detect_cwe") === "Static detectors"
    && util.stageLabel("some_new_stage") === "Some New Stage");
  ck("progressText renders a fuzzer's live execs/crashes",
    util.progressText("fuzz.progress", { execs: 12340, crashes: 3, corpus: 45 }) === "12,340 execs · 3 crashes · corpus 45");
  ck("progressText renders a stage percent + message",
    /^57% carving/.test(util.progressText("job.progress", { pct: 57, msg: "carving" })));

  // Reopening a case rebuilds its run log from run history (regression: it showed empty).
  {
    const rows = util.buildRunLog([
      { stage: "ingest_triage", status: "done", target_id: "t1", created_at: 1 },
      { stage: "disassemble", status: "done", target_id: "t1", created_at: 2 },
      { stage: "directed_fuzz", status: "done", target_id: "t1", created_at: 3 },
      { stage: "root_cause", status: "error", target_id: "t1", created_at: 4, error: "boom" },
      { stage: "root_cause", status: "done", target_id: "t1", created_at: 5 },  // newer wins
    ], [{ id: "t1", filename: "uaf.c" }]);
    ck("buildRunLog drops triage, orders by time, and keeps the latest attempt per stage",
      rows.length === 3
      && rows.map((r) => r.stage).join(",") === "disassemble,directed_fuzz,root_cause"
      && rows[2].status === "done");            // the newer root_cause replaced the errored one
    ck("buildRunLog surfaces a failed stage's error and tags rows in a multi-binary case",
      (() => {
        const r2 = util.buildRunLog(
          [{ stage: "detect_cwe", status: "error", target_id: "a", created_at: 1, error: "x".repeat(300) }],
          [{ id: "a", filename: "one.bin" }, { id: "b", filename: "two.bin" }]);
        return r2[0].status === "error" && r2[0].detail.length === 140
          && /· one\.bin$/.test(r2[0].label);
      })());
  }

  const pocSet = [
    { id: "p1", finding_id: "F1", verified: true },
    { id: "p2", finding_id: "F2", verified: true },
    { id: "p3", finding_id: null, verified: true },  // proved a crash not filed as its own finding
  ];
  ck("pocsForFinding attaches a PoC to the finding it proves",
    util.pocsForFinding(pocSet, "F1", "F1").map((p) => p.id).join() === "p1,p3");
  ck("pocsForFinding does not leak another finding's PoC",
    !util.pocsForFinding(pocSet, "F2", "F1").some((p) => p.id === "p1"));
  ck("pocsForFinding orphans an unlinked PoC only onto the top demonstrated finding",
    util.pocsForFinding(pocSet, "F2", "F1").map((p) => p.id).join() === "p2"
    && util.pocsForFinding(pocSet, "F1", "F1").some((p) => p.id === "p3"));

  // ---------- api.js: the REST contract ----------
  const calls = [];
  global.fetch = async (url, opts = {}) => {
    calls.push({ url, method: opts.method, headers: opts.headers || {}, body: opts.body });
    return {
      ok: true, status: 200, statusText: "OK",
      text: async () => JSON.stringify({ ok: true, id: "x1", run_id: "r1" }),
    };
  };
  const { api } = await load("api.js");
  await api.createCase("demo");
  ck("createCase POSTs /cases as JSON",
    calls.at(-1).url === "/cases" && calls.at(-1).method === "POST"
    && calls.at(-1).headers["Content-Type"] === "application/json");
  await api.uploadTarget("C1", { name: "prog.bin" });
  ck("uploadTarget posts to the case's target route with a filename header",
    calls.at(-1).url === "/cases/C1/targets"
    && calls.at(-1).headers["X-Filename"] === "prog.bin");
  await api.createRun("fuzz", { targetId: "T1", params: { input_mode: "argv" } });
  const rb = JSON.parse(calls.at(-1).body);
  ck("createRun sends stage + target_id + params",
    calls.at(-1).url === "/runs" && rb.stage === "fuzz"
    && rb.target_id === "T1" && rb.params.input_mode === "argv");
  await api.advice("T9");
  ck("advice GETs the target advice route", calls.at(-1).url === "/targets/T9/advice");
  ck("reportUrl/artifactUrl build the expected paths",
    api.reportUrl("C1", "sarif") === "/cases/C1/report?format=sarif"
    && api.artifactUrl("deadbeef") === "/artifacts/deadbeef");

  // ---------- autopilot.js: the deep, capability-driven pipeline ----------
  // A scripted server: advice recommends coverage_fuzz, the capability map says what is possible
  // (boundary_fuzz is NOT), a crash with a captured input exists, and a verified L2 PoC is built.
  // The stub answers by URL so the orchestrator's real sequencing and gating are exercised.
  const posted = [];
  const postedParams = {};
  const AVAIL = ["disassemble", "detect_cwe", "cve_scan", "coverage_fuzz", "fuzz", "heap_check",
    "directed_fuzz", "concolic", "root_cause", "build_poc", "poc_primitive", "build_exploit",
    "behavior_trace", "dynamic_taint", "extract_secrets", "synthesize_poc",
    // the capabilities wired in the "complete every capability" pass
    "debug_monitor", "multi_debug", "synthesize_injection", "synthesize_secret"];
  const capStage = (s) => ({ stage: s, label: s, available: true, why: null });
  global.fetch = async (url, opts = {}) => {
    const method = opts.method || "GET";
    const j = (obj) => ({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify(obj) });
    if (url === "/targets/T1/advice")
      return j({ headline: "Looks like an ELF.", shape: "an ELF executable", backend: "coverage_fuzz",
        input_mode: "stdin", plan: [{ stage: "coverage_fuzz", params: { input_mode: "stdin" }, ready: true }] });
    if (url === "/targets/T1/capabilities")
      return j({ stages: {
        find: AVAIL.map(capStage),
        // one capability that cannot run here, to prove it is reported not silently dropped
        feed: [{ stage: "boundary_fuzz", label: "Boundary fuzz", available: false, why: "no IPC boundary" }],
      } });
    if (method === "POST" && /\/targets\/[^/]+\/replay$/.test(url)) {
      posted.push("replay");
      return j({ runs: 5, crashed: 5, signal: "SIGSEGV", deterministic: true, input_sha: JSON.parse(opts.body).input_sha });
    }
    if (method === "POST" && url === "/runs") {
      const b = JSON.parse(opts.body); posted.push(b.stage); postedParams[b.stage] = b.params || {};
      return { ok: true, status: 201, statusText: "Created", text: async () => JSON.stringify({ run_id: `run-${b.stage}`, from_cache: false }) };
    }
    if (/\/runs\/[^/]+\/output$/.test(url)) {
      const stage = url.slice("/runs/run-".length, -"/output".length);
      if (stage === "root_cause") return j({ output: { signal: "SIGSEGV",
        classification: { class: "stack-return-overwrite", cwe: "CWE-121" },
        exploitability: { rating: "EXPLOITABLE", score: 90 } } });
      if (stage === "disassemble") return j({ output: { function_count: 12, strings: ["a", "b"] } });
      if (stage === "coverage_fuzz") return j({ output: { backend: "aflpp", execs: 12000,
        coverage: { kind: "block", blocks_hit: 120, blocks_known: 200, pct: 60 } } });
      return j({ output: null });
    }
    if (url.startsWith("/runs/")) return j({ id: url.slice(6), status: "done" });
    if (url === "/targets/T1/functions") return j(new Array(12).fill({}));
    // The crash records the sha of the exact input that faulted -- the PoC ladder needs it.
    if (url === "/targets/T1/dynresults") return j([{ crashed: true, signal: "SIGSEGV", input_sha: "cafe1234" }]);
    if (url === "/targets/T1/pocs") return j([{ id: "p1", finding_id: "F1", level: "L2", verified: true, bundle_sha: "abc", signal: "SIGSEGV" }]);
    if (url === "/targets/T1/findings") return j([{ id: "F1", state: "poc-backed" }]);
    return j({});
  };
  // Re-import with a cache-buster so the module picks up the new global.fetch closure.
  const ap = await import(pathToFileURL(path.join(appDir, "autopilot.js")).href + `?t=${Date.now()}`);
  const events = [];
  const ctrl = ap.newController();
  const summary = await ap.runAutopilot(ctrl, (e) => events.push(e), { targetId: "T1", caseId: "C1" });

  ck("pipeline recovers structure before detecting", posted.indexOf("disassemble") < posted.indexOf("detect_cwe"));
  ck("pipeline runs the recommended dynamic backend (coverage_fuzz), not the alternative (fuzz)",
    posted.includes("coverage_fuzz") && !posted.includes("fuzz"));
  ck("deep run exercises more than the core ladder (cve_scan, heap_check, directed_fuzz)",
    posted.includes("cve_scan") && posted.includes("heap_check") && posted.includes("directed_fuzz"));
  ck("every applicable capability runs (debug_monitor, boundary skipped-if-NA, synth injection/secret, multi_debug)",
    posted.includes("debug_monitor") && posted.includes("multi_debug")
    && posted.includes("synthesize_injection") && posted.includes("synthesize_secret"));
  ck("multi_debug (which requires a crashing input) is handed one",
    postedParams.multi_debug?.input_sha === "cafe1234");
  ck("a crash drives the full PoC/exploit ladder",
    ["root_cause", "build_poc", "poc_primitive", "build_exploit"].every((s) => posted.includes(s))
    && posted.indexOf("root_cause") < posted.indexOf("build_poc"));
  ck("crash-analysing stages get the crashing input's sha",
    postedParams.root_cause?.input_sha === "cafe1234"
    && postedParams.build_poc?.input_sha === "cafe1234"
    && postedParams.behavior_trace?.input_sha === "cafe1234"
    && postedParams.heap_check?.input_sha === "cafe1234");
  ck("stages that only run WITHOUT a crash are skipped once one exists (concolic, synthesize_poc)",
    !posted.includes("concolic") && !posted.includes("synthesize_poc"));
  ck("an inapplicable capability is reported, not silently dropped",
    events.some((e) => e.kind === "unavailable" && e.items.some((u) => u.stage === "boundary_fuzz" && u.why)));
  ck("each completed stage reports WHAT it found, not just that it finished",
    events.some((e) => e.kind === "stage-done" && e.stage === "root_cause" && /CWE-121|EXPLOITABLE/.test(e.detail || ""))
    && events.some((e) => e.kind === "stage-done" && e.stage === "disassemble" && /12 function/.test(e.detail || "")));
  ck("fuzzing reports coverage in its detail line and emits a coverage event",
    events.some((e) => e.kind === "stage-done" && e.stage === "coverage_fuzz" && /60% block coverage \(120\/200\)/.test(e.detail || ""))
    && events.some((e) => e.kind === "coverage" && e.coverage && e.coverage.pct === 60));
  ck("a verified PoC yields outcome 'poc'", summary.outcome === "poc");
  ck("progress ended with a done event", events.at(-1).kind === "done");
  ck("a false-positive review replays each crash and reports a verdict",
    posted.includes("replay")
    && events.some((e) => e.kind === "verification" && e.verification && e.verification.deterministic === true));

  // ---------- runAutopilotCase: multi-target + the cross-binary analyses ----------
  // Two binaries in one case. Each gets its own deep pipeline; then the case-level stages that
  // look ACROSS binaries (link_case, ipc_model, cross_taint, whole_system) run once for the case.
  const casePosted = [];       // {stage, target, case}
  global.fetch = async (url, opts = {}) => {
    const method = opts.method || "GET";
    const j = (obj) => ({ ok: true, status: 200, statusText: "OK", text: async () => JSON.stringify(obj) });
    const mAdv = url.match(/^\/targets\/([^/]+)\/advice$/);
    if (mAdv) return j({ headline: "elf", backend: "coverage_fuzz", input_mode: "stdin",
      plan: [{ stage: "coverage_fuzz", params: { input_mode: "stdin" } }] });
    if (/^\/targets\/[^/]+\/capabilities$/.test(url))
      return j({ stages: { find: AVAIL.map(capStage) } });
    if (method === "POST" && url === "/runs") {
      const b = JSON.parse(opts.body);
      casePosted.push({ stage: b.stage, target: b.target_id || null, case: b.case_id || null });
      return { ok: true, status: 201, statusText: "Created", text: async () => JSON.stringify({ run_id: `run-${b.stage}`, from_cache: false }) };
    }
    if (/\/output$/.test(url)) return j({ output: null });
    if (url.startsWith("/runs/")) return j({ status: "done" });
    if (/^\/cases\/[^/]+\/findings$/.test(url)) return j([]);
    if (/\/functions$/.test(url)) return j([{}, {}]);
    if (/\/dynresults$/.test(url)) return j([]);     // no crash: keeps each target's run short
    if (/\/pocs$/.test(url)) return j([]);
    if (/\/findings$/.test(url)) return j([]);
    return j({});
  };
  const ap2 = await import(pathToFileURL(path.join(appDir, "autopilot.js")).href + `?c=${Date.now()}`);
  const cev = [];
  const cres = await ap2.runAutopilotCase(ap2.newController(), (e) => cev.push(e),
    { targetIds: ["A", "B"], caseId: "CASE1" });
  const caseStages = casePosted.filter((p) => p.case && !p.target).map((p) => p.stage);
  const perTargetOf = (t) => casePosted.filter((p) => p.target === t).map((p) => p.stage);

  ck("each binary gets its own deep pipeline",
    perTargetOf("A").includes("disassemble") && perTargetOf("B").includes("disassemble")
    && perTargetOf("A").includes("coverage_fuzz") && perTargetOf("B").includes("coverage_fuzz"));
  ck("the case is linked across binaries after the per-target runs",
    caseStages.includes("link_case") && caseStages.includes("ipc_model")
    && caseStages.includes("cross_taint") && caseStages.includes("whole_system"));
  ck("case stages carry a case_id and no target_id",
    casePosted.filter((p) => p.stage === "cross_taint").every((p) => p.case && !p.target));
  ck("the case run ends with a single done event", cev.filter((e) => e.kind === "done").length === 1);
  ck("the case run reports an outcome", typeof cres.outcome === "string");

  console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.log("FAIL  harness threw: " + (e && e.stack || e)); process.exit(1); });
