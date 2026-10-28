// The workbench root. Owns state, wires the Autopilot controller to the API, and renders the
// results-first view. Design target: drop one or more binaries, click once, get a
// proof-of-concept -- and, with several binaries, the cross-binary analyses too.

import { h, render } from "preact";
import { useState, useEffect, useRef, useCallback } from "preact/hooks";
import { api, waitForRun } from "./api.js";
import { isFolderPick, folderArchive } from "./archive.js";
import { runAutopilotCase, newController, cancel as cancelAutopilot, coverageOf } from "./autopilot.js";
import { rankFindings, pocsForFinding, fmtTime, progressText, stageLabel, dedupeFindings, buildRunLog, buildVerdicts, filterByViz, filterByCuration, curationCounts, containingFunction, failedTargets, operatorSettings } from "./util.js";
import {
  html, DropZone, TargetSummary, ProgressLog, ConsolePanel, FuzzConsole, RunHeader, FuzzHealthPanel, AttemptLogModal, AttemptLogsList, DynamicCoverageBanner, FindingCard, EmptyResults, Spinner, UnavailablePanel, RunScorecard, SystemMap, CoveragePanel, CodeView, PipelinePlan, EvidenceModal, FunctionsModal, VerdictStrip, VerdictCard, AnalysisDrawer, ShellVerdict, ExploitsPanel, DrawerFacts, TargetBar, FunctionsPanel, StringsPanel, DisasmPanel, DiffPanel, ScansPanel, SelftestPanel, CrashesPanel, CallGraphCanvas, CaseOverview, EngagementMap, CurationFilter,
  RunSignalsStrip, DoctorPanel, SeedsField, BuildFoot,
} from "./components.js";

let _conSeq = 0;

const stageLabelSafe = (s) => (s ? stageLabel(s) : "");

// Match a finding's function address against a function row's address (hex or int, PIE-shifted
// forms compared loosely on the low bits).
function addrMatch(a, b) {
  const n = (x) => (typeof x === "string" ? (parseInt(x, 16) || parseInt(x, 10)) : x);
  const na = n(a), nb = n(b);
  return na != null && nb != null && (na === nb || (na & 0xffff) === (nb & 0xffff));
}

let _logSeq = 0;

// Turn an Autopilot emit() event into a human log row. Returns null for events that only
// trigger a data refresh and should not clutter the log.
// Non-stage events -> an info row (or null to ignore). Stage start/done/error are handled
// separately so a stage is ONE row that transitions, not a start line plus a done line.
function eventToLog(ev) {
  switch (ev.kind) {
    case "advice": return null;   // shown once, on the target summary (setAdvice); not echoed here
    case "info": return { tone: "info", text: ev.message };
    case "cancelled": return { tone: "warn", text: "Cancelled." };
    case "done": {
      const msg = {
        poc: "Done — a verified proof-of-concept is ready below.",
        crash: "Done — reproduced a crash; see the findings below.",
        static: "Done — no crash reproduced; static findings below.",
        cancelled: "Stopped.",
      }[ev.outcome] || "Done.";
      return { tone: ev.outcome === "poc" ? "ok" : "info", text: msg };
    }
    default: return null;   // start/stage-*/unavailable handled elsewhere
  }
}

// A SERVER-side case event ({type, payload, id}) -> an append-only log row for the background run,
// so its log reads step by step like the interactive one. The plan panel shows the live/current
// state, so here we log only the transitions that COMPLETE a step (done/skipped/error/cancelled),
// carrying the "what it found" detail; the noisy per-exec progress stays out of the log.
function bgEventToLog(ev, names) {
  const p = ev.payload || {};
  const nm = (id) => (names && names.get(id)) || (id ? String(id).slice(0, 8) : "a target");
  if (ev.type === "autopilot.target_error") {
    // A target whose analysis ABORTED is a failure, not a quiet gap in the results.
    return { tone: "bad", text: `${nm(p.target_id)}: analysis aborted${p.stage ? ` in ${p.stage}` : ""} — ${p.error || "error"}. The remaining targets continue; this one's results are incomplete.` };
  }
  if (ev.type === "autopilot.error") {
    return { tone: "bad", text: `Background run stopped with an error: ${p.error || "unknown"}` };
  }
  if (ev.type === "autopilot.stage") {
    if (!p.state || p.state === "running") return null;
    // Report the stage outcome HONESTLY. A stage that DECLINED (ran and could not do its work --
    // afl aborted, no IPC channel, target would not start), was SKIPPED (never reached), timed
    // out, or was cancelled is NOT a success and must not render as a green check. The backend
    // already distinguishes these (orchestrate `_emit_stage`); only the UI was flattening them.
    const status = ({ error: "error", timeout: "timeout", declined: "declined",
                      skipped: "skipped", cancelled: "cancelled" })[p.state] || "done";
    return { kind: "stage", stage: p.stage, label: (p.label || p.stage),
             detail: p.detail || null, status };
  }
  if (ev.type === "autopilot.done") {
    const failed = Array.isArray(p.failed_targets) ? p.failed_targets : [];
    if (p.target_errors || failed.length) {
      // NOT a clean "done": say how many targets failed, and which.
      const n = p.target_errors || failed.length;
      return { tone: "bad",
               text: `Background run finished — ${p.outcome || "done"}, but ${n} target${n === 1 ? "" : "s"} FAILED${failed.length ? `: ${failed.map(nm).join(", ")}` : ""}.` };
    }
    return { tone: p.outcome === "poc" ? "ok" : "info",
             text: `Background run finished — ${p.outcome || "done"}.` };
  }
  return null;
}

// The human label for a fuzzing stage, from its event-type prefix (e.g. "directed_fuzz.progress").
const _FUZZ_LABEL = { fuzz: "Black-box fuzzing", directed: "Directed fuzzing",
  directed_fuzz: "Directed fuzzing", coverage: "Coverage fuzzing", coverage_fuzz: "Coverage fuzzing",
  env_fuzz: "Env-var fuzzing", net_fuzz: "Network fuzzing", libfuzzer: "libFuzzer harness" };
function fuzzStageLabel(type) {
  const head = String(type).split(".")[0];
  return _FUZZ_LABEL[head] || _FUZZ_LABEL[head.split("_")[0]] || head;
}

// A fuzzing / coverage / directed event -> one compact Console line, so an operator can watch
// what the fuzzer is actually doing (campaign start, crash harvest, did-not-run reason) in real
// time instead of a silent run. Prefers an explicit message/note, else a few scalar fields;
// skips the bulky array payloads (argv, channels, candidates) that are not line-sized.
function fuzzSummary(type, p) {
  // An engine's attempt-log summary: its verdict over every attempt it made.
  if (/\.attempts$/.test(type) && p.verdict_note) {
    return `${p.engine || type.split(".")[0]}: ${p.verdict_note}`;
  }
  if (p.msg) return p.msg;
  if (p.note) return p.note;
  const skip = new Set(["argv", "channels", "arrays", "candidates", "blocks"]);
  const bits = [];
  for (const [k, v] of Object.entries(p)) {
    if (v == null || typeof v === "object" || skip.has(k)) continue;
    bits.push(`${k}=${v}`);
    if (bits.length >= 6) break;
  }
  return bits.length ? bits.join("  ") : type;
}

// Run options persist across reloads / "New analysis" so an operator who re-runs the same target
// shape does not retype argv, the libs dir, and the engine choices each time. Best-effort: a private
// window or blocked storage just falls back to the defaults.
const RUNOPTS_KEY = "lykos-runopts";
function loadRunOpts() { try { return JSON.parse(localStorage.getItem(RUNOPTS_KEY) || "{}") || {}; } catch { return {}; } }

// The findings-list triage filter (doc 47 P3) is a per-operator view preference, remembered.
const CURFILTER_KEY = "lykos-curfilter";
function loadCurFilter() { try { return localStorage.getItem(CURFILTER_KEY) || "hide_fp"; } catch { return "hide_fp"; } }

// A curation the operator just saved, re-applied over a findings read that was already in flight
// when it was saved (the background poll re-reads findings every few seconds, and a response that
// left the server before the POST would otherwise flip the card back for one tick). Dropped as
// soon as the server's copy agrees.
function applyLocalCuration(fs, local) {
  if (!local.size) return fs;
  const same = (a, b) => (a ? `${a.status}|${a.note}` : "") === (b ? `${b.status}|${b.note}` : "");
  return (fs || []).map((f) => {
    if (!local.has(f.id)) return f;
    const mine = local.get(f.id);
    if (same(f.curation, mine.value)) { local.delete(f.id); return f; }
    if (f.curation && f.curation.updated_at && f.curation.updated_at > mine.at) { local.delete(f.id); return f; }
    return { ...f, curation: mine.value };
  });
}

function App() {
  const _ro = loadRunOpts();
  const [caseId, setCaseId] = useState(null);
  const [targets, setTargets] = useState([]);
  const [advice, setAdvice] = useState(null);
  const [findings, setFindings] = useState([]);
  const [pocs, setPocs] = useState([]);
  const [log, setLog] = useState([]);
  const [unavailable, setUnavailable] = useState([]);
  const [running, setRunning] = useState(false);
  const [ran, setRan] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [health, setHealth] = useState(null);
  const [recentCases, setRecentCases] = useState([]);
  const [sysmap, setSysmap] = useState(null);
  const [coverage, setCoverage] = useState({});
  const [verifications, setVerifications] = useState({});  // input_sha -> replay review result
  const [codeFn, setCodeFn] = useState(null);       // {fn, finding} for the open code view
  const [evidence, setEvidence] = useState(null);   // {finding, focus} for the evidence inspector
  const [funcBrowse, setFuncBrowse] = useState(null); // {targetId, name, functions} for the function browser
  const [showCandidates, setShowCandidates] = useState(false); // triage: reveal speculative candidates
  const [activeTid, setActiveTid] = useState(null);   // the target focused in the workbench shell
  const [tab, setTab] = useState("findings");         // active workbench tab
  const [viz, setViz] = useState(null);               // Case Overview click-filter ({severity}/{cwe})
  const [funcsByT, setFuncsByT] = useState({});       // lazy per-target caches for the tab views
  const [cgByT, setCgByT] = useState({});             // call-graph edges per target
  const [fnView, setFnView] = useState("graph");      // Functions tab: graph or table
  const [stringsByT, setStringsByT] = useState({});
  const [dynByT, setDynByT] = useState({});
  const [disasmFn, setDisasmFn] = useState(null);     // getFunction detail for the Disassembly tab
  const [disasmSel, setDisasmSel] = useState({});     // targetId -> selected function id
  const [diffVerify, setDiffVerify] = useState(null); // poc_diff run result for the Diff tab
  const [patchDiff, setPatchDiff] = useState(null);   // patch_diff (changed-function localization) result
  const [scans, setScans] = useState({});             // operator scans: {variant|weggli|diff: {running,data,error}}
  const [harnessRun, setHarnessRun] = useState(null); // on-demand harness (deep fn fuzzing) status
  const [bg, setBg] = useState(null);               // server-side background autopilot status
  const [budgetMin, setBudgetMin] = useState(_ro.budgetMin ?? "");   // Autopilot budget in MINUTES ("" = size-aware default)
  const [converge, setConverge] = useState(_ro.converge ?? false);  // run-to-convergence (minutes become the ceiling)
  const [blackBox, setBlackBox] = useState(_ro.blackBox ?? true);    // include the black-box `fuzz` stage (uncheck to skip)
  const [covFuzz, setCovFuzz] = useState(_ro.covFuzz ?? true);      // coverage-guided (afl qemu-mode) fuzzing
  const [dirFuzz, setDirFuzz] = useState(_ro.dirFuzz ?? true);      // directed fuzzing
  const [concolicOn, setConcolicOn] = useState(_ro.concolicOn ?? true); // concolic (angr/symqemu) execution
  const [libfuzzerOn, setLibfuzzerOn] = useState(_ro.libfuzzerOn ?? true); // source libFuzzer campaign
  const [sysroot, setSysroot] = useState(_ro.sysroot ?? "");        // target-libraries dir -> QEMU_LD_PREFIX
  const [deepSeed, setDeepSeed] = useState(_ro.deepSeed ?? false);   // aggressive parser-buffer seed synthesis
  const [invArgv, setInvArgv] = useState(_ro.invArgv ?? "");       // operator invocation: argv template, @@ = input file
  const [invMode, setInvMode] = useState(_ro.invMode ?? "auto");   // input channel: auto|stdin|file|arg|env
  // Persist the run options so they survive a reload / "New analysis".
  useEffect(() => {
    try {
      localStorage.setItem(RUNOPTS_KEY, JSON.stringify({
        budgetMin, converge, blackBox, covFuzz, dirFuzz, concolicOn, libfuzzerOn,
        sysroot, deepSeed, invArgv, invMode }));
    } catch { /* storage blocked (private window) -- defaults are fine */ }
  }, [budgetMin, converge, blackBox, covFuzz, dirFuzz, concolicOn, libfuzzerOn,
      sysroot, deepSeed, invArgv, invMode]);
  // WHAT THE RUN DID, per target. The UI showed findings with no account of the work behind
  // them, and there was no endpoint to ask: the CLI printed this and the HTML report rendered
  // it, while the primary interface could not.
  const [scorecard, setScorecard] = useState([]);
  const [bgActivity, setBgActivity] = useState(null); // {msg, pct} live intra-stage progress
  const [consoleLines, setConsoleLines] = useState([]); // job.exec: tool commands + I/O
  const consoleSeen = useRef(new Set());              // de-dupe exec events by server id
  const [fuzzLive, setFuzzLive] = useState(null);     // live fuzzing telemetry (latest .progress)
  const [fuzzHealth, setFuzzHealth] = useState(null); // per-engine fuzzing health verdict (R1)
  const [attemptLogs, setAttemptLogs] = useState([]);  // every fuzz attempt log in the case
  const [openLog, setOpenLog] = useState(null);        // {sha, engine} shown in the log viewer
  const [fuzzState, setFuzzState] = useState(null);   // live Running/Converging/Stalled badge (U2)
  const fuzzTrendRef = useRef({ cov: null, grewAt: 0, seenAt: 0 }); // coverage-growth trend
  const [invChosen, setInvChosen] = useState(null);   // auto-discovered invocation (R2: "driving as")
  const [curFilter, setCurFilter] = useState(loadCurFilter); // findings-list operator-triage filter
  const [cgFocus, setCgFocus] = useState(null);       // {targetId, addr, title}: finding shown in the call graph
  const [runSignals, setRunSignals] = useState(null); // honesty signals: failed targets, degraded sandbox, ...
  const [triageByT, setTriageByT] = useState({});     // targetId -> crash triage (grouped, ranked)
  const [seeds, setSeeds] = useState([]);             // operator seed files stored in the case
  const [seedBusy, setSeedBusy] = useState(false);
  const [doctor, setDoctor] = useState(null);         // engine readiness on this host
  const [selftest, setSelftest] = useState(null);     // the tool's own validation gates (background)
  const [selftestHist, setSelftestHist] = useState(null);
  const [buildInfo, setBuildInfo] = useState(null);   // which build is serving (footer)
  useEffect(() => { try { localStorage.setItem(CURFILTER_KEY, curFilter); } catch {} }, [curFilter]);
  // The effective theme: an explicit choice (data-theme, set pre-paint from localStorage) wins,
  // else the OS preference. The toggle flips it, applies it to <html>, and persists the choice.
  const [theme, setTheme] = useState(() => {
    try {
      const set = document.documentElement.getAttribute("data-theme");
      if (set) return set;
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    } catch { return "dark"; }
  });
  const toggleTheme = useCallback(() => {
    setTheme((cur) => {
      const next = cur === "light" ? "dark" : "light";
      try { document.documentElement.setAttribute("data-theme", next); localStorage.setItem("lykos-theme", next); } catch {}
      return next;
    });
  }, []);
  const ctrlRef = useRef(null);
  const lastFocus = useRef(null);   // the element to restore focus to when a modal closes
  const bgPollRef = useRef(0);
  const bgEventsAfter = useRef(-1);   // last case-event id logged for the background run (-1 = seed)
  // The CURRENT target list, for long-lived async loops. The background poller is a chain of
  // setTimeout ticks that outlives the render it was created in; reading `targets` from its closure
  // gave it the list from when the poll STARTED -- [] when a case is reopened from the landing page
  // -- so every tick re-read PoCs for zero targets and wiped them (and the system map) from view.
  const targetsRef = useRef(targets);
  targetsRef.current = targets;
  const activeTidRef = useRef(null);   // the focused target, for the poller's crash-list refresh
  const curLocal = useRef(new Map());  // finding id -> {value, at}: curations saved, not yet re-read

  // Everything that belongs to ONE case. Switching case (reopen / new upload / New analysis) must
  // clear all of it: the previous case's engine-health verdict, attempt logs, focused target,
  // scorecard, console and open modals used to survive into the next case and read as its own.
  const resetCaseView = useCallback(() => {
    setLog([]); setFindings([]); setPocs([]); setAdvice(null); setUnavailable([]); setSysmap(null);
    setCoverage({}); setVerifications({}); setScorecard([]); setFuzzHealth(null); setAttemptLogs([]);
    setOpenLog(null); setFuzzLive(null); setFuzzState(null); setInvChosen(null); setBgActivity(null);
    setConsoleLines([]); consoleSeen.current = new Set();
    setActiveTid(null); setTab("findings"); setViz(null); setCgFocus(null);
    setRunSignals(null); setTriageByT({}); setSeeds([]);
    setCodeFn(null); setEvidence(null); setFuncBrowse(null);
    setDisasmFn(null); setDisasmSel({}); setDiffVerify(null); setPatchDiff(null); setScans({}); setHarnessRun(null);
    fuzzTrendRef.current = { cov: null, grewAt: 0, seenAt: 0 };
    curLocal.current = new Map();
    setBg(null); bgPollRef.current++; bgEventsAfter.current = -1;
  }, []);


  // Follow a call to the function it names -- in the SAME binary, or, when the symbol is an
  // import resolved to another component, across the binary boundary into that binary's function.
  // This is the multi-binary "follow it all the way through": walk the call chain wherever it goes.
  const followCall = useCallback(async (name, fromTargetId, crumbs) => {
    const bare = (n) => (n || "").replace(/^(sym\.imp\.|sym\.|imp\.|_)/g, "").replace(/@.*$/, "");
    const want = bare(name);
    const findIn = async (tid) => {
      const fns = await api.functions(tid).catch(() => []);
      return (fns || []).find((f) => bare(f.name) === want && f.blocks) // prefer a real body
        || (fns || []).find((f) => bare(f.name) === want);
    };
    try {
      let targetId = fromTargetId;
      let match = await findIn(targetId);
      // Cross-binary: the symbol is imported here and DEFINED (exported) in another component.
      if ((!match || !match.blocks) && targets.length > 1) {
        const sm = sysmap || await api.systemmap(caseId).catch(() => null);
        const edge = (sm && sm.edges || []).find((e) => (e.symbols || (e.symbol ? [e.symbol] : [])).some((s) => bare(s) === want) && e.src === fromTargetId);
        if (edge && edge.dst) {
          const there = await findIn(edge.dst);
          if (there) { targetId = edge.dst; match = there; }
        }
      }
      if (!match) { setError(`Could not resolve ${want} to a function with a body.`); return; }
      const detail = await api.getFunction(match.id);
      const tgt = targets.find((t) => t.id === targetId);
      const crossed = targetId !== fromTargetId ? ` (${tgt ? tgt.filename : "other binary"})` : "";
      setCodeFn((cur) => ({ fn: detail, finding: cur && cur.finding, source: tgt && tgt.source,
        targetId, crumbs: [...(crumbs || []), want + crossed] }));
    } catch (e) {
      setError(e.message || String(e));
    }
  }, [targets, caseId, sysmap]);

  const _bareName = (n) => (n || "").replace(/^(sym\.imp\.|sym\.|imp\.|_)/g, "").replace(/@.*$/, "");

  // The cross-binary CALLERS of a function: other components that import this function's symbol.
  // From a sink in one binary you can walk UP into the binary that reaches it -- the other half
  // of "follow it all the way through".
  const xbinCallersOf = useCallback(async (detail, targetId) => {
    if (targets.length < 2) return [];
    const sm = sysmap || await api.systemmap(caseId).catch(() => null);
    const want = _bareName(detail.name);
    const out = [];
    for (const e of (sm && sm.edges) || []) {
      if (e.dst === targetId && (e.symbols || (e.symbol ? [e.symbol] : [])).some((s) => _bareName(s) === want)) {
        const t = targets.find((x) => x.id === e.src);
        out.push({ targetId: e.src, filename: t ? t.filename : "other", symbol: want });
      }
    }
    return out;
  }, [targets, caseId, sysmap]);

  // Jump UP into a cross-binary caller: find, in the calling binary, the function whose call
  // graph reaches this symbol, and open it.
  const followCrossCaller = useCallback(async (xc, crumbs) => {
    try {
      const cg = await api.callgraph(xc.targetId).catch(() => []);
      const edge = (cg || []).find((e) => _bareName(e.dst_name) === xc.symbol);
      const fns = await api.functions(xc.targetId).catch(() => []);
      const caller = edge ? (fns || []).find((f) => addrMatch(f.addr, edge.src_addr)) : null;
      if (!caller) { setError(`Could not locate the ${xc.filename} function that calls ${xc.symbol}.`); return; }
      const detail = await api.getFunction(caller.id);
      const xc2 = await xbinCallersOf(detail, xc.targetId);
      const t = targets.find((x) => x.id === xc.targetId);
      setCodeFn((cur) => ({ fn: detail, finding: cur && cur.finding, source: t && t.source,
        targetId: xc.targetId, xbinCallers: xc2, crumbs: [...(crumbs || []), `${xc.symbol} ↑ (${xc.filename})`] }));
    } catch (e) { setError(e.message || String(e)); }
  }, [targets, xbinCallersOf]);

  // Open the code view for a finding: resolve its function by address, then load the detail.
  const viewCode = useCallback(async (finding) => {
    try {
      const fns = await api.functions(finding.target_id).catch(() => []);
      const match = (fns || []).find((f) => addrMatch(f.addr, finding.function_addr))
        || (fns || []).find((f) => addrMatch(f.addr, finding.site_addr))
        // a finding that knows only its fault/sink site: the function whose range holds it
        || containingFunction(fns, finding.site_addr || finding.function_addr);
      if (!match) { setError("Could not locate the function for this finding."); return; }
      const detail = await api.getFunction(match.id);
      const tgt = targets.find((t) => t.id === finding.target_id);
      const xc = await xbinCallersOf(detail, finding.target_id);
      setCodeFn({ fn: detail, finding, source: tgt && tgt.source, targetId: finding.target_id, xbinCallers: xc, crumbs: [detail.name || "fn"] });
    } catch (e) {
      setError(e.message || String(e));
    }
  }, [targets, xbinCallersOf]);

  // Open the function browser for a target: pop the modal immediately (loading), then fetch the
  // recovered functions. The modal renders a spinner until `functions` arrives.
  const browseFunctions = useCallback(async (targetId) => {
    const tgt = targets.find((t) => t.id === targetId);
    setFuncBrowse({ targetId, name: (tgt && tgt.filename) || targetId.slice(0, 8), functions: null });
    try {
      const fns = await api.functions(targetId);
      setFuncBrowse((cur) => (cur && cur.targetId === targetId ? { ...cur, functions: fns || [] } : cur));
    } catch (e) {
      setFuncBrowse((cur) => (cur && cur.targetId === targetId ? { ...cur, functions: [] } : cur));
      setError(e.message || String(e));
    }
  }, [targets]);

  // Open one function from the browser into the code view (same drill-in as a finding, but with
  // no finding attached). Reuses the cross-binary caller resolution so xrefs still work.
  const openFunction = useCallback(async (fn, targetId) => {
    try {
      const detail = await api.getFunction(fn.id);
      const tgt = targets.find((t) => t.id === targetId);
      const xc = await xbinCallersOf(detail, targetId);
      setFuncBrowse(null);
      setCodeFn({ fn: detail, finding: null, source: tgt && tgt.source, targetId,
        xbinCallers: xc, crumbs: [detail.name || fn.name || "fn"] });
    } catch (e) {
      setError(e.message || String(e));
    }
  }, [targets, xbinCallersOf]);

  const loadRecent = useCallback(async () => {
    const cs = await api.listCases().catch(() => []);
    setRecentCases(cs || []);
  }, []);

  useEffect(() => {
    api.health().then((h) => setHealth(h && h.status)).catch(() => setHealth("down"));
    loadRecent();
    api.version().then(setBuildInfo).catch(() => setBuildInfo(null));
  }, [loadRecent]);

  // Engine readiness (doctor). The server probes in the background; poll while it does, bounded.
  const doctorPoll = useRef(0);
  const loadDoctor = useCallback(async (refresh = false) => {
    const token = ++doctorPoll.current;
    for (let i = 0; i < 120; i++) {
      let d;
      try { d = await api.doctor(refresh && i === 0); } catch (e) { d = { state: "error", error: e.message || String(e) }; }
      if (token !== doctorPoll.current) return;
      setDoctor(d);
      if (!d || d.state !== "probing") return;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }, []);
  useEffect(() => { loadDoctor(false); }, [loadDoctor]);

  // Self-test: start one gate, then poll its progress until it finishes (they take minutes).
  const selftestPoll = useRef(0);
  const pollSelftest = useCallback(async () => {
    const token = ++selftestPoll.current;
    for (;;) {
      let st;
      try { st = await api.selftest(); } catch (e) { st = { state: "error", error: e.message || String(e) }; }
      if (token !== selftestPoll.current) return;
      setSelftest(st);
      if (!st || !st.running) return;
      await new Promise((r) => setTimeout(r, 2000));
    }
  }, []);
  const startSelftest = useCallback(async (kind, options) => {
    try { await api.startSelftest(kind, options); }
    catch (e) { setSelftest((cur) => ({ ...(cur || {}), kind, error: e.message || String(e) })); return; }
    pollSelftest();
  }, [pollSelftest]);
  const loadSelftestHistory = useCallback(async () => {
    try { setSelftestHist(await api.selftestHistory()); }
    catch (e) { setSelftestHist({ error: e.message || String(e) }); }
  }, []);
  useEffect(() => { pollSelftest(); }, [pollSelftest]);   // pick up a self-test already running

  // Keyboard-first modal behaviour, for the three overlays app.js owns (code view, evidence
  // inspector, function browser). Escape closes the top-most open one; when a modal opens focus
  // moves into it, and when the last one closes focus returns to whatever opened it. The three
  // components stay presentational -- this cross-cutting behaviour lives with the state.
  const anyModal = !!(codeFn || evidence || funcBrowse);
  useEffect(() => {
    if (!anyModal) return;
    const onKey = (e) => {
      if (e.key !== "Escape") return;
      if (codeFn) setCodeFn(null);
      else if (evidence) setEvidence(null);
      else if (funcBrowse) setFuncBrowse(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [anyModal, codeFn, evidence, funcBrowse]);
  useEffect(() => {
    if (anyModal) {
      lastFocus.current = document.activeElement;
      requestAnimationFrame(() => {
        const el = document.querySelector(".modal-back .modal");
        if (el) { try { el.focus({ preventScroll: true }); } catch { el.focus(); } }
      });
    } else if (lastFocus.current) {
      try { lastFocus.current.focus({ preventScroll: true }); } catch {}
      lastFocus.current = null;
    }
  }, [anyModal]);

  const pushLog = useCallback((row) => {
    if (!row) return;
    setLog((cur) => [...cur, { id: ++_logSeq, ...row }]);
  }, []);

  // A job.exec event -> one console line. Deduped by the server event id (both the foreground
  // controller and the background tail can deliver the same one), capped so a long fuzzing run
  // does not grow the DOM without bound.
  const pushConsole = useCallback((evId, payload) => {
    if (!payload) return;
    const key = evId != null ? `e${evId}` : `s${++_conSeq}`;
    if (evId != null) {
      if (consoleSeen.current.has(key)) return;
      consoleSeen.current.add(key);
      // The de-dupe set must not grow for the life of a long fuzzing run (the lines are capped at
      // 500; the set of ids seen was not). Duplicates only ever arrive for RECENT events, so keep
      // the newest ids (a Set iterates in insertion order).
      if (consoleSeen.current.size > 4000) consoleSeen.current = new Set([...consoleSeen.current].slice(-2000));
    }
    setConsoleLines((cur) => {
      const next = [...cur, { id: key, ...payload }];
      return next.length > 500 ? next.slice(next.length - 500) : next;
    });
  }, []);

  // A fresh case per analysis session. Reusing whatever case happened to exist first piled
  // every upload into one case; instead each session gets its own, and the old ones stay on the
  // server, reopenable from the recent list -- "New analysis" no longer loses anything.
  const ensureCase = useCallback(async () => {
    if (caseId) return caseId;
    const c = await api.createCase(`Analysis ${new Date().toLocaleString()}`);
    setCaseId(c.id);
    return c.id;
  }, [caseId]);

  // Results are case-wide (findings across every uploaded binary), and PoCs are gathered from
  // each target and merged -- a bundle belongs to the finding it proves, wherever it lives.
  const refreshResults = useCallback(async (cid, tlist) => {
    const id = cid || caseId;
    const ts = tlist || targetsRef.current;
    if (!id) return;
    const [fs, psArrays, sm] = await Promise.all([
      api.caseFindings(id).catch(() => []),
      Promise.all((ts || []).map((t) => api.pocs(t.id).catch(() => []))),
      (ts || []).length > 1 ? api.systemmap(id).catch(() => null) : Promise.resolve(null),
    ]);
    setFindings(applyLocalCuration(fs || [], curLocal.current));
    setPocs((psArrays || []).flat());
    setSysmap(sm);
    api.attemptLogs(id).then((l) => setAttemptLogs(Array.isArray(l) ? l : [])).catch(() => {});
    // Honesty signals (incremental server-side, cheap to poll) and the focused target's crash
    // rows + triage, which used to be fetched once and then go stale for the rest of a run.
    api.runSignals(id).then((rs) => setRunSignals(rs || null)).catch(() => {});
    const at = activeTidRef.current || ((ts || [])[0] && ts[0].id);
    if (at) {
      api.dynresults(at).then((ds) => setDynByT((c) => ({ ...c, [at]: ds || [] }))).catch(() => {});
      api.crashTriage(at).then((tr) => setTriageByT((c) => ({ ...c, [at]: tr || null }))).catch(() => {});
    }
  }, [caseId, targets]);

  // Poll the server-side background Autopilot for a case. It keeps running even if this tab is
  // closed, so reopening a case picks the run back up. Refreshes results as it progresses.
  // Declared BEFORE reopenCase/onBackground, which list it as a dependency: a useCallback that
  // closes over a later `const` hits it in the temporal dead zone and throws at first render,
  // which blanks the whole app.
  const pollBackground = useCallback(async (cid) => {
    if (!cid) return;
    const token = ++bgPollRef.current;
    // Tail the case event stream so the background run's step-by-step log appears here too, not
    // just the plan panel. Seed past the current tail on the first tick so we log only NEW events.
    const tailEvents = async () => {
      try {
        const evs = await api.events(cid, Math.max(0, bgEventsAfter.current));
        for (const ev of evs) {
          if (ev.id > bgEventsAfter.current) bgEventsAfter.current = ev.id;
          if (bgEventsAfter.current >= 0 && token === bgPollRef.current) {
            // Live intra-stage progress ("disassembled 3000/7180 functions") coalesces into one
            // activity line instead of flooding the log with a row per batch.
            if (ev.type === "job.progress") {
              const p = ev.payload || {};
              if (p.msg) setBgActivity({ msg: p.msg, pct: p.pct != null ? p.pct : null });
              continue;
            }
            if (ev.type === "job.exec") { pushConsole(ev.id, ev.payload); continue; }
            // Fuzzing/coverage/directed milestones -> the Console, so "what is the fuzzer doing?"
            // has a visible answer. Discrete domain events only (campaign start, harvest, done,
            // did-not-run) -- not the per-batch job.progress above, which would flood the log.
            if (ev.type === "fuzz.health") {
              // R1: the per-engine health verdict (not telemetry) -- capture it, don't log it as a
              // console line. Says WHY the dynamic engines contributed what they did.
              setFuzzHealth(ev.payload || null);
              continue;
            }
            if (/\.attempts$/.test(ev.type)) {
              // An engine finished and stored its attempt log: refresh the case's list.
              api.attemptLogs(cid).then((l) => setAttemptLogs(Array.isArray(l) ? l : [])).catch(() => {});
            }
            if (ev.type === "coverage.invocation") {
              // R2: the invocation the autopilot AUTO-DISCOVERED and is driving the target with
              // (so the fuzzer reaches the parser, not the usage banner). Surface it as "driving as".
              const p = ev.payload || {};
              if (p.argv) setInvChosen({ argv: p.argv, why: p.why, source: "auto-discovered" });
              continue;
            }
            if (/^(coverage|fuzz|directed|env_fuzz|net_fuzz|libfuzzer|concolic|harness)[._]/.test(ev.type)) {
              // Live fuzzing telemetry: a `.progress` carries execs/rate/elapsed/budget/coverage,
              // and the stage's terminal event clears the live panel. Everything else is a console
              // milestone line.
              if (/\.progress$/.test(ev.type)) {
                const p = ev.payload || {};
                const now = Date.now();
                setFuzzLive({ stage: ev.type.split(/[._]/)[0], label: fuzzStageLabel(ev.type),
                              ...p, at: now });
                // U2 live state: is coverage still growing (Running), has it gone flat at a healthy
                // rate (Converging/steady), or are heartbeats still arriving at all? The "stalled"
                // (no-heartbeat) case is decided in the poll tick, since it is the ABSENCE of this.
                const cov = p.blocks_hit != null ? Number(p.blocks_hit)
                          : (p.edges_found != null ? Number(p.edges_found) : null);
                const tr = fuzzTrendRef.current;
                let grew = false;
                if (cov != null && !Number.isNaN(cov)) {
                  if (tr.cov == null || cov > tr.cov) { grew = true; tr.grewAt = now; }
                  tr.cov = Math.max(tr.cov == null ? 0 : tr.cov, cov);
                }
                tr.seenAt = now;
                const sinceGrowth = tr.grewAt ? now - tr.grewAt : 0;
                if (cov == null) setFuzzState({ label: "running", tone: "ok" });
                else if (grew) setFuzzState({ label: "finding coverage", tone: "ok" });
                else if (sinceGrowth > 20000) setFuzzState({ label: "coverage steady", tone: "warn" });
                else setFuzzState({ label: "running", tone: "ok" });
              } else if (/\.(done|coverage_unavailable|noprogress|deps)$/.test(ev.type)) {
                setFuzzLive(null);
                setFuzzState(null);
                fuzzTrendRef.current = { cov: null, grewAt: 0, seenAt: 0 };
              }
              pushConsole(ev.id, { cmd: fuzzSummary(ev.type, ev.payload || {}), note: ev.type });
              continue;
            }
            const row = bgEventToLog(ev, new Map((targetsRef.current || []).map((t) => [t.id, t.filename])));
            if (row) { pushLog(row); setBgActivity(null); }
          }
        }
      } catch { /* transient; retry next tick */ }
    };
    if (bgEventsAfter.current < 0) {
      // Seed past the case's NEWEST event. `events(cid, 0)` is the OLDEST page (500 rows), so on a
      // long case the cursor landed 500 events in and the poller then replayed the whole earlier
      // history into the log and console as if it were happening live.
      try { const seed = await api.eventsTail(cid, 1); bgEventsAfter.current = seed.reduce((m, e) => Math.max(m, e.id), 0); }
      catch { bgEventsAfter.current = 0; }
    }
    const tick = async () => {
      if (token !== bgPollRef.current) return;      // superseded by a newer poll
      let st;
      try { st = await api.backgroundStatus(cid); } catch { st = null; }
      // Re-check after the await: a reset / reopen while the request was in flight bumps the
      // token, and this (old case's) status must not land on the new case's screen.
      if (token !== bgPollRef.current) return;
      setBg(st && st.state && st.state !== "none" ? st : null);
      await tailEvents();
      if (token !== bgPollRef.current) return;
      if (st && st.running) {
        // U2 stalled detection: a campaign was heartbeating (seenAt set) but has gone quiet for a
        // while -- the target wedged / afl hung -- which is the ABSENCE of a `.progress`, so it is
        // caught here rather than in the event handler. The heartbeat is every <=3s, so 15s of
        // silence is a real stall, not a slow target between beats.
        const tr = fuzzTrendRef.current;
        if (tr.seenAt && Date.now() - tr.seenAt > 15000) {
          setFuzzState({ label: "stalled — no heartbeat", tone: "bad" });
        }
        refreshResults(cid, targetsRef.current);
        setTimeout(tick, 2500);
      } else if (st && (st.state === "done" || st.state === "cancelled" || st.state === "error")) {
        setBgActivity(null);
        setFuzzLive(null);
        setFuzzState(null);
        fuzzTrendRef.current = { cov: null, grewAt: 0, seenAt: 0 };
        refreshResults(cid, targetsRef.current);
      } else {
        // st === null (a transient status-fetch failure: timeout/ECONNRESET under fuzzing load) or a
        // not-yet-terminal state -> KEEP POLLING. Without this one blip froze the live UI for the
        // rest of the run (the spinner, plan, findings and fuzz badges all stopped updating).
        setTimeout(tick, 2500);
      }
    };
    tick();
  }, [refreshResults, pushLog, pushConsole]);

  // Reopen a previous analysis: its targets, findings and PoCs are all still on the server.
  const reopenCase = useCallback(async (cid) => {
    setError(null); setUploading(true);
    resetCaseView();
    try {
      const ts = await api.listTargets(cid).catch(() => []);
      // Re-attach each target's triage detail from its triage run, so a reopened case shows the
      // same rich file panel as a fresh upload.
      const runs = await api.listRuns(cid).catch(() => []);
      const triageRun = {};
      for (const r of runs || []) {
        if (r.stage === "ingest_triage" && r.status === "done" && !triageRun[r.target_id]) triageRun[r.target_id] = r.id;
      }
      await Promise.all((ts || []).map(async (t) => {
        const rid = triageRun[t.id];
        if (rid) t.details = await api.runOutput(rid).then((r) => r.output).catch(() => null);
      }));
      setCaseId(cid);
      setTargets(ts || []);
      setRan(true);
      // Rebuild the run log from the case's own history, so a reopened analysis shows what
      // already ran (and what failed) instead of an empty log.
      setLog(buildRunLog(runs, ts).map((row) => ({ id: ++_logSeq, ...row })));
      // Backfill the console with the last run's tool commands, so reopening a case shows the
      // work that was done rather than an empty panel (live commands still stream on top).
      consoleSeen.current = new Set();
      try {
        // The case's NEWEST events: `events(cid, 0)` returned the oldest 500, so a long case
        // "backfilled" the console with its first commands, not the last run's.
        const evs = await api.eventsTail(cid, 2000);
        const execs = (evs || []).filter((e) => e.type === "job.exec").slice(-250);
        setConsoleLines(execs.map((e) => {
          consoleSeen.current.add(`e${e.id}`);
          return { id: `e${e.id}`, ...(e.payload || {}) };
        }));
      } catch { setConsoleLines([]); }
      if (ts && ts.length) {
        const adv = await api.advice(ts[0].id).catch(() => null);
        setAdvice(adv);
      }
      const [fs, psArrays, sm, verifs, cards] = await Promise.all([
        api.caseFindings(cid).catch(() => []),
        Promise.all((ts || []).map((t) => api.pocs(t.id).catch(() => []))),
        // Cross-binary system map (multi-binary cases) and the false-positive review verdicts
        // both live only in the live event stream otherwise, so a reopened case lost its
        // SystemMap panel and every VerifyBadge. Fetch them from the server on reopen.
        (ts || []).length > 1 ? api.systemmap(cid).catch(() => null) : Promise.resolve(null),
        api.verifications(cid).catch(() => ({})),
        api.scorecard(cid).catch(() => null),
      ]);
      setFindings(fs || []);
      setPocs((psArrays || []).flat());
      setSysmap(sm);
      setVerifications(verifs || {});
      setScorecard((cards && cards.cards) || []);
      api.runSignals(cid).then((rs) => setRunSignals(rs || null)).catch(() => {});
      api.seeds(cid).then((r) => setSeeds((r && r.seeds) || [])).catch(() => {});
      // Reopened case: recover the fuzzing-health verdict from the latest scorecard card (it lives
      // in the live event stream otherwise, which a reopen has no access to).
      const _fh = ((cards && cards.cards) || []).map((c) => c && c.fuzz_health).filter(Boolean);
      if (_fh.length) setFuzzHealth(_fh[_fh.length - 1]);
      // Rebuild the coverage panel from the fuzz runs' outputs, so a reopened case shows how
      // much of each binary the earlier search reached -- keeping the best block-coverage read.
      const cov = {};
      for (const r of runs || []) {
        if (!r.target_id || r.status !== "done") continue;
        if (!/fuzz$/.test(r.stage)) continue;
        const o = await api.runOutput(r.id).then((x) => x.output).catch(() => null);
        const c = coverageOf(o);
        if (c && (!cov[r.target_id] || (c.pct || 0) > (cov[r.target_id].pct || 0))) cov[r.target_id] = c;
      }
      setCoverage(cov);
      pollBackground(cid);   // pick up a background run still going for this case
    } catch (e) {
      setError(`could not reopen the case: ${e.message || e}`);
    } finally {
      setUploading(false);
    }
  }, [pollBackground, resetCaseView]);

  const onBackground = useCallback(async () => {
    if (!caseId || !targets.length) return;
    try {
      // minutes -> seconds; blank/0 sends nothing, so the server picks a size-aware default. In
      // convergence mode the minutes are the SAFETY CEILING (search runs until coverage plateaus,
      // bounded by this), not a hard budget.
      const secs = Number(budgetMin) > 0 ? Math.round(Number(budgetMin) * 60) : undefined;
      // Operator invocation: how the binary is really run. argv is a shell string with @@ for the
      // input file (the server shlex-splits it, like the CLI's --argv); the channel overrides the
      // autopilot's guess. Both optional -- blank/"auto" lets discovery decide, as today.
      const { overrides, skipStages } = operatorSettings({ invArgv, invMode, sysroot, deepSeed, seeds,
        blackBox, covFuzz, dirFuzz, concolicOn, libfuzzerOn });
      await api.startBackground(caseId, targets.map((t) => t.id), secs, overrides, converge, skipStages);
      setRan(true);
      pollBackground(caseId);
    } catch (e) { setError(e.message || String(e)); }
  }, [caseId, targets, pollBackground, budgetMin, invArgv, invMode, converge, blackBox,
      covFuzz, dirFuzz, concolicOn, libfuzzerOn, sysroot, deepSeed, seeds]);

  // Seed upload / removal (stored in the case; one request per file, each capped at 1 MiB).
  const addSeeds = useCallback(async (fileList) => {
    const files = Array.from(fileList || []);
    if (!files.length || !caseId) return;
    setSeedBusy(true);
    try {
      for (const f of files) {
        try { await api.uploadSeed(caseId, f); }
        catch (e) { setError(`seed ${f.name}: ${e.message || e}`); }
      }
      const r = await api.seeds(caseId).catch(() => null);
      if (r) setSeeds(r.seeds || []);
    } finally { setSeedBusy(false); }
  }, [caseId]);
  const removeSeed = useCallback(async (sha) => {
    if (!caseId) return;
    try { await api.deleteSeed(caseId, sha); } catch (e) { setError(`could not remove the seed: ${e.message || e}`); }
    const r = await api.seeds(caseId).catch(() => null);
    if (r) setSeeds(r.seeds || []);
  }, [caseId]);


  // Upload one or more files. `append` adds to the current case; otherwise it starts fresh.
  const onFiles = useCallback(async (fileList, append = false) => {
    let files = Array.from(fileList || []);
    if (!files.length) return;
    setError(null);
    setUploading(true);
    // A FOLDER pick (a source tree) comes back as many files with relative paths. Pack the whole
    // tree into one archive client-side and upload THAT -- the server ingests it as a source
    // project (dependency-CVE + the source bug scanners), which is the point of a folder upload.
    try {
      if (isFolderPick(fileList)) {
        pushLog({ tone: "ok", text: `Packing ${files.length} files into a source archive…` });
        // Show WHAT is going in -- a folder upload that silently became "nothing" was the real
        // engagement complaint. List the member paths (capped) so the operator sees the contents.
        const names = files.map((f) => f.webkitRelativePath || f.name).filter(Boolean);
        if (names.length) pushLog({ tone: "info", text:
          `Contents: ${names.slice(0, 40).join(", ")}${names.length > 40 ? `  …(+${names.length - 40} more)` : ""}` });
        files = [await folderArchive(fileList)];
      }
    } catch (e) {
      setUploading(false);
      setError(`could not pack the folder: ${e.message || e}`);
      return;
    }
    if (!append) { resetCaseView(); setRan(false); }
    try {
      const cid = await ensureCase();
      const got = append ? [...targets] : [];
      for (const file of files) {
        const up = await api.uploadTarget(cid, file);
        // Triage runs asynchronously on upload. Wait for it before reading the target, or the
        // row comes back half-triaged (file_type "unknown", inconsistent advice).
        if (up.run_id) await waitForRun(up.run_id, { timeoutMs: 120000 }).catch(() => {});
        const t = await api.getTarget(up.id);
        // The rich file facts (entry point, imports, sections, mitigations detail) live in the
        // triage run's output, not the target row -- attach them for the file panel.
        if (up.run_id) t.details = await api.runOutput(up.run_id).then((r) => r.output).catch(() => null);
        // Source-derived target? Keep its source for the code view and the file panel.
        const srcResp = await api.targetSource(up.id).catch(() => null);
        if (srcResp && srcResp.source) t.source = srcResp;
        got.push(t);
        pushLog({ tone: "ok", text: `Uploaded ${t.filename} — triaged as ${t.file_type || "unknown"}.` });
        // A multi-file (binary + its libs) upload ingests as ONE target carrying companion deps;
        // name them so the operator sees what actually came in rather than one opaque row.
        const deps = Array.isArray(t.deps) ? t.deps : (t.deps ? Object.keys(t.deps) : []);
        if (deps.length) pushLog({ tone: "info", text:
          `  with ${deps.length} companion file${deps.length > 1 ? "s" : ""}: ${deps.slice(0, 20).join(", ")}${deps.length > 20 ? ", …" : ""}` });
      }
      setTargets(got);
      if (got.length && !advice) {
        const adv = await api.advice(got[0].id).catch(() => null);
        setAdvice(adv);
      }
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setUploading(false);
    }
  }, [ensureCase, pushLog, targets, advice, resetCaseView]);

  // Remove an uploaded file from the left rail. The server (DELETE /targets/<id>) cascades the
  // target's rows and component edges; here we drop it from the list and move focus off it.
  const removeTarget = useCallback(async (id) => {
    const victim = targets.find((t) => t.id === id);
    try {
      await api.deleteTarget(id);
    } catch (e) {
      setError(`could not remove the file: ${e.message || e}`);
      return;
    }
    const left = targets.filter((t) => t.id !== id);
    setTargets(left);
    if (activeTid === id) setActiveTid(left.length ? left[0].id : null);
    // Prune its PoCs from the merged view; case-wide findings refresh on the next results read.
    setPocs((ps) => (ps || []).filter((p) => p.target_id !== id));
    pushLog({ tone: "info", text: `Removed ${victim ? victim.filename : "file"} from the case.` });
  }, [targets, activeTid, pushLog]);

  const onAutopilot = useCallback(async () => {
    if (!targets.length) return;
    setError(null);
    setRunning(true);
    setRan(true);
    setUnavailable([]);
    setCoverage({}); setVerifications({});
    const ctrl = newController();
    ctrlRef.current = ctrl;
    const ids = targets.map((t) => t.id);
    const emit = (ev) => {
      if (ev.kind === "stage-start") {
        setLog((cur) => [...cur, { id: ++_logSeq, kind: "stage", stage: ev.stage, label: ev.label, status: "running" }]);
      } else if (ev.kind === "stage-progress") {
        const txt = progressText(ev.type, ev.payload);
        if (txt) setLog((cur) => {
          for (let i = cur.length - 1; i >= 0; i--) {
            if (cur[i].kind === "stage" && cur[i].stage === ev.stage && cur[i].status === "running") {
              const c = cur.slice(); c[i] = { ...c[i], progress: txt }; return c;
            }
          }
          return cur;
        });
      } else if (ev.kind === "stage-done" || ev.kind === "stage-error") {
        const status = ev.kind === "stage-error" ? "error" : "done";
        const detail = ev.kind === "stage-error" ? ev.message : ev.detail;
        setLog((cur) => {
          for (let i = cur.length - 1; i >= 0; i--) {
            if (cur[i].kind === "stage" && cur[i].stage === ev.stage && cur[i].status === "running") {
              const c = cur.slice();
              c[i] = { ...c[i], status, detail, cached: ev.cached };
              return c;
            }
          }
          return [...cur, { id: ++_logSeq, kind: "stage", stage: ev.stage, label: ev.label, status, detail, cached: ev.cached }];
        });
      } else if (ev.kind === "exec") {
        pushConsole(ev.id, ev.payload);
      } else {
        pushLog(eventToLog(ev));
      }
      if (ev.kind === "refresh") refreshResults(caseId, targets);
      if (ev.kind === "advice" && ev.advice && !advice) setAdvice(ev.advice);
      if (ev.kind === "unavailable") setUnavailable((cur) => mergeUnavailable(cur, ev.items));
      if (ev.kind === "coverage") setCoverage((cur) => {
        const prev = cur[ev.targetId];
        return (!prev || (ev.coverage.pct || 0) > (prev.pct || 0)) ? { ...cur, [ev.targetId]: ev.coverage } : cur;
      });
      if (ev.kind === "verification") setVerifications((cur) => ({ ...cur, [ev.input_sha]: ev.verification }));
    };
    // The same operator settings the server run gets: invocation, uploaded seeds, engine switches.
    const { overrides, skipStages } = operatorSettings({ invArgv, invMode, sysroot, deepSeed, seeds,
      blackBox, covFuzz, dirFuzz, concolicOn, libfuzzerOn });
    if (skipStages.length) overrides.skip_stages = skipStages;
    try {
      await runAutopilotCase(ctrl, emit, { targetIds: ids, caseId, overrides });
    } catch (e) {
      pushLog({ tone: "bad", text: `Autopilot stopped: ${e.message}` });
    } finally {
      await refreshResults(caseId, targets);
      setRunning(false);
      ctrlRef.current = null;
    }
  }, [targets, caseId, advice, pushLog, refreshResults, invArgv, invMode, sysroot, deepSeed, seeds,
      blackBox, covFuzz, dirFuzz, concolicOn, libfuzzerOn]);

  const onCancel = useCallback(() => {
    if (ctrlRef.current) cancelAutopilot(ctrlRef.current);
  }, []);

  // Click a verdict chip -> scroll to (and focus) that target's verdict card.
  const scrollToVerdict = useCallback((tid) => {
    const el = document.getElementById(`verdict-${tid}`);
    if (el) { el.scrollIntoView({ behavior: "smooth", block: "start" }); try { el.focus({ preventScroll: true }); } catch { el.focus(); } }
  }, []);

  const onReset = useCallback(() => {
    if (running) return;
    setCaseId(null);   // the next upload starts a fresh case; this one stays on the server
    setTargets([]); resetCaseView(); setRan(false); setError(null);
    loadRecent();      // the analysis just finished now appears in the recent list
  }, [running, loadRecent, resetCaseView]);

  // Operator triage (doc 47 P3): record the verdict server-side, then update the card in place.
  // A card that folds several findings (dedupe group) curates every one of them, so the verdict
  // cannot silently leave its siblings behind to resurface as an uncurated card.
  const curate = useCallback(async (finding, status, note) => {
    const ids = (finding.group_ids && finding.group_ids.length) ? finding.group_ids : [finding.id];
    try {
      const out = await Promise.all(ids.map((id) => api.setCuration(id, status, note)));
      const byId = new Map(out.map((r) => [r.finding_id,
        r.cleared ? null : { status: r.status, note: r.note, updated_at: r.updated_at }]));
      const now = Math.floor(Date.now() / 1000);
      for (const [id, value] of byId) curLocal.current.set(id, { value, at: now });
      setFindings((cur) => cur.map((f) => (byId.has(f.id) ? { ...f, curation: byId.get(f.id) } : f)));
      setEvidence((ev) => (ev && byId.has(ev.finding.id)
        ? { ...ev, finding: { ...ev.finding, curation: byId.get(ev.finding.id) } } : ev));
    } catch (e) {
      setError(`could not save the triage: ${e.message || e}`);
    }
  }, []);

  // Crash triage -> the finding a crash group belongs to, in the evidence inspector.
  const openFindingById = useCallback(async (fid) => {
    const f = findings.find((x) => x.id === fid) || await api.getFinding(fid).catch(() => null);
    if (f) setEvidence({ finding: f, focus: null });
    else setError("Could not load that finding.");
  }, [findings]);

  // Cross-link (doc 49 2b): a finding -> its function's node in the target's call graph.
  const showInGraph = useCallback((finding) => {
    setActiveTid(finding.target_id);
    setTab("functions");
    setFnView("graph");
    setCgFocus({ targetId: finding.target_id, addr: finding.function_addr || finding.site_addr,
                 title: finding.title || finding.cwe || "finding" });
  }, []);

  // A background-run control (pause/resume/stop) that fails must say so; the bare promise was
  // dropped and a refused click looked exactly like one that worked.
  const bgControl = useCallback((fn) => {
    Promise.resolve().then(fn).catch((e) => setError(`background run: ${e.message || e}`));
  }, []);

  // Select a function to disassemble in the Disassembly tab: remember it per target, load its detail.
  const selectDisasm = useCallback(async (fn) => {
    setDisasmSel((c) => ({ ...c, [fn.target_id || (activeTid)]: fn.id }));
    setDisasmFn(null);
    try { setDisasmFn(await api.getFunction(fn.id)); }
    catch (e) { setDisasmFn({ ...fn, decompiled: "(failed to load disassembly)" }); }
  }, [activeTid]);

  // Verified regression diff: re-run baseline A's PoC inputs against candidate B (the poc_diff
  // stage) and show whether the fault still reproduces.
  const runPocDiff = useCallback(async (aId, bId) => {
    const key = aId + ">" + bId;
    if (!aId || !bId || aId === bId) { setDiffVerify({ key, error: "pick two different targets" }); return; }
    setDiffVerify({ key, running: true });
    try {
      const run = await api.createRun("poc_diff", { targetId: bId, params: { baseline_target_id: aId } });
      await waitForRun(run.run_id);
      const out = await api.runOutput(run.run_id);
      setDiffVerify({ key, data: (out && out.output) || { applicable: false, note: "no result" } });
    } catch (e) { setDiffVerify({ key, error: e.message || String(e) }); }
  }, []);

  // Patch-diff (N-day): localize the functions whose body changed between baseline A and build B
  // (the patch_diff stage), file them as steerable leads, and refresh so they show in the findings.
  const runPatchDiff = useCallback(async (aId, bId) => {
    const key = aId + ">" + bId;
    if (!aId || !bId || aId === bId) { setPatchDiff({ key, error: "pick two different builds" }); return; }
    setPatchDiff({ key, running: true });
    try {
      const run = await api.createRun("patch_diff", { targetId: bId, params: { baseline_target_id: aId } });
      await waitForRun(run.run_id);
      const out = await api.runOutput(run.run_id);
      setPatchDiff({ key, data: (out && out.output) || { leads: 0, changed: 0 } });
      refreshResults(caseId, targets);
    } catch (e) { setPatchDiff({ key, error: e.message || String(e) }); }
  }, [caseId, targets, refreshResults]);

  // Operator scans (the Scans tab): variant hunt, source-pattern scan, differential test. Each is a
  // stage run like any other; the result is read back from its output and findings refreshed.
  const SCAN_STAGE = { variant: "variant_scan", weggli: "weggli_scan", diff: "diff_test" };
  const runScan = useCallback(async (kind, { targetId, params } = {}) => {
    setScans((cur) => ({ ...cur, [kind]: { running: true } }));
    try {
      const run = await api.createRun(SCAN_STAGE[kind], targetId ? { targetId, params } : { caseId, params });
      const done = await waitForRun(run.run_id);
      if (done && done.status && done.status !== "done") throw new Error(done.error || done.status);
      const out = await api.runOutput(run.run_id);
      setScans((cur) => ({ ...cur, [kind]: { data: (out && out.output) || { applicable: false, note: "the scan returned nothing" } } }));
      refreshResults(caseId, targets);
    } catch (e) { setScans((cur) => ({ ...cur, [kind]: { error: e.message || String(e) } })); }
  }, [caseId, targets, refreshResults]);

  // Operator-initiated DEEP FUNCTION FUZZING (the harness stage: T1 rank -> T2 drive -> T4
  // constant-dict -> T5 DoS oracle -> T6 stateful sequences). Deliberately NOT part of the default
  // run (operator steer: not every binary wants per-function fuzzing); the operator triggers it on
  // demand here. Declines cleanly on a non-x86-64 target or before disassemble, and files its
  // function-level findings into the usual panels.
  const runHarness = useCallback(async (tid) => {
    if (!tid || (harnessRun && harnessRun.running)) return;
    setHarnessRun({ targetId: tid, running: true });
    try {
      const run = await api.createRun("harness", { targetId: tid, params: {} });
      await waitForRun(run.run_id, { timeoutMs: 300000 });
      await refreshResults(caseId, targets);
      const fs = await api.targetFindings(tid).catch(() => null);
      const list = Array.isArray(fs) ? fs : (fs && fs.items) || (fs && fs.findings) || [];
      const n = list.filter((f) => f.detector === "harness").length;
      // The stage says WHY it declined (x86-64 only / run disassemble first / no drivable parser)
      // in its return; read it so the badge shows the reason instead of a bare "0 findings" that
      // reads as "does nothing". A genuine zero-crash run is reported distinctly too.
      const out = await api.runOutput(run.run_id).then((r) => r.output).catch(() => null);
      setHarnessRun({ targetId: tid, result: {
        findings: n,
        supported: out ? out.supported !== false : true,
        note: out && out.note,
        functions: out && out.functions } });
    } catch (e) {
      setHarnessRun({ targetId: tid, error: e.message || String(e) });
    }
  }, [caseId, targets, refreshResults, harnessRun]);

  // Lazily fetch a tab's data the first time it is needed for the focused target (and always the
  // crash rows, which gate the conditional Crashes tab). Cached per target so switching is instant.
  const _at = activeTid || (targets[0] && targets[0].id);
  useEffect(() => {
    if (!_at) return;
    const needFns = (tab === "functions" || tab === "disasm") && !funcsByT[_at];
    if (needFns) api.functions(_at).then((fs) => setFuncsByT((c) => ({ ...c, [_at]: fs || [] }))).catch(() => setFuncsByT((c) => ({ ...c, [_at]: [] })));
    if (tab === "functions" && !cgByT[_at]) api.callgraph(_at).then((cg) => setCgByT((c) => ({ ...c, [_at]: cg || [] }))).catch(() => setCgByT((c) => ({ ...c, [_at]: [] })));
    if (tab === "strings" && !stringsByT[_at]) api.strings(_at, { limit: 2000 }).then((ss) => setStringsByT((c) => ({ ...c, [_at]: (ss && ss.items) || (Array.isArray(ss) ? ss : []) }))).catch(() => setStringsByT((c) => ({ ...c, [_at]: [] })));
    if (!dynByT[_at]) api.dynresults(_at).then((ds) => setDynByT((c) => ({ ...c, [_at]: ds || [] }))).catch(() => setDynByT((c) => ({ ...c, [_at]: [] })));
    if (tab === "crashes" && !(_at in triageByT)) api.crashTriage(_at).then((tr) => setTriageByT((c) => ({ ...c, [_at]: tr || null }))).catch(() => setTriageByT((c) => ({ ...c, [_at]: null })));
  }, [tab, _at, funcsByT, cgByT, stringsByT, dynByT, triageByT]);
  activeTidRef.current = _at || null;

  const ranked = dedupeFindings(rankFindings(findings));
  const topDemoId = ranked.find((f) => f.state === "poc-backed")?.id;
  const pocsFor = (f) => pocsForFinding(pocs, f.id, topDemoId);
  const demonstrated = ranked.filter((f) => f.state === "poc-backed" || f.state === "confirmed");
  // Triage split: what the tool has EVIDENCE for (poc-backed / confirmed / corroborated) vs the
  // speculative inventory (candidate = one detector flagged a pattern, nothing corroborated it).
  // The candidates are what made the results feel like "a lot of findings that don't lead anywhere";
  // they are ranked last already, but here they are tucked behind a labelled, counted toggle so the
  // demonstrated findings are what you actually see. When nothing is demonstrated, candidates show
  // by default -- otherwise the list would look empty despite the detectors having flagged things.
  const notable = ranked.filter((f) => f.state !== "candidate");
  const candidates = ranked.filter((f) => f.state === "candidate");
  const candidatesVisible = showCandidates || notable.length === 0;
  const cardFor = (f) => html`<${FindingCard} key=${f.id}
    finding=${verByFinding[f.id] ? { ...f, verification: verByFinding[f.id] } : f}
    pocs=${pocsFor(f)} mitigations=${mitOf(f)}
    reportUrl=${api.reportUrl} artifactUrl=${api.artifactUrl} onViewCode=${viewCode}
    onInspect=${(finding, focus) => setEvidence({ finding, focus })}
    onCurate=${curate} onShowInGraph=${showInGraph} />`;
  const multi = targets.length > 1;
  // finding -> its false-positive review (via the PoC that carries the crashing input's sha)
  const verByFinding = {};
  for (const p of pocs) if (p.finding_id && p.input_sha && verifications[p.input_sha]) verByFinding[p.finding_id] = verifications[p.input_sha];
  const mitOf = (f) => (targets.find((t) => t.id === f.target_id) || {}).mitigations;

  // Verdict layer: one per target, worst-effect-first. `busy` folds the server-side background run
  // in with the foreground one so the Analysis drawer stays open through either kind of run.
  const verdicts = targets.length ? buildVerdicts(targets, findings, pocs, coverage) : [];
  const busy = running || !!(bg && bg.running);
  const drawerHasContent = !!(log.length || consoleLines.length || Object.keys(coverage).length || (bg && bg.plan && bg.plan.length) || busy);

  // ── Workbench shell: the target focused in the rail, and its findings / pocs / verdict ──────
  const activeTarget = targets.find((t) => t.id === activeTid) || targets[0] || null;
  const activeVerdict = activeTarget ? verdicts.find((v) => v.target.id === activeTarget.id) : null;
  const activeRanked = activeTarget ? ranked.filter((f) => f.target_id === activeTarget.id) : [];
  // The findings LIST honours a Case Overview click-filter; the overview itself always sees the
  // full set (so its donut/bars reflect the whole target, not the filtered subset).
  // ...and the operator's triage filter (default: hide what they marked false positive; the
  // filter bar counts what it hides, so a hidden finding is never invisible).
  const curCounts = curationCounts(activeRanked);
  const vizRanked = filterByCuration(filterByViz(activeRanked, viz), curFilter);
  const activeNotable = vizRanked.filter((f) => f.state !== "candidate");
  const activeCandidates = vizRanked.filter((f) => f.state === "candidate");
  const activePocs = activeTarget ? pocs.filter((p) => p.finding_id && activeRanked.some((f) => f.id === p.finding_id)) : [];
  // The finding behind the worst DEMONSTRATED effect (what the L3 rung narrates), preferring the
  // verdict's headline finding over merely the first poc-backed row.
  const topDemoFinding = (activeVerdict && activeVerdict.headline && activeVerdict.headline.findingId
    && activeRanked.find((f) => f.id === activeVerdict.headline.findingId))
    || activeRanked.find((f) => f.state === "poc-backed") || null;
  // Per-target verdict dot for the rail.
  const dotClass = (v) => v && v.status === "demonstrated" ? "d-crit" : v && v.status === "potential" ? "d-warn" : v && v.crashed ? "d-warn" : "d-none";
  const lvlTag = (v) => v && v.level ? `L${v.level}` : v && v.candidateLevel ? `(L${v.candidateLevel})` : v && v.crashed ? "crash" : "—";
  // Targets whose analysis ABORTED this run: shown as failed in the rail, never as a quiet "—".
  const failedMap = failedTargets(runSignals, bg);
  // The run controls (used in the rail): background running / resume / run / stop.
  const runControls = html`
    ${bg && bg.running ? html`
      <div class="bg-status"><${Spinner} label=${bg.paused
        ? "Paused — will resume where it left off"
        : `Background — ${bg.stage ? stageLabelSafe(bg.stage) : "starting"}`} /></div>
      ${bg.paused
        ? html`<button class="btn small primary" title="resume the run from where it paused"
                 onClick=${() => bgControl(() => api.resumeBackground(caseId))}>▶ Resume</button>`
        : html`<button class="btn ghost small" title="pause between stages — the current stage finishes, then it waits (no work lost) until you resume"
                 onClick=${() => bgControl(() => api.pauseBackground(caseId))}>⏸ Pause</button>`}
      <button class="btn ghost small" onClick=${() => bgControl(() => api.cancelBackground(caseId))}>■ Stop background</button>
    ` : !running ? html`
      <button class="btn primary" onClick=${onBackground}
              title=${bg && bg.state === "cancelled"
                ? "continue: re-runs the pipeline, reusing every stage that already completed (cached) so it picks up where it was stopped rather than starting over"
                : "the full pipeline on the server: every applicable stage, a wall-clock budget it divides between phases, and a scorecard of what it did"}>
        ${(bg && bg.state === "cancelled") ? "▶ Continue run"
          : (bg && bg.state === "error") ? "Run Autopilot again"
          : (ran ? "Run Autopilot again" : "▶ Run Autopilot")}</button>
      <fieldset class="run-group">
        <legend>budget</legend>
        <label class="budget-field" title=${converge
            ? "run-to-convergence: keep fuzzing until coverage plateaus; this slider is the SAFETY CEILING (max minutes). The non-fuzzing analysis is complete either way — only fuzzing depth changes."
            : "per-target wall-clock budget in minutes. The non-fuzzing analysis (static, CVE, taint, crashless exploit) is complete regardless; this is how long fuzzing gets. Blank = auto (scales with binary size)."}>
          <span class="budget-lbl">${converge ? "ceiling" : "budget"}</span>
          <input type="range" min="5" max="120" step="5" aria-label="fuzzing budget (minutes)"
                 list="budget-presets"
                 value=${budgetMin === "" ? 20 : budgetMin}
                 onInput=${(e) => setBudgetMin(e.target.value)}
                 style="vertical-align:middle;width:9em" />
          <datalist id="budget-presets">
            <option value="5"></option><option value="20"></option><option value="60"></option>
          </datalist>
          <span class="budget-val">${budgetMin === "" ? "20 min" : `${budgetMin} min`}</span>
        </label>
        <div class="budget-presets" role="group" aria-label="budget presets">
          ${[["quick", 5], ["standard", 20], ["thorough", 60]].map(([lbl, m]) => html`
            <button type="button" key=${lbl}
              class=${`budget-preset${Number(budgetMin === "" ? 20 : budgetMin) === m ? " active" : ""}`}
              title=${`${lbl} — ${m} min`}
              onClick=${() => setBudgetMin(String(m))}>${lbl}<span class="bp-min">${m}m</span></button>`)}
        </div>
        <label class="run-check" title="Run to convergence: keep fuzzing until coverage stops growing (the slider becomes the safety ceiling), instead of stopping at a fixed time. For when you can leave it running.">
          <input type="checkbox" checked=${converge} onChange=${(e) => setConverge(e.target.checked)} />
          <span>to convergence</span>
        </label>
      </fieldset>
      <fieldset class="run-group">
        <legend>engines</legend>
        <div class="engine-toggles">
          <label class="run-check" title="Black-box fuzzing (the built-in fuzz stage). Uncheck to skip it for this run — the rest of the pipeline (coverage/directed fuzzing, concolic, the full exploit ladder) still runs. Useful when black-box mutation is just burning budget on this target.">
            <input type="checkbox" checked=${blackBox} onChange=${(e) => setBlackBox(e.target.checked)} /><span>black-box</span>
          </label>
          <label class="run-check" title="Coverage-guided fuzzing (AFL++ qemu-mode). Uncheck to skip it for this run.">
            <input type="checkbox" checked=${covFuzz} onChange=${(e) => setCovFuzz(e.target.checked)} /><span>coverage</span>
          </label>
          <label class="run-check" title="Directed fuzzing (steered at flagged sinks / leads). Uncheck to skip it for this run.">
            <input type="checkbox" checked=${dirFuzz} onChange=${(e) => setDirFuzz(e.target.checked)} /><span>directed</span>
          </label>
          <label class="run-check" title="Concolic execution (angr/symqemu) — solves guarded branches. Uncheck to skip it for this run (it can be the slowest stage).">
            <input type="checkbox" checked=${concolicOn} onChange=${(e) => setConcolicOn(e.target.checked)} /><span>concolic</span>
          </label>
          <label class="run-check" title="Source libFuzzer campaign (only applies when source is available). Uncheck to skip it for this run.">
            <input type="checkbox" checked=${libfuzzerOn} onChange=${(e) => setLibfuzzerOn(e.target.checked)} /><span>libfuzzer</span>
          </label>
          <label class="run-check" title="Deep seed discovery: synthesize parser-buffer seeds for daemon/library functions the autopilot's entry-point seeding cannot reach. Findings are candidate-tier (attacker-reachability assumed, not proven). Normal auto-seeding (format models, dictionaries, entry params) runs regardless.">
            <input type="checkbox" checked=${deepSeed} onChange=${(e) => setDeepSeed(e.target.checked)} /><span>deep seed</span>
          </label>
        </div>
      </fieldset>
      <fieldset class="run-group">
        <legend>invocation</legend>
        <label class="inv-field" title="The target's OWN shared libraries: a directory holding its loader (ld-linux…) and .so files. Point afl-qemu / concolic at these so a binary built against a different glibc runs against its own libraries instead of this host's — the fix for 'symbol lookup error / Fork server handshake failed'. Leave blank to use the host's libraries.">
          <input type="text" placeholder="target libraries dir" aria-label="target libraries directory"
                 value=${sysroot} onInput=${(e) => setSysroot(e.target.value)} />
        </label>
        <label class="inv-field" title="How the binary is really invoked, as a shell string with @@ where the fuzzed input file goes — e.g.  -c @@  or  parse --in @@. Blank = lykos discovers it. This is the single thing that decides whether the fuzzer reaches the parser; it reaches every stage, same as the CLI's --argv.">
          <input type="text" placeholder="invocation (e.g.  -c @@)" aria-label="invocation argv"
                 value=${invArgv} onInput=${(e) => setInvArgv(e.target.value)} />
        </label>
        <select class="inv-mode" aria-label="input channel" title="input channel — how the fuzzed bytes reach the target. Auto lets lykos decide (and @@ in the invocation implies a file)."
                value=${invMode} onChange=${(e) => setInvMode(e.target.value)}>
          <option value="auto">channel: auto</option>
          <option value="stdin">stdin</option>
          <option value="file">file (@@)</option>
          <option value="arg">first arg</option>
          <option value="env">env var</option>
        </select>
        <${SeedsField} seeds=${seeds} busy=${seedBusy} onAdd=${addSeeds} onRemove=${removeSeed} />
      </fieldset>
      <button class="btn ghost small" onClick=${onAutopilot}
              title="run the stages from this tab instead: finer per-stage feedback, but a shorter pipeline and no scorecard — closing the tab stops it">
        ⚙ In this tab</button>
    ` : html`
      <button class="btn danger" onClick=${onCancel}>■ Stop</button>
    `}`;
  // Data-driven tab set: analytical tabs carry a count once their data has loaded; the Crashes tab
  // appears only when a run reproduced a crash for the focused target.
  const _atid = activeTarget && activeTarget.id;
  const activeFuncs = _atid ? funcsByT[_atid] : null;
  const activeStrings = _atid ? stringsByT[_atid] : null;
  const activeCrashes = _atid ? (dynByT[_atid] || []).filter((d) => d.crashed) : [];
  // Which function the call graph highlights: a finding the operator sent here ("◎ Call graph"),
  // else the demonstrated finding. Resolved to its CONTAINING function, so a finding that only
  // knows its fault/sink address still lands on a node.
  const focusActive = !!(cgFocus && cgFocus.targetId === _atid);
  const _hlAddr = focusActive ? cgFocus.addr
    : (topDemoFinding && (topDemoFinding.function_addr || topDemoFinding.site_addr));
  const cgHighlightFn = containingFunction(activeFuncs, _hlAddr);
  const cgHighlight = cgHighlightFn ? cgHighlightFn.addr : _hlAddr;
  // Category subsets for the conditional tabs (each appears only when it has content).
  const _heapDet = new Set(["heap_trace", "heap_check"]);
  const _taintDet = new Set(["tainted_deref", "cross_taint", "dynamic_taint"]);
  const heapFindings = activeRanked.filter((f) => _heapDet.has(f.detector) || /CWE-(122|415|416)\b/.test(f.cwe || ""));
  const taintFindings = activeRanked.filter((f) => _taintDet.has(f.detector));
  const cveFindings = activeRanked.filter((f) => f.detector === "cve_scan" || /^CVE-/i.test(f.cwe || ""));
  const hasCoverage = !!(activeTarget && coverage[activeTarget.id]);
  // Tab metadata (label + optional count), and the GROUPING that keeps the top bar to one row:
  // the code views (functions/disasm/strings) and the dynamic views (crashes/coverage/heap/taint/
  // cves) each collapse under one group with a contextual sub-tab row, instead of 11 flat tabs.
  // Engagement map phases (doc 49 Theme 2a) for the active target: the path from recovery to proof,
  // each node clickable to the tab where that phase's evidence lives, muted when not reached.
  const _acov = activeTarget ? coverage[activeTarget.id] : null;
  const engPhases = activeTarget ? [
    { label: "Recover",
      detail: activeFuncs && activeFuncs.length ? `${activeFuncs.length} functions` : "binary loaded",
      reached: true, nav: "functions" },
    { label: "Detect",
      detail: `${activeRanked.length} finding${activeRanked.length === 1 ? "" : "s"}`,
      reached: activeRanked.length > 0, nav: "findings" },
    { label: "Search",
      detail: _acov && _acov.pct != null ? `${_acov.pct}% covered`
        : activeCrashes.length ? `${activeCrashes.length} crash${activeCrashes.length === 1 ? "" : "es"}`
        : "not executed",
      reached: !!(hasCoverage || activeCrashes.length),
      nav: hasCoverage ? "coverage" : activeCrashes.length ? "crashes" : null },
    { label: "Prove",
      detail: activeVerdict && activeVerdict.level ? `L${activeVerdict.level}`
        : activeVerdict && activeVerdict.candidateLevel ? `candidate L${activeVerdict.candidateLevel}`
        : "no PoC",
      reached: !!(activeVerdict && activeVerdict.level), nav: "exploits" },
  ] : [];
  const tabMeta = {
    findings: { label: "Findings", n: activeRanked.length },
    exploits: { label: "Exploits", n: activePocs.length },
    functions: { label: "Functions & call graph", n: activeFuncs ? activeFuncs.length : undefined },
    disasm: { label: "Disassembly" },
    strings: { label: "Strings", n: activeStrings ? activeStrings.length : undefined },
    crashes: { label: "Crashes", n: (_atid && triageByT[_atid] && triageByT[_atid].distinct) || activeCrashes.length },
    coverage: { label: "Coverage" },
    heap: { label: "Heap", n: heapFindings.length },
    taint: { label: "Taint", n: taintFindings.length },
    cves: { label: "CVEs", n: cveFindings.length },
    diff: { label: "Diff" },
    scans: { label: "Scans" },
    console: { label: "Console", n: consoleLines.length },
  };
  const groupDefs = [
    { id: "overview", label: "Overview", tabs: ["findings"], n: activeRanked.length },
    { id: "exploits", label: "Exploits", tabs: ["exploits"], n: activePocs.length },
    { id: "code", label: "Code", tabs: ["functions", "disasm", "strings"] },
    { id: "dynamic", label: "Dynamic", tabs: [
      ...(activeCrashes.length ? ["crashes"] : []),
      ...(hasCoverage ? ["coverage"] : []),
      ...(heapFindings.length ? ["heap"] : []),
      ...(taintFindings.length ? ["taint"] : []),
      ...(cveFindings.length ? ["cves"] : []),
    ] },
    { id: "diff", label: "Diff & scans", tabs: ["diff", "scans"] },
    { id: "console", label: "Console", tabs: ["console"], n: consoleLines.length },
  ].filter((g) => g.tabs.length);
  const activeGroup = groupDefs.find((g) => g.tabs.includes(tab)) || groupDefs[0];

  return html`
    <div class=${targets.length ? "app app-wb" : "app"}>
      <header class="topbar">
        <div class="brand"><span class="logo">◆</span> lykos <span class="tag">workbench</span></div>
        <div class="top-right">
          ${health ? html`<span class=${`hz hz-${health === "ok" ? "ok" : "bad"}`}>${health === "ok" ? "server ready" : "server " + health}</span>` : null}
          ${targets.length && !running ? html`<button class="btn ghost" onClick=${onReset}>New analysis</button>` : null}
          <button class="btn ghost theme-toggle" onClick=${toggleTheme}
            title=${theme === "light" ? "Switch to dark theme" : "Switch to light theme"}
            aria-label="Toggle colour theme">${theme === "light" ? "🌙" : "☀"}</button>
          <a class="btn ghost" href="/classic.html" title="The previous interface">Classic UI</a>
        </div>
      </header>

      ${error ? html`<div class="banner err">${error}</div>` : null}

      ${!targets.length ? html`
        <main class="stack">
          <section>
            <${DropZone} onFiles=${(fl) => onFiles(fl, false)} busy=${uploading} />
            ${uploading ? html`<div class="center"><${Spinner} label="Uploading and triaging…" /></div>` : null}
            <${DoctorPanel} doctor=${doctor} onRefresh=${() => loadDoctor(true)} compact=${true} />
            <${SelftestPanel} st=${selftest} history=${selftestHist} onStart=${startSelftest} onHistory=${loadSelftestHistory} />
            ${recentCases.length ? html`
              <div class="card recent">
                <div class="recent-head">Recent analyses</div>
                ${recentCases.slice(0, 10).map((c) => html`
                  <button class="recent-row" key=${c.id} onClick=${() => reopenCase(c.id)}>
                    <span class="recent-name">${c.name}</span>
                    <span class="recent-when">${fmtTime(c.created_at)}</span>
                  </button>`)}
              </div>` : null}
          </section>
        </main>
      ` : html`
        <div class="wb">
          <!-- left rail: targets + pipeline + run -->
          <nav class="wb-rail">
            <div>
              <div class="rail-sec-h">Targets ${targets.length > 1 ? `· ${targets.length}` : ""}</div>
              <div class="rail-targets">
                ${targets.map((t) => {
                  const v = verdicts.find((x) => x.target.id === t.id);
                  const on = activeTarget && t.id === activeTarget.id;
                  return html`<div class=${`rail-target${on ? " active" : ""}`} key=${t.id}
                    onClick=${() => { setActiveTid(t.id); setTab("findings"); setViz(null); }}>
                    <span class=${`rail-dot ${dotClass(v)}`}></span>
                    <span class="rail-tname">${t.filename}</span>
                    ${failedMap.has(t.id) ? html`<span class="rail-tlvl rail-failed"
                        title=${(() => { const e = failedMap.get(t.id) || {}; return `analysis aborted${e.stage ? ` in ${e.stage}` : ""}${e.error ? `: ${e.error}` : ""} — results for this target are incomplete`; })()}>failed</span>`
                      : html`<span class=${`rail-tlvl${v && !v.level && v.candidateLevel ? " rail-cand" : ""}`}
                        title=${v && !v.level && v.candidateLevel ? `candidate L${v.candidateLevel}: a PoC recipe exists but nothing verified it by execution` : ""}>${lvlTag(v)}</span>`}
                    <button class="rail-rm" title="Remove this file" aria-label=${`Remove ${t.filename}`}
                      disabled=${running || (bg && bg.running)}
                      onClick=${(e) => { e.stopPropagation(); removeTarget(t.id); }}>✕</button>
                  </div>`;
                })}
              </div>
              ${!running && !(bg && bg.running) ? html`<div style="margin-top:8px;"><${DropZone} onFiles=${(fl) => onFiles(fl, true)} busy=${uploading} compact=${true} /></div>` : null}
            </div>
            ${bg && bg.plan && bg.plan.length ? html`
              <div>
                <div class="rail-sec-h">Pipeline</div>
                <div class="rail-pipe">
                  ${bg.plan.map((s) => html`<div class=${`rail-step rs-${s.state || "pending"}`} key=${s.stage}>
                    <span class="rs-ico" title=${s.state || "pending"}>${s.state === "done" ? "✓" : s.state === "running" ? "◆" : s.state === "error" ? "✕" : s.state === "declined" ? "!" : s.state === "timeout" ? "⏱" : (s.state === "skipped" || s.state === "cancelled") ? "–" : "·"}</span>
                    <span>${s.label || s.stage}</span>
                  </div>`)}
                </div>
              </div>` : null}
          </nav>

          <!-- main: run bar + live fuzz console + verdict + tabs + panel -->
          <main class="wb-main">
            <div class="wb-runbar">${runControls}</div>
            <!-- R2: how the target is actually being driven (operator-supplied or auto-discovered),
                 so "did the fuzzer reach the parser" is visible rather than a guess. -->
            ${(() => {
              const op = invArgv.trim();
              const argv = op ? op
                : (invChosen ? (Array.isArray(invChosen.argv) ? invChosen.argv.join(" ") : invChosen.argv) : null);
              if (!argv) return null;
              const src = op ? "operator" : "auto-discovered";
              const name = activeTarget ? activeTarget.filename : "target";
              return html`<div class="driving-as" title=${(invChosen && invChosen.why) || "how the target is invoked; @@ is where the fuzzed input goes"}>
                <span class="da-lbl">driving as</span>
                <code>${name} ${argv}</code>
                <span class=${`da-src da-${op ? "op" : "auto"}`}>${src}</span></div>`;
            })()}
            <!-- Live fuzzing pulse + the Running/Converged/Stalled badge, directly under the run
                 bar so it is visible DURING a run on ANY tab. COMPACT here (a one-line strip): the
                 full telemetry card lives in the Console tab, so the same panel is not drawn twice. -->
            <${FuzzConsole} live=${fuzzLive} state=${fuzzState} compact=${true} />
            ${bgActivity ? html`<div class="bg-activity">${bgActivity.pct != null ? html`<span class="bg-pct">${Math.round(bgActivity.pct)}%</span>` : null}<span class="bg-act-msg">${bgActivity.msg}</span></div>` : null}
            <!-- The run's honesty signals (failed targets, degraded sandbox, ranked taint, tiered
                 recovery, capped crashes, hangs, lease renewals): compact chips, every tab. -->
            <${RunSignalsStrip} signals=${runSignals} bg=${bg} targets=${targets} />
            <${TargetBar} target=${activeTarget} onBrowseFunctions=${browseFunctions} />
            ${multi ? (() => {
              const dem = verdicts.filter((v) => v.status === "demonstrated").length;
              const pot = verdicts.filter((v) => v.status === "potential").length;
              const clean = verdicts.length - dem - pot;
              return html`<div class="wb-rollup">
                <span>${verdicts.length} targets</span>
                ${dem ? html`<span class="rollup-bad">${dem} exploited</span>` : null}
                ${pot ? html`<span class="rollup-warn">${pot} potential</span>` : null}
                ${clean ? html`<span class="rollup-muted">${clean} no crash</span>` : null}
              </div>`;
            })() : null}
            <${ShellVerdict} verdict=${activeVerdict} artifactUrl=${api.artifactUrl} />
            <${SystemMap} map=${sysmap} />

            <div class="wb-tabs">
              ${groupDefs.map((g) => html`<button key=${g.id}
                class=${`wb-tab${g.tabs.includes(tab) ? " active" : ""}`}
                onClick=${() => setTab(g.tabs.includes(tab) ? tab : g.tabs[0])}>
                ${g.label}${g.n ? html`<span class="tab-n">${g.n}</span>` : null}
              </button>`)}
              ${caseId ? html`<span class="tab-exports">
                <a class="btn small ghost" href=${api.reportUrl(caseId, "html")} target="_blank">HTML</a>
                <a class="btn small ghost" href=${api.reportUrl(caseId, "sarif")} target="_blank">SARIF</a>
                <a class="btn small ghost" href=${api.reportUrl(caseId, "json")} target="_blank">JSON</a>
              </span>` : null}
            </div>
            ${activeGroup && activeGroup.tabs.length > 1 ? html`
              <div class="wb-subtabs">
                ${activeGroup.tabs.map((t) => html`<button key=${t}
                  class=${`wb-subtab${tab === t ? " active" : ""}`}
                  onClick=${() => setTab(t)}>
                  ${tabMeta[t].label}${tabMeta[t].n ? html`<span class="tab-n">${tabMeta[t].n}</span>` : null}
                </button>`)}
              </div>` : null}

            ${tab === "findings" ? html`
              <div class="wb-panel">
                <!-- When NO dynamic engine could execute the target, say so HERE, next to the
                     findings -- a static-only (L0) result is a setup outcome, not a clean binary,
                     and the remedy (supply the target's libraries) belongs where the operator reads
                     the results, not only in the Console tab. -->
                <${DynamicCoverageBanner} health=${fuzzHealth} ran=${ran} />
                ${engPhases.length ? html`<${EngagementMap} phases=${engPhases} onNav=${setTab} />` : null}
                ${activeRanked.length ? html`<${CaseOverview} findings=${activeRanked}
                  pocs=${activePocs} filter=${viz} onFilter=${setViz} />` : null}
                ${activeRanked.length ? html`<${CurationFilter} mode=${curFilter} onChange=${setCurFilter} counts=${curCounts} />` : null}
                ${activeRanked.length && !vizRanked.length ? html`<div class="card empty">No finding matches this filter — ${activeRanked.length} in total.</div>` : null}
                ${activeRanked.length ? html`
                  ${activeNotable.map(cardFor)}
                  ${activeCandidates.length ? html`
                    <div class="triage-bar">
                      <button class="btn small ghost triage-toggle" onClick=${() => setShowCandidates((s) => !s)}>
                        ${candidatesVisible ? "▾" : "▸"} ${activeCandidates.length} candidate${activeCandidates.length === 1 ? "" : "s"}
                      </button>
                      <span class="triage-note">flagged patterns not yet demonstrated${activeNotable.length === 0 ? " — nothing corroborated yet" : ""}</span>
                    </div>
                    ${candidatesVisible ? activeCandidates.map(cardFor) : null}
                  ` : null}
                ` : html`<${EmptyResults} ran=${ran} />`}
              </div>
            ` : tab === "exploits" ? html`
              <div class="wb-panel">
                <${ExploitsPanel} verdict=${activeVerdict} pocs=${activePocs} topFinding=${topDemoFinding} artifactUrl=${api.artifactUrl} loadBundle=${api.bundle} />
              </div>
            ` : tab === "functions" ? html`
              <div class="wb-panel">
                <div class="fn-topbar">
                  <div class="fn-viewtabs">
                    <button class=${`fn-viewtab${fnView === "graph" ? " active" : ""}`} onClick=${() => setFnView("graph")}>Call graph</button>
                    <button class=${`fn-viewtab${fnView === "table" ? " active" : ""}`} onClick=${() => setFnView("table")}>Functions</button>
                  </div>
                  <div class="fn-actions">
                    ${harnessRun && harnessRun.targetId === _atid && !harnessRun.running ? html`
                      <span class=${`fn-harness-note${harnessRun.error || (harnessRun.result && harnessRun.result.supported === false) ? " bad" : ""}`}>
                        ${(() => {
                          if (harnessRun.error) return `harness: ${harnessRun.error}`;
                          const r = harnessRun.result || {};
                          // A clean decline (x86-64 only / run disassemble first / no drivable
                          // parser) must read as a declined reason, not a silent "0 findings".
                          if (r.supported === false) return `harness declined — ${r.note || "not applicable to this target"}`;
                          if (r.findings) return `harness: ${r.findings} function-level finding(s)`;
                          // Supported run with no crash: distinguish from a decline.
                          if (r.note) return `harness: ${r.note}`;
                          return `harness: 0 faults${r.functions != null ? ` — ${r.functions} function(s) driven` : ""}`;
                        })()}
                      </span>` : null}
                    <button class="fn-harness" disabled=${!!(harnessRun && harnessRun.running) || !_atid}
                      title="Rank this binary's functions and fuzz the most promising ones directly under the emulator — constant-guided inputs, an unbounded-allocation oracle, and stateful message sequences. Operator-initiated; not part of a normal run. x86-64; needs disassembly first."
                      onClick=${() => runHarness(_atid)}>
                      ${harnessRun && harnessRun.running && harnessRun.targetId === _atid
                        ? html`<${Spinner} /> Deep fuzzing…` : "⚡ Deep function fuzzing"}
                    </button>
                  </div>
                </div>
                ${focusActive ? html`<div class="cg-focus">
                    ${cgHighlightFn
                      ? html`Highlighting <code>${cgHighlightFn.name || cgHighlightFn.addr}</code> — the function behind “${cgFocus.title}”.`
                      : html`“${cgFocus.title}” is at <code>${cgFocus.addr}</code>, which is not inside any recovered function${activeFuncs ? "" : " (functions still loading)"}.`}
                    <button class="btn xsmall ghost" onClick=${() => setCgFocus(null)}>clear</button></div>` : null}
                ${fnView === "graph"
                  ? html`<${CallGraphCanvas} functions=${activeFuncs} edges=${_atid ? cgByT[_atid] : null}
                      onOpen=${(fn) => openFunction(fn, _atid)}
                      highlightAddr=${cgHighlight} />`
                  : html`<${FunctionsPanel} functions=${activeFuncs} onOpen=${(fn) => openFunction(fn, _atid)} />`}
              </div>
            ` : tab === "disasm" ? html`
              <div class="wb-panel">
                <${DisasmPanel} functions=${activeFuncs} detail=${disasmFn}
                  selectedId=${disasmSel[_atid]} loading=${disasmSel[_atid] && !disasmFn}
                  onSelect=${(fn) => selectDisasm({ ...fn, target_id: _atid })} />
              </div>
            ` : tab === "strings" ? html`
              <div class="wb-panel"><${StringsPanel} strings=${activeStrings} /></div>
            ` : tab === "crashes" ? html`
              <div class="wb-panel"><${CrashesPanel} crashes=${_atid ? dynByT[_atid] : null}
                triage=${_atid ? triageByT[_atid] : undefined} artifactUrl=${api.artifactUrl}
                onOpenFinding=${openFindingById} /></div>
            ` : tab === "coverage" ? html`
              <div class="wb-panel"><${CoveragePanel} coverage=${coverage} targets=${activeTarget ? [activeTarget] : targets} onDrill=${browseFunctions} /></div>
            ` : tab === "heap" ? html`
              <div class="wb-panel">
                <div class="cat-intro">Heap primitives discovered by tracing the target's allocator — the seeds for tcache poisoning and arbitrary write.</div>
                ${heapFindings.map(cardFor)}
              </div>
            ` : tab === "taint" ? html`
              <div class="wb-panel">
                <div class="cat-intro">Attacker-controlled data flows: values from untrusted input that reach a dangerous sink or a computed pointer.</div>
                ${taintFindings.map(cardFor)}
              </div>
            ` : tab === "cves" ? html`
              <div class="wb-panel">
                <div class="cat-intro">Known-CVE matches from fingerprinting this binary's components against the offline vulnerability database.</div>
                ${cveFindings.map(cardFor)}
              </div>
            ` : tab === "diff" ? html`
              <div class="wb-panel"><${DiffPanel} targets=${targets} findings=${ranked} onVerify=${runPocDiff} verify=${diffVerify} onPatchDiff=${runPatchDiff} patch=${patchDiff} /></div>
            ` : tab === "scans" ? html`
              <div class="wb-panel"><${ScansPanel} targets=${targets} activeId=${_atid} seeds=${seeds}
                scans=${scans} onRun=${runScan} /></div>
            ` : tab === "console" ? html`
              <div class="wb-panel">
                <!-- Lead with the persistent, whole-run live header (every phase, not just fuzzing),
                     so the Console is a live run command-center. -->
                <${RunHeader} bg=${bg} />
                ${bg && bg.plan ? html`<${PipelinePlan} plan=${bg.plan} targetName=${bg.target_name} target=${bg.target} targets=${bg.targets} now=${bg.now} />` : null}
                <!-- Lead with the live tool-command console (the actual rizin/gdb/qemu/afl commands
                     and their I/O) -- that is what "Console" means and what an analyst wants to see;
                     the human-readable Run log follows it. -->
                <${FuzzConsole} live=${fuzzLive} state=${fuzzState} converge=${!!(bg && bg.converge)} />
                <${ConsolePanel} lines=${consoleLines} />
                <${ProgressLog} entries=${log} running=${running} />
                <${CoveragePanel} coverage=${coverage} targets=${targets} onDrill=${browseFunctions} />
                <!-- Run-mechanics live in the Console (the activity hub), NOT duplicated onto every
                     tab (they used to render outside the tab switch, so engine health + "what this
                     run did" painted on Overview, Exploits, Dynamic and Diff too -- the overlap). -->
                <${FuzzHealthPanel} health=${fuzzHealth} onOpenLog=${(sha, engine) => setOpenLog({ sha, engine })} />
                <${AttemptLogsList} logs=${attemptLogs} onOpen=${(sha, engine) => setOpenLog({ sha, engine })} />
                <${RunScorecard} cards=${scorecard} targetName=${activeTarget && activeTarget.filename} />
                <${UnavailablePanel} items=${unavailable} />
                <${DoctorPanel} doctor=${doctor} onRefresh=${() => loadDoctor(true)} />
                <${SelftestPanel} st=${selftest} history=${selftestHist} onStart=${startSelftest} onHistory=${loadSelftestHistory} />
              </div>
            ` : html`<div class="wb-soon">This view is coming to the workbench.</div>`}
          </main>
        </div>
      `}

      ${openLog ? html`<${AttemptLogModal} sha=${openLog.sha} engine=${openLog.engine}
        fetchPage=${api.attemptLog} artifactUrl=${api.artifactUrl} onClose=${() => setOpenLog(null)} />` : null}
      ${codeFn ? html`<${CodeView} fn=${codeFn.fn} finding=${codeFn.finding} source=${codeFn.source}
        crumbs=${codeFn.crumbs} xbinCallers=${codeFn.xbinCallers}
        onNavigate=${(name) => followCall(name, codeFn.targetId, codeFn.crumbs)}
        onFollowCaller=${(xc) => followCrossCaller(xc, codeFn.crumbs)}
        onClose=${() => setCodeFn(null)} />` : null}

      ${evidence ? html`<${EvidenceModal} finding=${evidence.finding} focus=${evidence.focus}
        pocs=${pocsFor(evidence.finding)} artifactUrl=${api.artifactUrl}
        onViewCode=${viewCode} onShowInGraph=${showInGraph} onClose=${() => setEvidence(null)} />` : null}

      ${funcBrowse ? html`<${FunctionsModal} name=${funcBrowse.name} functions=${funcBrowse.functions}
        onOpen=${(fn) => openFunction(fn, funcBrowse.targetId)} onClose=${() => setFuncBrowse(null)} />` : null}
      <${BuildFoot} info=${buildInfo} />
    </div>`;
}

// Merge unavailable-capability reports from several targets into one deduplicated list.
function mergeUnavailable(cur, items) {
  const by = new Map((cur || []).map((u) => [u.stage, u]));
  for (const u of items || []) if (!by.has(u.stage)) by.set(u.stage, u);
  return [...by.values()];
}

render(html`<${App} />`, document.getElementById("root"));
