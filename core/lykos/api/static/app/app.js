// The workbench root. Owns state, wires the Autopilot controller to the API, and renders the
// results-first view. Design target: drop one or more binaries, click once, get a
// proof-of-concept -- and, with several binaries, the cross-binary analyses too.

import { h, render } from "preact";
import { useState, useEffect, useRef, useCallback } from "preact/hooks";
import { api, waitForRun } from "./api.js";
import { runAutopilotCase, newController, cancel as cancelAutopilot, coverageOf } from "./autopilot.js";
import { rankFindings, pocsForFinding, fmtTime, progressText, stageLabel, dedupeFindings, buildRunLog, buildVerdicts } from "./util.js";
import {
  html, DropZone, TargetSummary, ProgressLog, ConsolePanel, FindingCard, EmptyResults, Spinner, UnavailablePanel, SystemMap, CoveragePanel, CodeView, PipelinePlan, EvidenceModal, FunctionsModal, VerdictStrip, VerdictCard, AnalysisDrawer, ShellVerdict, ExploitsPanel, DrawerFacts, FunctionsPanel, StringsPanel, DisasmPanel, DiffPanel, CrashesPanel, CallGraphCanvas,
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
function bgEventToLog(ev) {
  const p = ev.payload || {};
  if (ev.type === "autopilot.stage") {
    if (!p.state || p.state === "running") return null;
    const status = p.state === "error" ? "error" : "done";
    const suffix = p.state === "skipped" ? " (skipped)" : p.state === "cancelled" ? " (stopped)" : "";
    return { kind: "stage", stage: p.stage,
             label: (p.label || p.stage) + suffix,
             detail: p.detail || null, status };
  }
  if (ev.type === "autopilot.done") {
    return { tone: p.outcome === "poc" ? "ok" : "info",
             text: `Background run finished — ${p.outcome || "done"}.` };
  }
  return null;
}

function App() {
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
  const [funcsByT, setFuncsByT] = useState({});       // lazy per-target caches for the tab views
  const [cgByT, setCgByT] = useState({});             // call-graph edges per target
  const [fnView, setFnView] = useState("graph");      // Functions tab: graph or table
  const [stringsByT, setStringsByT] = useState({});
  const [dynByT, setDynByT] = useState({});
  const [disasmFn, setDisasmFn] = useState(null);     // getFunction detail for the Disassembly tab
  const [disasmSel, setDisasmSel] = useState({});     // targetId -> selected function id
  const [diffVerify, setDiffVerify] = useState(null); // poc_diff run result for the Diff tab
  const [bg, setBg] = useState(null);               // server-side background autopilot status
  const [bgActivity, setBgActivity] = useState(null); // {msg, pct} live intra-stage progress
  const [consoleLines, setConsoleLines] = useState([]); // job.exec: tool commands + I/O
  const consoleSeen = useRef(new Set());              // de-dupe exec events by server id
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
  const bgPollRef = useRef(0);
  const bgEventsAfter = useRef(-1);   // last case-event id logged for the background run (-1 = seed)


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
        || (fns || []).find((f) => addrMatch(f.addr, finding.site_addr));
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
  }, [loadRecent]);

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
    const ts = tlist || targets;
    if (!id) return;
    const [fs, psArrays, sm] = await Promise.all([
      api.caseFindings(id).catch(() => []),
      Promise.all((ts || []).map((t) => api.pocs(t.id).catch(() => []))),
      (ts || []).length > 1 ? api.systemmap(id).catch(() => null) : Promise.resolve(null),
    ]);
    setFindings(fs || []);
    setPocs((psArrays || []).flat());
    setSysmap(sm);
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
            const row = bgEventToLog(ev);
            if (row) { pushLog(row); setBgActivity(null); }
          }
        }
      } catch { /* transient; retry next tick */ }
    };
    if (bgEventsAfter.current < 0) {
      try { const seed = await api.events(cid, 0); bgEventsAfter.current = seed.reduce((m, e) => Math.max(m, e.id), 0); }
      catch { bgEventsAfter.current = 0; }
    }
    const tick = async () => {
      if (token !== bgPollRef.current) return;      // superseded by a newer poll
      let st;
      try { st = await api.backgroundStatus(cid); } catch { st = null; }
      setBg(st && st.state && st.state !== "none" ? st : null);
      await tailEvents();
      if (st && st.running) {
        refreshResults(cid, targets);
        setTimeout(tick, 2500);
      } else if (st && (st.state === "done" || st.state === "cancelled" || st.state === "error")) {
        setBgActivity(null);
        refreshResults(cid, targets);
      }
    };
    tick();
  }, [refreshResults, targets, pushLog, pushConsole]);

  // Reopen a previous analysis: its targets, findings and PoCs are all still on the server.
  const reopenCase = useCallback(async (cid) => {
    setError(null); setUploading(true);
    setLog([]); setUnavailable([]);
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
        const evs = await api.events(cid, 0);
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
      const [fs, psArrays, sm, verifs] = await Promise.all([
        api.caseFindings(cid).catch(() => []),
        Promise.all((ts || []).map((t) => api.pocs(t.id).catch(() => []))),
        // Cross-binary system map (multi-binary cases) and the false-positive review verdicts
        // both live only in the live event stream otherwise, so a reopened case lost its
        // SystemMap panel and every VerifyBadge. Fetch them from the server on reopen.
        (ts || []).length > 1 ? api.systemmap(cid).catch(() => null) : Promise.resolve(null),
        api.verifications(cid).catch(() => ({})),
      ]);
      setFindings(fs || []);
      setPocs((psArrays || []).flat());
      setSysmap(sm);
      setVerifications(verifs || {});
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
    } finally {
      setUploading(false);
    }
  }, [pollBackground]);

  const onBackground = useCallback(async () => {
    if (!caseId || !targets.length) return;
    try {
      await api.startBackground(caseId, targets.map((t) => t.id));
      setRan(true);
      pollBackground(caseId);
    } catch (e) { setError(e.message || String(e)); }
  }, [caseId, targets, pollBackground]);


  // Upload one or more files. `append` adds to the current case; otherwise it starts fresh.
  const onFiles = useCallback(async (fileList, append = false) => {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    setError(null);
    setUploading(true);
    if (!append) { setLog([]); setFindings([]); setPocs([]); setAdvice(null); setRan(false); setUnavailable([]); setSysmap(null); setCoverage({}); setVerifications({}); setBg(null); bgPollRef.current++; bgEventsAfter.current = -1; }
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
  }, [ensureCase, pushLog, targets, advice]);

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
    try {
      await runAutopilotCase(ctrl, emit, { targetIds: ids, caseId });
    } catch (e) {
      pushLog({ tone: "bad", text: `Autopilot stopped: ${e.message}` });
    } finally {
      await refreshResults(caseId, targets);
      setRunning(false);
      ctrlRef.current = null;
    }
  }, [targets, caseId, advice, pushLog, refreshResults]);

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
    setTargets([]); setAdvice(null); setFindings([]); setPocs([]);
    setLog([]); setRan(false); setError(null); setUnavailable([]); setSysmap(null); setCoverage({}); setVerifications({});
    setBg(null); bgPollRef.current++; bgEventsAfter.current = -1;
    loadRecent();      // the analysis just finished now appears in the recent list
  }, [running, loadRecent]);

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
  }, [tab, _at, funcsByT, cgByT, stringsByT, dynByT]);

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
    onInspect=${(finding, focus) => setEvidence({ finding, focus })} />`;
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
  const activeNotable = activeRanked.filter((f) => f.state !== "candidate");
  const activeCandidates = activeRanked.filter((f) => f.state === "candidate");
  const activePocs = activeTarget ? pocs.filter((p) => p.finding_id && activeRanked.some((f) => f.id === p.finding_id)) : [];
  // The finding behind the worst DEMONSTRATED effect (what the L3 rung narrates), preferring the
  // verdict's headline finding over merely the first poc-backed row.
  const topDemoFinding = (activeVerdict && activeVerdict.headline && activeVerdict.headline.findingId
    && activeRanked.find((f) => f.id === activeVerdict.headline.findingId))
    || activeRanked.find((f) => f.state === "poc-backed") || null;
  // Per-target verdict dot for the rail.
  const dotClass = (v) => v && v.status === "demonstrated" ? "d-crit" : v && v.status === "potential" ? "d-warn" : v && v.crashed ? "d-warn" : "d-none";
  const lvlTag = (v) => v && v.level ? `L${v.level}` : v && v.crashed ? "crash" : "—";
  // The run controls (used in the rail): background running / resume / run / stop.
  const runControls = html`
    ${bg && bg.running ? html`
      <div class="bg-status"><${Spinner} label=${`Background — ${bg.stage ? stageLabelSafe(bg.stage) : "starting"}`} /></div>
      <button class="btn ghost small" onClick=${() => api.cancelBackground(caseId)}>■ Stop background</button>
    ` : bg && (bg.state === "cancelled" || bg.state === "error") ? html`
      <button class="btn primary" onClick=${onBackground}>▷ Resume run</button>
    ` : !running ? html`
      <button class="btn primary" onClick=${onAutopilot}>${ran ? "Run Autopilot again" : "▶ Run Autopilot"}</button>
      <button class="btn ghost small" onClick=${onBackground} title="run on the server; survives closing the tab">▷ In background</button>
    ` : html`
      <button class="btn danger" onClick=${onCancel}>■ Stop</button>
    `}`;
  // Data-driven tab set: analytical tabs carry a count once their data has loaded; the Crashes tab
  // appears only when a run reproduced a crash for the focused target.
  const _atid = activeTarget && activeTarget.id;
  const activeFuncs = _atid ? funcsByT[_atid] : null;
  const activeStrings = _atid ? stringsByT[_atid] : null;
  const activeCrashes = _atid ? (dynByT[_atid] || []).filter((d) => d.crashed) : [];
  // Category subsets for the conditional tabs (each appears only when it has content).
  const _heapDet = new Set(["heap_trace", "heap_check"]);
  const _taintDet = new Set(["tainted_deref", "cross_taint", "dynamic_taint"]);
  const heapFindings = activeRanked.filter((f) => _heapDet.has(f.detector) || /CWE-(122|415|416)\b/.test(f.cwe || ""));
  const taintFindings = activeRanked.filter((f) => _taintDet.has(f.detector));
  const cveFindings = activeRanked.filter((f) => f.detector === "cve_scan" || /^CVE-/i.test(f.cwe || ""));
  const hasCoverage = !!(activeTarget && coverage[activeTarget.id]);
  const tabDefs = [
    { id: "findings", label: "Findings", n: activeRanked.length },
    { id: "exploits", label: "Exploits", n: activePocs.length },
    { id: "functions", label: "Functions & call graph", n: activeFuncs ? activeFuncs.length : undefined },
    { id: "disasm", label: "Disassembly" },
    { id: "strings", label: "Strings", n: activeStrings ? activeStrings.length : undefined },
    ...(activeCrashes.length ? [{ id: "crashes", label: "Crashes", n: activeCrashes.length }] : []),
    ...(hasCoverage ? [{ id: "coverage", label: "Coverage" }] : []),
    ...(heapFindings.length ? [{ id: "heap", label: "Heap", n: heapFindings.length }] : []),
    ...(taintFindings.length ? [{ id: "taint", label: "Taint", n: taintFindings.length }] : []),
    ...(cveFindings.length ? [{ id: "cves", label: "CVEs", n: cveFindings.length }] : []),
    { id: "diff", label: "Diff" },
    { id: "console", label: "Console", n: consoleLines.length },
  ];

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
                  return html`<button class=${`rail-target${on ? " active" : ""}`} key=${t.id}
                    onClick=${() => { setActiveTid(t.id); setTab("findings"); }}>
                    <span class=${`rail-dot ${dotClass(v)}`}></span>
                    <span class="rail-tname">${t.filename}</span>
                    <span class="rail-tlvl">${lvlTag(v)}</span>
                  </button>`;
                })}
              </div>
              ${!running && !(bg && bg.running) ? html`<div style="margin-top:8px;"><${DropZone} onFiles=${(fl) => onFiles(fl, true)} busy=${uploading} compact=${true} /></div>` : null}
            </div>
            ${bg && bg.plan && bg.plan.length ? html`
              <div>
                <div class="rail-sec-h">Pipeline</div>
                <div class="rail-pipe">
                  ${bg.plan.map((s) => html`<div class=${`rail-step rs-${s.status || "pending"}`} key=${s.stage}>
                    <span class="rs-ico">${s.status === "done" ? "✓" : s.status === "running" ? "◆" : s.status === "error" ? "✕" : "·"}</span>
                    <span>${s.label || s.stage}</span>
                  </div>`)}
                </div>
              </div>` : null}
            <div class="rail-run">
              ${bgActivity ? html`<div class="bg-activity">${bgActivity.pct != null ? html`<span class="bg-pct">${Math.round(bgActivity.pct)}%</span>` : null}<span class="bg-act-msg">${bgActivity.msg}</span></div>` : null}
              ${runControls}
            </div>
          </nav>

          <!-- main: verdict + tabs + panel -->
          <main class="wb-main">
            ${multi ? html`<${VerdictStrip} verdicts=${verdicts} onSelect=${(tid) => { setActiveTid(tid); setTab("findings"); }} />` : null}
            <${ShellVerdict} verdict=${activeVerdict} artifactUrl=${api.artifactUrl} />
            <${SystemMap} map=${sysmap} />

            <div class="wb-tabs">
              ${tabDefs.map((td) => html`<button key=${td.id}
                class=${`wb-tab${tab === td.id ? " active" : ""}`}
                onClick=${() => setTab(td.id)}>
                ${td.label}${td.n != null ? html`<span class="tab-n">${td.n}</span>` : null}
              </button>`)}
              ${caseId ? html`<span class="tab-exports">
                <a class="btn small ghost" href=${api.reportUrl(caseId, "html")} target="_blank">HTML</a>
                <a class="btn small ghost" href=${api.reportUrl(caseId, "sarif")} target="_blank">SARIF</a>
                <a class="btn small ghost" href=${api.reportUrl(caseId, "json")} target="_blank">JSON</a>
              </span>` : null}
            </div>

            ${tab === "findings" ? html`
              <div class="wb-panel">
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
                <${ExploitsPanel} verdict=${activeVerdict} pocs=${activePocs} topFinding=${topDemoFinding} artifactUrl=${api.artifactUrl} />
              </div>
            ` : tab === "functions" ? html`
              <div class="wb-panel">
                <div class="fn-viewtabs">
                  <button class=${`fn-viewtab${fnView === "graph" ? " active" : ""}`} onClick=${() => setFnView("graph")}>Call graph</button>
                  <button class=${`fn-viewtab${fnView === "table" ? " active" : ""}`} onClick=${() => setFnView("table")}>Functions</button>
                </div>
                ${fnView === "graph"
                  ? html`<${CallGraphCanvas} functions=${activeFuncs} edges=${_atid ? cgByT[_atid] : null}
                      onOpen=${(fn) => openFunction(fn, _atid)}
                      highlightAddr=${topDemoFinding && (topDemoFinding.function_addr || topDemoFinding.site_addr)} />`
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
              <div class="wb-panel"><${CrashesPanel} crashes=${_atid ? dynByT[_atid] : null} artifactUrl=${api.artifactUrl} /></div>
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
              <div class="wb-panel"><${DiffPanel} targets=${targets} findings=${ranked} onVerify=${runPocDiff} verify=${diffVerify} /></div>
            ` : tab === "console" ? html`
              <div class="wb-panel">
                ${bg && bg.plan ? html`<${PipelinePlan} plan=${bg.plan} targetName=${bg.target_name} target=${bg.target} targets=${bg.targets} />` : null}
                <${ProgressLog} entries=${log} running=${running} />
                <${ConsolePanel} lines=${consoleLines} />
                <${CoveragePanel} coverage=${coverage} targets=${targets} onDrill=${browseFunctions} />
              </div>
            ` : html`<div class="wb-soon">This view is coming to the workbench.</div>`}

            <${UnavailablePanel} items=${unavailable} />
          </main>

          <!-- right drawer: persistent target facts -->
          <aside class="wb-drawer">
            <${DrawerFacts} target=${activeTarget} onBrowseFunctions=${browseFunctions} />
            ${activeTarget && advice && activeTarget.id === (targets[0] && targets[0].id) ? html`<div class="headline" style="border:none;padding:0;">${typeof advice === "string" ? advice : (advice.message || advice.text || "")}</div>` : null}
          </aside>
        </div>
      `}

      ${codeFn ? html`<${CodeView} fn=${codeFn.fn} finding=${codeFn.finding} source=${codeFn.source}
        crumbs=${codeFn.crumbs} xbinCallers=${codeFn.xbinCallers}
        onNavigate=${(name) => followCall(name, codeFn.targetId, codeFn.crumbs)}
        onFollowCaller=${(xc) => followCrossCaller(xc, codeFn.crumbs)}
        onClose=${() => setCodeFn(null)} />` : null}

      ${evidence ? html`<${EvidenceModal} finding=${evidence.finding} focus=${evidence.focus}
        pocs=${pocsFor(evidence.finding)} artifactUrl=${api.artifactUrl}
        onViewCode=${viewCode} onClose=${() => setEvidence(null)} />` : null}

      ${funcBrowse ? html`<${FunctionsModal} name=${funcBrowse.name} functions=${funcBrowse.functions}
        onOpen=${(fn) => openFunction(fn, funcBrowse.targetId)} onClose=${() => setFuncBrowse(null)} />` : null}
    </div>`;
}

// Merge unavailable-capability reports from several targets into one deduplicated list.
function mergeUnavailable(cur, items) {
  const by = new Map((cur || []).map((u) => [u.stage, u]));
  for (const u of items || []) if (!by.has(u.stage)) by.set(u.stage, u);
  return [...by.values()];
}

render(html`<${App} />`, document.getElementById("root"));
