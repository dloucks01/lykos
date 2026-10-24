// The run-honesty surfaces, crash triage, engine readiness, seeds and the build footer.
//
// Runs the real util.js helpers and the real Preact components (vendored preact + htm, resolved
// with the same loader hook gui_render.js uses) and asserts the precision rules:
//   * a target whose analysis aborted is FAILED (chip + rail), whether the server's event log or
//     only the live status knows it -- never a quiet gap;
//   * a degraded sandbox / ranked taint / tiered recovery / capped crashes / hang / lease renewal
//     each surface as one compact chip, and a clean run shows nothing;
//   * an UNVERIFIED PoC never sets a target's (or a crash group's) level -- it is a candidate;
//   * crash triage renders one ranked row per root cause, with count, level and links;
//   * the doctor panel names a missing REQUIRED engine; the footer names the build.
const path = require("path");
const { register } = require("node:module");
const { pathToFileURL } = require("node:url");

const given = process.argv[2] || "core/lykos/api/static/index.html";
const staticDir = path.dirname(given);
process.env.LYKOS_STATIC = staticDir;
const hook = `
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const dir = process.env.LYKOS_STATIC;
const M = {
  'preact': join(dir, 'vendor', 'preact.module.js'),
  'preact/hooks': join(dir, 'vendor', 'hooks.module.js'),
  'htm': join(dir, 'vendor', 'htm.module.js'),
};
export async function resolve(spec, ctx, next) {
  if (M[spec]) return { url: pathToFileURL(M[spec]).href, shortCircuit: true };
  return next(spec, ctx);
}`;
register("data:text/javascript," + encodeURIComponent(hook));

let pass = true;
const ck = (n, cond) => { pass = pass && !!cond; console.log(`${cond ? "PASS" : "FAIL"}  ${n}`); };

function walk(node, acc) {
  if (node == null || node === false || node === true) return;
  if (typeof node === "string" || typeof node === "number") { acc.text.push(String(node)); return; }
  if (Array.isArray(node)) { node.forEach((c) => walk(c, acc)); return; }
  const props = node.props || {};
  if (typeof node.type === "string") acc.tags.push(node.type);
  if (props.class) acc.classes.push(props.class);
  if (props.href) acc.hrefs.push(props.href);
  if (props.title) acc.titles.push(String(props.title));
  if (typeof node.type === "function") {
    try { walk(node.type(props), acc); return; } catch (e) { acc.threw.push(String(e)); return; }
  }
  walk(props.children, acc);
}
function info(vnode) {
  const acc = { text: [], tags: [], classes: [], hrefs: [], titles: [], threw: [] };
  walk(vnode, acc);
  return { ...acc, all: acc.text.join("") };
}

(async () => {
  const U = await import(pathToFileURL(path.join(staticDir, "app", "util.js")).href);
  const C = await import(pathToFileURL(path.join(staticDir, "app", "components.js")).href);
  const { h } = await import(pathToFileURL(path.join(staticDir, "vendor", "preact.module.js")).href);
  const targets = [{ id: "T1", filename: "a.bin" }, { id: "T2", filename: "b.bin" }];

  // ---- failed targets: event log, live status, or both ------------------------------------
  const sigFailed = { failed_targets: ["T2"], target_errors: [{ target_id: "T2", stage: "fuzz",
    error: "OperationalError: database is locked" }], isolation: [], taint: [], recovery: [],
    crashes_capped: [], hangs: [], lease_renewed: null, outcome: { outcome: "static" } };
  ck("failedTargets reads the server signals", U.failedTargets(sigFailed, null).has("T2"));
  ck("failedTargets reads the LIVE status before the event log has it",
    U.failedTargets(null, { target_errors: [{ target_id: "T1", stage: "disassemble", error: "x" }] }).has("T1"));
  ck("a done event alone still marks the target failed",
    U.failedTargets({ failed_targets: ["T1"] }, null).has("T1"));
  const chips = U.runSignalChips(sigFailed, null, targets);
  const fc = chips.find((c) => c.key === "failed");
  ck("a failed target is a BAD chip, named", fc && fc.tone === "bad" && /1 target FAILED/.test(fc.label)
    && fc.detail.some((d) => /b\.bin: analysis aborted in fuzz/.test(d)));
  ck("a clean run yields no chips", U.runSignalChips({ failed_targets: [], target_errors: [], isolation: [],
    taint: [], recovery: [], crashes_capped: [], hangs: [], lease_renewed: null }, { target_errors: [] }, targets).length === 0);
  ck("no signals at all yields no chips", U.runSignalChips(null, null, targets).length === 0);

  // ---- the other signals -------------------------------------------------------------------
  const sigAll = {
    failed_targets: [], target_errors: [],
    isolation: [{ engine: "coverage", isolation: "rlimits-only", note: "no bwrap" },
                { engine: "env_fuzz", isolation: "rlimits-only" }],
    taint: [{ target_id: "T1", total: 9000, unreachable: 1000, analyzed: 4000, skipped_reachable: 4000,
              note: "4000 reachable function(s) were NOT analysed" },
            { target_id: "T2", total: 6000, unreachable: 3000, analyzed: 3000, skipped_reachable: 0 }],
    recovery: [{ target_id: "T1", analysis_tier: "aa", degradations: ["cut at aa"], functions: 700,
                 total_functions: 900, recovery_failed: false }],
    crashes_capped: [{ target_id: "T1", distinct: 47, proving: 32 }],
    hangs: [{ target_id: "T1", engine: "fuzz", input_sha: "abcdef0123456789", mode: "stdin", timeout: 4 }],
    lease_renewed: { count: 3 },
  };
  const all = U.runSignalChips(sigAll, null, targets);
  const by = (k) => all.find((c) => c.key === k);
  ck("degraded sandbox is one warn chip naming the engines",
    by("iso") && by("iso").tone === "warn" && /rlimits-only/.test(by("iso").label) && /coverage, env-var/.test(by("iso").label));
  ck("taint with reachable loss: 'analysed N of M reachable'",
    by("taint-T1") && by("taint-T1").tone === "warn" && /analysed 4000 of 8000 reachable/.test(by("taint-T1").label));
  ck("taint ranked with no reachable loss is informational",
    by("taint-T2") && by("taint-T2").tone === "info");
  ck("tiered recovery says the tier and function count",
    by("rec-T1") && /tier aa/.test(by("rec-T1").label) && /700\/900 functions/.test(by("rec-T1").label));
  ck("capped crashes: proving X of Y", by("cap-T1") && /proving 32 of 47/.test(by("cap-T1").label));
  ck("hangs are a CWE-835 chip", by("hangs") && /1 hang\/DoS input \(CWE-835\)/.test(by("hangs").label));
  ck("lease renewals are counted", by("lease") && /×3/.test(by("lease").label));
  ck("multi-target chips name their target", /^a\.bin: /.test(by("cap-T1").label));
  const failRec = U.runSignalChips({ recovery: [{ target_id: "T1", recovery_failed: true, note: "rizin crashed" }] }, null, targets);
  ck("a failed recovery is BAD, not a degradation", failRec[0] && failRec[0].tone === "bad" && /recovery FAILED/.test(failRec[0].label));

  // ---- the strip renders chips (and nothing for a clean run) -------------------------------
  const strip = info(h(C.RunSignalsStrip, { signals: sigFailed, bg: null, targets }));
  ck("RunSignalsStrip renders without throwing", strip.threw.length === 0);
  ck("RunSignalsStrip shows the failed chip and its detail", /1 target FAILED/.test(strip.all) && /database is locked/.test(strip.all));
  ck("RunSignalsStrip is a <details> (compact; detail on demand)", strip.tags.includes("details") && strip.tags.includes("summary"));
  ck("RunSignalsStrip renders nothing for a clean run", C.RunSignalsStrip({ signals: null, bg: null, targets }) === null);

  // ---- an unverified PoC never sets a level ------------------------------------------------
  const tgt = { id: "T1", filename: "a.bin" };
  const finds = [{ id: "F1", target_id: "T1", state: "corroborated", evidence: [] }];
  const vUnver = U.verdictForTarget(tgt, finds, [{ finding_id: "F1", level: "L3", verified: false }], {});
  ck("unverified L3 recipe: level 0, candidateLevel 3", vUnver.level === 0 && vUnver.candidateLevel === 3);
  const vMix = U.verdictForTarget(tgt, finds, [{ finding_id: "F1", level: "L3", verified: false },
                                                { finding_id: "F1", level: "L2", verified: true }], {});
  ck("verified L2 + unverified L3: level 2, candidate 3", vMix.level === 2 && vMix.candidateLevel === 3);
  const vVer = U.verdictForTarget(tgt, finds, [{ finding_id: "F1", level: "L3", verified: true }], {});
  ck("verified L3: level 3, no candidate", vVer.level === 3 && vVer.candidateLevel === 0);
  const sv = info(h(C.ShellVerdict, { verdict: vUnver, artifactUrl: (x) => `/artifacts/${x}` }));
  ck("ShellVerdict labels an unverified level as a candidate, not executed",
    /candidate L3/.test(sv.all) && /not executed/.test(sv.all));
  ck("ShellVerdict fills no rung for an unverified recipe",
    !sv.classes.some((c) => /vd-rung filled/.test(c)));

  // ---- crash triage --------------------------------------------------------------------------
  const crashes = Array.from({ length: 43 }, (_, i) => ({ crashed: true, signal: "SIGSEGV",
    fault_pc: i < 40 ? "0x401136" : null, input_sha: `in${i}`, input_mode: "stdin" }));
  const triage = { crashes: 43, distinct: 2, prove_cap: 32, over_prove_cap: false, groups: [
    { rank: 1, signal: "SIGSEGV", fault_pc: "0x401136", defect_key: null, channel: "stdin",
      resolved: true, count: 40, input_count: 40, representative: "in0", best_level: 3,
      candidate_level: 0, poc: { level: "L3", bundle_sha: "B1" },
      exploitability: { rating: "EXPLOITABLE", score: 90, why: "pc control" },
      findings: [{ id: "F1", title: "Stack overflow", cwe: "CWE-121", state: "poc-backed" }] },
    { rank: 2, signal: "SIGSEGV", fault_pc: null, defect_key: null, channel: "file", resolved: false,
      count: 3, input_count: 3, representative: "in40", best_level: 0, candidate_level: 3,
      poc: null, exploitability: null, findings: [] },
  ] };
  let opened = null;
  const cp = info(h(C.CrashesPanel, { crashes, triage, artifactUrl: (x) => `/artifacts/${x}`,
    onOpenFinding: (id) => { opened = id; } }));
  ck("CrashesPanel (triage) renders without throwing", cp.threw.length === 0);
  ck("…counts root causes, not inputs", /2/.test(cp.all) && /distinct root causes/.test(cp.all) && /43 crashing executions/.test(cp.all));
  ck("…the top group shows its verified level and count", cp.all.includes("L3") && cp.all.includes("×40"));
  ck("…an unverified level is a candidate", cp.all.includes("cand. L3"));
  ck("…an unresolved bucket says so", cp.all.includes("unresolved") && cp.all.includes("no fault PC · file"));
  ck("…links the PoC bundle and the representative input",
    cp.hrefs.includes("/artifacts/B1") && cp.hrefs.includes("/artifacts/in0"));
  ck("…keeps the raw per-input list one click away", /all 43 crashing inputs/.test(cp.all));
  const capped = info(h(C.CrashesPanel, { crashes, triage: { ...triage, over_prove_cap: true },
    artifactUrl: (x) => x }));
  ck("…over the prove cap, an unlevelled group is not called unexploitable", /proves at most 32/.test(capped.all));
  const loading = info(h(C.CrashesPanel, { crashes, triage: undefined, artifactUrl: (x) => x }));
  ck("…falls back to the raw list while grouping loads", /43 reproduced crashes/.test(loading.all));

  // ---- doctor / seeds / footer ----------------------------------------------------------------
  const doc = { state: "done", present: 2, total: 3, required_missing: ["bubblewrap"], toolchain: "toolchain: host PATH",
    tools: [{ key: "python", title: "Python 3", tier: "required", present: true, found: "3.12" },
            { key: "bwrap", title: "bubblewrap", tier: "required", present: false, without: "rlimits only", install: "apt-get install bubblewrap" },
            { key: "afl", title: "AFL++", tier: "optional", present: true, found: "4.0" }] };
  const dp = info(h(C.DoctorPanel, { doctor: doc, onRefresh: () => {} }));
  ck("DoctorPanel renders without throwing", dp.threw.length === 0);
  ck("DoctorPanel names a missing REQUIRED engine", /1 REQUIRED missing/.test(dp.all) && dp.all.includes("bubblewrap"));
  ck("DoctorPanel shows readiness N/M", dp.all.includes("2/3 ready"));
  const dprobe = info(h(C.DoctorPanel, { doctor: { state: "probing", tools: [] } }));
  ck("DoctorPanel while probing says so", /Checking which engines work/.test(dprobe.all));
  const sf = info(h(C.SeedsField, { seeds: [{ sha256: "a".repeat(64), name: "conf.ini", size: 10 }],
    onAdd: () => {}, onRemove: () => {}, busy: false }));
  ck("SeedsField lists stored seeds and offers + seeds", sf.all.includes("conf.ini") && sf.all.includes("+ seeds") && sf.threw.length === 0);
  const bf = info(h(C.BuildFoot, { info: { version: "0.0.1", display: "lykos 0.0.1 · ac8c83c · code 2026-10-24", source: "git", commit: "ac8c83c5", built: "2026-10-24T16:00:00Z" } }));
  ck("BuildFoot shows the build line", bf.all.includes("ac8c83c") && bf.all.includes("commit date 2026-10-24"));
  const bfNone = info(h(C.BuildFoot, { info: { version: "0.0.1", display: "lykos 0.0.1", source: "none" } }));
  ck("BuildFoot flags an unidentified build", /no commit stamp/.test(bfNone.all));

  console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
