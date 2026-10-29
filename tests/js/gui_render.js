// Execute the real Preact components under node and assert the trees they build.
//
// gui_modules.js proves the logic; gui_static.js proves everything parses. This closes the
// last gap without a browser: it runs components.js through the ACTUAL vendored Preact + htm
// -- resolving the bare "preact"/"htm" specifiers with an ESM loader hook, the way the import
// map does in the browser -- and walks the resulting vnode trees. A broken htm template, a
// mis-wired prop, or a component that throws on render fails here, where a grep and a syntax
// check both pass. No npm install and no DOM library: htm+h build plain vnode objects, so the
// components render to a tree we can inspect directly.
const path = require("path");
const { register } = require("node:module");
const { pathToFileURL } = require("node:url");

const given = process.argv[2] || "core/lykos/api/static/index.html";
const staticDir = path.dirname(given);
process.env.LYKOS_STATIC = staticDir;

// Loader hook: map the three bare specifiers to the vendored files, exactly as the page's
// <script type="importmap"> does. Registered from a data: URL so the harness stays one file.
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

// Flatten a preact vnode tree into plain text and collect element types + hrefs.
function walk(node, acc) {
  if (node == null || node === false || node === true) return;
  if (typeof node === "string" || typeof node === "number") { acc.text.push(String(node)); return; }
  if (Array.isArray(node)) { node.forEach((c) => walk(c, acc)); return; }
  const props = node.props || {};
  if (typeof node.type === "string") acc.tags.push(node.type);
  if (props.href) acc.hrefs.push(props.href);
  if (props.class) acc.classes.push(props.class);
  // A function component: invoke it so its own subtree is included (pure, no hooks here).
  if (typeof node.type === "function") {
    try { walk(node.type(props), acc); return; } catch (e) { acc.threw.push(String(e)); return; }
  }
  walk(props.children, acc);
}
function renderInfo(vnode) {
  const acc = { text: [], tags: [], hrefs: [], classes: [], threw: [] };
  walk(vnode, acc);
  return { ...acc, all: acc.text.join(" ") };
}

(async () => {
  const C = await import(pathToFileURL(path.join(staticDir, "app", "components.js")).href);
  const h = (fn, props) => ({ type: fn, props: props || {} });

  // ---- DropZone: the fewest-clicks entry point ----
  let info = renderInfo(h(C.DropZone, { onFiles() {}, busy: false }));
  ck("DropZone renders without throwing", info.threw.length === 0);
  ck("DropZone offers a file input", info.tags.includes("input"));
  ck("DropZone invites a drop of one or more binaries", /drop one or more binaries/i.test(info.all));

  // ---- FindingCard: results-first, with the exploitation section foreground ----
  // Evidence is the real {channel, detail} trail the server produces for a demonstrated crash.
  const finding = {
    id: "F1", cwe: "CWE-121", title: "Stack buffer overflow in bug()", severity: "critical",
    state: "poc-backed", detector: "stack_frame", site_count: 1, proven_sites: 1, site_addr: 4198742,
    evidence: [
      { channel: "dynamic", detail: "SIGSEGV with input 06232b08 (found by AFL++ coverage-guided fuzzing; minimized 30->16B)" },
      { channel: "root-cause", detail: "stack-return-overwrite (CWE-121): the saved return address was overwritten; faulting instruction `ret`" },
      { channel: "exploitability", detail: "exploitability: EXPLOITABLE (90/100) -- return address overwritten -> control of execution" },
      { channel: "effects", detail: JSON.stringify([
        { kind: "dos", title: "Denial of service", status: "demonstrated",
          proof: { type: "input", sha: "feed01", note: "reliably terminates the process" } },
        { kind: "rce", title: "Remote code execution / control-flow hijack", status: "potential" },
      ]) },
      { channel: "poc", detail: "verified PoC bundle 52cf" },
    ],
  };
  const pocs = [{ id: "p1", level: "L2", verified: true, bundle_sha: "deadbeef", input_sha: "feed01", signal: "SIGSEGV" }];
  info = renderInfo(h(C.FindingCard, {
    finding: { ...finding, verification: { runs: 5, crashed: 5, signal: "SIGSEGV", deterministic: true } },
    pocs, mitigations: { nx: "on", pie: "off", canary: "off" },
    reportUrl: (c, f) => `/cases/${c}/report?format=${f}`, artifactUrl: (s) => `/artifacts/${s}`,
  }));
  ck("FindingCard renders without throwing", info.threw.length === 0);
  ck("FindingCard gives exploitation next-steps tuned by mitigations",
    /What an attacker does next/i.test(info.all) && /ROP|ret2libc/.test(info.all) && /addresses are fixed/i.test(info.all));
  ck("FindingCard offers the crashing input for download",
    info.hrefs.some((hh) => hh === "/artifacts/feed01") && /Crashing input/.test(info.all));
  ck("FindingCard shows the false-positive review verdict",
    /verified 5\/5/.test(info.all));
  ck("FindingCard shows the PoC level once (L2), not doubled (LL2)",
    /\bL2\b/.test(info.all) && !/LL2/.test(info.all));
  ck("FindingCard shows the title", /Stack buffer overflow/.test(info.all));
  ck("FindingCard shows the CWE and fault address", /CWE-121/.test(info.all) && /0x401156/.test(info.all));
  ck("FindingCard surfaces the exploitability rating and score", /EXPLOITABLE/.test(info.all) && /90\/100/.test(info.all));
  ck("FindingCard shows the END EFFECT badges (demonstrated DoS + potential RCE)",
    /End effect/i.test(info.all) && /Denial of service/.test(info.all)
    && /Remote code execution/.test(info.all)
    && /demonstrated/.test(info.all) && /potential/.test(info.all));
  ck("FindingCard shows a demonstrated effect's PROOF note and download link",
    /reliably terminates the process/.test(info.all)
    && info.hrefs.some((hh) => hh === "/artifacts/feed01"));
  ck("FindingCard does not dump the raw effects JSON as Evidence",
    !/"kind"/.test(info.all) && (info.all.match(/end effects:/gi) || []).length === 0);
  ck("FindingCard explains the mechanism (how it can be exploited)",
    /How it can be exploited/i.test(info.all) && /return address was overwritten/.test(info.all));
  ck("FindingCard offers a downloadable PoC bundle",
    info.hrefs.some((hh) => hh === "/artifacts/deadbeef") && info.tags.includes("a"));
  ck("FindingCard marks a demonstrated finding", info.classes.some((c) => /\bdemo\b/.test(c)));

  // The "found by <stage>" provenance chip is a plain label by default, and becomes a clickable
  // button (the finding->stage cross-link) when onStage + finding.stage are both present.
  const prov = renderInfo(h(C.FindingCard, {
    finding: { ...finding, stage: "directed_fuzz", stage_label: "Directed fuzzing" },
    pocs, reportUrl: () => "", artifactUrl: (s) => `/artifacts/${s}`,
  }));
  ck("FindingCard shows the discovering stage", /found by\s+Directed fuzzing/.test(prov.all) && prov.threw.length === 0);
  ck("FindingCard provenance chip is NOT a button without onStage", !prov.classes.some((c) => /stage-prov clk/.test(c)));
  const provClick = renderInfo(h(C.FindingCard, {
    finding: { ...finding, stage: "directed_fuzz", stage_label: "Directed fuzzing" },
    pocs, onStage() {}, reportUrl: () => "", artifactUrl: (s) => `/artifacts/${s}`,
  }));
  ck("FindingCard provenance chip becomes a clickable button with onStage",
    provClick.threw.length === 0 && provClick.classes.some((c) => /stage-prov clk/.test(c)));

  // Per-finding detail (doc 49 2d): the confirmation ladder, exploitability and attack surface
  // render in the card -- GUI parity with the report, from the API's shared analysis fields.
  const detail = renderInfo(h(C.FindingCard, {
    finding: { ...finding, state: "corroborated",
      analysis: { state: "corroborated", next_state: "confirmed",
        why_state: "A second independent signal supports the initial detection.",
        to_promote: "To confirm: prove the sink is reachable from an attacker-controlled input." },
      exploitability: { class_primitive: "format string -> %n write-what-where",
        ceiling: "L2", ceiling_reason: "PIE: no in-band leak", targets_live: "L3",
        mitigations_in_way: ["NX — no executable stack/heap"] },
      reachability: { attack_surface: "on" } },
    pocs: [], reportUrl: () => "", artifactUrl: (s) => `/artifacts/${s}`,
  }));
  ck("FindingCard renders the confirmation ladder (why + what's missing)",
    detail.threw.length === 0 && /second independent signal/.test(detail.all)
    && /To reach\s+confirmed/.test(detail.all));
  ck("FindingCard renders exploitability (primitive + ceiling + mitigations in the way)",
    /format string/.test(detail.all) && /weaponization reached\s+L2\s+and stopped/.test(detail.all)
    && /NX/.test(detail.all));
  ck("FindingCard renders the attack surface with its tone class",
    /On the fuzzed attack surface/.test(detail.all) && detail.classes.some((c) => /surf-on/.test(c)));

  // A candidate must NOT be styled as demonstrated.
  const cand = renderInfo(h(C.FindingCard, {
    finding: { id: "F2", cwe: "CWE-120", title: "strcpy", severity: "high", state: "candidate" },
    pocs: [], reportUrl: () => "", artifactUrl: (s) => `/artifacts/${s}`,
  }));
  ck("FindingCard does not mark a candidate as demonstrated", !cand.classes.some((c) => /\bdemo\b/.test(c)));

  // ---- TargetSummary + Badge ----
  info = renderInfo(h(C.TargetSummary, {
    target: { filename: "vuln", file_type: "elf", arch: "x86", bits: 64, sha256: "a".repeat(64), size: 15936 },
    advice: { headline: "Looks like an ELF executable." },
  }));
  ck("TargetSummary renders the filename and headline",
    /vuln/.test(info.all) && /Looks like an ELF/.test(info.all) && info.threw.length === 0);

  info = renderInfo(h(C.Badge, { state: "poc-backed" }));
  ck("Badge labels poc-backed state", /PoC-backed/.test(info.all));

  // ---- SystemMap: the multi-binary analysis made visible ----
  info = renderInfo(h(C.SystemMap, { map: {
    nodes: [{ id: "a1", filename: "client" }, { id: "b2", filename: "libvuln.so" }],
    edges: [{ src: "a1", dst: "b2", kind: "dynamic-link", symbols: ["process"] }],
  } }));
  ck("SystemMap renders the cross-binary edge with its binaries and symbol",
    info.threw.length === 0 && /client/.test(info.all) && /libvuln\.so/.test(info.all) && /process/.test(info.all));
  // A single binary has no cross-binary picture to show.
  const solo = renderInfo(h(C.SystemMap, { map: { nodes: [{ id: "a1", filename: "x" }], edges: [] } }));
  ck("SystemMap shows nothing for a single-binary case", solo.tags.length === 0 && solo.all.trim() === "");

  // ---- FuzzHealthPanel: how every fuzz attempt ENDED, and whether the campaign gained anything ----
  info = renderInfo(h(C.FuzzHealthPanel, { onOpenLog() {}, health: { verdict: "idle",
    note: "1 engine(s) executed the target but none reached any code beyond its seeds",
    engines: [
      { engine: "fuzz", status: "failed", execs: 900, log: "ab".repeat(32),
        reason: "900 of 900 attempts never reached the program -- exit 127, libfoo.so.1",
        outcomes: { no_start: 900 } },
      { engine: "coverage_fuzz", status: "no_gain", execs: 300, afl_execs: 51000, log: "cd".repeat(32),
        reason: "ran 300 attempts but reached nothing beyond what its seeds reached",
        outcomes: { clean_exit: 30, error_exit: 270 },
        value: { unit: "edges", seed_coverage: 31, gained: 0, last_gain_s: null } },
    ] } }));
  ck("FuzzHealthPanel names an error loop with the loader message",
    info.threw.length === 0 && /FAILED/.test(info.all) && /libfoo\.so\.1/.test(info.all));
  ck("FuzzHealthPanel shows a no-gain engine and what its seeds reached",
    /no gain/.test(info.all) && /\+0 edges beyond seeds \(seeds: 31\)/.test(info.all) && /never gained/.test(info.all));
  ck("FuzzHealthPanel offers each engine's attempt log",
    (info.all.match(/attempt log/g) || []).length === 2);
  info = renderInfo(h(C.OutcomeBar, { counts: { clean_exit: 25, error_exit: 75 } }));
  ck("OutcomeBar labels each outcome with its share", /ran clean\s*25\s*%/.test(info.all) && /error exit\s*75\s*%/.test(info.all));
  ck("OutcomeBar renders nothing with no attempts", renderInfo(h(C.OutcomeBar, { counts: {} })).all.trim() === "");

  // ---- CoveragePanel: how much of the binary the fuzzing reached ----
  info = renderInfo(h(C.CoveragePanel, {
    targets: [{ id: "t1", filename: "prog" }],
    coverage: { t1: { kind: "block", pct: 62, hit: 124, known: 200 } },
  }));
  ck("CoveragePanel shows the binary, its percentage and the block count",
    info.threw.length === 0 && /prog/.test(info.all) && /62%/.test(info.all) && /124\/200/.test(info.all));
  ck("CoveragePanel renders nothing with no coverage data",
    renderInfo(h(C.CoveragePanel, { coverage: {}, targets: [] })).all.trim() === "");
  // With onDrill, each coverage row becomes a clickable drill-in to that binary's functions.
  info = renderInfo(h(C.CoveragePanel, {
    targets: [{ id: "t1", filename: "prog" }],
    coverage: { t1: { kind: "block", pct: 62, hit: 124, known: 200 } },
    onDrill() {},
  }));
  ck("CoveragePanel rows are clickable to drill into functions when onDrill is given",
    info.classes.some((c) => /\bclk\b/.test(c)) && /Click a row to drill/i.test(info.all));

  // ---- TargetSummary disassembly drill-in ----
  // A recovered function count + onBrowseFunctions renders the "Disassembly · N functions" button.
  info = renderInfo(h(C.TargetSummary, {
    target: { id: "t1", filename: "vuln", file_type: "elf", arch: "x86", bits: 64,
      details: { function_count: 142 } },
    onBrowseFunctions() {},
  }));
  ck("TargetSummary offers a disassembly drill-in with the function count",
    info.threw.length === 0 && /Disassembly/.test(info.all) && /142 functions/.test(info.all)
    && info.classes.some((c) => /disasm-drill/.test(c)));
  // No count and no handler -> no drill-in button (nothing to browse yet).
  const noDrill = renderInfo(h(C.TargetSummary, {
    target: { id: "t1", filename: "vuln", file_type: "elf" },
  }));
  ck("TargetSummary omits the drill-in before disassembly has run",
    !noDrill.classes.some((c) => /disasm-drill/.test(c)));

  // ---- CodeView: the function behind a finding ----
  // Decompiled available -> show it.
  info = renderInfo(h(C.CodeView, {
    finding: { cwe: "CWE-121", function_addr: "0x401156", site_addr: "0x401156" },
    fn: { name: "handle", addr: "0x401156", signature: "void handle(char *)",
      decompiled: "void handle(char *in) {\n  char buf[16];\n  strcpy(buf, in);\n}",
      frame: { vars: [{ name: "buf", type: "char [16]", size: 16 }] },
      callees: [{ dst_name: "strcpy" }], callers: [{ src_name: "main" }] },
    onClose() {},
  }));
  ck("CodeView shows the function name, decompiled code and the buffer",
    info.threw.length === 0 && /handle/.test(info.all) && /strcpy\(buf, in\)/.test(info.all) && /char \[16\]/.test(info.all));
  ck("CodeView shows the call edges", /strcpy/.test(info.all) && /main/.test(info.all));

  // With onNavigate, the call edges become clickable to follow the call (across binaries too).
  info = renderInfo(h(C.CodeView, {
    finding: { cwe: "CWE-121", function_addr: "0x1", site_addr: "0x1" },
    fn: { name: "main", addr: "0x1", callees: [{ dst_name: "process" }], callers: [] },
    crumbs: ["main"], onNavigate() {}, onClose() {},
  }));
  ck("CodeView makes calls clickable to follow them", info.tags.includes("button") && /process/.test(info.all));
  ck("CodeView invites following a call across binaries", /across binaries/i.test(info.all));

  // No decompiled -> fall back to disassembly with the fault site highlighted.
  info = renderInfo(h(C.CodeView, {
    finding: { cwe: "CWE-121", function_addr: "0x401156", site_addr: 4198742 /* 0x401156 */ },
    fn: { name: "handle", addr: "0x401156", decompiled: "You need to install the plugin",
      ir: { blocks: [{ instructions: [
        { addr: 4198740, text: "push rbp" },
        { addr: 4198742, text: "call strcpy" },
      ] }] } },
    onClose() {},
  }));
  ck("CodeView falls back to disassembly when decompiled C is unavailable",
    /showing disassembly/i.test(info.all) && /call strcpy/.test(info.all));
  ck("CodeView highlights the fault site in the disassembly",
    info.classes.some((c) => /asm-hit/.test(c)) && /site/.test(info.all));

  info = renderInfo(h(C.CallGraphMini, {
    fn: { name: "comprexx", callers: [{ src_name: "main" }],
          callees: [{ dst_name: "strcpy" }, { dst_name: "malloc" }] },
    onNavigate() {},
  }));
  ck("CallGraphMini draws an ego call graph (center + neighbours)",
    info.threw.length === 0 && /comprexx/.test(info.all) && /strcpy/.test(info.all) && /main/.test(info.all)
    && info.classes.some((c) => /cg-center/.test(c))
    && info.classes.some((c) => /cg-caller/.test(c))
    && info.classes.some((c) => /cg-callee/.test(c)));
  ck("CallGraphMini renders nothing for a leaf with no edges",
    renderInfo(h(C.CallGraphMini, { fn: { name: "leaf", callers: [], callees: [] } })).threw.length === 0);

  // ---- CaseOverview: the interactive analytics dashboard (severity donut, CWE bars, ladder) ----
  const ovFindings = [
    { id: "a", cwe: "CWE-121", severity: "critical", state: "poc-backed", detector: "build_exploit" },
    { id: "b", cwe: "CWE-787", severity: "high", state: "corroborated", detector: "cve_fingerprint" },
    { id: "c", cwe: "CWE-787", severity: "high", state: "corroborated", detector: "cve_fingerprint" },
    { id: "d", cwe: "CWE-78", severity: "medium", state: "candidate", detector: "scriptscan" },
  ];
  const ovPocs = [{ level: "L1", verified: true }, { level: "L3", verified: true }];
  let clicked = null;
  info = renderInfo(h(C.CaseOverview, {
    findings: ovFindings, pocs: ovPocs, filter: null, onFilter: (s) => { clicked = s; },
  }));
  ck("CaseOverview renders without throwing", info.threw.length === 0);
  ck("CaseOverview draws an SVG severity donut", info.tags.includes("svg") && info.tags.includes("path"));
  ck("CaseOverview shows the total finding count", /\b4\b/.test(info.all));
  ck("CaseOverview lists the top CWEs", /CWE-787/.test(info.all) && /CWE-121/.test(info.all));
  ck("CaseOverview draws the L0..L3 weaponization ladder reaching L3",
    /Detected/.test(info.all) && /Exploit/.test(info.all)
    // pocs reach L3, so all four rungs (L0..L3) are lit
    && info.classes.filter((c) => /^ov-step reached/.test(c)).length === 4);
  ck("CaseOverview shows the detector mix", /cve_fingerprint/.test(info.all) && /scriptscan/.test(info.all));
  ck("CaseOverview is empty-safe with no findings",
    renderInfo(h(C.CaseOverview, { findings: [], pocs: [] })).threw.length === 0);
  // a filtered render exposes the clear affordance
  ck("CaseOverview offers a clear-filter control when a filter is active",
    /clear/i.test(renderInfo(h(C.CaseOverview,
      { findings: ovFindings, pocs: ovPocs, filter: { severity: "critical" }, onFilter() {} })).all));

  // ---------- RunScorecard: what the run DID ----------
  // The workbench showed findings with no account of the work behind them: no executions, no
  // declines, no never-scheduled list, no absorbed count. There was no endpoint to ask, so of
  // two targets with zero crashes, one that executed 2,756 times and one that executed zero
  // because a stage upstream ate the budget looked identical. This is a REAL card, copied from
  // a 420-second run on one small ELF.
  const realCard = {
    target_id: "t1", filename: "vuln",
    baseline: { ran: true, crashed: false, note: "" },
    executions: { total: 14737, per_second: 76.9, by_engine: { fuzz: 10473, directed: 4264 } },
    crashes: 64,
    capability: {
      registered: 45, scheduled: 34, worked: new Array(22).fill("s"),
      declined: new Array(12).fill("s"), errored: [],
      never_scheduled: ["concolic", "firmware_carve", "net_fuzz", "poc_diff", "unpack"],
    },
    declined: { libfuzzer: "no source for this target (libFuzzer needs C/C++ source)" },
    absorbed: { total: 3, sites: 2, top: [{ site: "lykos.analyze.elf.parse:118", count: 2 }] },
  };
  info = renderInfo(h(C.RunScorecard, { cards: [realCard], targetName: "vuln" }));
  ck("RunScorecard renders without throwing", info.threw.length === 0);
  ck("RunScorecard reports the baseline verdict", /ran, exited normally/.test(info.all));
  ck("RunScorecard reports executions and the per-engine split",
    /14,737/.test(info.all) && /fuzz 10,473/.test(info.all));
  // The walk concatenates each text node with its own separator, and this line is built from
  // several interpolations, so match whitespace loosely rather than pinning the spacing.
  ck("RunScorecard reports the capability tally against the registry",
    /22\s+did work/.test(info.all) && /of\s+45\s+registered/.test(info.all)
    && /12\s+declined/.test(info.all));
  ck("RunScorecard names the stages never reached", /concolic/.test(info.all));
  ck("RunScorecard gives a decline its reason", /no source for this target/.test(info.all));
  ck("RunScorecard reports what the run absorbed, with the worst site",
    /3 best-effort/.test(info.all) && /lykos\.analyze\.elf\.parse:118/.test(info.all));
  // Zero absorbed is the USEFUL reading: it says a thin result is the target's doing, not ours.
  info = renderInfo(h(C.RunScorecard, {
    cards: [Object.assign({}, realCard, { absorbed: { total: 0, sites: 0, top: [] } })] }));
  ck("RunScorecard says so when a run absorbed nothing",
    /nothing . no step failed quietly/.test(info.all));
  // An INCOMPLETE card: a stage was still finishing when it was built, so every count is a
  // floor. On `zigzag` the card said 0 executions while a cancelled stage went on to report 64,
  // and the gate then failed the target with "executed it zero times". A reader has to be able
  // to see which kind of zero they are looking at.
  info = renderInfo(h(C.RunScorecard, {
    cards: [Object.assign({}, realCard, { settled: false })] }));
  ck("RunScorecard flags a card built before every stage reported",
    /Incomplete/.test(info.all) && /floor, not a total/.test(info.all));
  ck("RunScorecard does not cry incomplete when it settled",
    !/Incomplete/.test(renderInfo(h(C.RunScorecard,
      { cards: [Object.assign({}, realCard, { settled: true })] })).all));
  ck("RunScorecard is empty-safe with no card",
    renderInfo(h(C.RunScorecard, { cards: [] })).threw.length === 0);
  // A card for another binary must not be shown as this one's.
  info = renderInfo(h(C.RunScorecard, { cards: [realCard], targetName: "other" }));
  ck("RunScorecard falls back to the first card rather than rendering nothing",
    info.threw.length === 0 && /14,737/.test(info.all));

  // ---- ScanResult: the operator scans (variant hunt / source patterns / differential test) ----
  info = renderInfo(h(C.ScanResult, { kind: "variant", st: { data: { applicable: true,
    function: "parse_header", reference: "a", matched: 1, note: "A match is a CANDIDATE",
    results: [
      { target_id: "b", filename: "b", scanned: true, functions: 9,
        hits: [{ name: "parse_header", addr: "0x401136", similarity: 0.97 }] },
      { target_id: "c", filename: "c", scanned: true, functions: 4, hits: [] },
      { target_id: "d", filename: "d", scanned: false, note: "no recovered functions (not disassembled)", hits: [] }] } } }));
  ck("ScanResult(variant) renders without throwing", info.threw.length === 0);
  ck("ScanResult(variant) names the match, the clean target and the UNSCANNED one distinctly",
    /MATCH/.test(info.all) && /0\.97/.test(info.all) && /no match/.test(info.all)
    && /not scanned/.test(info.all) && /not disassembled/.test(info.all));
  ck("ScanResult(variant) says a match is a candidate", /CANDIDATE/.test(info.all));
  info = renderInfo(h(C.ScanResult, { kind: "weggli", st: { data: { applicable: true, queries_run: 30,
    findings: [{ name: "strcpy-into-stack", cwe: "CWE-121", severity: "high", why: "w", count: 2,
                 files: ["a.c", "b.c", "c.c", "d.c", "e.c"] }] } } }));
  ck("ScanResult(weggli) lists the pattern, its CWE and files (capped)",
    info.threw.length === 0 && /CWE-121/.test(info.all) && /strcpy-into-stack/.test(info.all)
    && /\+1 more/.test(info.all) && /candidate findings/.test(info.all));
  info = renderInfo(h(C.ScanResult, { kind: "diff", st: { data: { applicable: true, compared: true,
    execs: 40, delta_diversity: 3, note: "Each disagreement is a candidate bug",
    inconclusive: { lenient: 2 },
    discrepancies: [{ kind: "status", input: "58", partitions: { reject: ["strict"], ok: ["lenient"] } }] } } }));
  ck("ScanResult(diff) shows the disagreement and which side did what",
    info.threw.length === 0 && /1\s+disagreement/.test(info.all) && /\[reject\] strict/.test(info.all));
  ck("ScanResult(diff) names inconclusive runs instead of counting them as agreement",
    /Inconclusive runs/.test(info.all) && /lenient ×2/.test(info.all));
  info = renderInfo(h(C.ScanResult, { kind: "diff", st: { data: { applicable: false, note: "differential testing needs 2+ targets" } } }));
  ck("ScanResult shows a decline's reason", /needs 2\+ targets/.test(info.all));
  info = renderInfo(h(C.ScanResult, { kind: "weggli", st: { error: "boom" } }));
  ck("ScanResult shows a failure", /source-pattern scan\s+failed:\s+boom/.test(info.all));

  // ---- SelftestPanel: the tool's own gates, from the GUI ----
  info = renderInfo(h(C.SelftestPanel, { st: null, onStart() {}, onHistory() {} }));
  ck("SelftestPanel offers every gate and says they check the tool, not a target",
    info.threw.length === 0 && /Architecture gate/.test(info.all) && /Real-program gate/.test(info.all)
    && /Detection benchmark/.test(info.all) && /not a target/.test(info.all));
  info = renderInfo(h(C.SelftestPanel, { st: { state: "done", running: false, kind: "archgate",
    result: { verdict: "FAIL", reason: "aarch64 lost L3", table: "arch level" } }, onStart() {} }));
  ck("SelftestPanel shows a gate's verdict, reason and table",
    /FAIL/.test(info.all) && /aarch64 lost L3/.test(info.all) && /arch level/.test(info.all)
    && info.classes.some((c) => /dv-vuln/.test(c)));
  info = renderInfo(h(C.SelftestPanel, { st: { state: "error", running: false, kind: "eval", error: "no compiler" }, onStart() {} }));
  ck("SelftestPanel shows a failed self-test as a failure", /self-test failed/.test(info.all) && /no compiler/.test(info.all));
  info = renderInfo(h(C.SelftestPanel, { st: null, onStart() {}, history: { runs: 3, path: "eval-history.jsonl",
    text: "static/candidate recall 1.0", regressions: [{}] } }));
  ck("SelftestPanel shows the benchmark history and flags a regression",
    /3\s+recorded run/.test(info.all) && /recall 1\.0/.test(info.all) && /1\s+series regressed/.test(info.all));

  console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.log("FAIL  harness threw: " + (e && e.stack || e)); process.exit(1); });
