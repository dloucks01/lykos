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

  // ---- CoveragePanel: how much of the binary the fuzzing reached ----
  info = renderInfo(h(C.CoveragePanel, {
    targets: [{ id: "t1", filename: "prog" }],
    coverage: { t1: { kind: "block", pct: 62, hit: 124, known: 200 } },
  }));
  ck("CoveragePanel shows the binary, its percentage and the block count",
    info.threw.length === 0 && /prog/.test(info.all) && /62%/.test(info.all) && /124\/200/.test(info.all));
  ck("CoveragePanel renders nothing with no coverage data",
    renderInfo(h(C.CoveragePanel, { coverage: {}, targets: [] })).all.trim() === "");

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

  console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.log("FAIL  harness threw: " + (e && e.stack || e)); process.exit(1); });
