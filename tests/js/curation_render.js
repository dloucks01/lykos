// Operator curation of findings (doc 47 P3) + the finding -> call-graph cross-link (doc 49 2b).
//
// Runs the real util.js helpers and the real Preact components (vendored preact + htm, resolved
// with the same loader hook gui_render.js uses) and asserts:
//   * the triage filter hides ONLY what the operator marked false positive, and counts it;
//   * a card that folds several findings carries every folded id, so a triage covers them all;
//   * the card shows the operator's verdict BESIDE the tool's state badge -- never instead of it;
//   * a finding with only a fault/sink address still resolves to its containing function.
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
  if (props.onClick) acc.clicks.push({ text: [], props, node });
  if (typeof node.type === "function") {
    try { walk(node.type(props), acc); return; } catch (e) { acc.threw.push(String(e)); return; }
  }
  walk(props.children, acc);
}
function renderInfo(vnode) {
  const acc = { text: [], tags: [], classes: [], threw: [], clicks: [] };
  walk(vnode, acc);
  return { ...acc, all: acc.text.join(" ") };
}
// Find the first vnode matching a predicate (descending into function components).
function find(node, pred) {
  if (node == null || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const c of node) { const r = find(c, pred); if (r) return r; } return null; }
  if (pred(node)) return node;
  const props = node.props || {};
  if (typeof node.type === "function") { try { return find(node.type(props), pred); } catch { return null; } }
  return find(props.children, pred);
}

(async () => {
  const U = await import(pathToFileURL(path.join(staticDir, "app", "util.js")).href);
  const C = await import(pathToFileURL(path.join(staticDir, "app", "components.js")).href);
  const h = (fn, props) => ({ type: fn, props: props || {} });

  // ---- the filter ----
  const fs = [
    { id: "a", state: "poc-backed", curation: { status: "false_positive", note: "harness only" } },
    { id: "b", state: "candidate", curation: { status: "needs_review", note: "" } },
    { id: "c", state: "candidate", curation: null },
    { id: "d", state: "confirmed", curation: { status: "true_positive", note: "repro'd" } },
    { id: "e", state: "candidate", curation: { status: null, note: "just a note" } },
  ];
  const ids = (l) => l.map((f) => f.id).join("");
  ck("default filter hides exactly the false positives", ids(U.filterByCuration(fs, "hide_fp")) === "bcde");
  ck("unknown filter mode falls back to hiding false positives only", ids(U.filterByCuration(fs, "zzz")) === "bcde");
  ck("'all' hides nothing", ids(U.filterByCuration(fs, "all")) === "abcde");
  ck("'false_positive' shows only false positives", ids(U.filterByCuration(fs, "false_positive")) === "a");
  ck("'needs_review' shows only those flagged", ids(U.filterByCuration(fs, "needs_review")) === "b");
  ck("'uncurated' counts a note-only finding as not yet triaged", ids(U.filterByCuration(fs, "uncurated")) === "ce");
  const cnt = U.curationCounts(fs);
  ck("counts per status", cnt.false_positive === 1 && cnt.true_positive === 1
    && cnt.needs_review === 1 && cnt.uncurated === 2);
  ck("the operator's verdict is never labelled with the tool's 'Confirmed' state",
    !Object.values(U.CURATION_LABEL).some((l) => /^confirmed$/i.test(l)));

  // ---- dedupe groups carry every folded id ----
  const grouped = U.dedupeFindings([
    { id: "g1", cwe: "CWE-134", state: "candidate", detector: "static" },
    { id: "g2", cwe: "CWE-134", state: "candidate", detector: "static" },
    { id: "g3", cwe: "CWE-134", state: "candidate", detector: "static" },
    { id: "p1", cwe: "CWE-121", state: "poc-backed", detector: "poc" },
  ]);
  const rep = grouped.find((f) => f.cwe === "CWE-134");
  ck("a folded card lists every finding it stands for",
    rep && rep.group_count === 3 && rep.group_ids.join(",") === "g1,g2,g3");

  // ---- containing function ----
  const fns = [{ id: 1, addr: "0x401000", size: 0x80, name: "main" },
               { id: 2, addr: "0x401100", size: 0x40, name: "parse" },
               { id: 3, addr: "0x401200", size: 0, name: "stub" }];
  ck("exact start address resolves", U.containingFunction(fns, "0x401100").name === "parse");
  ck("an integer site inside a function resolves to it", U.containingFunction(fns, 0x401123).name === "parse");
  ck("a hex-string site inside a function resolves to it", U.containingFunction(fns, "0x401010").name === "main");
  ck("an address in no function is null, not a guess", U.containingFunction(fns, 0x401180) === null);
  ck("no address / no functions is null", U.containingFunction(fns, null) === null
    && U.containingFunction(null, 0x401000) === null);

  // ---- the card ----
  const finding = {
    id: "F1", cwe: "CWE-121", title: "Stack buffer overflow in bug()", severity: "critical",
    state: "poc-backed", detector: "stack_frame", site_addr: 4198742, evidence: [],
    curation: { status: "false_positive", note: "only reachable from the test harness", updated_at: 1 },
  };
  let calls = [];
  const onCurate = (f, st, note) => calls.push([f.id, st, note]);
  let info = renderInfo(h(C.FindingCard, { finding, pocs: [], artifactUrl: (s) => `/artifacts/${s}`,
    onCurate, onShowInGraph() {}, onViewCode() {} }));
  ck("FindingCard with curation renders without throwing", info.threw.length === 0);
  ck("the card still shows the TOOL's state badge", info.classes.some((c) => /badge state-poc-backed/.test(c)));
  ck("the card shows the operator's verdict as its own chip",
    info.classes.some((c) => /cur-chip cur-false_positive/.test(c)) && /False positive/.test(info.all));
  ck("a false positive is dimmed, not removed", info.classes.some((c) => /card finding.*cur-dim/.test(c)));
  ck("the note is shown on the card", /only reachable from the test harness/.test(info.all));
  ck("all three triage buttons are offered",
    /False positive/.test(info.all) && /True positive/.test(info.all) && /Needs review/.test(info.all));
  ck("the card offers the call-graph cross-link", /Call graph/.test(info.all));
  ck("View code is offered for a finding that knows only its site", /View code/.test(info.all));

  // clicking the ACTIVE status clears it and keeps the note; another status sets it
  const vnode = C.FindingCard({ finding, pocs: [], artifactUrl: (s) => s, onCurate });
  const fpBtn = find(vnode, (n) => n.type === "button" && /cur-btn cur-false_positive/.test(n.props.class || ""));
  const nrBtn = find(vnode, (n) => n.type === "button" && /cur-btn cur-needs_review/.test(n.props.class || ""));
  fpBtn.props.onClick(); nrBtn.props.onClick();
  ck("clicking the active status clears it, keeping the note",
    calls[0][0] === "F1" && calls[0][1] === null && calls[0][2] === finding.curation.note);
  ck("clicking another status sets it", calls[1][1] === "needs_review");
  ck("the active button is marked pressed", fpBtn.props["aria-pressed"] === "true");
  // the note form submits the textarea's value
  calls = [];
  const form = find(vnode, (n) => n.type === "form");
  form.props.onSubmit({ preventDefault() {}, currentTarget: { elements: { note: { value: "new note" } } } });
  ck("saving the note keeps the status and sends the new text",
    calls.length === 1 && calls[0][1] === "false_positive" && calls[0][2] === "new note");

  // without onCurate (read-only contexts) there is no triage bar, and no curation is no chip
  info = renderInfo(h(C.FindingCard, { finding: { ...finding, curation: null }, pocs: [], artifactUrl: (s) => s }));
  ck("no onCurate -> no triage controls", !/Needs review/.test(info.all) && info.threw.length === 0);
  ck("an uncurated card is not dimmed", !info.classes.some((c) => /cur-dim/.test(c)));

  // ---- the filter bar ----
  info = renderInfo(h(C.CurationFilter, { mode: "hide_fp", onChange() {}, counts: cnt }));
  ck("the filter bar says how many false positives it is hiding", /1\s+marked false positive hidden/.test(info.all));
  info = renderInfo(h(C.CurationFilter, { mode: "all", onChange() {}, counts: cnt }));
  ck("nothing is announced as hidden when nothing is", !/hidden/.test(info.all));

  console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
  process.exit(pass ? 0 : 1);
})().catch((e) => { console.log("FAIL  harness threw: " + (e && e.stack || e)); process.exit(1); });
