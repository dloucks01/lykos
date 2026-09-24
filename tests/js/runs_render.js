// Render the run list headlessly. The flat version truncated to 14 with no target name on any
// row, so with four binaries in a case you could not tell which run belonged to which -- and
// the runs past the cap, INCLUDING the only one that errored, were simply not drawn.
const fs = require("fs");
const _pm = require("path");
const _given = process.argv[2] || "core/lykos/api/static/index.html";
// These harnesses validate the CLASSIC single-file UI (now classic.html), whose
// inline <script> they render headlessly. The new workbench is modular ESM and is
// covered by gui_modules.js / gui_static.js instead.
const _classic = /classic\.html$/.test(_given) ? _given
  : _pm.join(_pm.dirname(_given), "classic.html");
const src = fs.readFileSync(_classic, "utf8")
  .match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const runs = {innerHTML: ""};
const stub = () => ({innerHTML: "", textContent: "", value: "", style: {},
  classList: {toggle() {}, add() {}, remove() {}}, dataset: {}, options: [], hidden: false,
  focus() {}, setAttribute() {}, appendChild() {}, onclick: null, addEventListener() {},
  scrollIntoView() {}});
global.document = {getElementById: id => (id === "runs" ? runs : stub()),
  querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  createElement: stub, body: stub()};
global.window = {addEventListener() {}, location: {href: ""}};
global.fetch = () => new Promise(() => {});
global.WebSocket = function () {};
global.localStorage = {getItem: () => null, setItem() {}};
global.matchMedia = () => ({matches: false, addEventListener() {}});
eval(src + `
;globalThis.__names=n=>{TARGET_NAME=n;};
;globalThis.__render=rs=>{RUNS_ALL=false;renderRuns(rs);};
;globalThis.__all=rs=>{RUNS_ALL=true;renderRuns(rs);};
`);

const now = Math.floor(Date.now() / 1000);
const mk = (i, tid, status, error) => ({id: "r" + i, case_id: "c", target_id: tid,
  stage: "detect_cwe", status, error: error || null, created_at: now - i,
  started_at: now - i, ended_at: now - i + 1});
// 24 done runs across two targets, plus one OLD error that the cap would have swallowed
const data = [
  ...Array.from({length: 12}, (_, i) => mk(i, "t1", "done")),
  ...Array.from({length: 11}, (_, i) => mk(20 + i, "t2", "done")),
  mk(90, "t2", "error", "FileNotFoundError(2, 'No such file or directory')"),
  mk(91, null, "done"),
];
__names({t1: "jhead_x86-64", t2: "app.jar"});

let pass = true;
const ck = (n, got, want) => {
  const ok = got === want; pass = pass && ok;
  console.log(`${ok ? "PASS" : "FAIL"}  ${n}: ${got}${ok ? "" : " (want " + want + ")"}`);
};
const H = () => runs.innerHTML;
const rows = () => (H().match(/class="kv runrow"/g) || []).length;

__render(data);
ck("groups are rendered", (H().match(/class="rungrp"/g) || []).length, 3);
ck("rows carry the binary's name", H().includes("jhead_x86-64") && H().includes("app.jar"), true);
ck("case-level runs are labelled", H().includes("case-level"), true);
// the whole point: a failure is never hidden by truncation, however old it is
ck("the old error is still drawn", H().includes("FileNotFoundError"), true);
ck("the error group is badged", /1 error/.test(H()), true);
ck("the rest are capped", rows() < data.length, true);
ck("and it says how many are hidden", /show \d+ older run/.test(H()), true);
__all(data);
ck("show-all draws everything", rows(), data.length);
__render([]);
ck("no runs renders the empty state", H().includes("No runs yet"), true);
process.exit(pass ? 0 : 1);
