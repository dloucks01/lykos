// Render the Findings Board headlessly and assert what the operator actually sees.
//
// Every other GUI test in this repo asserts that source text EXISTS -- that a function is
// named, that a label appears. None of them would notice a board that renders zero rows, and
// one nearly shipped: `t.open || ... || BOARD_OPEN[k]` short-circuits, so the chevron on a
// default-open tier did nothing. That is invisible to a grep and obvious here.
const fs = require("fs");
const path = process.argv[2];
const src = fs.readFileSync(path, "utf8").match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];

const board = {innerHTML: "", focus() {}};
const stub = () => ({innerHTML: "", textContent: "", value: "", style: {},
  classList: {toggle() {}, add() {}, remove() {}}, dataset: {}, options: [], hidden: false,
  focus() {}, setAttribute() {}, appendChild() {}, onclick: null, addEventListener() {},
  scrollIntoView() {}});
global.document = {getElementById: id => (id === "board" ? board : stub()),
  querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  createElement: stub, body: stub()};
global.window = {addEventListener() {}, location: {href: ""}};
global.fetch = () => new Promise(() => {});      // never resolves: no startup side effects
global.WebSocket = function () {};
global.localStorage = {getItem: () => null, setItem() {}};
global.matchMedia = () => ({matches: false, addEventListener() {}});

// BOARD_DATA/BOARD_FILTER/BOARD_OPEN are `let`-scoped inside the page script, so they are
// reachable only from inside it.
eval(src + `
;globalThis.__set=(d,f)=>{BOARD_DATA=d;BOARD_FILTER=f;BOARD_OPEN={};renderBoard();};
;globalThis.__open=(k,v)=>{BOARD_OPEN[k]=v;renderBoard();};
;globalThis.__reset=()=>{BOARD_OPEN={};};
`);

const data = [
  {id: "1", state: "confirmed", severity: "high", cwe: "CWE-125", title: "Reproduced crash",
   confidence: .9, site_count: 1, detector: "fuzz", evidence: [{}]},
  {id: "2", state: "corroborated", severity: "medium", cwe: "CWE-120", title: "memcpy",
   confidence: .7, site_count: 3, detector: "dangerous_api", evidence: [{}]},
  ...Array.from({length: 16}, (_, i) => ({id: "c" + i, state: "candidate", severity: "low",
    cwe: "CWE-134", title: "printf " + i, confidence: .5, site_count: 1,
    detector: "dangerous_api", evidence: [{}]})),
];
const R = () => (board.innerHTML.match(/class="frow/g) || []).length;
const H = () => (board.innerHTML.match(/class="tierhd"/g) || []).length;
let pass = true;
const ck = (n, got, want) => {
  const ok = got === want; pass = pass && ok;
  console.log(`${ok ? "PASS" : "FAIL"}  ${n}: ${got}${ok ? "" : " (want " + want + ")"}`);
};

__set(data, {q: "", sev: "", state: ""});
ck("three evidence tiers", H(), 3);
// the point of the whole change: on a real parser the unproven tier IS the list, so it starts
// collapsed and the two demonstrated findings are what is on screen
ck("unproven collapsed by default", R(), 2);
ck("unproven count on the header", /Unproven[\s\S]{0,140}?tcount">16</.test(board.innerHTML), true);
__open("cand", true);
ck("expanding unproven shows everything", R(), 18);
__reset(); __open("proven", false);
ck("a default-open tier can be collapsed", R(), 1);
__set(data, {q: "", sev: "", state: "candidate"});
ck("an explicit state filter opens that tier", R(), 16);
__set(data, {q: "printf 3", sev: "", state: ""});
ck("a text filter opens the tiers that match", R(), 1);
__set([], {q: "", sev: "", state: ""});
ck("an empty case renders no tier headers", H(), 0);
process.exit(pass ? 0 : 1);
