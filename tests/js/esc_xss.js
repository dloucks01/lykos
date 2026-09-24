// Guard the UI against stored XSS from a hostile binary. A crafted symbol name, section
// name, import string or address in an analysed sample flows into the operator's console;
// esc() is what must neutralise it, in BOTH text and quoted-attribute contexts. This renders
// the page's own esc()/renderFuncs against a stubbed DOM and asserts the payload cannot
// escape. It would have failed before esc() escaped quotes and before the addr fields were
// wrapped in esc().
const fs = require("fs");
const _pm = require("path");
const _given = process.argv[2] || "core/lykos/api/static/index.html";
// These harnesses validate the CLASSIC single-file UI (now classic.html), whose
// inline <script> they render headlessly. The new workbench is modular ESM and is
// covered by gui_modules.js / gui_static.js instead.
const _classic = /classic\.html$/.test(_given) ? _given
  : _pm.join(_pm.dirname(_given), "classic.html");
const src = fs.readFileSync(_classic, "utf8").match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];

const stub = () => ({innerHTML: "", textContent: "", value: "", style: {},
  classList: {toggle() {}, add() {}, remove() {}}, dataset: {}, options: [], hidden: false,
  focus() {}, setAttribute() {}, appendChild() {}, onclick: null, addEventListener() {},
  scrollIntoView() {}, setSelectionRange() {}, querySelector: () => null,
  querySelectorAll: () => []});
const funcsEl = stub();
global.document = {getElementById: id => (id === "funcs" ? funcsEl : stub()),
  querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
  createElement: stub, body: stub()};
global.window = {addEventListener() {}, location: {href: ""}};
global.fetch = () => new Promise(() => {});      // never resolves: no startup side effects
global.WebSocket = function () {};
global.localStorage = {getItem: () => null, setItem() {}};
global.matchMedia = () => ({matches: false, addEventListener() {}});

// esc is a function declaration and FUNCS a `let`, both reachable only from inside the script.
eval(src + `
;globalThis.__esc = esc;
;globalThis.__renderFuncs = (list) => { FUNCS = list; renderFuncs(""); };
`);

let pass = true;
const ck = (n, cond) => { pass = pass && cond; console.log(`${cond ? "PASS" : "FAIL"}  ${n}`); };

const e = globalThis.__esc;
// esc() must remove every HTML-significant char so it is safe in text AND attr="${esc(x)}".
ck("esc escapes <", !e("<b>").includes("<"));
ck("esc escapes >", !e("<b>").includes(">"));
ck("esc escapes the double quote (attribute breakout)", !e('a"b').includes('"'));
ck("esc escapes the single quote", !e("a'b").includes("'"));
ck("esc escapes the backtick", !e("a`b").includes("`"));
ck("esc escapes the ampersand", e("a&b").includes("&amp;"));
const payload = `"><img src=x onerror=alert(1)>`;
const escd = e(payload);
ck("esc neutralises an img/onerror payload",
   !escd.includes("<") && !escd.includes(">") && !escd.includes('"'));

// renderFuncs must escape a hostile function name AND a hostile address into the DOM.
globalThis.__renderFuncs([{id: "1", name: `x"><img src=x onerror=alert(1)>`,
  addr: `0x1"><script>alert(1)</script>`, signature: "", size: 0}]);
const html = funcsEl.innerHTML;
ck("renderFuncs escapes a hostile symbol name", !html.includes("<img src=x onerror="));
ck("renderFuncs escapes a hostile address", !html.includes("<script>alert(1)</script>"));
ck("renderFuncs leaves no raw payload angle brackets", !/<img|<script/i.test(html));

process.exit(pass ? 0 : 1);
