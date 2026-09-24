// Parse the page's inline script. A syntax error anywhere in 120 KB takes the whole GUI down
// with a blank panel and a console message nobody is watching for; every other check in this
// suite would still pass.
const fs = require("fs");
const vm = require("vm");
const _pm = require("path");
const _given = process.argv[2] || "core/lykos/api/static/index.html";
// These harnesses validate the CLASSIC single-file UI (now classic.html), whose
// inline <script> they render headlessly. The new workbench is modular ESM and is
// covered by gui_modules.js / gui_static.js instead.
const _classic = /classic\.html$/.test(_given) ? _given
  : _pm.join(_pm.dirname(_given), "classic.html");
const page = _classic;
const m = fs.readFileSync(page, "utf8").match(/<script[^>]*>([\s\S]*?)<\/script>/);
if (!m) { console.log("FAIL  no inline <script> found in " + page); process.exit(1); }
try {
  new vm.Script(m[1], {filename: page});
  console.log("PASS  inline script parses (" + m[1].length + " chars)");
} catch (e) {
  console.log("FAIL  " + e.message);
  process.exit(1);
}
