// Structural checks on the new workbench shell and its module graph.
//
// The modular UI can fail in ways the logic tests never see: a broken import map (a bare
// "preact" that resolves to nothing → a blank page and one console error nobody watches for),
// a missing module <script>, or a syntax error in a Preact-importing module the node logic
// harness cannot load. This validates the wiring in index.html and syntax-checks every app
// module and vendored runtime file with `node --check`, which parses without resolving imports.
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const given = process.argv[2] || "core/lykos/api/static/index.html";
const staticDir = path.dirname(given);
const html = fs.readFileSync(given, "utf8");

let pass = true;
const ck = (n, cond) => { pass = pass && !!cond; console.log(`${cond ? "PASS" : "FAIL"}  ${n}`); };

// ---- import map: the three bare specifiers the app imports must all resolve ----
const mapMatch = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
ck("index.html declares an import map", !!mapMatch);
let imap = {};
if (mapMatch) {
  try { imap = JSON.parse(mapMatch[1]).imports || {}; }
  catch (e) { ck("import map is valid JSON", false); }
}
for (const spec of ["preact", "preact/hooks", "htm"]) {
  const target = imap[spec];
  ck(`import map maps "${spec}"`, !!target);
  if (target) {
    const rel = target.replace(/^\.\//, "");
    ck(`  → ${rel} exists`, fs.existsSync(path.join(staticDir, rel)));
  }
}

// ---- the app is loaded as a module, and the root mount point exists ----
ck("app entry is a <script type=module>", /<script\s+type="module"\s+src="\.\/app\/app\.js">/.test(html));
ck("mount point #root is present", /id="root"/.test(html));

// ---- every app module and vendored file parses ----
const files = [
  ...fs.readdirSync(path.join(staticDir, "app")).filter((f) => f.endsWith(".js")).map((f) => path.join("app", f)),
  ...fs.readdirSync(path.join(staticDir, "vendor")).filter((f) => f.endsWith(".js")).map((f) => path.join("vendor", f)),
];
for (const rel of files) {
  const full = path.join(staticDir, rel);
  try {
    execFileSync(process.execPath, ["--check", "--input-type=module", full], { stdio: "pipe" });
    ck(`${rel} parses as an ES module`, true);
  } catch (e) {
    // --check with a file path ignores --input-type on some node builds; fall back to piping
    // the source in as module input, which honours it.
    try {
      execFileSync(process.execPath, ["--check", "--input-type=module"], {
        input: fs.readFileSync(full), stdio: ["pipe", "pipe", "pipe"],
      });
      ck(`${rel} parses as an ES module`, true);
    } catch (e2) {
      ck(`${rel} parses as an ES module`, false);
      console.log("      " + String((e2.stderr || e2.message || "").toString()).split("\n").slice(0, 2).join(" "));
    }
  }
}

// ---- app modules must import Preact through the bare specifiers, not a relative vendor path
//      (which would bypass the import map and load a second Preact copy) ----
const appJs = fs.readFileSync(path.join(staticDir, "app", "app.js"), "utf8");
ck("app.js imports preact by bare specifier", /from\s+"preact"/.test(appJs));
ck("app.js does not deep-link the vendored preact file", !/from\s+"[^"]*vendor\/preact/.test(appJs));
ck("classic UI is still reachable from the app", /classic\.html/.test(appJs));

console.log(pass ? "ALL PASS" : "FAILURES ABOVE");
process.exit(pass ? 0 : 1);
