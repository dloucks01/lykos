// The custom-format builder, driven headlessly.
//
// `specToBuilder` ends in a catch-all that turns any unrecognised field type into a blob. A
// builtin model's nested group/array/shadow fields all hit it, so loading one into the editor
// and pressing "Use this spec" would replace a full grammar with magic + a pile of blobs --
// strictly worse than what the campaign picks unaided, and presented as a customisation.
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
const stub = () => ({innerHTML: "", textContent: "", value: "", style: {},
  classList: {toggle() {}, add() {}, remove() {}}, dataset: {}, options: [], hidden: false,
  focus() {}, setAttribute() {}, appendChild() {}, onclick: null, addEventListener() {},
  scrollIntoView() {}});
global.document = {getElementById: () => stub(), querySelector: () => null,
  querySelectorAll: () => [], addEventListener() {}, createElement: stub, body: stub()};
global.window = {addEventListener() {}, location: {href: ""}};
global.fetch = () => new Promise(() => {});
global.WebSocket = function () {};
global.localStorage = {getItem: () => null, setItem() {}};
global.matchMedia = () => ({matches: false, addEventListener() {}});
eval(src);

let pass = true;
const ck = (n, got, want) => {
  const ok = got === want; pass = pass && ok;
  console.log(`${ok ? "PASS" : "FAIL"}  ${n}: ${got}${ok ? "" : " (want " + want + ")"}`);
};

// what the editor CAN express round-trips
const simple = [{type: "magic", value: "%PDF"}, {type: "u32", name: "len", endian: "little",
                 length_of: "data"}, {type: "blob", name: "data"}];
ck("a magic/int/blob spec is editable", builderCanEdit(simple), true);
const round = specToBuilder(simple);
ck("...and round-trips to three fields", round.length, 3);
ck("...keeping the integer as an integer", round[1].type, "u32");

// what it cannot: a builtin's nested grammar
const builtin = [{type: "magic", value: {b64: "/9j/"}},
                 {type: "group", name: "segment", fields: [{type: "u16", name: "len"}]},
                 {type: "array", name: "entries", count_of: "n"},
                 {type: "shadow", name: "crc"}];
ck("a nested builtin model is NOT editable", builderCanEdit(builtin), false);
// the old behaviour, for the record: every nested field collapsed to a blob
const lossy = specToBuilder(builtin);
ck("...and loading it anyway would flatten it", lossy.filter(f => f.type === "blob").length, 3);
process.exit(pass ? 0 : 1);
