// Folder upload: pack a directory pick into one archive the server ingests as a source tree.
//
// A source project is a TREE, and the analysis needs the whole tree. The browser hands a folder
// pick back as a flat FileList with per-file relative paths; archive.js rebuilds it as a USTAR
// tar (gzipped when the browser can). This harness drives it under node -- which has File, Blob,
// CompressionStream and DecompressionStream -- and verifies the archive round-trips: every path
// and byte comes back out of the tar it produced. A regression here means a silently corrupt
// source upload, invisible to a grep.
const path = require("path");
const { pathToFileURL } = require("url");

const given = process.argv[2] || "core/lykos/api/static/index.html";
const appDir = path.join(path.dirname(given), "app");
const load = (name) => import(pathToFileURL(path.join(appDir, name)).href);

let pass = true;
const ck = (n, cond) => { pass = pass && !!cond; console.log(`${cond ? "PASS" : "FAIL"}  ${n}`); };

function mkFile(relPath, text) {
  const f = new File([text], relPath.split("/").pop(), { type: "text/plain" });
  Object.defineProperty(f, "webkitRelativePath", { value: relPath });
  return f;
}

// Parse a USTAR tar (Uint8Array) back to {path: text}, so the test does not depend on system tar.
function untar(bytes) {
  const dec = new TextDecoder();
  const out = {};
  let off = 0;
  while (off + 512 <= bytes.length) {
    const name = dec.decode(bytes.slice(off, off + 100)).replace(/\0.*$/, "");
    const prefix = dec.decode(bytes.slice(off + 345, off + 500)).replace(/\0.*$/, "");
    if (!name) break;                                      // the two zero blocks that end the tar
    const size = parseInt(dec.decode(bytes.slice(off + 124, off + 136)).replace(/\0.*$/, "").trim() || "0", 8);
    const full = prefix ? `${prefix}/${name}` : name;
    const data = bytes.slice(off + 512, off + 512 + size);
    out[full] = dec.decode(data);
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

(async () => {
  const arc = await load("archive.js");
  const files = [
    mkFile("myapp/main.c", "#include <stdio.h>\nint main(){return 0;}\n"),
    mkFile("myapp/src/deep/util.c", "int u(){return 42;}\n"),
    mkFile("myapp/Makefile", "all:\n\tcc -o myapp main.c\n"),
  ];
  ck("a directory pick is recognised as a folder", arc.isFolderPick(files));
  ck("a flat single-file pick is NOT a folder", !arc.isFolderPick([new File(["x"], "a.bin")]));

  const blob = await arc.folderArchive(files);
  ck("the archive is named after the folder", /^myapp\.tar(\.gz)?$/.test(blob.name));
  let raw = new Uint8Array(await blob.arrayBuffer());
  if (blob.name.endsWith(".gz")) {
    const ds = new Blob([raw]).stream().pipeThrough(new DecompressionStream("gzip"));
    raw = new Uint8Array(await new Response(ds).arrayBuffer());
  }
  const back = untar(raw);
  ck("every file path survives the round-trip (incl. nested)",
     ["myapp/main.c", "myapp/src/deep/util.c", "myapp/Makefile"].every((p) => p in back));
  ck("file contents are intact", back["myapp/src/deep/util.c"] === "int u(){return 42;}\n");

  console.log(pass ? "ALL PASS" : "SOME FAILED");
  process.exit(pass ? 0 : 1);
})();
