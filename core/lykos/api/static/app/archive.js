// Pack a picked FOLDER into one archive, client-side, with no dependencies.
//
// A source project is a TREE, and the analysis (dependency-CVE, int-overflow, use-after-free,
// tainted-sink source scanners) needs the whole tree, not one file. The browser hands a directory
// pick back as a flat FileList where each File carries its `webkitRelativePath`; this rebuilds the
// tree as a USTAR tar (a dead-simple 512-byte-record format) and, when the browser supports it,
// gzips it with the native CompressionStream. The server already extracts a tar/tar.gz upload and
// ingests the directory as a source project -- so this needs no new endpoint.

const BLOCK = 512;
const _enc = new TextEncoder();

function _octal(value, width) {
  // tar stores numbers as NUL-terminated octal ASCII in a fixed-width field.
  let s = value.toString(8);
  if (s.length > width - 1) s = s.slice(-(width - 1));          // keep the low digits if huge
  return s.padStart(width - 1, "0") + "\0";
}

function _writeStr(buf, off, str, len) {
  const b = _enc.encode(str);
  for (let i = 0; i < len; i++) buf[off + i] = i < b.length ? b[i] : 0;
}

// USTAR splits a long path into name[100] + prefix[155]; return [name, prefix] or null if it does
// not fit (a path longer than 255, which a release source tree effectively never has).
function _splitPath(path) {
  const bytes = _enc.encode(path);
  if (bytes.length <= 100) return [path, ""];
  // split on a '/' so that the tail fits in name[100] and the head in prefix[155]
  for (let i = path.length - 1; i >= 0; i--) {
    if (path[i] !== "/") continue;
    const name = path.slice(i + 1), prefix = path.slice(0, i);
    if (_enc.encode(name).length <= 100 && _enc.encode(prefix).length <= 155) return [name, prefix];
  }
  return null;
}

function _header(path, size) {
  const h = new Uint8Array(BLOCK);
  const split = _splitPath(path);
  if (!split) return null;                                      // path too long -> skip the file
  const [name, prefix] = split;
  _writeStr(h, 0, name, 100);
  _writeStr(h, 100, _octal(0o644, 8), 8);                       // mode
  _writeStr(h, 108, _octal(0, 8), 8);                           // uid
  _writeStr(h, 116, _octal(0, 8), 8);                           // gid
  _writeStr(h, 124, _octal(size, 12), 12);                      // size
  _writeStr(h, 136, _octal(Math.floor(Date.now() / 1000), 12), 12);  // mtime
  for (let i = 148; i < 156; i++) h[i] = 0x20;                  // chksum field = spaces for the sum
  h[156] = 0x30;                                                // typeflag '0' (regular file)
  _writeStr(h, 257, "ustar\0", 6);                              // magic
  h[263] = 0x30; h[264] = 0x30;                                 // version "00"
  _writeStr(h, 345, prefix, 155);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += h[i];
  _writeStr(h, 148, sum.toString(8).padStart(6, "0") + "\0 ", 8);  // chksum: 6 octal, NUL, space
  return h;
}

// Build an uncompressed USTAR tar (Uint8Array) from [{path, data}] records.
function _tar(records) {
  const blocks = [];
  let total = 0;
  for (const r of records) {
    const hdr = _header(r.path, r.data.length);
    if (!hdr) continue;                                         // over-long path: skip, don't corrupt
    blocks.push(hdr); total += BLOCK;
    blocks.push(r.data); total += r.data.length;
    const pad = (BLOCK - (r.data.length % BLOCK)) % BLOCK;
    if (pad) { blocks.push(new Uint8Array(pad)); total += pad; }
  }
  blocks.push(new Uint8Array(BLOCK * 2)); total += BLOCK * 2;   // two zero blocks terminate a tar
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of blocks) { out.set(b, off); off += b.length; }
  return out;
}

async function _gzip(bytes) {
  if (typeof CompressionStream === "undefined") return null;    // old browser: caller uploads .tar
  const cs = new CompressionStream("gzip");
  const stream = new Blob([bytes]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// True when a FileList came from a directory pick (its files carry a relative path with a folder).
export function isFolderPick(fileList) {
  const files = Array.from(fileList || []);
  return files.length > 0 && files.some((f) => (f.webkitRelativePath || "").includes("/"));
}

// Pack a directory-pick FileList into one archive Blob (gzipped tar when possible, else tar),
// ready to POST to the target-upload endpoint. `.name` is set so the server sees a source tree.
export async function folderArchive(fileList) {
  const files = Array.from(fileList || []);
  const records = [];
  let root = "";
  for (const f of files) {
    const path = f.webkitRelativePath || f.name;
    if (!root && path.includes("/")) root = path.split("/")[0];
    const data = new Uint8Array(await f.arrayBuffer());
    records.push({ path, data });
  }
  const tar = _tar(records);
  const gz = await _gzip(tar);
  const base = (root || "source").replace(/[^A-Za-z0-9._-]/g, "_");
  if (gz) return new File([gz], `${base}.tar.gz`, { type: "application/gzip" });
  return new File([tar], `${base}.tar`, { type: "application/x-tar" });
}
