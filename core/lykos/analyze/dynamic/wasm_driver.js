// Drive a WebAssembly module with one input and report what happened.
//
//   node wasm_driver.js <module.wasm> <report.json>      input on stdin
//
// A wasm module is not an executable: it has no process, no argv and (unless it is a WASI
// command) no entry point. So "running" one means choosing how to hand it the input, and that
// choice is where a harness invents false positives. Two shapes are driven, in this order:
//
//   1. a WASI COMMAND -- it exports `_start` and reads fd 0. A real entry point, so nothing is
//      assumed: the input goes to stdin exactly as it would for a native program.
//   2. a REACTOR / library -- no `_start`, so the input is written into the module's own linear
//      memory and passed to each two-argument export as (pointer, length), the near-universal
//      convention for handing bytes to a wasm library.
//
// Shape 2 is a GUESS, and a wrong guess traps for reasons that are the harness's fault rather
// than the module's: call `row(r, c)` as if it were `parse(ptr, len)` and it reads
// tbl[65536][0], far past the end of memory. So every trap is re-checked on a FRESH instance
// with an EMPTY input: a genuine (ptr,len) entry point cannot fault on a zero-length buffer,
// and if it faults anyway the trap is the convention rather than a defect this input reached --
// reported as not-drivable, not as a crash.
//
// The verdict is written to the report FILE, never to stderr. A WASI module can write whatever
// it likes to fd 2, so a marker on stderr would be forgeable by the target -- and a fuzzer
// rewarded for crashes will learn to print one. The report path is not preopened for the
// module, so it cannot reach it.
'use strict';
const fs = require('fs');

const modPath = process.argv[2];
const reportPath = process.argv[3];

function report(obj) {
  try { fs.writeFileSync(reportPath, JSON.stringify(obj)); } catch (e) { /* nothing left to do */ }
}

function readStdin() {
  try { return fs.readFileSync(0); } catch (e) { return Buffer.alloc(0); }
}

// Every declared import gets a stub, so a module built against an environment we do not have
// still INSTANTIATES. A missing import is a link error, which would otherwise look exactly
// like "this module cannot be analysed" for every input.
function stubs(mod) {
  const im = {};
  for (const d of WebAssembly.Module.imports(mod)) {
    im[d.module] = im[d.module] || {};
    if (d.kind === 'function') im[d.module][d.name] = () => 0;
    else if (d.kind === 'memory') im[d.module][d.name] = new WebAssembly.Memory({ initial: 2 });
    else if (d.kind === 'global') im[d.module][d.name] =
      new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
    else if (d.kind === 'table') im[d.module][d.name] =
      new WebAssembly.Table({ initial: 1, element: 'anyfunc' });
  }
  return im;
}

function isWasi(mod) {
  if (!WebAssembly.Module.exports(mod).some((e) => e.name === '_start')) return false;
  return WebAssembly.Module.imports(mod).some((d) => d.module.startsWith('wasi_'));
}

function runWasi(bytes) {
  let WASI;
  try { ({ WASI } = require('node:wasi')); }
  catch (e) { return { notdrivable: 'this node has no WASI support for a wasm command module' }; }
  // stdin/stdout/stderr are passed EXPLICITLY: the input arrives on fd 0 and a WASI
  // command that never gets it reads zero bytes and looks like a clean run on every input.
  const wasi = new WASI({ version: 'preview1', args: ['prog'], env: {},
                          stdin: 0, stdout: 1, stderr: 2, returnOnExit: true });
  const mod = new WebAssembly.Module(bytes);
  const inst = new WebAssembly.Instance(mod, wasi.getImportObject());
  try { return { exit: wasi.start(inst) | 0 }; }
  catch (e) { return { trap: e && e.message ? e.message : String(e), entry: '_start' }; }
}

// Call every two-argument export as f(ptr, len) with `data` staged in linear memory. Returns
// the FIRST trap, so the campaign attributes the fault to the export that produced it.
function runReactor(mod, data) {
  const inst = new WebAssembly.Instance(mod, stubs(mod));
  const ex = inst.exports;
  const mem = Object.values(ex).find((v) => v instanceof WebAssembly.Memory);
  if (!mem) return { notdrivable: 'the module exports no memory, so the input has nowhere to go' };
  // Grow by a page and stage the input THERE, rather than at a fixed address: the module's own
  // data, stack and heap live in the pages it was built with, and overwriting them would make
  // the module fault on our corruption instead of on its own defect.
  const ptr = mem.grow(1) * 65536;
  if (data.length) new Uint8Array(mem.buffer, ptr, data.length).set(data);
  const fns = Object.entries(ex).filter(([, v]) => typeof v === 'function' && v.length === 2);
  if (!fns.length) {
    return { notdrivable: 'no exported function takes two arguments, so there is no (ptr,len) '
                          + 'entry point to hand the input to' };
  }
  for (const [name, fn] of fns) {
    try { fn(ptr, data.length); }
    catch (e) { return { trap: e && e.message ? e.message : String(e), entry: name }; }
  }
  return { exit: 0 };
}

function main() {
  const bytes = fs.readFileSync(modPath);
  let mod;
  try { mod = new WebAssembly.Module(bytes); }
  catch (e) {
    // Not a valid module at all. That is a fact about the FILE, not a defect reached by this
    // input, and every input would report it identically.
    return report({ status: 'notdrivable',
                    message: 'the module did not validate: ' + (e && e.message ? e.message : e) });
  }
  // Read stdin ONLY for the reactor path. A WASI command reads fd 0 itself, and draining it
  // here left the module reading zero bytes -- which looks exactly like a clean run on every
  // input, so the whole WASI substrate silently found nothing.
  const r = isWasi(mod) ? runWasi(bytes) : runReactor(mod, readStdin());
  if (r.notdrivable) return report({ status: 'notdrivable', message: r.notdrivable });
  if (r.trap) {
    if (r.entry !== '_start') {
      // The convention check described at the top of this file.
      let base;
      try { base = runReactor(mod, Buffer.alloc(0)); } catch (e) { base = {}; }
      if (base.trap) {
        return report({ status: 'notdrivable', entry: r.entry,
                        message: 'export ' + r.entry + ' traps on an empty input too ('
                                 + base.trap + '), so it does not take (ptr,len) and this trap '
                                 + 'is the calling convention rather than a defect' });
      }
    }
    return report({ status: 'trap', message: r.trap, entry: r.entry });
  }
  return report({ status: 'clean', exit: r.exit | 0 });
}

try {
  main();
} catch (e) {
  report({ status: 'notdrivable',
           message: 'the driver could not run this module: ' + (e && e.message ? e.message : e) });
}
