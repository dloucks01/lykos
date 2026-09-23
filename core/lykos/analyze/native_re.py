"""Native (no-JVM) RE backend: rizin/radare2 for structure + decompilation, pypcode for the
Ghidra P-Code IR the detectors consume.

This is the Phase-1 (doc 24) alternative to the Ghidra-headless backend. It produces the SAME
analysis dict ``ghidra.parse_result`` returns -- ``{"program": {...}, "functions": [...],
"strings": [...], "imports": [...]}`` with per-function ``cfg`` (blocks -> instructions ->
``pcode``), ``frame``/``params``/``vars``, ``calls``, and ``decompiled`` -- so the disassemble
stage, the DB persistence, and every downstream detector (bounds/taint/int-overflow) run
unchanged.

Why this shape works with no Java:
  * The Ghidra *decompiler* and its SLEIGH lifter are C++, not Java. rizin+rz-ghidra (Kali
    package) or radare2+r2ghidra expose the decompiler; **pypcode** wraps the same SLEIGH
    engine to emit real Ghidra P-Code per instruction. So the P-Code the detectors parse is
    byte-for-byte the Ghidra IR -- just produced without the JVM.
  * What is genuinely weaker than full Ghidra is the *auto-analysis* (function boundaries,
    types, switch tables) feeding the decompiler -- see doc 24 for the honest delta.

The decompiled-C field uses the tool's Ghidra decompiler (``pdg`` from rz-ghidra/r2ghidra) when
present, else the built-in pseudo-decompiler (``pdc``) as a readable stand-in.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

# Exhaustive by default: analyze EVERY function. A large kernel (the vxWorks 6.9 image is ~7200
# functions) previously had its function set silently TRUNCATED to the first 1200, so the CWE
# detectors -- which read the persisted function rows -- only ever saw ~17% of the program and the
# real defects in the rest were invisible. We now analyze all of them; the cost (minutes on a big
# binary) is paid by batching the per-function pass so it reports progress and survives a partial
# failure without losing the work already done. 0 = unlimited (the default); set LYKOS_MAX_FUNCS to
# a positive number only to deliberately cap a run.
_MAX_FUNCS = int(os.environ.get("LYKOS_MAX_FUNCS", "0") or "0")
# The per-function structural pass is chunked into batches of this many functions. Each batch is a
# separate rizin invocation, so a batch that times out or errors costs only that batch -- the
# functions from prior batches are already on disk and get built and persisted. Smaller batches =
# finer progress + finer failure granularity; larger = less rizin-startup overhead.
_BATCH = max(1, int(os.environ.get("LYKOS_FUNC_BATCH", "500") or "500"))
# At or below this many functions the structural pass runs whole-program `aaa` (one pass): its
# emulation-based type propagation recovers array types, so buffers are detected precisely and the
# pass is still quick. Above it, `aaa` per batch would dominate the runtime, so we use the fast
# per-function path and recover buffers from stack geometry instead.
_AAA_MAX = int(os.environ.get("LYKOS_AAA_MAX", "2000") or "2000")
# The (advisory, slowest) decompiled-C pass. Decompiling thousands of functions up front would take
# many minutes and risk losing everything on a timeout, and the detectors use the pypcode P-Code,
# not the C. So we decompile up to this many up front (small binaries come back fully decompiled),
# and EVERY OTHER function is decompiled lazily on demand when the analyst opens it (see the
# /functions/{id} endpoint). Nothing is permanently skipped. 0 disables the up-front pass entirely.
_MAX_DECOMPILE = int(os.environ.get("LYKOS_MAX_DECOMPILE", "400") or "400")
# Cap the per-string xref pass (axtj per string address) -- a big binary has tens of thousands of
# strings and computing an xref for each is another slow per-item loop. Strings are still all
# listed; only the xref sites beyond this cap are skipped.
_MAX_STRING_XREFS = int(os.environ.get("LYKOS_MAX_STRING_XREFS", "1500") or "1500")

# r2/rizin arch+bits+endian -> pypcode SLEIGH language id. Extend as architectures are added;
# an unmapped target still analyses (structure + decompile), only its P-Code is empty.
_SLEIGH = {
    ("x86", 64, "little"): "x86:LE:64:default",
    ("x86", 32, "little"): "x86:LE:32:default",
    ("arm", 32, "little"): "ARM:LE:32:v8",
    ("arm", 32, "big"): "ARM:BE:32:v8",
    ("arm", 64, "little"): "AARCH64:LE:64:v8A",
    ("aarch64", 64, "little"): "AARCH64:LE:64:v8A",
    ("ppc", 32, "big"): "PowerPC:BE:32:default",
    ("ppc", 64, "big"): "PowerPC:BE:64:default",
    ("mips", 32, "big"): "MIPS:BE:32:default",
    ("mips", 32, "little"): "MIPS:LE:32:default",
}

def locate_native(config: Optional[str] = None) -> Optional[Path]:
    """Path to the rizin or radare2 CLI, preferring rizin (the rz-ghidra host). Honours
    LYKOS_RIZIN / LYKOS_R2, then PATH."""
    for env in ("LYKOS_RIZIN", "LYKOS_R2"):
        v = os.environ.get(env)
        if v and Path(v).exists():
            return Path(v)
    if config and Path(config).exists():
        return Path(config)
    for name in ("rizin", "r2", "radare2"):
        w = shutil.which(name)
        if w:
            return Path(w)
    return None


def _run(cli: Path, binary: Path, script: str, *, ctx=None, timeout: int,
         scratch: Optional[Path] = None) -> None:
    """Run a rizin/radare2 command script. Output is captured by the script itself via per-
    command file redirection (`cmd > file`), NOT by parsing stdout -- this is the only approach
    that is portable across rizin and radare2. rizin's `?e` markers do not print and abort the
    command chain, and rizin warns to stderr during `ij`, so we never rely on stdout ordering.

    The script is delivered through a file with `-i`, never inline with `-c`: a statically linked
    sanitizer build carries thousands of functions, and the per-function structural/decompile
    pass then builds a multi-megabyte command string that overflows ARG_MAX -- the raw
    OSError(E2BIG, 'Argument list too long') that took `disassemble` (and thus the whole
    analysis) down on every ASan source target. A file has no such limit; rizin is run
    unsandboxed here, so it can read the script from the scratch dir alongside its output files.

    Two flags matter: not -2 (closing stderr makes rizin abort when it warns), and
    bin.relocs.apply for correct call targets."""
    import tempfile
    d = str(scratch) if scratch is not None else None
    fd, spath = tempfile.mkstemp(prefix="rzscript-", suffix=".rz", dir=d)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(script)
        cmd = [str(cli), "-q", "-e", "scr.color=0", "-e", "bin.relocs.apply=true",
               "-i", spath, str(binary)]
        # stdin MUST be /dev/null. rizin, seeing a non-TTY stdin (a worker's inherited pipe),
        # treats it as a COMMAND STREAM and blocks reading it -- so `disassemble` hangs forever
        # with no CPU whenever the server's stdin is not already /dev/null (e.g. ./RUN.sh launched
        # so the worker inherits an open pipe). Immediate EOF makes rizin quit after -i as intended.
        if ctx is not None:
            ctx.run_subprocess(cmd, timeout=timeout, stdin=subprocess.DEVNULL)
        else:
            subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _emit(ctx, *, pct=None, msg=None):
    """Best-effort progress emit. Never raises: progress is a courtesy, not part of the result,
    and a ctx that lacks progress() (or one that fails) must not take the analysis down."""
    if ctx is None:
        return
    try:
        if pct is not None:
            ctx.progress(pct=pct, msg=msg)
        else:
            ctx.progress(msg=msg)
    except Exception:
        pass


def _readj(path: Path, default):
    """Read + JSON-parse a file a rizin command redirected into; default if missing/empty/bad."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _redir(cmd: str, path: Path) -> str:
    """A rizin command whose output is redirected to a file (`cmd > path`)."""
    return f"{cmd} > {path}"


def _vn(ctx, v) -> str:
    """Format one P-Code varnode exactly as ExportAnalysis.java does: registers as
    'reg:NAME:size', constants as 'const:0xVAL:size', everything else 'space:0xOFF:size'."""
    sp = v.space.name
    if sp == "register":
        try:
            rn = ctx.getRegisterName(v.space, v.offset, v.size)
        except Exception:
            rn = None
        return f"reg:{rn}:{v.size}" if rn else f"register:{hex(v.offset)}:{v.size}"
    if sp == "const":
        return f"const:{hex(v.offset)}:{v.size}"
    return f"{sp}:{hex(v.offset)}:{v.size}"


def _have_pypcode() -> bool:
    try:
        import pypcode  # noqa: F401
        return True
    except Exception:                                        # noqa: BLE001
        return False


def _pcode_worker_path() -> Path:
    """Path to the standalone pcode_worker.py. Materialize it from the package when it is not a
    real file on disk (e.g. running from a zipapp), so it can be handed to a child interpreter."""
    here = Path(__file__).parent / "pcode_worker.py"
    if here.exists():
        return here
    import tempfile
    from importlib import resources
    data = (resources.files("lykos.analyze") / "pcode_worker.py").read_bytes()
    p = Path(tempfile.mkdtemp(prefix="lykos-pcodew-")) / "pcode_worker.py"
    p.write_bytes(data)
    return p


class _Lifter:
    """Ghidra P-Code via pypcode (SLEIGH, no JVM), lifted in a SEPARATE PROCESS.

    pypcode is a C extension that can crash the interpreter (a native double-free / SIGABRT on some
    instruction encodings -- seen on ppc64 big-endian). Lifting in-process would abort the whole
    server, so `lift_all` runs pcode_worker.py as a child: a crash there is contained, and the
    parent keeps every function's structure plus whatever P-Code was flushed. Falls back to empty
    P-Code when pypcode/the language is unavailable -- structure/decompile still work."""

    def __init__(self, langid: Optional[str]):
        self.langid = langid or None
        self.available = bool(langid) and _have_pypcode()

    def lift_all(self, instrs: list, *, ctx=None, timeout: int = 600) -> dict:
        """Lift many instructions at once in a child process. `instrs` is [(addr_int, hexbytes)].
        Returns {addr_hex: [op_strings]}. On a crash/timeout the child dies and we return whatever
        it flushed (possibly nothing) -- the analysis continues with that much P-Code."""
        if not self.available or not instrs:
            return {}
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="lykos-pcode-"))
        inp, outp = d / "in.json", d / "out.jsonl"
        try:
            inp.write_text(json.dumps({"langid": self.langid,
                                       "instrs": [[a, h] for a, h in instrs]}))
            worker = _pcode_worker_path()
            cmd = [sys.executable, str(worker), str(inp), str(outp)]
            env_path = os.pathsep.join(p for p in sys.path if p)   # pypcode wherever the parent has it
            popen_env = dict(os.environ, PYTHONPATH=env_path)
            try:
                if ctx is not None:
                    ctx.run_subprocess(cmd, timeout=timeout, env=popen_env)
                else:
                    subprocess.run(cmd, timeout=timeout, capture_output=True, check=False,
                                   stdin=subprocess.DEVNULL, env=popen_env)
            except Exception:                              # noqa: BLE001 -- crash/timeout: use partial
                pass
            out = {}
            try:
                with open(outp, errors="replace") as fh:
                    for line in fh:                        # skip a torn final line from a hard crash
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        out[row["a"]] = row.get("p") or []
            except OSError:
                pass
            return out
        finally:
            shutil.rmtree(d, ignore_errors=True)


def _clean_name(n: Optional[str]) -> Optional[str]:
    """Normalise a rizin/r2 symbol name to the plain form Ghidra emits, so the detectors (which
    match clean names like 'strcpy') fire unchanged. rizin decorates names: 'sym.imp.strcpy',
    'sym.strcpy', 'dbg.bug', 'reloc.puts', trailing '_NNN', a '@plt' suffix."""
    if not n:
        return n
    for pre in ("sym.imp.", "sym.func.", "sym.", "imp.", "dbg.", "reloc.", "loc.", "flirt."):
        if n.startswith(pre):
            n = n[len(pre):]
            break
    if n.endswith("@plt"):
        n = n[:-4]
    return n


def _is_import(rawname: Optional[str]) -> bool:
    """True when a rizin symbol denotes an imported / PLT-thunk function (Ghidra marks these
    'external')."""
    r = rawname or ""
    return r.startswith(("sym.imp.", "imp.", "reloc.")) or "@plt" in r or ".plt" in r


def _langid(prog: dict) -> Optional[str]:
    arch = (prog.get("arch") or "").lower()
    bits = int(prog.get("bits") or 0)
    endian = "big" if str(prog.get("endian") or "little").lower().startswith("b") else "little"
    return _SLEIGH.get((arch, bits, endian))


_BUFFER_SLOT_MIN = int(os.environ.get("LYKOS_BUFFER_SLOT_MIN", "16") or "16")


def _infer_buffers(vars_: list) -> list:
    """Size each stack local from the gap to the next-higher local, and mark the large ones as
    buffers even when the type was not recovered as an array.

    Without a decompiler that propagates array types (rz-ghidra `pdg`), rizin types a `char[64]`
    as a plain slot, so `is_buffer` ('[' in the type) is never set and the stack-smash detector
    stays silent on exactly the stripped/undecompiled binaries that need it most -- e.g. a whole
    VxWorks kernel where 6000+ functions had stack frames but ZERO recovered buffers. A local
    occupying >= 16 bytes is the classic smashable region; the detector still only fires when such
    a slot COINCIDES with an unbounded copy in the same function, so this widens recall without
    turning every large local into a finding on its own."""
    locs = [v for v in vars_ if isinstance(v.get("offset"), int) and v["offset"] < 0]
    locs.sort(key=lambda v: v["offset"])          # most negative (furthest from frame base) first
    for i, v in enumerate(locs):
        nxt = locs[i + 1]["offset"] if i + 1 < len(locs) else 0
        slot = nxt - v["offset"]
        if slot > 0 and not v.get("size"):
            v["size"] = slot
        if slot >= _BUFFER_SLOT_MIN and not v.get("is_buffer"):
            v["is_buffer"] = True
            v["buffer_inferred"] = True           # geometry, not a recovered array type
    return vars_


def _frame_and_vars(afvj: dict) -> tuple:
    """Turn rizin/r2 afvj (reg/bp/sp variable lists) into the schema's params + frame.vars +
    geometry. is_buffer = the recovered type is an array ('[' in the type) OR a large stack slot."""
    params, vars_, local_size = [], [], 0
    for p in (afvj.get("reg") or []):
        params.append({"name": p.get("name"), "type": p.get("type"), "reg": p.get("ref")})
    for v in (afvj.get("bp") or []) + (afvj.get("sp") or []):
        ref = v.get("ref") or {}
        off = ref.get("offset") if isinstance(ref, dict) else None
        typ = v.get("type") or ""
        vars_.append({"name": v.get("name"), "type": typ, "offset": off,
                      "is_buffer": "[" in typ})
        if isinstance(off, int) and off < 0:
            local_size = max(local_size, -off)
    frame = {"frame_size": local_size, "local_size": local_size,
             "param_size": 0, "ret_offset": 0, "vars": _infer_buffers(vars_)}
    return params, frame


def _frame_vars_rizin(meta: dict) -> tuple:
    """rizin embeds variables in aflj: `stackvars` [{name, arg, type, storage:{stack:off}}] and
    `regvars`. Locals (arg=false) become frame.vars (is_buffer = array type); args become
    params. This is what the bounds detector keys on (a fixed-size stack buffer + a sink)."""
    params, vars_, local_size = [], [], 0
    for v in (meta.get("stackvars") or []):
        st = v.get("storage") or {}
        off = st.get("stack") if isinstance(st, dict) else None
        typ = v.get("type") or ""
        if v.get("arg"):
            params.append({"name": v.get("name"), "type": typ})
        else:
            vars_.append({"name": v.get("name"), "type": typ, "offset": off,
                          "is_buffer": "[" in typ})
        if isinstance(off, int) and off < 0:
            local_size = max(local_size, -off)
    for r in (meta.get("regvars") or []):
        if r.get("arg"):
            params.append({"name": r.get("name"), "type": r.get("type")})
    frame = {"frame_size": local_size, "local_size": local_size,
             "param_size": 0, "ret_offset": 0, "vars": _infer_buffers(vars_)}
    return params, frame


def _faddr(f: dict):
    """Function start address: rizin uses `offset`, radare2 6.x uses `addr`."""
    a = f.get("offset")
    return a if a is not None else f.get("addr")


def analyze(binary: Path, *, ctx=None, timeout: int = 900) -> dict:
    """Full native analysis producing the ghidra.parse_result schema, via file redirection
    (portable across rizin and radare2)."""
    # Ensure the vendored toolchain is on PATH (rizin) and pypcode is on sys.path, even when the
    # caller did not go through cli.main (tests, embeddings, a worker started directly).
    # Idempotent -- a second call is a no-op.
    try:
        from .. import vendorenv
        vendorenv.activate()
    except Exception:
        pass
    cli = locate_native()
    if cli is None:
        raise RuntimeError("no rizin/radare2 found for the native RE backend")
    binary = Path(binary)

    import tempfile
    scratch = ctx.scratch() if ctx is not None else Path(tempfile.mkdtemp(prefix="lykos-nre-"))
    T = Path(scratch) / "nre"
    T.mkdir(parents=True, exist_ok=True)

    # Pass 1: program metadata + function list + strings + imports, each redirected to a file.
    _run(cli, binary, "aaa;" + ";".join([
        _redir("ij", T / "ij"), _redir("aflj", T / "funcs"),
        _redir("izj", T / "strings"), _redir("iij", T / "imports")]),
        ctx=ctx, timeout=timeout, scratch=T)
    ij = _readj(T / "ij", {})
    binf = ij.get("bin", {}) if isinstance(ij, dict) else {}
    core = ij.get("core", {}) if isinstance(ij, dict) else {}
    prog = {
        "format": core.get("format") or binf.get("class") or "",
        "arch": binf.get("arch") or "", "bits": binf.get("bits") or 0,
        "endian": binf.get("endian") or "little",
        "compiler": binf.get("compiler") or "",
        "image_base": hex(binf.get("baddr") or 0),
    }
    prog["language"] = _langid(prog) or f'{prog["arch"]}:{prog["bits"]}'
    lifter = _Lifter(_langid(prog))

    aflj = _readj(T / "funcs", [])
    izj = _readj(T / "strings", [])
    iij = _readj(T / "imports", [])
    fn_by_addr = {_faddr(f): f for f in aflj if isinstance(f, dict) and _faddr(f) is not None}
    # EXHAUSTIVE by default: every function is analyzed. A positive LYKOS_MAX_FUNCS caps it on
    # request; 0 (the default) means no cap. The old default silently kept only the first 1200,
    # which blinded the detectors to the rest of a large program.
    total_fns = len(fn_by_addr)
    if _MAX_FUNCS and total_fns > _MAX_FUNCS:
        fn_by_addr = dict(list(fn_by_addr.items())[:_MAX_FUNCS])
        _emit(ctx, msg=f"{total_fns} functions — capped to {_MAX_FUNCS} (LYKOS_MAX_FUNCS)")
    target_fns = len(fn_by_addr)

    # rizin embeds stack vars + call refs in aflj (per function); radare2 does not, and its
    # `afvj`/`afxj` commands do -- but on rizin `afvj` is unknown and ABORTS the -c chain. So we
    # take vars/calls from aflj on rizin, and only add afvj/afxj to the pass on radare2.
    embedded = any(isinstance(f, dict) and ("stackvars" in f or "callrefs" in f) for f in aflj)

    # Pass 2 (structure): CFG + disasm + stack vars per function, redirected to per-function files.
    #
    # Two strategies, chosen by size:
    #   * small binary (<= _AAA_MAX functions): ONE analysis pass that runs whole-program `aaa`
    #     first. `aaa` propagates types (emulation), so a `char[16]` comes back typed as an array
    #     and is_buffer is set from the type -- the precise signal the bounds detector wants. Cheap
    #     at this size, and one pass is fine because it finishes quickly.
    #   * large binary (> _AAA_MAX): BATCHED per-function `af @ addr` with NO whole-program `aaa`.
    #     Pass 1 already discovered every function, so `af` (analyze just this one) is ~60x cheaper
    #     than re-running `aaa` per batch -- 500 kernel functions in ~0.5s -- and batching means the
    #     run reports progress and never loses everything (a batch that times out is skipped, its
    #     predecessors already written). `aaa`-quality types are lost, so _infer_buffers recovers
    #     buffers from stack geometry instead.
    addrs = list(fn_by_addr)
    done = 0
    failed_batches = 0

    def _reraise_if_cancel(e):
        # A cancel/timeout must PROPAGATE, not be swallowed as a "failed batch": otherwise a user
        # cancel keeps grinding through every remaining batch and the stage reports a partial
        # "done". Identified by class name to avoid importing the jobs layer into analysis code.
        if type(e).__name__ in ("StageCancelled", "StageTimeout", "KeyboardInterrupt"):
            raise e

    def _fn_cmds(a):
        parts = [f"s {a}", _redir("afbj", T / f"{a}.b"), _redir("pdfj", T / f"{a}.o")]
        if not embedded:                                  # radare2: pull vars/calls via commands
            parts.append(_redir("afvj", T / f"{a}.v"))
            parts.append(_redir("afxj", T / f"{a}.x"))
        return parts

    if target_fns <= _AAA_MAX:
        parts = ["aaa"]
        for a in addrs:
            parts += _fn_cmds(a)
        try:
            _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)
        except Exception as e:                            # noqa: BLE001
            _reraise_if_cancel(e)
            failed_batches += 1
            _emit(ctx, msg=f"structural pass did not finish ({type(e).__name__}); "
                           f"building the functions that were written")
        _emit(ctx, pct=75, msg=f"disassembled {target_fns} functions")
    else:
        for i in range(0, len(addrs), _BATCH):
            if ctx is not None:
                ctx.check_cancel()                        # honor a cancel/timeout between batches
            chunk = addrs[i:i + _BATCH]
            parts = []
            for a in chunk:
                parts.append(f"af @ {a}")
                parts += _fn_cmds(a)
            try:
                _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)
            except Exception as e:                        # noqa: BLE001 -- one batch, not the run
                _reraise_if_cancel(e)
                failed_batches += 1
                _emit(ctx, msg=f"disassembly batch {i // _BATCH + 1} did not finish "
                               f"({type(e).__name__}); keeping the {done} functions already done")
            done += len(chunk)
            pct = 5 + int(70 * done / max(1, target_fns))  # 5..75% is the structural pass
            _emit(ctx, pct=min(75, pct),
                  msg=f"disassembled {min(done, target_fns)}/{target_fns} functions")

    # Pass 3 (decompile): advisory C, the slowest step. We decompile only up to _MAX_DECOMPILE up
    # front (small binaries come back fully decompiled); every other function decompiles lazily on
    # demand when opened (see the /functions/{id} endpoint), so nothing is permanently skipped and a
    # big binary is not held up for minutes producing C that the detectors never read.
    if _MAX_DECOMPILE and target_fns <= _MAX_DECOMPILE:
        dec_cmd = "pdg" if _has_pdg(cli, binary, ctx, timeout) else "pdc"
        dparts = ["aaa"]
        for a in addrs:
            dparts.append(f"s {a}")
            dparts.append(_redir(dec_cmd, T / f"{a}.d"))
        try:
            _run(cli, binary, ";".join(dparts), ctx=ctx, timeout=timeout, scratch=T)
        except Exception:
            pass
    elif target_fns > _MAX_DECOMPILE:
        _emit(ctx, pct=78, msg=f"decompiled C is on-demand for {target_fns} functions "
                               f"(opens decompile the function you click; detectors use P-Code)")

    _emit(ctx, pct=80, msg=f"lifting P-Code for {target_fns} functions")
    functions = _build_functions(T, fn_by_addr, lifter, embedded, ctx=ctx, timeout=timeout)
    strings = _build_strings(cli, binary, izj, T, ctx=ctx, timeout=timeout)
    imports = [i.get("name") for i in iij if isinstance(i, dict) and i.get("name")]

    return {"program": prog, "function_count": len(functions),
            "functions": functions, "strings": strings, "imports": imports,
            # honest bookkeeping: how complete this analysis is, surfaced by the stage.
            "total_functions": total_fns, "analyzed_functions": len(functions),
            "partial": bool(failed_batches) or (_MAX_FUNCS and total_fns > _MAX_FUNCS),
            "failed_batches": failed_batches}


def decompile_one(binary: Path, addr, *, ctx=None, timeout: int = 120) -> str:
    """Decompile a SINGLE function on demand and return its C (or "" if unavailable).

    The disassemble stage decompiles only a bounded number of functions up front (decompiling
    thousands would take minutes and mostly go unread), so the /functions/{id} endpoint calls this
    to decompile the one function an analyst actually opened, then caches the result on the row.
    Uses `af @ addr` -- no whole-program analysis -- so it is fast even on a huge binary."""
    try:
        cli = locate_native()
    except Exception:
        cli = None
    if cli is None or addr is None:
        return ""
    a = int(addr, 16) if isinstance(addr, str) and addr.lower().startswith("0x") \
        else int(addr) if isinstance(addr, str) else addr
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="lykos-dec1-"))
    try:
        dec_cmd = "pdg" if _has_pdg(cli, Path(binary), ctx, timeout) else "pdc"
        out = d / "d"
        script = f"af @ {a};s {a};" + _redir(dec_cmd, out)
        _run(cli, Path(binary), script, ctx=ctx, timeout=timeout, scratch=d)
        try:
            return _decompiled(out.read_text(errors="replace"))
        except OSError:
            return ""
    except Exception:
        return ""
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _has_pdg(cli: Path, binary: Path, ctx, timeout: int) -> bool:
    """Is the Ghidra decompiler (rz-ghidra `pdg`) available? Probe by redirecting its help to a
    file: rz-ghidra prints usage; a rizin/r2 without it writes nothing (and, unlike a chained
    command, a lone unknown command is harmless)."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="lykos-pdg-"))
    try:
        _run(cli, binary, _redir("pdg?", d / "p"), ctx=None, timeout=min(timeout, 60))
        try:
            txt = (d / "p").read_text(errors="replace")
        except OSError:
            return False
        # A tool WITHOUT the decompiler answers `pdg?` with an install/error message, which is
        # non-empty -- so "any output" wrongly reported it present and the error text got stored
        # as the decompilation. Require real usage text and reject the known "install me" reply.
        if _is_missing_decompiler(txt):
            return False
        return "pdg" in txt.lower() or len(txt.strip()) > 8
    except Exception:
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _is_missing_decompiler(txt: str) -> bool:
    """The reply a tool gives for `pdg` when rz-ghidra / r2ghidra is not installed."""
    t = (txt or "").lower()
    return ("r2pm" in t or "rz-pm" in t or "install the plugin" in t
            or "you need to install" in t or "unknown command" in t or "cannot find" in t)


def _build_functions(T: Path, fn_by_addr: dict, lifter: "_Lifter", embedded: bool,
                     ctx=None, timeout: int = 600) -> list:
    functions = []
    # P-Code is lifted OUT OF PROCESS (pypcode can crash on some encodings), so we first build every
    # function with empty pcode while collecting the instruction bytes, then lift them all in one
    # child and fill the results in. `pending` holds (addr, ins_dict) so the fill is a dict lookup.
    to_lift = {}                                             # addr_int -> hexbytes (deduped)
    pending = []                                             # (addr_int, ins_dict) to fill
    for faddr, meta in fn_by_addr.items():
        afbj = _readj(T / f"{faddr}.b", [])
        pdfj = _readj(T / f"{faddr}.o", {})
        afvj = _readj(T / f"{faddr}.v", {})
        afxj = _readj(T / f"{faddr}.x", [])
        try:
            decompiled = _decompiled((T / f"{faddr}.d").read_text(errors="replace"))
        except OSError:
            decompiled = ""

        ops = pdfj.get("ops", []) if isinstance(pdfj, dict) else \
            (pdfj if isinstance(pdfj, list) else [])
        ins_by_addr = {}
        for o in ops:
            a = o.get("offset") if o.get("offset") is not None else o.get("addr")  # rizin|r2
            if a is None or o.get("type") == "invalid":
                continue
            hexb = o.get("bytes", "") or ""
            ins = {"addr": hex(a), "text": o.get("disasm") or o.get("opcode") or "", "pcode": []}
            ins_by_addr[a] = ins
            if hexb:
                to_lift[a] = hexb
                pending.append((a, ins))

        blocks, edges = [], 0
        for b in (afbj if isinstance(afbj, list) else []):
            baddr = b.get("addr")
            bsize = b.get("size") or 0
            insns = [ins_by_addr[a] for a in sorted(ins_by_addr)
                     if baddr is not None and baddr <= a < baddr + bsize]
            succ = [hex(s) for s in (b.get("jump"), b.get("fail")) if isinstance(s, int)]
            edges += len(succ)
            blocks.append({"addr": hex(baddr) if isinstance(baddr, int) else str(baddr),
                           "succ": succ, "instructions": insns})

        # vars + calls: from aflj-embedded fields on rizin, from afvj/afxj files on radare2.
        if embedded:
            params, frame = _frame_vars_rizin(meta)
            callrefs = meta.get("callrefs") or []
        else:
            params, frame = _frame_and_vars(afvj)
            callrefs = afxj if isinstance(afxj, list) else []
        calls = []
        for c in callrefs:
            if (c.get("type") or "").upper() not in ("CALL", "CCALL", "UCALL"):
                continue
            dst = c.get("to")
            raw = (fn_by_addr.get(dst) or {}).get("name")
            frm = c.get("from")
            calls.append({
                "site_addr": hex(frm) if isinstance(frm, int) else None,
                          "dst_addr": hex(dst) if isinstance(dst, int) else None,
                          "dst_name": _clean_name(raw),
                          "external": _is_import(raw)})

        functions.append({
            "addr": hex(faddr), "name": _clean_name(meta.get("name")) or f"fcn.{faddr:x}",
            "size": meta.get("size") or 0, "signature": meta.get("signature") or "",
            "calling_convention": meta.get("cc") or meta.get("calltype") or "",
            "thunk": bool(meta.get("is-pure") or meta.get("is_pure")),
            "varargs": False, "decompiled": decompiled,
            "blocks": len(blocks), "edges": edges,
            "cfg": {"blocks": blocks, "edges": edges},
            "params": params, "frame": frame, "calls": calls,
        })

    # Lift every instruction's P-Code in ONE isolated child, then fill it into the built functions.
    if to_lift:
        _emit(ctx, msg=f"lifting P-Code for {len(to_lift)} instructions (isolated)")
        pcode_map = lifter.lift_all(sorted(to_lift.items()), ctx=ctx, timeout=timeout)
        for a, ins in pending:
            ops = pcode_map.get(hex(a))
            if ops:
                ins["pcode"] = ops
    return functions


import re as _re
_ANSI = _re.compile(r"\x1b\[[0-9;]*m")


def _decompiled(text: str) -> str:
    """pdg emits C directly; pdc emits pseudo-C. Return whichever, trimmed and with the terminal
    colour codes pdc leaves in stripped -- but never the tool's "install the decompiler" reply,
    which is not source and should read as 'none'."""
    t = _ANSI.sub("", text or "").strip()
    return "" if (not t or _is_missing_decompiler(t)) else t


def _build_strings(cli: Path, binary: Path, izj, T: Path, *, ctx, timeout) -> list:
    """Strings + their xref sites (axtj per string address), each redirected to a file."""
    strings = []
    addrs = [s.get("vaddr") for s in (izj if isinstance(izj, list) else [])
             if isinstance(s, dict) and isinstance(s.get("vaddr"), int)][:_MAX_STRING_XREFS]
    xrefs_by_addr = {}
    if addrs:
        parts = ["aaa"]
        for a in addrs:
            parts.append(f"s {a}")
            parts.append(_redir("axtj", T / f"x_{a}"))
        _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)
        for a in addrs:
            xj = _readj(T / f"x_{a}", [])
            xrefs_by_addr[a] = [hex(x.get("from")) for x in (xj if isinstance(xj, list) else [])
                                if isinstance(x, dict) and isinstance(x.get("from"), int)]
    for s in (izj if isinstance(izj, list) else []):
        va = s.get("vaddr")
        strings.append({"addr": hex(va) if isinstance(va, int) else "",
                        "value": s.get("string") or "",
                        "xrefs": xrefs_by_addr.get(va, [])})
    return strings
