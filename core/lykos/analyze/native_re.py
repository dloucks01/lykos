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
from pathlib import Path
from typing import Optional

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


class _Lifter:
    """Per-instruction Ghidra P-Code via pypcode (SLEIGH, no JVM). Falls back to empty pcode
    when pypcode is absent or the language is unmapped -- structure/decompile still work."""

    def __init__(self, langid: Optional[str]):
        self.ctx = None
        if not langid:
            return
        try:
            import pypcode
            self.pypcode = pypcode
            self.ctx = pypcode.Context(langid)
        except Exception:
            self.ctx = None

    def pcode(self, raw: bytes, addr: int) -> list:
        if self.ctx is None or not raw:
            return []
        try:
            tx = self.ctx.translate(raw, base_address=addr, max_instructions=1)
        except Exception:
            return []
        ops = []
        for op in tx.ops:
            if op.opcode.name == "IMARK":
                continue
            s = op.opcode.name
            for vin in op.inputs:
                s += " " + _vn(self.ctx, vin)
            if op.output is not None:
                s += " -> " + _vn(self.ctx, op.output)
            ops.append(s)
        return ops


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


def _frame_and_vars(afvj: dict) -> tuple:
    """Turn rizin/r2 afvj (reg/bp/sp variable lists) into the schema's params + frame.vars +
    geometry. is_buffer = the recovered type is an array ('[' in the type)."""
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
             "param_size": 0, "ret_offset": 0, "vars": vars_}
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
             "param_size": 0, "ret_offset": 0, "vars": vars_}
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

    # rizin embeds stack vars + call refs in aflj (per function); radare2 does not, and its
    # `afvj`/`afxj` commands do -- but on rizin `afvj` is unknown and ABORTS the -c chain. So we
    # take vars/calls from aflj on rizin, and only add afvj/afxj to the pass on radare2.
    embedded = any(isinstance(f, dict) and ("stackvars" in f or "callrefs" in f) for f in aflj)

    # Pass 2 (structure): CFG + disasm per function, redirected to per-function files.
    parts = ["aaa"]
    for a in fn_by_addr:
        parts.append(f"s {a}")
        parts.append(_redir("afbj", T / f"{a}.b"))
        parts.append(_redir("pdfj", T / f"{a}.o"))
        if not embedded:                                  # radare2: pull vars/calls via commands
            parts.append(_redir("afvj", T / f"{a}.v"))
            parts.append(_redir("afxj", T / f"{a}.x"))
    _run(cli, binary, ";".join(parts), ctx=ctx, timeout=timeout, scratch=T)

    # Pass 3 (decompile): a SEPARATE run so an empty/failed decompiler cannot abort the
    # structural pass. Decompiled C is advisory (the detectors use the pypcode P-Code); it is
    # fine for this to come back empty (e.g. rz-ghidra not wired for `pdg`).
    dec_cmd = "pdg" if _has_pdg(cli, binary, ctx, timeout) else "pdc"
    dparts = ["aaa"]
    for a in fn_by_addr:
        dparts.append(f"s {a}")
        dparts.append(_redir(dec_cmd, T / f"{a}.d"))
    try:
        _run(cli, binary, ";".join(dparts), ctx=ctx, timeout=timeout, scratch=T)
    except Exception:
        pass

    functions = _build_functions(T, fn_by_addr, lifter, embedded)
    strings = _build_strings(cli, binary, izj, T, ctx=ctx, timeout=timeout)
    imports = [i.get("name") for i in iij if isinstance(i, dict) and i.get("name")]

    return {"program": prog, "function_count": len(functions),
            "functions": functions, "strings": strings, "imports": imports}


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


def _build_functions(T: Path, fn_by_addr: dict, lifter: "_Lifter", embedded: bool) -> list:
    functions = []
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
            raw = bytes.fromhex(o.get("bytes", "")) if o.get("bytes") else b""
            ins_by_addr[a] = {"addr": hex(a), "text": o.get("disasm") or o.get("opcode") or "",
                              "pcode": lifter.pcode(raw, a)}

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
             if isinstance(s, dict) and isinstance(s.get("vaddr"), int)]
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
