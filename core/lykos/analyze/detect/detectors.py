"""Deterministic CWE detectors + call-graph reachability correlation.

A detector is `fn(DetectContext) -> list[candidate dict]`. `correlate()` is a post-pass that
promotes candidates when a second channel agrees (the confidence lifecycle, doc 05). This
first cut ships: dangerous-API sinks (rule), hard-coded secrets (string), and input->sink
reachability over the call graph (an approximate taint channel).
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .catalog import ADVISORY, DANGEROUS, SOURCES, normalize

DETECTORS = []


def register_detector(fn):
    DETECTORS.append(fn)
    return fn


@dataclass
class DetectContext:
    target_id: str
    case_id: str
    call_edges: list                 # list[CallEdge]
    strings: list                    # list[StringRef]
    functions: list = field(default_factory=list)
    mitigations: dict = field(default_factory=dict)   # target's mitigation flags (triage)
    frames: dict = field(default_factory=dict)        # func addr -> stack frame (from decompiler)
    func_irs: dict = field(default_factory=dict)      # func addr -> IR {blocks,edges} (call-site disasm)
    bits: int = 0                                     # target word size (32/64), for arg-passing ABI
    arch: str = "x86"                                 # target arch; the CWE-121 dest gate is x86-only
    toolchain: str = ""                               # source language / toolchain (go, rust, c++, ...)
    # zero-arg callable returning the target's bytes (or None). Read lazily, only by detectors that
    # need a constant from the image (a rodata format string, a global array's st_size).
    image: object = None
    cache: dict = field(default_factory=dict)         # per-run memo for the image-derived views


def _image_sections(ctx: "DetectContext") -> list:
    """The target's ELF section headers (with the bytes) -- [] when there is no readable ELF image.
    Memoised on the context."""
    if "sections" not in ctx.cache:
        secs, data = [], None
        try:
            data = ctx.image() if callable(ctx.image) else None
            if data and data[:4] == b"\x7fELF":
                from ..elf import _raw_sections
                secs = _raw_sections(data, data[4] == 2, "<" if data[5] == 1 else ">")
        except Exception:                                 # noqa: BLE001 -- degenerate image
            secs = []
        ctx.cache["sections"] = (secs, data)
    return ctx.cache["sections"]


def _rodata_cstr(ctx: "DetectContext", vaddr, limit: int = 512):
    """The NUL-terminated string at virtual address `vaddr` in an allocated, file-backed section of
    the image (`.rodata` et al.), or None. Lets a short literal the string extractor skipped (a
    two-byte `%d`) still be read where the code references it."""
    v = _naddr(vaddr)
    if v is None:
        return None
    secs, data = _image_sections(ctx)
    for sec in secs:
        # SHF_ALLOC and not SHT_NOBITS (.bss has no bytes in the file)
        if not (sec["flags"] & 2) or sec["type"] == 8 or not sec["addr"]:
            continue
        if sec["addr"] <= v < sec["addr"] + sec["size"]:
            off = sec["offset"] + (v - sec["addr"])
            end = data.find(b"\x00", off, min(len(data), off + limit))
            if end < 0:
                return None
            try:
                return data[off:end].decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


def _global_objects(ctx: "DetectContext") -> dict:
    """{name: (vaddr, st_size)} for the image's OBJECT symbols -- the exact extent of a global array
    (a compile-time fact from the symbol table, unlike a recovered stack frame). {} when stripped."""
    if "objects" not in ctx.cache:
        objs = {}
        try:
            _secs, data = _image_sections(ctx)
            if data:
                from ..poc.exploit import elf_objects_sized
                objs = elf_objects_sized(data) or {}
        except Exception:                                 # noqa: BLE001
            objs = {}
        ctx.cache["objects"] = objs
    return ctx.cache["objects"]


def _cand(cwe, title, severity, detector, evidence, *, function_addr=None,
          site_addr=None, dedup_key, state="candidate", confidence=0.4, site_detail=None):
    """One OCCURRENCE of a defect.

    `dedup_key` names the defect, not the place: occurrences sharing a key merge into one
    finding and each contributes a site. Keying on the address made every call site its own
    finding, so the count tracked compiler inlining -- the same program at -O0 produced 230
    findings where the distro build produced 27.
    """
    return {"cwe": cwe, "title": title, "severity": severity, "detector": detector,
            "evidence": list(evidence), "function_addr": function_addr,
            "site_addr": site_addr, "dedup_key": dedup_key, "state": state,
            "confidence": confidence, "site_detail": site_detail}


# ------------------------------------------------------------- dangerous-API sinks (rule)
@register_detector
def dangerous_api(ctx: DetectContext):
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        if n not in DANGEROUS:
            continue
        cwe, sev, desc = DANGEROUS[n]
        cand = _cand(
            cwe, f"{desc}", sev, "dangerous_api",
            [{"channel": "pattern", "detail": f"call to {n}() at {e.site_addr}"}],
            function_addr=e.src_addr, site_addr=e.site_addr,
            dedup_key=f"{cwe}:dangerous_api:{n}",
            confidence=0.4)
        cand["api"] = n
        out.append(cand)
    return out


# High-signal dangerous sinks whose mere IMPORT by a PE is worth reporting: command/process
# execution, unbounded string copies, and file download. Low-signal I/O (memcpy/malloc/open/printf)
# is NOT flagged on import -- it needs a call site + taint to be a defect, and every PE imports it,
# so flagging the import would be noise. These are the defect-by-presence sinks.
_PE_IMPORT_SINKS = frozenset({
    "system", "popen", "execve", "execl", "execlp", "execvp",
    "WinExec", "_wsystem", "CreateProcessA", "CreateProcessW", "CreateProcessAsUserW",
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "wsprintfA", "wsprintfW", "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
    "StrCpyA", "StrCpyW", "StrCatW", "wcscpy", "wcscat",
    "URLDownloadToFileA", "URLDownloadToFileW",
})


@register_detector
def windows_dangerous_imports(ctx: DetectContext):
    """A PE's dangerous Win32/CRT imports (`dangerous_api`'s static twin for Windows). rizin does not
    resolve a PE's IAT thunks into named call edges, so `dangerous_api` -- which keys on the call
    graph -- misses `WinExec`/`wsprintf`/`ShellExecute`/... on a PE even though the import plainly
    says the program CAN call them. This reads the import table straight from the image (via `pe.parse`)
    and files each high-signal sink import as an honest CANDIDATE (same posture + dedup key as
    `dangerous_api`, so an API that IS resolved to a call edge collapses to one finding). ELF/other
    formats return nothing (the call-graph path already covers them)."""
    data = ctx.image() if callable(getattr(ctx, "image", None)) else None
    if not data or data[:2] != b"MZ":                     # PE only; ELF is covered by dangerous_api
        return []
    try:
        from ..pe import parse as _pe_parse
        syms = (_pe_parse(data).imports or {}).get("symbols") or []
    except Exception:                                     # noqa: BLE001 -- a malformed PE: no imports
        return []
    out, seen = [], set()
    for sym in syms:
        n = normalize(sym)
        if n not in _PE_IMPORT_SINKS or n in seen:
            continue
        seen.add(n)
        cwe, sev, desc = DANGEROUS[n]
        cand = _cand(
            cwe, desc, sev, "windows_dangerous_imports",
            [{"channel": "pattern", "detail": f"PE imports {n}() (dangerous Win32/CRT sink)"}],
            dedup_key=f"{cwe}:dangerous_api:{n}", confidence=0.4)
        cand["api"] = n
        out.append(cand)
    return out


# -------------------------------------------------- Go / Rust language-aware sinks (call-graph)
# Go and Rust are memory-safe, so their bugs are not overflows but INJECTION / TRAVERSAL / SSRF
# through the standard library: a runtime command, path, SQL query or URL built from untrusted
# input. The C data-flow taint does not apply (different ABI/runtime), but the call graph does --
# retained package.function symbols name the sink and the source. Flag the sink, and corroborate
# when an untrusted-input source reaches it over the call graph. Substring-matched against the
# recovered names (rizin renders `os/exec.Command` as `os_exec.Command`, etc.).
_GO_SINKS = (
    ("exec.Command", "CWE-78", "high", "OS command execution (os/exec.Command) with a runtime argument"),
    ("exec.CommandContext", "CWE-78", "high", "OS command execution (os/exec.CommandContext)"),
    ("os.StartProcess", "CWE-78", "high", "process execution with a runtime path"),
    ("syscall.Exec", "CWE-78", "high", "syscall.Exec with a runtime path"),
    ("os.OpenFile", "CWE-22", "medium", "file open with a runtime path"),
    ("os.Open", "CWE-22", "medium", "file open with a runtime path"),
    ("os.ReadFile", "CWE-22", "medium", "file read with a runtime path"),
    ("os.Create", "CWE-22", "medium", "file create with a runtime path"),
    ("os.Remove", "CWE-22", "medium", "file remove with a runtime path"),
    ("ioutil.ReadFile", "CWE-22", "medium", "file read with a runtime path"),
    ("sql._DB_.Query", "CWE-89", "high", "SQL query built at runtime"),
    ("sql._DB_.Exec", "CWE-89", "high", "SQL statement built at runtime"),
    ("sql._DB_.QueryRow", "CWE-89", "high", "SQL query built at runtime"),
    ("http.Get", "CWE-918", "medium", "outbound HTTP request to a runtime URL (SSRF)"),
    ("http.Post", "CWE-918", "medium", "outbound HTTP request to a runtime URL (SSRF)"),
    ("template.HTML", "CWE-79", "medium", "unescaped HTML from a runtime value (XSS)"),
)
# Rust std symbols (current rizin renders `::`, e.g. `std::sys::process::unix::common::Command::spawn`;
# older builds rendered `..`). The command sinks are the EXECUTION methods -- spawn / do_exec / output
# / status -- not `Command::new`, because the clap arg-parser also has a `Command::new` that never
# execs, so keying on construction would be a false candidate. Match both separators to survive the
# rizin rendering change.
_RUST_SINKS = (
    # The exec/spawn methods are rendered either directly (`...common::Command::spawn`) or through the
    # trait-impl form (`_<impl ...Command>::do_exec`), which inserts a `>` before `::` -- match both.
    ("Command::spawn", "CWE-78", "high", "OS command execution (std::process::Command::spawn)"),
    ("Command>::spawn", "CWE-78", "high", "OS command execution (std::process::Command::spawn)"),
    ("Command..spawn", "CWE-78", "high", "OS command execution (std::process::Command::spawn)"),
    ("Command::do_exec", "CWE-78", "high", "OS command execution (std::process::Command exec)"),
    ("Command>::do_exec", "CWE-78", "high", "OS command execution (std::process::Command exec)"),
    ("Command..do_exec", "CWE-78", "high", "OS command execution (std::process::Command exec)"),
    ("Command::output", "CWE-78", "high", "OS command execution (std::process::Command::output)"),
    ("Command>::output", "CWE-78", "high", "OS command execution (std::process::Command::output)"),
    ("Command::status", "CWE-78", "high", "OS command execution (std::process::Command::status)"),
    ("Command>::status", "CWE-78", "high", "OS command execution (std::process::Command::status)"),
    ("fs::read", "CWE-22", "medium", "file read with a runtime path (std::fs)"),
    ("fs..read", "CWE-22", "medium", "file read with a runtime path (std::fs)"),
    ("File::open", "CWE-22", "medium", "file open with a runtime path (std::fs::File)"),
    ("File..open", "CWE-22", "medium", "file open with a runtime path (std::fs::File)"),
    ("File::create", "CWE-22", "medium", "file create with a runtime path"),
    ("File..create", "CWE-22", "medium", "file create with a runtime path"),
)
# Untrusted-input sources (call-graph reachability). Go: argv/env/flags, stdin readers, HTTP req.
_GO_SOURCES = ("os.Args", "os.Getenv", "flag._FlagSet_", "bufio._Reader_.Read", "bufio._Scanner_.",
               "http._Request_", "ioutil.ReadAll", "io.ReadAll", "os.Stdin")
_RUST_SOURCES = ("env::args", "env..args", "env::var", "env..var", "io::stdin", "io..stdin",
                 "read_line", "read_to_string")
#: a Rust binary's call graph is unmistakable -- symbols carry the `::h<16 hex>` mangling hash, and
#: the panic runtime (`rust_begin_unwind` / `core::panicking`) is always linked. Used to recognise a
#: Rust target when triage did not record the toolchain (it often does not for a static Rust ELF).
_RUST_SIG = re.compile(r"::h[0-9a-f]{16}\b")


@register_detector
def lang_sinks(ctx: DetectContext):
    tc = (ctx.toolchain or "").lower()
    # detect language from the toolchain hint, or fall back to the call graph (Go has runtime.*;
    # Rust carries the `::h<hex>` symbol mangling and the panic runtime). The fallback matters: a
    # static Rust/Go ELF often reaches detect with no recorded toolchain, and without it lang_sinks
    # silently returned nothing on exactly the native-service binaries it exists for.
    is_go = tc == "go" or any("runtime." in (e.dst_name or "") for e in ctx.call_edges)
    is_rust = not is_go and (tc == "rust" or any(
        ("rust_begin_unwind" in (e.dst_name or "") or "core::panicking" in (e.dst_name or "")
         or _RUST_SIG.search(e.dst_name or "")) for e in ctx.call_edges))
    if not (is_go or is_rust):
        return []
    sinks = _GO_SINKS if is_go else _RUST_SINKS
    sources = _GO_SOURCES if is_go else _RUST_SOURCES

    def _hit(name, needles):
        n = name or ""
        return any(k in n for k in needles)
    src_fns = {e.src_addr for e in ctx.call_edges if _hit(e.dst_name, sources)}
    callers = defaultdict(set)
    for e in ctx.call_edges:
        if e.dst_addr:
            callers[e.dst_addr].add(e.src_addr)
    lang = "go" if is_go else "rust"
    out, seen = [], set()
    for e in ctx.call_edges:
        hit = next(((cwe, sev, desc) for pat, cwe, sev, desc in sinks
                    if e.dst_name and pat in e.dst_name), None)
        if not hit:
            continue
        cwe, sev, desc = hit
        reachable = e.src_addr is not None and reaches_within(e.src_addr, src_fns, callers)
        key = (cwe, e.dst_name, e.src_addr)
        if key in seen:
            continue
        seen.add(key)
        cand = _cand(
            cwe, f"{desc} ({lang})", sev, "lang_sinks",
            [{"channel": "pattern", "detail": f"{lang} sink {e.dst_name}() at {e.site_addr}"}]
            + ([{"channel": "taint-reachability",
                 "detail": "untrusted input reaches this sink (call graph)"}] if reachable else []),
            function_addr=e.src_addr, site_addr=e.site_addr,
            dedup_key=f"{cwe}:lang_sinks:{e.dst_name}",
            state="corroborated" if reachable else "candidate",
            confidence=0.7 if reachable else 0.4)
        out.append(cand)
    return out


# ---------------------------------------------------------- TOCTOU race (check-then-use on a path)
# The classic time-of-check-to-time-of-use: the program tests a filesystem path (access/stat) and
# then, believing the answer still holds, operates on it (open/unlink/exec/chmod...). Between the two
# calls an attacker can swap the path (a symlink race), so the operation hits a different file than
# the one that was checked -- a privilege/authorisation bypass (CWE-367). Detected purely from the
# ORDER of calls within a function: a check followed by a later use. Kept low-confidence (the pair is
# sometimes benign) and one per function, so it is reviewable inventory, not an assertion.
_TOCTOU_CHECK = {"access", "faccessat", "faccessat2", "euidaccess", "eaccess",
                 "stat", "lstat", "stat64", "lstat64", "fstatat", "newfstatat", "__xstat", "__lxstat"}
_TOCTOU_USE = {"open", "open64", "openat", "fopen", "fopen64", "freopen", "creat", "creat64",
               "unlink", "unlinkat", "remove", "rename", "renameat", "chmod", "fchmodat", "lchmod",
               "chown", "lchown", "fchownat", "mkdir", "rmdir", "symlink", "link", "truncate",
               "execve", "execl", "execlp", "execv", "execvp", "system", "mount"}


@register_detector
def toctou_race(ctx: DetectContext):
    by_fn = {}
    for e in ctx.call_edges:
        by_fn.setdefault(e.src_addr, []).append(e)
    out = []
    for fn, edges in by_fn.items():
        edges = sorted(edges, key=lambda e: _naddr(e.site_addr) or 0)
        for chk in (e for e in edges if normalize(e.dst_name) in _TOCTOU_CHECK):
            ca = _naddr(chk.site_addr) or 0
            use = next((e for e in edges if normalize(e.dst_name) in _TOCTOU_USE
                        and (_naddr(e.site_addr) or 0) > ca), None)
            if use:
                c, u = normalize(chk.dst_name), normalize(use.dst_name)
                out.append(_cand(
                    "CWE-367", "TOCTOU race: a path is checked, then used", "medium", "toctou_race",
                    [{"channel": "pattern", "detail": f"{c}() at {chk.site_addr} then {u}() at "
                      f"{use.site_addr} -- the file can be swapped (symlink race) in between"}],
                    function_addr=fn, site_addr=chk.site_addr,
                    dedup_key=f"CWE-367:toctou:{c}->{u}", confidence=0.35))
                break                                  # one per function is enough
    return out


# ------------------------------- stack buffer overflow (decompiler stack-frame + unbounded copy)
# Copies with no length bound; a fixed stack buffer + one of these is the classic smash.
_UNBOUNDED_COPY = {"strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf", "sscanf"}
# A scanf string conversion (%s / %[...]); _SCANF_UNBOUNDED is the WIDTHLESS (dangerous) subset --
# `%s`/`%ls`/`%[` with no width, but not `%16s`. Drops the width-bounded-scanf false positive.
_SCANF_CONV = re.compile(r"%\*?\d*[hlLjztq]*[s\[]")
_SCANF_UNBOUNDED = re.compile(r"%\*?(?![\d])[hlLjztq]*[s\[]")
# The subset whose DESTINATION buffer is the first argument -- the only ones the destination gate
# can reason about. scanf/sscanf take the buffer as a later variadic argument (arg0 is the format
# string), so the gate must not run on them.
_ARG0_DEST = {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}

# For CWE-121 we require the copy's DESTINATION to actually be the stack frame. Without this a
# function that owns any stack buffer AND calls strcpy is flagged even when the strcpy writes to a
# caller-provided/heap pointer -- e.g. VxWorks _hostTblSearchByName2 copies into a 64-byte slot it
# sub-allocates from a caller buffer, not its stack, yet was reported as a 16-byte stack smash.


def _naddr(a):
    if a is None:
        return None
    if isinstance(a, int):
        return a
    s = str(a)
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _as_int(v, default=None):
    """An int from a decompiler field that may arrive as an int, a decimal / hex string (`"-0x10"`),
    or None. `default` when it is none of those -- a degenerate frame record must not sink a
    whole detector (the stage drops a detector that raises, which files nothing for the target)."""
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 0)
    except (TypeError, ValueError):
        return default


def _blocks_of(ir):
    """The IR's blocks that are well-formed dicts (an IR may be None or carry a junk block)."""
    return [b for b in ((ir or {}).get("blocks") or []) if isinstance(b, dict)]


def _frame_vars(frame):
    """(offset -> size, name -> offset) for a decompiler frame, skipping records whose offset is
    unreadable."""
    vsize, names = {}, {}
    for v in ((frame or {}).get("vars") or []):
        if not isinstance(v, dict):
            continue
        off = _as_int(v.get("offset"))
        if off is None:
            continue
        vsize[off] = _as_int(v.get("size"), 0) or 0
        if v.get("name"):
            names[v["name"]] = off
    return vsize, names


# a memory operand naming the ADDRESS OF a stack local. The stack pointer (esp/rsp/sp) is always
# the frame; a frame pointer (ebp/rbp/x29) counts only with a NEGATIVE displacement (a positive one
# is an incoming argument at rbp+8...). An index register is allowed, so `[rbp + rcx - 0x20]`
# (&buf[i], common at -O2) still reads as stack -- the earlier `rbp\s*-` form missed it.
_STACK_MEM = re.compile(r"\[[^\]]*(?:"
                        r"\bvar_[0-9a-fh]+\b"                     # rizin-named local
                        r"|\b(?:esp|rsp|sp)\b"                    # stack pointer -> always the frame
                        # frame pointer minus an offset (a local); r2 renders small offsets in
                        # DECIMAL (`[rbp - 8]`) and larger ones in hex (`[rbp - 0x50]`), so accept
                        # both -- requiring 0x silently missed every buffer within 15 bytes of rbp.
                        r"|\b(?:ebp|rbp|x29|w29|fp)\b[^\]]*-\s*(?:#\s*)?(?:0x[0-9a-f]+|\d+)"
                        r")", re.I)
_DEST_REG64 = "rdi"                                   # SysV first integer arg
_X86_REGS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
             "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
# every x86-64 register view -> its full 64-bit register (`eax`/`ax`/`al` -> `rax`, `r8d` -> `r8`)
_X86_CANON = {}
for _q, _d, _w, _b in (("rax", "eax", "ax", "al"), ("rbx", "ebx", "bx", "bl"),
                       ("rcx", "ecx", "cx", "cl"), ("rdx", "edx", "dx", "dl"),
                       ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
                       ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl")):
    for _a in (_q, _d, _w, _b):
        _X86_CANON[_a] = _q
for _n in range(8, 16):
    for _a in (f"r{_n}", f"r{_n}d", f"r{_n}w", f"r{_n}b"):
        _X86_CANON[_a] = f"r{_n}"


def _x86_aliases(reg: str) -> set:
    c = _X86_CANON.get((reg or "").lower())
    return {a for a, q in _X86_CANON.items() if q == c} if c else {reg}
_ARITH = re.compile(r"\s*(add|sub|xor|and|or|imul|mul|shl|shr|sar|neg|inc|dec|lea)\s+", re.I)


def _lea_target_is_stack(rhs: str) -> bool:
    """True when `lea reg, <rhs>` takes the address of a stack local. `_STACK_MEM` covers the
    register-relative (`[rbp - 0x10]`, `[rsp + ..]`) and generic `var_NNNh` forms; this ALSO accepts
    rizin's *named* locals. rizin labels recovered locals semantically -- `[va_args]`, `[src]`,
    `[dest]`, `[canary]` -- not only as `var_NNNh`, whereas r2 keeps them register-relative
    (`[rbp - 0x410]`); missing the named form silently dropped every stack-overflow site on the
    rizin backend the packages actually ship (r2, used in dev, hid it). A bracketed BARE identifier
    -- no `obj.`/`sym.`/`str.`/`reloc.`/... namespace (globals always carry one) and not a register
    (a register deref is a pointer value, not &frame) -- is such a local. Both exclusions err toward
    NOT adding stack, so this only ever widens recognition; it never turns a global into a finding."""
    if _STACK_MEM.search(rhs):
        return True
    m = re.search(r"\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]", rhs)
    return bool(m and "." not in rhs and m.group(1).lower() not in _X86_REGS)


def _mem_inner(rhs: str):
    m = re.search(r"\[([^\]]+)\]", rhs)
    return re.sub(r"\s+", "", m.group(1)).lower() if m else None


def _slot_store_class(texts, upto: int, inner: str) -> str:
    """A pointer was loaded from memory slot `inner` (`mov reg, [slot]`). Classify what was STORED
    there: ONLY a spilled stack address (`lea r,[buf]; mov [slot], r`) yields 'stack'. Anything else
    -- an arena/heap/struct pointer (`add`/a load/a call return), or no visible store -- is
    'nonstack'. Returning 'stack' only on a proven stack address is what keeps this from resurrecting
    the VxWorks arena false positive (whose slot is stored from pointer arithmetic)."""
    for j in range(upto, -1, -1):
        t = texts[j].split(";")[0]
        m = re.match(r"\s*mov\s+(?:dword |qword )?(\[[^\]]+\])\s*,\s*([a-z0-9]+)\s*$", t, re.I)
        if m and _mem_inner(m.group(1)) == inner:
            src = m.group(2).strip().lower()
            if src in _X86_REGS and _dest_reg_class(texts[:j + 1], src) == "stack":
                return "stack"
            return "nonstack"
    return "nonstack"


def _dest_reg_class(texts, reg: str) -> str:
    """Trace register `reg` backward through the block's disassembly to classify what it holds
    when the copy runs: 'stack' (the address of a stack local), 'nonstack' (a loaded pointer, a
    global/RIP-relative address, an immediate, or a call return value -- i.e. NOT this frame), or
    'unknown'. Follows reg-to-reg moves so `rdi <- rax <- lea rax,[var]` resolves, which is exactly
    how x86-64 -O0 sets up the argument."""
    reg = reg.lower()
    i = len(texts) - 2                                # skip the call instruction itself
    hops = 6
    while i >= 0 and hops > 0:
        t = texts[i].split(";")[0]                    # drop the disassembler's comment
        w = re.match(r"\s*(mov|lea|movzx|movsx)\s+" + re.escape(reg) + r"\s*,\s*(.+)$", t, re.I)
        if w:
            op, rhs = w.group(1).lower(), w.group(2).strip()
            if op == "lea":
                return "stack" if _lea_target_is_stack(rhs) else "nonstack"   # else global/other lea
            if "[" in rhs:                            # a memory load: a pointer VALUE, not &frame
                inner = _mem_inner(rhs)               # ...unless a stack address was spilled here
                if inner:                             # (checked by tracing the store to this slot)
                    return _slot_store_class(texts, i - 1, inner)
                return "nonstack"
            nxt = rhs.rstrip(",").lower()
            if nxt in _X86_REGS:                       # reg-to-reg: keep tracing the source
                reg = nxt; hops -= 1; i -= 1; continue
            return "nonstack"                          # immediate / global label
        if reg in ("rax", "eax") and re.match(r"\s*call\b", t, re.I):
            return "nonstack"                          # destination is a call return value (heap/…)
        if _ARITH.match(t) and re.match(r"\s*\w+\s+" + re.escape(reg) + r"\b", t, re.I):
            return "unknown"                           # computed without clear pointer provenance
        i -= 1
    return "unknown"


def _is_x86(arch: str) -> bool:
    a = (arch or "").lower()
    return a.startswith("x86") or a in ("i386", "i486", "i586", "i686", "amd64", "x64", "x86_64")


def _is_aarch64(arch: str) -> bool:
    a = (arch or "").lower()
    return a in ("aarch64", "arm64", "arm64e")


def _is_arm32(arch: str) -> bool:
    a = (arch or "").lower()
    return a in ("arm", "armv7", "armv6", "armhf", "armel", "thumb", "arm32") or a.startswith("armv")


# ARM/aarch64 registers, and the ones that hold a stack/frame base (sp, the aarch64 frame pointer
# x29, and the AArch32 frame pointers r7 (Thumb) / r11/fp (ARM)).
_ARM_REGS = ({f"r{i}" for i in range(16)} | {f"x{i}" for i in range(31)} | {f"w{i}" for i in range(31)}
             | {"sp", "lr", "fp", "ip"})
_ARM_STACK_BASE = {"sp", "x29", "w29", "r7", "r11", "fp"}
_ARM_FIRST_ARG = {"aarch64": "x0", "arm": "r0"}


def _dest_reg_class_arm(texts, reg: str, aarch64: bool) -> str:
    """Trace an ARM/aarch64 destination register backward. Stack: `add reg, sp/x29/r7/fp, #imm`
    or `mov reg, sp`. Nonstack: `adrp` / `add reg, pc` (PC-relative global), any `ldr reg, [..]`
    (a loaded pointer value), or a `bl`/`blx` return value in x0/r0. Reg-to-reg `mov` is followed.
    Erring toward 'stack'/'unknown' keeps a finding rather than dropping a real one."""
    reg = reg.lower()
    ret_regs = {"x0", "w0"} if aarch64 else {"r0"}
    i = len(texts) - 2
    hops = 8
    while i >= 0 and hops > 0:
        t = texts[i].split(";")[0].strip()
        # add/sub reg, <base>, #imm   (three-operand address computation)
        m = re.match(r"(?:add|sub|adds|subs)(?:\.w)?\s+" + re.escape(reg) + r"\s*,\s*([a-z0-9]+)\s*,", t, re.I)
        if m:
            base = m.group(1).lower()
            if base in _ARM_STACK_BASE:
                return "stack"
            if base == "pc":
                return "nonstack"                          # PC-relative global
            if base == reg:                                # add reg,reg,#imm -> keep tracing reg
                i -= 1
                continue
            reg = base
            hops -= 1
            i -= 1
            continue
        # two-operand `add reg, pc` (Thumb PC-relative global) / `add reg, sp`
        if re.match(r"add(?:\.w)?\s+" + re.escape(reg) + r"\s*,\s*pc\b", t, re.I):
            return "nonstack"
        if re.match(r"add(?:\.w)?\s+" + re.escape(reg) + r"\s*,\s*sp\b", t, re.I):
            return "stack"
        # aarch64 page-address of a global
        if re.match(r"adrp?\s+" + re.escape(reg) + r"\b", t, re.I):
            return "nonstack"
        # mov reg, sp -> stack ; mov reg, <reg2> -> follow
        m = re.match(r"mov(?:\.w)?\s+" + re.escape(reg) + r"\s*,\s*([a-z0-9]+)\s*$", t, re.I)
        if m:
            src = m.group(1).lower()
            if src == "sp":
                return "stack"
            if src in _ARM_REGS:
                reg = src
                hops -= 1
                i -= 1
                continue
            return "nonstack"                              # immediate
        # a load into reg. From a stack slot it may be a spilled buffer address (`add r,sp,#o;
        # str r,[sp,#s]; ldr reg,[sp,#s]`) -> trace the store; from anything else it is a pointer
        # value (heap / global via literal pool / struct field) -> nonstack.
        m = re.match(r"ldr(?:\.w)?\s+" + re.escape(reg) + r"\s*,\s*(\[[^\]]+\])", t, re.I)
        if m:
            inner = _mem_inner(m.group(1))
            if inner:                                  # spilled stack address? trace the store
                return _arm_slot_store_class(texts, i - 1, inner, aarch64)
            return "nonstack"
        if re.match(r"ldr(?:\.w)?\s+" + re.escape(reg) + r"\b", t, re.I):
            return "nonstack"
        # a call return value lands in x0/r0 (bl / blx / blr, but NOT conditional ble/blt/bls/blo)
        if reg in ret_regs and re.match(r"bl(?:x|r)?(?:\.w)?\s", t, re.I):
            return "nonstack"
        # any OTHER arithmetic/logical op that redefines reg (two-operand `add r3, r2` = &buf+index,
        # mul, orr, ...) is a def we cannot cleanly classify -> stop here as 'unknown' (kept) rather
        # than tracing past it to a stale earlier definition. (Stores/compares read reg, not write
        # it, so they are excluded.)
        if re.match(r"(?:add|adc|sub|sbc|rsb|mul|mla|mls|orr|orn|eor|and|bic|lsl|lsr|asr|ror|rrx"
                    r"|mvn|neg|umull|smull|umlal|smlal|uxt[bh]|sxt[bh]|clz|rev\d*)s?(?:\.w)?\s+"
                    + re.escape(reg) + r"\s*,", t, re.I):
            return "unknown"
        i -= 1
    return "unknown"


def _arm_slot_store_class(texts, upto: int, inner: str, aarch64: bool) -> str:
    """A pointer was loaded from ARM slot `inner`; 'stack' ONLY if a proven stack address was stored
    there (`add r,sp,#o; str r,[slot]`), else 'nonstack' (heap/struct/arena, or no visible store)."""
    for j in range(upto, -1, -1):
        t = texts[j].split(";")[0]
        m = re.match(r"\s*str(?:\.w)?\s+([a-z0-9]+)\s*,\s*(\[[^\]]+\])", t, re.I)
        if m and _mem_inner(m.group(2)) == inner:
            src = m.group(1).strip().lower()
            if src in _ARM_REGS and _dest_reg_class_arm(texts[:j + 1], src, aarch64) == "stack":
                return "stack"
            return "nonstack"
    return "nonstack"


def _copy_dest_class(ir: dict, site_addr, bits: int, arch: str = "x86") -> str:
    """Classify the destination of an unbounded copy at `site_addr` as 'stack', 'nonstack', or
    'unknown', by reading the disassembly leading up to the call.

    32-bit cdecl: the destination is the last value written to [esp] before the call (`mov [esp], r`
    or `push r`); 64-bit SysV: it is rdi. From there `_dest_reg_class` traces the register. Anything
    unresolved stays 'unknown' (kept, so a real bug is never turned into a false negative).

    The register/ABI patterns are per-architecture (x86/x86-64, arm, aarch64); on any other
    architecture this returns 'unknown' (keep) so the gate never suppresses a finding it cannot
    actually reason about."""
    if not (_is_x86(arch) or _is_aarch64(arch) or _is_arm32(arch)):
        return "unknown"
    site = _naddr(site_addr)
    if not ir or site is None:
        return "unknown"
    seq = None
    for b in ir.get("blocks", []) or []:
        ins = b.get("instructions") or []
        addrs = [_naddr(i.get("addr")) for i in ins]
        if site in addrs:
            seq = ins[:addrs.index(site) + 1]
            break
    if not seq:
        return "unknown"
    texts = [(i.get("text") or "") for i in seq]
    if _is_aarch64(arch):
        return _dest_reg_class_arm(texts, _ARM_FIRST_ARG["aarch64"], aarch64=True)
    if _is_arm32(arch):
        return _dest_reg_class_arm(texts, _ARM_FIRST_ARG["arm"], aarch64=False)
    if bits == 64:
        return _dest_reg_class(texts, _DEST_REG64)
    # 32-bit: the destination is the last value written to [esp] (or pushed) before the call.
    for j in range(len(texts) - 2, -1, -1):
        t = texts[j].split(";")[0]
        m = re.search(r"mov\s+(?:dword )?\[esp\],\s*(\S+)", t, re.I) \
            or re.search(r"^\s*push\s+(\S+)\s*$", t, re.I)
        if m:
            rhs = m.group(1).strip().lower()
            if rhs in _X86_REGS:
                return _dest_reg_class(texts[:j + 1], rhs)
            return "nonstack"                          # global / immediate destination
    return "unknown"


@register_detector
def stack_buffer_overflow(ctx: DetectContext):
    """Correlate the recovered stack frame with unbounded-copy sinks: a function that owns a
    fixed-size stack buffer AND calls an unbounded copy is a stack-smash candidate. Reports the
    recovered buffer size and the (approximate) distance from the buffer to the saved return
    address -- the offset an exploit would need."""
    if not ctx.frames:
        return []
    # A scanf/sscanf is only a stack smash when its format has an UNBOUNDED string conversion
    # (%s / %[...]); a width-limited one (%16s) is bounded and NOT a bug. We cannot resolve arg0
    # per call site, so gate on the target having ANY unbounded scanf format at all -- with none,
    # every scanf sink is a false positive (the %16s that flagged scanner). Conservative: if no
    # scanf format is recovered we cannot tell, so we do NOT suppress (keep the textbook finding).
    scanf_fmts = [getattr(x, "value", "") or "" for x in (ctx.strings or [])
                  if _SCANF_CONV.search(getattr(x, "value", "") or "")]
    scanf_maybe_unbounded = (not scanf_fmts) or any(_SCANF_UNBOUNDED.search(f) for f in scanf_fmts)
    sinks_by_func = defaultdict(list)
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        if n in _UNBOUNDED_COPY:
            if n in ("scanf", "sscanf") and not scanf_maybe_unbounded:
                continue                          # only width-bounded %Ns present -> not a bug
            sinks_by_func[e.src_addr].append((n, e.site_addr))
    out = []
    for addr, frame in ctx.frames.items():
        bufs = [v for v in ((frame or {}).get("vars") or [])
                if isinstance(v, dict) and v.get("is_buffer")]
        sinks = sinks_by_func.get(addr, [])
        if not bufs or not sinks:
            continue
        # tightest buffer = worst case (a size the decompiler left unreadable sorts last)
        buf = min(bufs, key=lambda v: _as_int(v.get("size"), 1 << 30))
        # distance from the buffer to the saved return address in Ghidra frame coords; unknown
        # (not a made-up 8) when the buffer's offset is unreadable
        ret_off, b_off = _as_int(frame.get("ret_offset")), _as_int(buf.get("offset"))
        off_to_ret = (None if b_off is None else
                      (ret_off - b_off) if ret_off is not None else abs(b_off) + 8)
        # Defect grain, like every other sink detector: one finding per unbounded copy
        # routine, each occurrence a SITE. Keying on the function address made every call
        # site its own high-severity finding -- seven near-identical rows on jhead, which was
        # most of its HIGH count and read as seven separate bugs.
        #
        # But every DISTINCT sink is its own defect: a function that calls both gets() and
        # sprintf() into the same frame is two stack-smashes, and reporting only sinks[0]
        # silently dropped the rest. Iterate the distinct sink names (sorted, for a stable
        # run), emitting a candidate per call site; the per-name dedup_key still merges
        # occurrences across functions into one finding per unbounded-copy routine.
        ir = ctx.func_irs.get(addr)
        sites_by_name: dict = defaultdict(list)
        for n, site in sinks:
            # Gate on the copy DESTINATION: only a copy whose destination resolves to this stack
            # frame is a stack smash. A destination that is provably a caller/heap pointer
            # ('nonstack') is dropped here; 'stack' and 'unknown' are kept, so we never turn a real
            # bug into a false negative when the disassembly is too complex to resolve.
            #
            # The gate ONLY applies to sinks whose buffer is the FIRST argument (strcpy/strcat/
            # sprintf/vsprintf/gets). For scanf/sscanf the destination buffer is a LATER, variadic
            # argument -- arg0 is the format string (a .rodata global) -- so classifying arg0 would
            # wrongly read every `scanf("%s", buf)` as a global destination and suppress a textbook
            # stack smash. Those are kept unconditionally.
            if n in _ARG0_DEST and ir is not None \
                    and _copy_dest_class(ir, site, ctx.bits, ctx.arch) == "nonstack":
                continue
            sites_by_name[n].append(site)
        for n in sorted(sites_by_name):
            for site in sites_by_name[n]:
                out.append(_cand(
                    "CWE-121",
                    f"Stack buffer overflow: unbounded {n}() into a fixed-size stack buffer",
                    "high", "stack_frame",
                    [{"channel": "pattern",
                      "detail": f"{n}() called in a function owning a fixed-size stack buffer"}],
                    function_addr=addr, site_addr=site,
                    site_detail=(f"{n}() at {site} into {buf.get('name')} "
                                 f"({buf.get('type')}, {buf.get('size')} B); "
                                 + (f"~{off_to_ret} bytes from the buffer to the saved return "
                                    f"address" if off_to_ret is not None else
                                    "distance to the saved return address unknown")),
                    dedup_key=f"CWE-121:stack_frame:{n}", confidence=0.55))
    return out


# ------------------------- unchecked privilege-management return (logic/auth: CWE-252 / CWE-273)
# A privileged daemon that calls setuid()/setgid()/chroot() and IGNORES the result keeps its
# privileges (or stays unchrooted) when the call fails -- a classic logic/auth defect that never
# crashes and is not injection or memory corruption: the program simply does the WRONG thing. The
# textbook case is `setuid(pw->pw_uid); /* continue as root if it failed */`. We flag a call to one
# of these whose return value is provably DISCARDED, read straight off the disassembly.
_PRIV_RET_FUNCS = {
    "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid",
    "setresuid", "setresgid", "setgroups", "initgroups", "chroot",
}
_RAX = ("rax", "eax", "ax", "al")
_RMW_MNEMS = {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "sal", "rol", "ror", "inc",
              "dec", "neg", "not", "imul", "mul", "adc", "sbb", "test", "cmp", "movzx", "movsx"}


def _reg_in(text: str) -> bool:
    return any(re.search(r"\b" + r + r"\b", text) for r in _RAX)


def _touches_return(mnem: str, ops: list):
    """How the instruction first touches the return register (rax/eax), Intel syntax (dest first):
    'read' (the value is tested / used as a source / stored / passed on -> it was checked or kept),
    'write' (the register is redefined -> the value was discarded), or None (not touched)."""
    if mnem == "call":
        return "write"                                   # a later call clobbers rax before any read
    if not ops:
        return None
    if mnem in ("xor", "sub") and len(ops) == 2 and ops[0] == ops[1] and ops[0] in _RAX:
        return "write"                                   # self-zero of the return reg
    reads = any(_reg_in(o) for o in ops[1:])             # the reg as a SOURCE operand
    if ops[0].startswith("[") and _reg_in(ops[0]):
        reads = True                                     # used as a memory base/index = read
    if mnem in _RMW_MNEMS and not ops[0].startswith("[") and _reg_in(ops[0]):
        reads = True                                     # read-modify-write reads its destination
    if reads:
        return "read"
    if ops[0] in _RAX:
        return "write"                                   # register destination = redefine
    return None


def _return_discarded(ir: dict, site_addr) -> bool:
    """True iff the return value of the call at `site_addr` is provably DISCARDED: scanning forward
    within the SAME basic block, the FIRST instruction that touches the return register writes it
    (a redefine, a self-zero, or a later `call`) before any read. A read first means it was checked
    or kept. If the register is never touched and the block ends (ret/jmp/branch) we return False
    (UNKNOWN): the value may propagate to the caller or be checked in a successor, so we stay
    conservative and never call a real check a bug."""
    site = _naddr(site_addr)
    if not ir or site is None:
        return False
    seq = None
    for b in ir.get("blocks", []) or []:
        ins = b.get("instructions") or []
        addrs = [_naddr(i.get("addr")) for i in ins]
        if site in addrs:
            seq = ins[addrs.index(site) + 1:]            # instructions AFTER the call, same block
            break
    if not seq:
        return False
    for i in seq:
        t = (i.get("text") or "").split(";")[0].strip().lower()
        if not t:
            continue
        parts = t.split(None, 1)
        ops = [o.strip() for o in parts[1].split(",")] if len(parts) > 1 else []
        kind = _touches_return(parts[0], ops)
        if kind == "read":
            return False                                 # checked / used / stored -> not discarded
        if kind == "write":
            return True                                  # redefined before any read -> discarded
    return False


@register_detector
def unchecked_privdrop(ctx: DetectContext):
    """Flag a privilege-management call whose return value is discarded (CWE-252 / CWE-273) -- a
    logic/auth bug: on failure the program keeps its privileges and carries on."""
    if not (_is_x86(ctx.arch) and ctx.func_irs):         # the rax/eax scan is x86/x86-64 only
        return []
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        if n not in _PRIV_RET_FUNCS:
            continue
        ir = ctx.func_irs.get(e.src_addr)
        if ir is None or not _return_discarded(ir, e.site_addr):
            continue
        out.append(_cand(
            "CWE-252",
            f"Unchecked return value of privilege-management call {n}()",
            "high", "unchecked_privdrop",
            [{"channel": "pattern", "detail": (
                f"call to {n}() at {e.site_addr} discards its return value (not tested before the "
                f"return register is clobbered). If {n}() fails, execution continues with the "
                "original privileges -- CWE-252 / CWE-273 (improper check for dropped privileges). "
                "A static pattern: attacker-reachability / exploitability is not proven here.")}],
            function_addr=e.src_addr, site_addr=e.site_addr,
            site_detail=f"{n}() return discarded at {e.site_addr}",
            dedup_key=f"CWE-252:unchecked_privdrop:{n}", confidence=0.55))
    return out


# ------------------------- world-writable file permissions (logic/access-control: CWE-732) -------
# A chmod()/fchmod() with an others-writable mode leaves a file any local user can rewrite -- a
# config, a script, a lock or a binary an attacker then controls. This is NOT a crash or injection:
# it is an access-control contract broken with a constant. umask does NOT apply to chmod/fchmod, so
# a literal mode IS the final permission, which makes the check precise: we read the mode immediate
# straight off the register the ABI passes it in.
#: call -> the register (and its 32-bit alias) that carries mode_t on x86-64 SysV.
_CHMOD_MODE_REG = {"chmod": ("rsi", "esi"), "fchmod": ("rsi", "esi"), "lchmod": ("rsi", "esi"),
                   "fchmodat": ("rdx", "edx")}
_IMM_RE = re.compile(r"^mov\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$", re.I)


def _imm_into_reg(ir: dict, site_addr, regs) -> "int | None":
    """The immediate most recently moved into `regs` (a register and its 32-bit alias) BEFORE the
    call at `site_addr`, within the same basic block -- e.g. `mov esi, 0x1ff` ahead of `call chmod`.
    Returns None if the mode is computed (not a literal) or the register is clobbered first, so a
    non-constant mode is never guessed at (no false positive)."""
    site = _naddr(site_addr)
    if not ir or site is None:
        return None
    seq = None
    for b in ir.get("blocks", []) or []:
        ins = b.get("instructions") or []
        addrs = [_naddr(i.get("addr")) for i in ins]
        if site in addrs:
            seq = ins[:addrs.index(site)]             # instructions strictly BEFORE the call
            break
    if not seq:
        return None
    for i in reversed(seq):
        t = (i.get("text") or "").split(";")[0].strip().lower()
        m = _IMM_RE.match(t)
        if m and m.group(1) in regs:
            v = m.group(2)
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        z = re.match(r"^xor\s+(\w+)\s*,\s*(\w+)\s*$", t)
        if z and z.group(1) in regs and z.group(1) == z.group(2):
            return 0                                  # `xor edi, edi` -- the -O2 zeroing idiom
        # the register written by any other instruction before we found a literal -> value is not a
        # constant we can read; stop rather than reach past the real definition.
        parts = t.split(None, 1)
        if len(parts) > 1:
            dst = parts[1].split(",", 1)[0].strip()
            if dst in regs:
                return None
    return None


@register_detector
def world_writable_perms(ctx: DetectContext):
    """Flag chmod()/fchmod() that sets an OTHERS-WRITABLE mode (CWE-732) -- an access-control bug:
    the file becomes modifiable by any local user. x86-64 (the mode is read from its arg register)."""
    if not (_is_x86(ctx.arch) and ctx.bits == 64 and ctx.func_irs):
        return []
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        regs = _CHMOD_MODE_REG.get(n)
        if not regs:
            continue
        ir = ctx.func_irs.get(e.src_addr)
        if ir is None:
            continue
        mode = _imm_into_reg(ir, e.site_addr, regs)
        if mode is None or not (mode & 0o0002):          # others-write bit must be set
            continue
        out.append(_cand(
            "CWE-732",
            f"World-writable file permissions set via {n}()",
            "medium", "world_writable_perms",
            [{"channel": "pattern", "detail": (
                f"{n}() at {e.site_addr} sets mode 0{mode & 0o7777:o}, which is OTHERS-WRITABLE. "
                "umask does not apply to chmod/fchmod, so this is the file's final permission: any "
                "local user can modify it (a config, script, lock or binary the program trusts) -- "
                "CWE-732. A static pattern; whether the file is security-relevant is not proven.")}],
            function_addr=e.src_addr, site_addr=e.site_addr,
            site_detail=f"{n}(mode=0{mode & 0o7777:o}) at {e.site_addr}",
            dedup_key=f"CWE-732:world_writable_perms:{n}", confidence=0.6))
    return out


# ------------------------- privilege-drop order (logic/access-control: CWE-696, CERT POS36-C) -----
# Dropping the user id before the group id is a classic revocation-order bug: once setuid() has
# relinquished root, the process may no longer have the privilege to call setgid(), which then fails
# -- silently -- and the process keeps the privileged GROUP. The correct order is setgroups/setgid
# THEN setuid.
#
# Two refinements over a bare "first uid call precedes first gid call" address comparison:
#   * a call whose id arguments are provably the constant 0 / -1 (`seteuid(0)`, `setuid(0)`,
#     `setreuid(-1, 0)`) is a privilege RAISE (or a no-op for root), not a drop. Counting it as a drop
#     fabricated the finding on the `seteuid(0); setgid(g); setuid(u)` restore-then-drop idiom, and a
#     raise between a temporary drop and a setgid() makes that setgid succeed, so it also bounds the
#     path search below. Read from the x86-64 argument registers; elsewhere nothing is excluded.
#   * the ordering is decided PER PATH over the function's CFG when it is available: a uid drop is
#     wrong-order when a gid call is reachable after it (forward edges only, so a loop back-edge is
#     not a path) and no gid drop reaches it first. A function-wide `min()` let a correct branch mask
#     a wrong-order branch (`if (a) {setgid; setuid;} else {setuid; setgid;}`). With no CFG the
#     address comparison is the fallback.
_SETUID_FAM = {"setuid", "setreuid", "setresuid", "seteuid"}
_SETGID_FAM = {"setgid", "setregid", "setresgid", "setegid", "setgroups", "initgroups"}
# id-argument registers (x86-64 SysV) of the calls whose all-0/-1 constant form is a raise / no-op.
# setgroups/initgroups are absent: `setgroups(0, NULL)` CLEARS the groups -- that is a drop.
_ID_ARG_REGS = {"setuid": ("edi",), "seteuid": ("edi",), "setreuid": ("edi", "esi"),
                "setresuid": ("edi", "esi", "edx"), "setgid": ("edi",), "setegid": ("edi",),
                "setregid": ("edi", "esi"), "setresgid": ("edi", "esi", "edx")}
_ID_UNCHANGED = {0xffffffff, 0xffffffffffffffff}        # (uid_t)-1: "leave this id unchanged"


def _is_priv_raise(ir, name: str, site) -> bool:
    """True when every id argument of this set*id call is a constant 0 or -1 with at least one 0 --
    i.e. the call sets an id TO root (a raise, or a no-op for a root process), never a drop.
    Indeterminate (computed) arguments return False: the call is kept as a drop."""
    regs = _ID_ARG_REGS.get(name)
    if not regs or not ir:
        return False
    vals = []
    for r in regs:
        v = _imm_into_reg(ir, site, (r, _X86_CANON[r]))
        if v is None or (v != 0 and v not in _ID_UNCHANGED):
            return False
        vals.append(v)
    return 0 in vals


def _wrong_order_paths(ir, uid_sites, gid_sites, raise_sites):
    """Per-path ordering over the function CFG. Returns (uid_site, gid_site) for the first uid drop
    after which a gid call is reachable (no raise in between) and that no gid drop precedes, or None
    when none exists. Returns False when the CFG does not hold every site (caller falls back)."""
    blocks = (ir or {}).get("blocks") or []
    kind = {a: "uid" for a in uid_sites}
    kind.update({a: "gid" for a in gid_sites})
    kind.update({a: "raise" for a in raise_sites})
    events, succ, where = {}, {}, {}
    for b in blocks:
        ba = _naddr(b.get("addr"))
        if ba is None:
            continue
        ev = []
        for i in b.get("instructions") or []:
            ia = _naddr(i.get("addr"))
            if ia in kind:
                ev.append((ia, kind[ia]))
                where[ia] = (ba, len(ev) - 1)
        events[ba] = ev
        # forward edges only: a back-edge (to a lower address) is a loop, not a fresh path
        succ[ba] = [s for s in (_naddr(x) for x in (b.get("succ") or [])) if s is not None and s > ba]
    if any(a not in where for a in kind):
        return False

    def reach(src, want, stop, first_only=True):
        """Sites of kind `want` reachable after `src`; a `stop` event ends that path, and so does
        the first `want` when `first_only`."""
        found = []
        ba, k = where[src]
        todo, seen = [(ba, k + 1)], set()
        while todo:
            blk, start = todo.pop()
            ended = False
            for a, kd in events.get(blk, [])[start:]:
                if kd == want:
                    found.append(a)
                    if first_only:
                        ended = True
                        break
                    continue
                if kd in stop:
                    ended = True
                    break
            if ended:
                continue
            for s in succ.get(blk, []):
                if s not in seen:
                    seen.add(s)
                    todo.append((s, 0))
        return found

    preceded = set()
    for g in gid_sites:
        preceded.update(reach(g, "uid", (), first_only=False))
    for u in sorted(uid_sites):
        if u in preceded:
            continue
        after = reach(u, "gid", ("raise",))
        if after:
            return u, min(after)
    return None


@register_detector
def privilege_drop_order(ctx: DetectContext):
    """Flag a function in which a user-id drop precedes a group-id drop on some path (CWE-696)."""
    uid_by_fn: dict = defaultdict(list)
    gid_by_fn: dict = defaultdict(list)
    raise_by_fn: dict = defaultdict(list)
    x64 = _is_x86(ctx.arch) and ctx.bits == 64
    irs = {_naddr(k): v for k, v in (ctx.func_irs or {}).items()}
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        fa, sa = _naddr(e.src_addr), _naddr(e.site_addr)
        if fa is None or sa is None or (n not in _SETUID_FAM and n not in _SETGID_FAM):
            continue
        if x64 and _is_priv_raise(irs.get(fa), n, sa):
            raise_by_fn[fa].append(sa)                    # sets an id TO root: not a drop
        elif n in _SETUID_FAM:
            uid_by_fn[fa].append(sa)
        else:
            gid_by_fn[fa].append(sa)
    out = []
    for fa, uids in uid_by_fn.items():
        gids = gid_by_fn.get(fa)
        if not gids:
            continue
        pair = _wrong_order_paths(irs.get(fa), uids, gids, raise_by_fn.get(fa, []))
        if pair is False:                                 # no usable CFG: address order
            if min(uids) >= min(gids):                    # gid already dropped first
                continue
            pair, how = (min(uids), min(gids)), "static address order"
        elif pair is None:
            continue
        else:
            how = "a gid call is reachable after the uid drop on the CFG"
        u, g = pair
        out.append(_cand(
            "CWE-696",
            "Privileges dropped in the wrong order (setuid before setgid)",
            "medium", "privilege_drop_order",
            [{"channel": "pattern", "detail": (
                f"this function drops the user id (uid-drop at {u:#x}) BEFORE the group id "
                f"(gid-drop at {g:#x}; {how}). Once the uid is relinquished the process may lack "
                "the privilege to drop the gid, which then fails silently and leaves the process in "
                "the privileged group -- CWE-696 / CERT POS36-C. Correct order is setgroups/setgid "
                "then setuid. Static ordering: confirm the path is feasible.")}],
            function_addr=hex(fa), site_addr=hex(u),
            dedup_key=f"CWE-696:privilege_drop_order:{fa:#x}", confidence=0.5))
    return out


# ------------------------------- width-bounded scanf that STILL overflows (the off-by-one class)
# `scanf("%16s", buf)` with `char buf[16]` is NOT safe: the conversion writes up to 16 chars PLUS a
# terminating NUL = 17 bytes into a 16-byte buffer. The width bound fools the coarse detector above
# (which suppresses any `%Ns`), so this reads the SPECIFIC width against the SPECIFIC destination
# buffer's size and reports when `width + 1 > size`. `==` is the classic single-NUL off-by-one (a
# poison-null-byte over the adjacent slot / saved frame pointer -- HTB scanner's real bug); `>` is a
# plain overflow with an under-sized width. x86-64 SysV only (the arg registers are ABI-specific).
_SCANF_VARIANTS = {"scanf": ("rdi", "rsi"), "sscanf": ("rsi", "rdx"), "fscanf": ("rsi", "rdx")}
_SCANF_STR_WIDTH = re.compile(r"%\*?(\d+)[hlLjztq]*[s\[]")     # %16s / %20[..] -> the width int
_R2_STR_SYM = re.compile(r"\bstr\.(\S+)")
# The variadic (pointer) argument registers, in order, for each variant -- the i-th CONSUMING
# conversion of the format writes through the i-th of these. Conversions past the register window
# are passed on the stack and are not tracked (skipped, never guessed).
_SCANF_ARGREGS = {"scanf": ("rsi", "rdx", "rcx", "r8", "r9"),
                  "sscanf": ("rdx", "rcx", "r8", "r9"), "fscanf": ("rdx", "rcx", "r8", "r9")}
# one scanf conversion: `%%`, or [*][width][m][length]<conv>, where a scanset `[...]` may open with
# `^` and/or a literal `]`.
_SCANF_SPEC = re.compile(r"%(?:(%)|(\*)?(\d*)(m)?(?:hh|h|ll|l|L|j|z|t|q)?"
                         r"(\[\^?\]?[^\]]*\]|[diouxXaAeEfFgGsScCpn]))")


def _scanf_conversions(fmt: str):
    """The ordered argument-consuming conversions of a scanf format, as `(arg_index, width, conv,
    alloc)`. `%%` and `%*...` consume no argument. None when the format uses positional `%n$`
    arguments (the order is then not the textual order, so nothing is mapped rather than guessed)."""
    if "$" in fmt:
        return None
    out = []
    k = 0
    for m in _SCANF_SPEC.finditer(fmt):
        if m.group(1) or m.group(2):                  # %% or an assignment-suppressed %*...
            continue
        conv = m.group(5)
        out.append((k, int(m.group(3)) if m.group(3) else None, conv[0], bool(m.group(4))))
        k += 1
    return out


_LEA_ABS = re.compile(r"^\s*lea\s+(\w+)\s*,\s*(?:[a-z]+\s+)?\[\s*(0x[0-9a-f]+)\s*\]\s*$", re.I)
_MOV_ABS = re.compile(r"^\s*mov\s+(\w+)\s*,\s*(0x[0-9a-f]{4,})\s*$", re.I)


_ARG_CLOBBER = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}


def _reg_def(texts, reg: str, hops: int = 1):
    """The instruction body that last DEFINES `reg` at the end of `texts`, following up to `hops`
    reg-to-reg `mov` copies -- each hop resumes the backward scan from the copy itself, so in
    `lea rdx,[rbp-0x80]; ...; mov rcx,rdx; mov rdx,rax` the value of rcx is the lea, not the later
    redefinition of rdx. Any view of the register (`edx` for `rdx`) counts as a write. A call in
    between clobbers a caller-saved register. None when no definition is found."""
    cur = _x86_aliases(reg)
    end, h = len(texts), 0
    while True:
        for k in range(end - 1, -1, -1):
            body = (texts[k] or "").split(";")[0].strip()
            mnem, ops = _ops(body)
            if mnem == "call":
                if {_X86_CANON.get(r) for r in cur} & _ARG_CLOBBER:
                    return None
                continue
            if mnem == "xchg" and any(o.lower() in cur for o in ops):
                return None
            if not ops or ops[0].lower() not in cur or mnem in _NO_WRITE:
                continue
            if mnem == "mov" and len(ops) == 2 and ops[1].lower() in _X86_CANON and h < hops:
                cur, end, h = _x86_aliases(ops[1].lower()), k, h + 1
                break
            return body
        else:
            return None


def _addr_for_reg(texts, reg: str):
    """The absolute constant ADDRESS `reg` holds at the end of `texts` -- `lea rdi, [0x402004]`
    (r2's rendering of a resolved rip-relative operand) or a non-PIE `mov edi, 0x402004` --
    following one reg-to-reg move hop. None otherwise."""
    body = _reg_def(texts, reg)
    for rx in (_LEA_ABS, _MOV_ABS):
        m = rx.match(body or "")
        if m:
            return int(m.group(2), 16)
    return None


def _format_at(ctx, texts, reg: str):
    """(format string, r2 flag name) for the format argument in `reg` at the end of `texts`: the
    literal read from the image at the address the register holds, else the flag name (resolved by
    the caller against the extracted strings). (None, None) when neither is recoverable."""
    a = _addr_for_reg(texts, reg)
    if a is not None:
        v = _rodata_cstr(ctx, a)
        if v is None:
            for s in ctx.strings or []:
                if _naddr(getattr(s, "addr", None)) == a:
                    v = getattr(s, "value", None)
                    break
        if v is not None:
            return v, None
    return None, _str_flag_for_reg(texts, reg)


def _r2_flagify(v: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", v)


def _resolve_scanf_format(sym: str, strings):
    """The REAL format string an r2 `str.<sym>` flag names, recovered from the binary's strings: r2
    builds the flag by replacing non-alphanumerics (`%16s %u` -> `_16s__u`), so a string whose
    flagified form equals the (flagified) symbol is that format. Returns the conversion list when
    every matching string agrees on it, else None (ambiguous or not found -- never guessed)."""
    key = _r2_flagify(sym)
    convs = None
    for s in strings or []:
        v = getattr(s, "value", "") or ""
        if "%" not in v:
            continue
        fv = _r2_flagify(v)
        # exact, or r2 truncated a long flag name (only trusted for a long, specific prefix)
        if fv != key and not (len(key) >= 24 and fv.startswith(key)):
            continue
        c = _scanf_conversions(v)
        if c is None:
            return None
        if convs is not None and c != convs:
            return None                                   # two different formats share the flag
        convs = c
    return convs


def _norm_call(text: str):
    """The callee name from a `call ...` instruction, normalised (`sym.imp.__isoc99_scanf` ->
    `scanf`)."""
    m = re.search(r"\bcall\s+(\S+)", text or "")
    if not m:
        return None
    tgt = m.group(1)
    tgt = re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", tgt)
    return normalize(tgt)


def _str_flag_for_reg(texts, reg: str):
    """The r2 `str.<flag>` name whose ADDRESS `reg` holds at the end of `texts`, following one
    reg-to-reg move hop (`lea rdx,str.x; mov rdi,rdx` -- the -O0 arg set-up). None otherwise."""
    m = re.match(r"lea\s+\w+\s*,\s*(.+)$", _reg_def(texts, reg) or "", re.I)
    if not m:
        return None
    sym = _R2_STR_SYM.search(m.group(1))
    return sym.group(1) if sym else None


def _stack_slot_for_reg(texts, reg: str, slot_names=None):
    """The rbp-relative slot (`-K`, an int) that `reg` holds the ADDRESS of at the end of `texts`,
    following one level of reg-to-reg move (`lea rax,[rbp-0x10]; mov rsi,rax`). None if `reg` is not
    a &frame-local at the call. Matches the -O0 argument set-up r2 emits.

    `slot_names` maps the decompiler's NAMED stack operands to their frame offsets (e.g. rizin's
    `var_18h` -> -24, from the frame table). The disassembly often renders a local as that name --
    `lea rax, qword [var_18h]` -- rather than a literal `[rbp - 0x18]`, and without the mapping the
    address of the buffer is simply not recovered (the whole slot comes back None). The offset is
    taken from the frame table, never parsed out of the name's digits."""
    body = _reg_def(texts, reg)                           # at most one mov hop, then the lea
    mnem, ops = _ops(body or "")
    if mnem != "lea" or len(ops) != 2:
        return None
    slot = _frame_slot(_mem_terms(ops[1], slot_names))
    return slot[1] if slot and slot[0] == "RBP" and slot[1] < 0 else None


def _memset_size_for_slot(texts, slot: int, slot_names=None):
    """Size of a `memset(&local, 0, IMM)` on `slot` earlier in the function (r2: `lea rax,[rbp-K];
    mov rdi,rax; mov edx,IMM; ...; call memset`). This is the buffer's zeroed extent -- a tighter,
    more reliable size than a decompiler frame var that merges the local with adjacent slots (rizin
    reports a padded 24 for a `char[16]` that abuts the saved rbp). None if not found.

    Each memset is read at ITS OWN position (identical `call memset` texts used to all resolve to the
    first one), its size must be the immediate that reaches THAT call (a size r2 renders as a symbol
    -- `mov edx, elf_phdr` for 0x40 -- used to leave an earlier memset's size standing), and when
    the slot is cleared more than once the LARGEST extent wins: a partial clear understates the
    buffer, and an understated size is a fabricated overflow."""
    best = None
    for k, t in enumerate(texts):
        if _norm_call(t.split(";")[0]) != "memset":
            continue
        pre = texts[:k]
        if _stack_slot_for_reg(pre, "rdi", slot_names) != slot:
            continue
        m = re.match(r"(?:mov|movabs)\s+(?:edx|rdx)\s*,\s*(0x[0-9a-f]+|\d+)\s*$",
                     _reg_def(pre, "rdx", hops=0) or "", re.I)
        if m:
            best = max(best or 0, int(m.group(1), 0))
    return best


@register_detector
def scanf_bounded_overflow(ctx: DetectContext):
    if not (_is_x86(ctx.arch) and ctx.bits == 64) or not ctx.func_irs:
        return []
    # widths that a REAL scanf format string in the binary uses (corroborates the width parsed from
    # an r2 str. flag, so a coincidental "16s" substring in some other symbol cannot fire this).
    real_widths = set()
    for s in (ctx.strings or []):
        for m in _SCANF_STR_WIDTH.finditer(getattr(s, "value", "") or ""):
            real_widths.add(int(m.group(1)))
    out = []
    for faddr, ir in ctx.func_irs.items():
        frame = ctx.frames.get(faddr) or {}
        # offset -> size, and name -> frame offset so a `lea rax, [var_18h]` operand resolves to
        # its slot (the disassembly names locals; it rarely spells out `[rbp - 0x18]`).
        vsize, slot_names = _frame_vars(frame)
        flat = [(i.get("addr"), (i.get("text") or ""))
                for b in _blocks_of(ir) for i in (b.get("instructions") or [])]
        texts = [t for _, t in flat]
        for idx, (addr, text) in enumerate(flat):
            variant = _norm_call(text)
            if variant not in _SCANF_VARIANTS:
                continue
            fmt_reg, buf_reg = _SCANF_VARIANTS[variant]
            pre = texts[:idx]
            # the format feeding the format register: the literal itself when the register holds
            # its address (read from the image), else the r2 `str.` flag naming it
            fmt, sym = _format_at(ctx, pre, fmt_reg)
            if fmt is None and not sym:
                continue
            # Each width bounds ITS OWN destination: `scanf("%4s %64s", small, big)` writes at most
            # 5 bytes into `small` and 65 into `big`. The conversions are mapped to their argument
            # registers in order from the REAL format string. Applying the largest width to the
            # first buffer (the earlier shape) asserted a HIGH overflow on a correctly-sized
            # `small`. When the real string cannot be recovered, only a format whose FIRST
            # conversion is the bounded string (`%16s...` -> flag `_16s...`) is mapped, to the
            # first argument -- anything else is skipped rather than guessed.
            # A literal read from the image IS the format (no corroboration needed); a width
            # recovered through a flag name must also appear in a real extracted format string.
            convs = (_scanf_conversions(fmt) if fmt is not None
                     else _resolve_scanf_format(sym, ctx.strings))
            checks = []                                   # (width, dest register)
            if convs is not None:
                regs = _SCANF_ARGREGS[variant]
                for k, w, conv, alloc in convs:
                    if w is None or alloc or conv not in ("s", "[") or k >= len(regs):
                        continue
                    if fmt is not None or w in real_widths:
                        checks.append((w, regs[k]))
            elif sym:
                m0 = re.match(r"_(\d+)[hlLjztq]*s", sym)
                if m0 and int(m0.group(1)) in real_widths:
                    checks.append((int(m0.group(1)), buf_reg))
            for n, dreg in checks:
                slot = _stack_slot_for_reg(pre, dreg, slot_names)
                if slot is None:
                    continue
                # Prefer the memset-zeroed extent: it is the exact buffer size, whereas a decompiler
                # frame var often merges the buffer with the slots above it (rizin pads a char[16]
                # that abuts the saved rbp to 24, which would hide the off-by-one). Fall back to the
                # frame size when the buffer is not memset.
                size = _memset_size_for_slot(pre, slot, slot_names) or vsize.get(slot)
                if not size:
                    continue
                if n + 1 <= size:                         # width + NUL fits -> genuinely safe
                    continue
                off = "off-by-one NUL" if n == size else f"{n + 1 - size}-byte"
                kind = "single-NUL off-by-one" if n == size else "overflow"
                out.append(_cand(
                    "CWE-787",
                    f"Width-bounded {variant}() overflows its stack buffer ({kind})",
                    "high", "scanf_bounded_overflow",
                    [{"channel": "pattern",
                      "detail": (f"{variant}(\"%{n}s\", &buf) at {addr} writes {n}+1 bytes into a "
                                 f"{size}-byte stack buffer at rbp{slot} ({off} past the end)")}],
                    function_addr=faddr, site_addr=addr,
                    site_detail=(f"{variant} %{n}s into a {size}-byte buffer (rbp{slot}); "
                                 f"writes {n + 1} bytes"),
                    dedup_key=f"CWE-787:scanf_bounded_overflow:{variant}", confidence=0.6))
    return out


# ------------------------------------- improper validation of an array index (CWE-129) ----------
# An integer the attacker supplies -- parsed by atoi/strtol, converted by scanf("%d"), or read raw
# with read() -- is used to index a FIXED-SIZE array (a stack local or a global object) with no
# dominating check that keeps it inside the array. Three verdicts, each of which holds whatever the
# input turns out to be (the universal-contract principle):
#   unchecked -- no dominating comparison bounds the index from above on SOME path to the access;
#                any array size is exceeded by a large enough value.
#   signed    -- the only bound is an upper one on a SIGNED value (`if (i < 10)`): i = -1 indexes
#                below the array whatever its size.
#   bound     -- the bound is both-sided but admits an index >= the element count (`i <= 16` on a
#                16-element array). Only asserted for a GLOBAL array, whose extent is the symbol
#                table's st_size; a recovered stack frame is not trusted for a size (bounds.py).
# Everything that could make the claim false is a SKIP, never a guess: an index slot that is
# written anywhere else or whose address escapes (a callee may clamp it), a dominating branch that
# reads the index and cannot be evaluated (a variable bound, a validator call), arithmetic the
# tracker does not model, an unknown array base. Precision over recall: this sees the -O0 frame-slot
# shape across blocks and the -O2 register shape within a block / into its sole successor.
# x86-64 only (the argument registers and operand syntax are ISA-specific).
_INT_PARSERS = {"atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtoimax",
                "strtoumax", "strtoq", "strtouq"}
_RAW_READS = {"read": "rsi", "recv": "rsi", "recvfrom": "rsi", "fread": "rdi", "pread": "rsi",
              "pread64": "rsi"}
_CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
_SIZE_PFX = re.compile(r"^(byte|word|dword|qword|xmmword|ymmword|tbyte)\s+(ptr\s+)?", re.I)
_NUM = re.compile(r"^(0x[0-9a-f]+|\d+)$", re.I)
_NO_WRITE = {"cmp", "test", "push", "call", "jmp", "ret", "nop", "endbr64", "leave", "bt"}


def _ops(body: str):
    parts = body.split(None, 1)
    if not parts:
        return "", []
    mnem = parts[0].lower()
    if len(parts) == 1:
        return mnem, []
    ops, depth, cur = [], 0, ""
    for ch in parts[1]:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            ops.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return mnem, ops


def _mem_terms(op: str, slot_names=None):
    """`dword [rbp + rax*4 - 0x60]` -> (width, [(reg, scale)], disp, [symbols]); None if `op` is not
    a memory operand or holds something unparseable. A rizin-named local (`[var_14h]`) is mapped
    to `rbp + offset` through the frame table."""
    m = re.search(r"\[([^\]]*)\]", op or "")
    if not m:
        return None
    w = _SIZE_PFX.match(op.strip())
    width = w.group(1).lower() if w else None
    inner = m.group(1).replace(" ", "").lower()
    if not inner:
        return None
    regs, disp, syms = [], 0, []
    for sign, term in re.findall(r"([+-]?)([^+-]+)", inner):
        neg = sign == "-"
        if "*" in term:
            a, b = term.split("*", 1)
            r, k = (a, b) if a in _X86_CANON else (b, a)
            if r not in _X86_CANON or not _NUM.match(k) or neg:
                return None
            regs.append((_X86_CANON[r], int(k, 0)))
        elif term in _X86_CANON:
            if neg:
                return None
            regs.append((_X86_CANON[term], 1))
        elif _NUM.match(term):
            disp += -int(term, 0) if neg else int(term, 0)
        elif slot_names and term in slot_names and not neg:
            regs.append(("rbp", 1))
            disp += int(slot_names[term])
        elif re.match(r"^[a-z_.$][\w.$@]*$", term) and not neg:
            syms.append(term)
        else:
            return None
    return width, regs, disp, syms


def _frame_slot(terms):
    """(BASE, disp) when the operand is a plain frame slot (`[rbp - 0x14]`, `[rsp + 0xc]`)."""
    if not terms:
        return None
    _w, regs, disp, syms = terms
    if len(regs) == 1 and regs[0][1] == 1 and regs[0][0] in ("rbp", "rsp") and not syms:
        return (regs[0][0].upper(), disp)
    return None


def _global_base(ctx, addr=None, sym=None):
    """(name, base addr, st_size, offset into it) for a global OBJECT at `addr`/`sym`, else None.
    Only a symbol-table object is a fixed-size array with a known extent; a bare address that lies
    in a file-backed or .bss data section is still a fixed global (extent unknown)."""
    objs = _global_objects(ctx)
    if sym:
        n = sym[4:] if sym.startswith("obj.") else None
        if n and n in objs:
            a, sz = objs[n]
            return n, a, sz, 0
        if n:
            return n, None, None, 0
        return None
    if addr is None:
        return None
    for n, (a, sz) in objs.items():
        if a <= addr < a + max(sz, 1):
            return n, a, sz, addr - a
    secs, _data = _image_sections(ctx)
    for sec in secs:
        if (sec["flags"] & 2) and not (sec["flags"] & 4) and sec["addr"] and \
                sec["addr"] <= addr < sec["addr"] + sec["size"] and \
                sec.get("name") in (".data", ".bss", ".rodata"):
            return None, addr, None, 0
    return None


class _IdxTracker:
    """Register -> symbolic value across one basic block, for the shapes an array access is built
    from. Values: ("idx", scale, off, src) = index*scale + off; ("fa", BASE, disp) = a frame address;
    ("ga", addr, name) = a global address; ("ptr", base, scale, off, src) = &array[index]."""

    def __init__(self, ctx, slots, slot_names, state=None):
        self.ctx, self.slots, self.slot_names = ctx, slots, slot_names
        self.st = dict(state or {})

    def _val(self, reg):
        return self.st.get(_X86_CANON.get(reg, reg))

    def _set(self, reg, v):
        c = _X86_CANON.get(reg)
        if c:
            if v is None:
                self.st.pop(c, None)
            else:
                self.st[c] = v

    def addr_of(self, terms):
        """The symbolic address a memory operand computes, or None."""
        if not terms:
            return None
        _w, regs, disp, syms = terms
        if len(syms) > 1:
            return None
        idx, base = None, None
        if syms:
            g = _global_base(self.ctx, sym=syms[0])
            if g is None:
                return None
            base = ("global", g[0], g[1], g[2], g[3] + disp)
            disp = 0
        for r, k in regs:
            v = self.st.get(r)
            if r in ("rbp", "rsp") and k == 1 and base is None and v is None:
                base = ("stack", r.upper(), None)          # disp is the array base
                continue
            if v and v[0] == "idx" and idx is None:
                idx = (v[1] * k, v[2] * k, v[3])
                continue
            if v and k == 1 and base is None and v[0] == "fa":
                base, disp = ("stack", v[1], None), disp + v[2]
                continue
            if v and k == 1 and base is None and v[0] == "ga":
                gb = self._gbase(v)
                if gb is None:
                    return None
                base, disp = ("global", gb[0], gb[1], gb[2], gb[3] + disp), 0
                continue
            if v and k == 1 and base is None and idx is None and v[0] == "ptr":
                return ("ptr", v[1], v[2], v[3] + disp, v[4])
            return None
        if base is None and idx is None and not regs and disp:
            g = _global_base(self.ctx, addr=disp)
            return ("ga", disp, g[0] if g else None) if g else None
        if base is None and idx is not None and disp >= 0x1000:
            g = _global_base(self.ctx, addr=disp)     # non-PIE `[rax*4 + 0x404060]`
            if g is not None:
                base = ("global", g[0], g[1], g[2], g[3])
        if base is None:
            # a bare index with a small addend: `lea rdx, [rax + 1]` -- keep the +1 in the offset so
            # a later `[base + rdx*s]` scales it (the -O2 unrolled `t[i]; t[i+1]` derived index).
            return ("idx", idx[0], idx[1] + disp, idx[2]) if idx else None
        if base[0] == "stack":
            base = ("stack", base[1], disp)
            if base[1] == "RBP" and disp >= 0:
                return None                                # rbp+K is an incoming argument
            if idx is None:
                return ("fa", base[1], disp)
            return ("ptr", base, idx[0], idx[1], idx[2])
        if idx is None:
            return ("ga", base[2], base[1]) if base[4] == 0 else None
        return ("ptr", base, idx[0], idx[1] + base[4], idx[2])

    def _gbase(self, ga):
        """The global object a ("ga", addr, name) value points into."""
        if ga[1] is not None:
            return _global_base(self.ctx, addr=ga[1])
        return _global_base(self.ctx, sym="obj." + ga[2]) if ga[2] else None

    def step(self, mnem, ops, call_name=None, reg_source=None):
        """Advance over one instruction; returns the &array[index] access it performs, if any:
        (ptr value, 'write'|'read')."""
        hit = None
        if mnem not in ("lea", "nop", "endbr64"):
            for i, op in enumerate(ops):
                t = _mem_terms(op, self.slot_names)
                if not t:
                    continue
                a = self.addr_of(t)
                if a and a[0] == "ptr" and a[1][0] in ("stack", "global"):
                    write = i == 0 and mnem not in ("cmp", "test", "push")
                    hit = (a, "write" if write else "read")
        if mnem == "call":
            for r in _CALLER_SAVED:
                self.st.pop(r, None)
            if reg_source is not None:
                self.st["rax"] = ("idx", 1, 0, reg_source)
            return hit
        if mnem == "cdqe":
            return hit                                     # rax <- sext(eax): same index value
        if mnem in ("cdq", "cqo"):
            self.st.pop("rdx", None)
            return hit
        if mnem in ("div", "idiv", "mul") or (mnem == "imul" and len(ops) == 1):
            self.st.pop("rax", None)                        # implicit rdx:rax result
            self.st.pop("rdx", None)
            return hit
        if not ops:
            return hit
        dst = ops[0].lower()
        dreg = dst if dst in _X86_CANON else None
        src = ops[1].lower() if len(ops) > 1 else None
        if mnem in ("mov", "movsxd", "movsx", "movzx") and dreg:
            if src in _X86_CANON:
                narrow = src not in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") and \
                    not re.match(r"^(e[a-z]{2}|r\d+d?)$", src)
                self._set(dreg, None if narrow else self._val(src))
                return hit
            t = _mem_terms(src, self.slot_names)
            if t is not None:
                s = _frame_slot(t)
                if s in self.slots and t[0] in ("dword", "qword", None):
                    self._set(dreg, ("idx", 1, 0, self.slots[s]))
                else:
                    self._set(dreg, None)
                return hit
            if src and _NUM.match(src):
                v = int(src, 0)
                g = _global_base(self.ctx, addr=v) if v >= 0x1000 else None
                self._set(dreg, ("ga", v, g[0]) if g else None)
                return hit
            if src and src.startswith("obj."):
                g = _global_base(self.ctx, sym=src)
                self._set(dreg, ("ga", g[1], g[0]) if g else None)
                return hit
            self._set(dreg, None)
            return hit
        if mnem == "lea" and dreg:
            a = self.addr_of(_mem_terms(src, self.slot_names)) if src else None
            self._set(dreg, a if a and a[0] in ("idx", "fa", "ga", "ptr") else None)
            return hit
        v = self._val(dreg) if dreg else None
        imm = int(src, 0) if src and _NUM.match(src) else None
        if dreg and v and mnem in ("shl", "sal") and imm is not None and v[0] == "idx" and imm < 16:
            self._set(dreg, ("idx", v[1] << imm, v[2] << imm, v[3]))
            return hit
        if dreg and v and mnem in ("add", "sub") and imm is not None:
            d = imm if mnem == "add" else -imm
            if v[0] == "idx":
                self._set(dreg, ("idx", v[1], v[2] + d, v[3]))
            elif v[0] == "ptr":
                self._set(dreg, ("ptr", v[1], v[2], v[3] + d, v[4]))
            elif v[0] == "fa":
                self._set(dreg, ("fa", v[1], v[2] + d))
            else:
                self._set(dreg, None)
            return hit
        if dreg and mnem == "add" and src in _X86_CANON:
            w = self._val(src)
            pair = {x[0]: x for x in (v, w) if x}
            if v and w and set(pair) == {"idx", "fa"}:
                i, f = pair["idx"], pair["fa"]
                self._set(dreg, None if f[1] == "RBP" and f[2] >= 0 else
                          ("ptr", ("stack", f[1], f[2]), i[1], i[2], i[3]))
            elif v and w and set(pair) == {"idx", "ga"}:
                i, gb = pair["idx"], self._gbase(pair["ga"])
                self._set(dreg, ("ptr", ("global", gb[0], gb[1], gb[2], gb[3]), i[1],
                                 i[2] + gb[3], i[3]) if gb else None)
            else:
                self._set(dreg, None)
            return hit
        if dreg and mnem == "imul" and len(ops) == 3 and _NUM.match(ops[2]):
            s = self._val(ops[1].lower())
            k = int(ops[2], 0)
            self._set(dreg, ("idx", s[1] * k, s[2] * k, s[3]) if s and s[0] == "idx" else None)
            return hit
        if mnem in ("xchg",):
            for o in ops:
                self._set(o.lower(), None)
            return hit
        if dreg and mnem not in _NO_WRITE:
            self._set(dreg, None)
        return hit


def _block_flat(ir):
    out = []
    for b in (ir or {}).get("blocks", []) or []:
        for j, i in enumerate(b.get("instructions") or []):
            body = (i.get("text") or "").split(";")[0].strip()
            out.append((b.get("addr"), j, i.get("addr"), body))
    return out


def _index_slot_sources(ctx, ir, slot_names):
    """Frame slots that hold an attacker-supplied integer, keyed (BASE, disp) -> source dict.
    A slot qualifies only when its sole writer is that source (plus constant initialisers before a
    pointer-filled source) and its address is taken nowhere else -- otherwise a later clamp or a
    callee could bound it unseen, and the slot is dropped."""
    flat = _block_flat(ir)
    cands = {}
    leas: dict = defaultdict(list)                        # slot -> [instruction addrs taking &slot]
    writes: dict = defaultdict(list)                      # slot -> [(addr, imm-or-None)]
    for k, (_b, _j, addr, body) in enumerate(flat):
        mnem, ops = _ops(body)
        if not ops:
            continue
        if mnem == "lea" and len(ops) == 2:
            s = _frame_slot(_mem_terms(ops[1], slot_names))
            if s:
                leas[s].append(_naddr(addr))
        elif mnem not in _NO_WRITE:
            s = _frame_slot(_mem_terms(ops[0], slot_names))
            if s:
                imm = ops[1] if len(ops) > 1 and _NUM.match(ops[1]) and mnem == "mov" else None
                writes[s].append((_naddr(addr), imm))
    texts = [body for (_b, _j, _a, body) in flat]
    for k, (blk, _j, addr, body) in enumerate(flat):
        name = _norm_call(body)
        if not name:
            continue
        a = _naddr(addr)
        if name in _INT_PARSERS:
            # the parser's argument must not be a constant string (atoi("5") is no input)
            if _addr_for_reg(texts[:k], "rdi") is not None or _str_flag_for_reg(texts[:k], "rdi"):
                continue
            for (b2, _j2, a2, body2) in flat[k + 1:k + 4]:
                if b2 != blk:
                    break
                mnem, ops = _ops(body2)
                if mnem == "mov" and len(ops) == 2 and ops[1].lower() in ("eax", "rax"):
                    s = _frame_slot(_mem_terms(ops[0], slot_names))
                    if s:
                        cands[s] = {"source": name, "source_site": hex(a), "slot": s,
                                    "store": _naddr(a2), "kind": "parsed", "block": blk}
                    break
                if mnem in ("cdqe", "nop") or (mnem == "mov" and ops and
                                               _X86_CANON.get(ops[0].lower()) != "rax"):
                    continue
                break
        elif name in _SCANF_VARIANTS:
            fmt_reg = _SCANF_VARIANTS[name][0]
            fmt, sym = _format_at(ctx, texts[:k], fmt_reg)
            convs = (_scanf_conversions(fmt) if fmt is not None
                     else (_resolve_scanf_format(sym, ctx.strings) if sym else None))
            regs = _SCANF_ARGREGS[name]
            for i, w, conv, alloc in (convs or []):
                if conv not in "diouxX" or alloc or i >= len(regs):
                    continue
                s = _stack_slot_for_reg(texts[:k], regs[i], slot_names)
                s = ("RBP", s) if s is not None else _rsp_slot_for_reg(texts[:k], regs[i])
                if s:
                    cands[s] = {"source": f"{name} %{conv}", "source_site": hex(a), "slot": s,
                                "kind": "pointer", "block": blk}
        elif name in _RAW_READS:
            s = _stack_slot_for_reg(texts[:k], _RAW_READS[name], slot_names)
            s = ("RBP", s) if s is not None else _rsp_slot_for_reg(texts[:k], _RAW_READS[name])
            if s:
                cands[s] = {"source": name, "source_site": hex(a), "slot": s, "kind": "pointer",
                            "block": blk}
    out = {}
    for s, c in cands.items():
        src = _naddr(c["source_site"])
        if c["kind"] == "parsed":
            if leas.get(s) or [w for w in writes.get(s, []) if w[0] != c["store"]]:
                continue
        else:
            if len(leas.get(s, [])) != 1:
                continue                                  # &slot also handed to someone else
            if any(w[1] is None or w[0] > src for w in writes.get(s, [])):
                continue                                  # re-written after the input arrives
        out[s] = c
    return out


def _x86_lea_incr_steps(ir, slot_names):
    """The register-mediated slot increment gcc -O0 emits for `arr[i++]`: `mov slot,R; lea k(R),D;
    mov D,slot` == slot += k (the PRE-increment value is needed for the subscript, so a direct
    `add $k,slot` cannot be used). Returns {slot: [(k, store_addr)]} -- recognised as an induction
    step by `_induction_slots`, which otherwise reads the `mov D,slot` as an opaque writer."""
    out: dict = defaultdict(list)
    for b in (ir.get("blocks") or []):
        rdef: dict = {}                       # reg -> ('slot', s) after `mov R,slot`; ('inc', s, k) after lea
        for i in b.get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _X86_CANON.get(ops[0].lower())
            if mnem == "mov" and dst and len(ops) == 2:                 # mov R, <src>
                t = _mem_terms(ops[1], slot_names)
                s = _frame_slot(t) if t else None
                rdef[dst] = ("slot", s) if (s is not None and t[0] in ("dword", "qword", None)) else None
                continue
            if mnem == "lea" and dst and len(ops) == 2:                 # lea D, [R + k]
                t = _mem_terms(ops[1], slot_names)
                v = None
                if t and len(t[1]) == 1 and t[1][0][1] == 1 and not t[3] and t[2] > 0:
                    base = rdef.get(t[1][0][0])
                    v = ("inc", base[1], t[2]) if (base and base[0] == "slot") else None
                rdef[dst] = v
                continue
            if mnem == "mov" and len(ops) == 2 and dst is None:         # mov slot, D  (the store-back)
                s = _frame_slot(_mem_terms(ops[0], slot_names))
                d = rdef.get(_X86_CANON.get(ops[1].lower()))
                if s is not None and d and d[0] == "inc" and d[1] == s:
                    out[s].append((d[2], i.get("addr")))
                continue
            if dst:
                rdef[dst] = None                                        # any other write clobbers it
    return out


def _induction_slots(ir, slot_names, input_slots=None):
    """Frame slots that are LOOP INDUCTION VARIABLES: exactly one initialiser (a constant `mov $c,slot`,
    or a copy of an unvalidated-INPUT slot `mov slot,r` after `mov r,[n]`) and exactly one constant-step
    update (`add $k, slot` / `inc slot`, or the register-mediated `arr[i++]` form via
    `_x86_lea_incr_steps`), with the slot's address never taken and no other writer. Returned as index
    sources (kind 'induction') so the dominating-guard analysis reads the loop's OWN bound and the
    induction verdict compares the index the loop reaches to the array -- flagging a counted loop that
    walks off a fixed array (`for(i=0;i<=10;i++) t[i]`, the descending `for(i=C;i>=0;i--) t[i]`, or the
    input-start `for(i=n;i>=0;i--) t[i]`). `input_slots` names the attacker-controlled slots."""
    flat = _block_flat(ir)
    incr = _x86_lea_incr_steps(ir, slot_names)             # register-mediated `slot += k` stores
    incr_addrs = {_naddr(a) for lst in incr.values() for (_k, a) in lst}
    blk_of = {_naddr(addr): blk for (blk, _j, addr, _b) in flat}
    inits: dict = defaultdict(list)                        # slot -> [(addr, const, block)]
    init_input: dict = {}                                  # slot -> the input slot it was copied from
    steps: dict = defaultdict(list)                        # slot -> [(step, step_block)]
    other: dict = defaultdict(int)                         # slot -> count of writes we cannot model
    leas: dict = defaultdict(int)
    for s, lst in incr.items():
        for (k, a) in lst:
            steps[s].append((k, blk_of.get(_naddr(a))))
    cur_blk = None
    reg_slot: dict = {}                                    # reg -> input slot it was just loaded from
    for (blk, _j, addr, body) in flat:
        if blk != cur_blk:
            cur_blk, reg_slot = blk, {}                    # the init copy is block-local, so is tracking
        mnem, ops = _ops(body)
        if not ops:
            continue
        if mnem == "lea" and len(ops) == 2:
            s = _frame_slot(_mem_terms(ops[1], slot_names))
            if s:
                leas[s] += 1
            continue
        if mnem == "mov" and len(ops) == 2 and _X86_CANON.get(ops[0].lower()):   # reg <- [input slot]
            ld = _frame_slot(_mem_terms(ops[1], slot_names))
            reg_slot[_X86_CANON[ops[0].lower()]] = ld if (input_slots and ld in input_slots) else None
        if mnem in _NO_WRITE:
            continue
        s = _frame_slot(_mem_terms(ops[0], slot_names))
        if not s:
            continue
        if mnem == "mov" and len(ops) == 2 and _NUM.match(ops[1]):
            inits[s].append((_naddr(addr), int(ops[1].lstrip("$"), 0), blk))
        elif mnem == "mov" and len(ops) == 2 and reg_slot.get(_X86_CANON.get(ops[1].lower())):
            inits[s].append((_naddr(addr), None, blk))     # i = n, a copy of an unvalidated-input slot
            init_input[s] = reg_slot[_X86_CANON[ops[1].lower()]]
        elif mnem in ("add", "sub") and len(ops) == 2 and _NUM.match(ops[1]):
            steps[s].append((int(ops[1].lstrip("$"), 0) * (1 if mnem == "add" else -1), blk))
        elif mnem in ("inc", "dec"):
            steps[s].append((1 if mnem == "inc" else -1, blk))
        elif _naddr(addr) in incr_addrs:
            continue                                       # the `arr[i++]` store-back, counted above
        else:
            other[s] += 1
    out = {}
    for s in set(inits) & set(steps):
        if leas.get(s) or other.get(s) or len(inits[s]) != 1 or len(steps[s]) != 1:
            continue
        init_addr, init_val, init_blk = inits[s][0]
        step_val, step_blk = steps[s][0]
        if step_val == 0:
            continue
        if s in init_input:                               # input-start counter: only the DESCENDING form
            if step_val >= 0:                             # (an ascending input-start is a separate shape)
                continue
            out[s] = {"source": "loop counter", "source_site": hex(init_addr), "slot": s,
                      "kind": "induction", "block": init_blk, "init": None, "step": step_val,
                      "step_block": step_blk, "init_input": init_input[s], "descending": True}
            continue
        if init_val < 0:                                  # a constant init must be non-negative
            continue
        out[s] = {"source": "loop counter", "source_site": hex(init_addr), "slot": s,
                  "kind": "induction", "block": init_blk, "init": init_val, "step": step_val,
                  "step_block": step_blk}
        if step_val < 0:                                  # a DESCENDING counter: max index is the init
            out[s]["descending"] = True
    return out


def _reg_natural_loops(blocks, preds, succ_map, dom):
    """{header -> body set} for every natural loop, INCLUDING a single-block self-loop (the shape
    `-O2` emits for a tight counted loop). Back edges to one header union their bodies."""
    loops: dict = defaultdict(set)
    for b in blocks:
        bb = b.get("addr")
        for h in succ_map.get(bb, ()):
            if h != bb and h not in dom.get(bb, ()):
                continue                                  # not a back edge
            body = {bb} if h == bb else {h, bb}
            stack = [] if h == bb else [bb]
            while stack:
                n = stack.pop()
                for p in preds.get(n, ()):
                    if p not in body:
                        body.add(p)
                        stack.append(p)
            loops[h].update(body)
    return loops


def _reg_const_init(by_addr, dom, header, body, reg):
    """The non-negative constant `reg` holds on entry to a loop, read from its single dominating
    preheader (`mov $c,%reg` / `xor %reg,%reg` as that block's last write to reg), or None. Used
    only to confirm a forward counter starting at a known value; the bound itself comes elsewhere."""
    pre = [d for d in dom.get(header, ()) if d != header and d not in body]
    if len(pre) != 1:
        return None                                       # no single, unambiguous preheader
    init = None
    for i in (by_addr.get(pre[0]) or {}).get("instructions") or []:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops:
            continue
        dreg = _X86_CANON.get(ops[0].lower())
        if dreg != reg:
            continue
        if mnem == "xor" and len(ops) == 2 and _X86_CANON.get(ops[1].lower()) == reg:
            init = 0
        elif mnem == "mov" and len(ops) == 2 and _NUM.match(ops[1]):
            init = int(ops[1], 0)
        else:
            init = None                                   # an opaque write: value unknown from here
    return init


def _induction_regs(blocks, preds, succ_map, dom, by_addr):
    """Registers that are LOOP INDUCTION VARIABLES held in a REGISTER, not a frame slot (the `-O2`
    shape: the counter is promoted out of the stack). For each natural loop a register qualifies iff
    it has EXACTLY ONE constant positive step (`add $k,%reg`/`inc`) inside the loop and no other
    writer in the loop -- so inside the loop it only ever increments, a monotone forward counter.
    The ENTRY value is not required to be a known constant: the bound comes from the loop's own exit
    test (a constant equality exit reaches `C - step`, which termination proves is hit; an unvalidated
    input length is unbounded), and neither reading uses the init, so a `-O2` loop whose first
    iteration gcc peeled into an odd/even remainder (no single dominating init) is still handled.
    Returns {header -> {reg: src}} (src carries reg/step/init/loop, no slot)."""
    out: dict = defaultdict(dict)
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        steps: dict = defaultdict(list)                   # reg -> [(k, site)]
        other: dict = defaultdict(int)                    # reg -> count of writes we cannot model
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                if not ops:
                    continue
                dreg = _X86_CANON.get(ops[0].lower())
                if dreg is None or mnem in _NO_WRITE:
                    continue                              # not a write to a general register
                if mnem in ("add", "sub") and len(ops) == 2 and _NUM.match(ops[1]):
                    steps[dreg].append((int(ops[1], 0) * (1 if mnem == "add" else -1), i.get("addr")))
                elif mnem in ("inc", "dec") and len(ops) == 1:
                    steps[dreg].append((1 if mnem == "inc" else -1, i.get("addr")))
                else:
                    other[dreg] += 1
        for reg, st in steps.items():
            if other.get(reg) or len(st) != 1 or st[0][0] == 0:
                continue                                  # not a lone, non-zero, otherwise-stable step
            init = _reg_const_init(by_addr, dom, header, body, reg)
            if st[0][0] < 0:                              # a DESCENDING counter: the greatest index is
                base = {"source": "loop counter", "source_site": st[0][1], "slot": None,  # the init,
                        "kind": "induction", "reg": reg, "step": st[0][0],                # a constant or
                        "header": header, "loop": frozenset(body), "descending": True}    # an input start
                if init is not None and init >= 0:
                    out[header][reg] = {**base, "init": init}
                else:                                     # init not a known constant: an input start is
                    out[header][reg] = {**base, "init": None, "init_input_reg": True}     # resolved later
                continue
            out[header][reg] = {"source": "loop counter", "source_site": st[0][1], "slot": None,
                                "kind": "induction", "reg": reg, "step": st[0][0],
                                "init": init if (init is not None and init >= 0) else 0,
                                "header": header, "loop": frozenset(body)}
    return out


def _loop_exit_const(exit_blk, src, canon, ne_branches):
    """R0_max (the greatest value the counter holds at the loop header) for a register-counter loop
    whose own exit test is the `-O2` equality form `cmp reg, C; <ne-branch> <in-loop>` (x86 `jne`,
    ARM `bne`): termination requires the counter to hit C exactly, so the last header value is
    C - step (a value provably reached). None when the exit is not this counter-vs-constant equality
    shape (an inequality or a register bound is read elsewhere). Using the full step as the
    header-to-test distance never over-states R0_max, so a flagged overrun is always reached.
    `canon(tok)` gives a register's canonical name (None for a non-register)."""
    ins = (exit_blk or {}).get("instructions") or []
    if not ins:
        return None
    mnem, ops = _ops((ins[-1].get("text") or "").split(";")[0].strip())
    if mnem not in ne_branches or not ops:
        return None
    loop_n = {_naddr(a) for a in src["loop"]}
    if _naddr(ops[0]) not in loop_n:                      # the not-equal edge must continue the loop
        return None
    reg = src["reg"]
    for i in reversed(ins[:-1]):
        m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
        if m2 not in ("cmp", "test"):
            continue
        if m2 == "cmp" and len(o2) == 2:
            a, b = o2[0].lower().lstrip("#"), o2[1].lower().lstrip("#")
            if canon(o2[0].lower()) == reg and _NUM.match(b):
                return int(b, 0) - src["step"]
            if canon(o2[1].lower()) == reg and _NUM.match(a):
                return int(a, 0) - src["step"]
        return None                                       # the flag-setter is not counter-vs-constant
    return None


def _x86_exit_const(exit_blk, src):
    return _loop_exit_const(exit_blk, src, _X86_CANON.get, ("jne", "jnz"))


def _attach_slot_loops(slots, all_loops, block_in_loops):
    """Give each SLOT induction source its loop body (the union of loops whose block holds the step),
    so `_slot_exit_const` can confirm the equality exit's not-equal edge continues the loop. Register
    inductions already carry `loop`; slot detectors do not compute the CFG, so it is attached here."""
    for src in slots.values():
        if src.get("kind") == "induction" and src.get("slot") and src.get("step_block") is not None \
                and "loop" not in src:
            body: set = set()
            for h in block_in_loops.get(src["step_block"], ()):
                body |= all_loops.get(h, set())
            if body:
                src["loop"] = frozenset(body)


def _slot_exit_const(exit_blk, src, slot_of, canon, ne_branches, load_mnems, store_mnems, cmp_mnems):
    """R0_max for a SLOT induction whose loop exit is the equality form `cmp i, C; <ne-branch>
    <in-loop>` with i a stack slot -- compared directly (`cmp [i], C`, x86) or after moving i into a
    register (`ldr r,[i]; cmp r,C` / `str r,[i]; cmp r,C`, aarch64/arm32). Termination needs i to hit
    C, so the header value reaches C - step. None otherwise. The slot-path twin of `_x86_exit_const`:
    branch_predicate turns `< C` / `<= C` into an upper bound but not `!= C`, so the `for(i=0;i!=C;i++)`
    equality exit needs this. `slot_of(op)` gives the slot key a memory operand reads (else None)."""
    ins = (exit_blk or {}).get("instructions") or []
    if not ins:
        return None
    mnem, ops = _ops((ins[-1].get("text") or "").split(";")[0].strip())
    if mnem not in ne_branches or not ops:
        return None
    if _naddr(ops[0]) not in {_naddr(a) for a in src.get("loop", ())}:
        return None                                       # the not-equal edge must continue the loop
    slot = src["slot"]
    slot_regs: set = set()                                # registers currently holding the slot value
    bound = None
    for i in ins[:-1]:
        m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
        if not o2:
            continue
        if (m2 in load_mnems or m2 in store_mnems) and len(o2) >= 2 and slot_of(o2[-1]) == slot:
            slot_regs.add(canon(o2[0].lower()))           # reg <-/-> slot: now holds the slot value
            continue
        if m2 in cmp_mnems and len(o2) >= 2:
            for x, y in ((o2[0], o2[1]), (o2[1], o2[0])):
                if _NUM.match(y.lstrip("#")) and (slot_of(x) == slot or canon(x.lower()) in slot_regs):
                    bound = int(y.lstrip("#"), 0)
            continue
        if o2 and canon(o2[0].lower()) in slot_regs:
            slot_regs.discard(canon(o2[0].lower()))       # overwritten: no longer the raw slot value
    return bound - src["step"] if bound is not None else None


_IND_INPUT_KINDS = ("register", "parsed", "pointer")


def _loop_exit_other_reg(exit_blk, counter_reg, canon, cmp_mnems):
    """The NON-counter register a loop's exit test compares the counter against (`cmp i, n` -> n), or
    None. `canon(tok)` gives a register's canonical name (None for a non-register); `cmp_mnems` is the
    ISA's flag-setting compare set. A constant operand (handled by the equality-exit path) returns
    None here, as does a compare that does not involve the counter."""
    ins = (exit_blk or {}).get("instructions") or []
    for i in reversed(ins[:-1]):
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if mnem not in cmp_mnems:
            continue
        if len(ops) < 2:
            return None
        a, b = ops[0], ops[1]
        ca = canon(a.lower()) if not _NUM.match(a.lstrip("#")) else None
        cb = canon(b.lower()) if not _NUM.match(b.lstrip("#")) else None
        if ca == counter_reg and cb and cb != counter_reg:
            return cb
        if cb == counter_reg and ca and ca != counter_reg:
            return ca
        return None                                       # first flag-setter is not counter-vs-register
    return None


# P-Code comparison opcodes: a length-tainted operand reaching one of these against a NON-CONSTANT
# other operand is a variable bound the predicate reader cannot evaluate (so the claim is withheld);
# the length reaching a branch only through a bit mask (INT_AND/OR/XOR) is a parity/remainder split
# that cannot bound the magnitude, so it is ignored.
_CMP_PCODE = {"INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "INT_EQUAL",
              "INT_NOTEQUAL", "INT_SUB", "INT_SBORROW", "INT_CARRY", "INT_SCARRY"}


def _length_regs_at(d, length_src, cx):
    """The registers holding `length_src` (raw, idx 1/0) at dominator block `d`: its definition
    register there, plus every head carrier -- the seeds for reading `d`'s branch over the value."""
    regs = set()
    o = cx["origin"].get(id(length_src))
    if o is not None and o[0] == d and len(o) >= 3 and o[2]:
        regs.add(o[2])
    for r, v in (cx["head"].get(d) or {}).items():
        if isinstance(v, tuple) and v and v[0] == "idx" and v[3] is length_src \
                and v[1] == 1 and v[2] == 0:
            regs.add(r)
    return regs


def _length_unreadable_cmp(ins, length_regs):
    """True iff the block's TERMINATING branch depends on the length value through a COMPARISON
    against a NON-CONSTANT -- a variable bound the predicate reader could not evaluate, so the claim
    must be withheld (the safe, no-false-positive direction). A bit test (`and n,1`, the -O2
    remainder parity split) or a comparison against a CONSTANT does not count: neither bounds the
    magnitude, so the length stays unchecked. Over-approximates toward True (withhold)."""
    from .bounds import _const_tok
    from .taint import _REG_FAMILY, _key, _parse

    def _width(tok):                                      # the varnode's byte size (3rd `:`-field)
        parts = (tok or "").split(":")
        try:
            return int(parts[2], 0) if len(parts) >= 3 else 0
        except ValueError:
            return 0

    if not ins:
        return False
    taint = set()
    boundt = set()                                        # varnodes = length compared to a non-constant
    for r in length_regs:
        for nm in _reg_variants(r):
            taint.add(("reg", nm))
            taint.update(("reg", f) for f in _REG_FAMILY.get(nm, ()))
    n = len(ins)
    for j, i in enumerate(ins):
        for pc in i.get("pcode") or []:
            try:
                mnem, _insk, outk, toks = _parse(pc)
            except Exception:
                continue
            if mnem == "CBRANCH":
                if j == n - 1 and len(toks) >= 3 and _key(toks[2]) in boundt:
                    return True
                continue
            if outk is None:
                continue
            opnds = toks[1:]
            tainted = [(_key(t) in taint) for t in opnds]
            if mnem in _CMP_PCODE and any(tainted):
                # a REAL variable bound compares the length to a full-width value (a GP register or
                # memory); the other operand being a 1-bit FLAG (`INT_NOTEQUAL OF, SF`, part of the
                # branch's own SF/OF/ZF combination) is not a bound and must not seed -- otherwise every
                # signed compare's flag math would read as "compared to a variable" and over-withhold.
                if any((not tainted[x]) and _const_tok(opnds[x]) is None and _width(opnds[x]) > 1
                       for x in range(len(opnds))):
                    boundt.add(outk)                      # length compared to a variable other operand
            if any(_key(t) in boundt for t in opnds):
                boundt.add(outk)                          # carry the variable-bound flag to the branch
            if any(tainted):                              # condition through the derived SF/OF/ZF flags
                taint.add(outk)
    return False


def _length_bound(by_addr, exit_src, length_src, cx):
    """The loop-LENGTH value's dominating-check bound: ('bounded', k, nn) | ('unchecked',) | None.
    DOMINATOR-ONLY (a guard must dominate the loop to bound the length on every path), so the `-O2`
    remainder-peeling branches -- a parity split and a counter-vs-length compare, NEITHER dominating
    the loop -- cannot defeat it the way the full backward `_reg_bound` walk does (that walk reaches
    the peel branches through non-dominating predecessors and reads them as undecidable, which is why
    an x86 `-O2` input-length loop was silent). A dominating branch the predicate reader cannot
    evaluate withholds the claim ONLY when it compares the length to a non-constant (a real variable
    bound); a parity/bit split is non-bounding and ignored."""
    best = None
    for d in cx["dom"].get(exit_src, ()):
        if d == exit_src:
            continue
        ins = (by_addr.get(d) or {}).get("instructions") or []
        if not ins or not cx["cond_term"](_ops((ins[-1].get("text") or "").split(";")[0].strip())[0]):
            continue
        e = _edge_bound(length_src, d, exit_src, cx)
        if e is None:
            if _length_unreadable_cmp(ins, _length_regs_at(d, length_src, cx)):
                return None                               # a variable bound we cannot read -> withhold
            continue                                      # a parity / bit test -> non-bounding, ignore
        if e[0] == "bounded" and (best is None or e[1] < best):
            best = e[1]
    return ("bounded", best, True) if best is not None else ("unchecked",)


def _reg_loop_input_bound(src, access_block, head, cx, by_addr, dom, preds, blocks, canon, cmp_mnems):
    """Bound for a register counter whose loop LENGTH is held in another register (`for(i=0;i<n;i++)`
    at -O2, n in a register). The length value's own DOMINATING-check bound (`_length_bound`) decides:
    UNVALIDATED input gives ('unchecked',); a guard/clamp `n<=k` means the counter reaches at most
    `k - step`, so ('bounded', k-step, nn) (an inner guard on the index clamps tighter through
    `_induction_bound`, which runs first). None when the exit is not a counter-vs-input-register test,
    or the length is not a raw tracked input value -- a clamp that rewrites n into an opaque register
    drops it here, silent."""
    succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
    ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, access_block, dom)
    if not ok or exit_src is None:
        return None
    rb = _loop_exit_other_reg(by_addr.get(exit_src), src["reg"], canon, cmp_mnems)
    if rb is None:
        return None
    v = (head.get(exit_src) or {}).get(rb)
    if not (v and v[0] == "idx" and v[1] == 1 and v[2] == 0):
        return None                                       # the loop length is not a raw tracked value
    rbsrc = v[3]
    if rbsrc.get("kind") not in _IND_INPUT_KINDS or id(rbsrc) not in cx["origin"]:
        return None                                       # not unvalidated input -> no claim
    chk = _length_bound(by_addr, exit_src, rbsrc, cx)
    if chk is None:
        return None
    if chk[0] == "unchecked":
        return ("unchecked",)
    if chk[0] == "bounded":
        return ("bounded", max(0, chk[1] - src["step"]), bool(chk[2]))
    return None


def _reg_input_start_bound(src, access_block, head, cx, by_addr, dom, preds, blocks, canon):
    """('unchecked',) for a DESCENDING REGISTER counter whose INIT is an unvalidated input
    (`int n=atoi(s); for(i=n;i>=0;i--) table[i]` at -O1/-O2, where gcc promotes the counter to a
    register), or None. The first iteration stores table[n], so an unbounded n overruns -- the
    register twin of the -O0 slot input-start case. The counter's init is its value in the loop's
    single preheader; resolved to an input source through the tracker (`cx['tail']`), it takes the
    same dominating-bound check as the ascending input-length path (`_length_bound` over the dominators
    of the header): no bound -> unchecked, a `if(n<=k)` guard/clamp -> silent (no false positive).
    The verdict rests on the init, not the exit relation, so the sign-test exit needs no reading."""
    header, body = src.get("header"), src.get("loop") or frozenset()
    if header is None:
        return None
    pre = [p for p in preds.get(header, ()) if p not in body]
    if len(pre) != 1:
        return None                                        # no single, unambiguous preheader
    v = (cx["tail"].get(pre[0]) or {}).get(src["reg"])
    if not (v and v[0] == "idx" and v[1] == 1 and v[2] == 0):
        return None                                        # the init is not a raw tracked value
    isrc = v[3]
    if isrc.get("kind") not in _IND_INPUT_KINDS or id(isrc) not in cx["origin"]:
        return None                                        # the init did not come from unvalidated input
    chk = _length_bound(by_addr, header, isrc, cx)         # a dominating bound on n makes it safe
    return ("unchecked",) if (chk and chk[0] == "unchecked") else None


def _access_loops_single_exit(blocks, preds, succ_map, access_block, dom):
    """(ok, exit_src): ok iff `access_block` sits inside a loop AND every natural loop containing it
    has exactly ONE exit edge; exit_src is the exit-edge source of the SMALLEST such loop (where the
    loop's termination test lives). A second exit is an early `break`/`return` that can stop the loop
    before the induction variable reaches the header's bound, so the claim is then withheld."""
    # Successors reached by a CALL (`bl getchar`), not by control flow: the ghidra backend lists a
    # call's target as a block successor, which would otherwise read as a second loop exit and defeat
    # the single-exit gate. A call target is never a loop exit, so drop it from the exit computation.
    call_targets = set()
    for b in blocks:
        for i in b.get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if mnem in ("call", "bl", "blx") and ops:
                call_targets.add(_naddr(ops[0]))
    found = False
    best = None                                           # (loop size, exit source) of the innermost
    for b in blocks:
        bb = b.get("addr")
        for h in succ_map.get(bb, ()):                    # a back edge bb -> h (h dominates bb)
            if h != bb and h not in dom.get(bb, ()):
                continue                                  # not a back edge (h == bb is a self-loop)
            loop = {bb} if h == bb else {h, bb}
            stack = [] if h == bb else [bb]               # a self-loop's body is just the block
            while stack:                                  # natural loop: preds of the latch up to h
                n = stack.pop()
                for p in preds.get(n, ()):
                    if p not in loop:
                        loop.add(p)
                        stack.append(p)
            if access_block not in loop:
                continue
            found = True
            exits = [(nn, s) for nn in loop for s in succ_map.get(nn, ())
                     if s not in loop and _naddr(s) not in call_targets]
            if len(exits) != 1:
                return (False, None)                      # a break/second exit -> not sound to claim
            if best is None or len(loop) < best[0]:
                best = (len(loop), exits[0][0])
    return (found, best[1] if best else None)


def _exit_input_slot(exit_blk, i_slot, input_slots, slot_names):
    """The INPUT slot the loop's exit compares the induction slot against (`i < n`), or None. The
    induction slot must also be read in the block (so this is the loop's own `i vs n` test).
    `input_slots` (from `_index_slot_sources`) already drops an n that is clamped or re-written after
    it arrives; the caller still checks n has no dominating bound (a guarded length is safe)."""
    ins = (exit_blk or {}).get("instructions") or []
    reads_i = False
    nslot = None
    for i in ins:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        for op in ops:
            s = _frame_slot(_mem_terms(op, slot_names))
            if s is not None and s == i_slot:
                reads_i = True
            if s is not None and s != i_slot and s in input_slots and mnem in ("cmp", "test", "sub"):
                nslot = s
    return nslot if reads_i else None


# Stream/input readers whose RETURN VALUE drives a loop: `while((c=getchar())!=EOF)`. A single-exit
# loop whose exit test consumes one of these each iteration runs an INPUT-controlled, unbounded number
# of times -- so a counter/pointer that walks a fixed array in that loop overruns it.
_LOOP_INPUT_CALLS = {"getchar", "getc", "fgetc", "getchar_unlocked", "getc_unlocked",
                     "fgetc_unlocked", "getline", "getdelim", "read", "recv", "recvfrom",
                     "fread", "pread", "pread64", "scanf", "fscanf"}


def _mem_bracket(op):
    """The whitespace-stripped inner text of a `[...]` memory operand, for matching a spill slot to
    its reload by identical address text (`[sp, #24]` / `[rbp - 0x8]`), or None."""
    m = re.search(r"\[([^\]]*)\]", op or "")
    return re.sub(r"\s+", "", m.group(1)) if m else None


def _call_name(ops):
    return normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", ops[0])) if ops else ""


def _exit_driven_by_input_call(exit_blk, ret_regs, canon, call_names=None):
    """True when the loop's single-exit block runs an input-reading call (getchar/getc/read/...) whose
    result -- held in the return register OR spilled to a frame slot and reloaded/compared -- feeds the
    block's terminating comparison. That makes the trip count input-/EOF-controlled (unbounded), not a
    bound on any counter. ISA-neutral: `ret_regs` are the call's result registers, `canon` the register
    canonicaliser, `call_names` (site addr -> name) resolves a call the decompiler left as a bare
    address (the ghidra arm32 backend). Handles both operand orders (ARM `str REG,[slot]` and x86
    `mov [slot],REG`)."""
    ins = (exit_blk or {}).get("instructions") or []
    call_j = None
    for j, i in enumerate(ins):
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        name = (call_names or {}).get(_naddr(i.get("addr"))) or _call_name(ops)
        if mnem in ("call", "bl", "blx") and name in _LOOP_INPUT_CALLS:
            call_j = j
    if call_j is None:
        return False
    treg = {canon(r) for r in ret_regs}
    tslot: set = set()
    tainted_cmp = False
    for i in ins[call_j + 1:]:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops:
            continue
        br = [_mem_bracket(o) for o in ops]
        reg0 = canon(ops[0].lower()) if ops else None
        if mnem in ("cmp", "cmn", "test", "subs", "tst", "teq"):
            if any(canon(o.lower()) in treg for o in ops) or any(b in tslot for b in br if b):
                tainted_cmp = True
            continue
        # a spill of the tainted result to a frame slot (ARM `str REG,[slot]`; x86 `mov [slot],REG`)
        if mnem in ("str", "strb", "strh", "stur") and len(ops) >= 2 and reg0 in treg and br[-1]:
            tslot.add(br[-1])
            continue
        if mnem == "mov" and len(ops) == 2 and br[0] and canon(ops[1].lower()) in treg:
            tslot.add(br[0])
            continue
        # a reload / move that propagates the taint onward
        if reg0 and mnem in ("ldr", "ldrsw", "ldrb", "ldrh", "ldrsb", "ldrsh") and br[-1] in tslot:
            treg.add(reg0)
            continue
        if reg0 and mnem in ("mov", "movzx", "movsx", "movsxd", "cpy") and len(ops) == 2:
            if br[1] in tslot or canon(ops[1].lower()) in treg:
                treg.add(reg0)
            elif reg0 in treg:
                treg.discard(reg0)                        # overwritten by an untainted value
            continue
    return tainted_cmp


def _induction_bound(blocks, by_addr, preds, access_block, slot, dom, bases, cond_term,
                     exit_input=None, exit_const=None, loop_body=None, exit_unbounded=None):
    """The bound on a LOOP INDUCTION index at the access, as a check tuple or None (ISA-neutral:
    `cond_term(mnem)` says a block ends in a conditional branch, `exit_input(exit_blk)` names the
    unvalidated-input loop length or None, `exit_const(exit_blk)` the greatest header value a
    constant equality exit permits -- the `-O2` register-counter `cmp reg,C; jne` form whose test
    sits in the access block itself, so no DOMINATING branch carries it; `exit_unbounded(exit_blk)`
    is True when the loop's exit is driven by an input-reading call (getchar/read/...), so the counter
    walks an input-controlled, unbounded number of times -- the `table[i++]` copy-until-EOF loop).
    Reads the loop's own exit bound WITHOUT guard_bound's increment-store bail (the step runs AFTER
    the iteration's access, and the slot has only its init + single increment, so the bound is not
    stale). The access must sit in a SINGLE-EXIT loop -- an early break could stop before the bound,
    so otherwise the claim is withheld. ('bounded', k, True) for a CONSTANT loop bound k; ('unchecked',)
    when the length is UNVALIDATED INPUT or the trip count is input-driven; None otherwise."""
    from . import bounds
    succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
    ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, access_block, dom)
    if not ok:
        return None
    best = None
    reaching = dom.get(access_block, ())
    for d in reaching:
        if d == access_block:
            continue
        if loop_body is not None and d not in loop_body:
            # A REGISTER counter: trust a dominating guard only INSIDE the loop (an inner `if(i<10)`),
            # where the register provably still holds the counter. Out-of-loop, the SAME register held
            # a different value before the counter's init -- a pre-loop guard on it (`cmp eax,10` on
            # the input n that later becomes the index register) would be misread as bounding the
            # counter, a false "safe"/overrun. A frame slot does not alias, so it passes loop_body=None.
            continue
        blk = by_addr.get(d)
        ins = (blk or {}).get("instructions") or []
        if not ins or not cond_term(_ops((ins[-1].get("text") or "").split(";")[0].strip())[0]):
            continue
        got = bounds.branch_predicate(ins, slot, bases)
        if got is None:
            continue
        e = bounds._edge_pred_bound(got, blk.get("succ") or [], reaching, access_block)
        if e is not None and (best is None or e[0] < best):
            best = e[0]                                   # the tightest dominating bound (inner guards)
    if exit_const is not None and exit_src is not None:
        c0 = exit_const(by_addr.get(exit_src))            # the loop's OWN equality bound (-O2 self-loop)
        if c0 is not None and (best is None or c0 < best):
            best = c0                                     # tightest wins, so an inner guard still clamps
    if best is not None:
        return ("bounded", best, True)
    nslot = exit_input(by_addr.get(exit_src)) if (exit_input and exit_src) else None
    # flag only when the input length has NO dominating bound of its own (`if(n<=10)` around the loop
    # makes it safe; the input-slot detectors already excluded an n clamped by re-assignment)
    if nslot is not None and bounds.guard_bound(blocks, exit_src, nslot, bases=bases, dom=dom) is None:
        return ("unchecked",)                             # loop length is unvalidated input -> overrun
    if exit_unbounded is not None and exit_src is not None and exit_unbounded(by_addr.get(exit_src)):
        return ("unchecked",)                             # trip count is input-call-driven -> unbounded
    return None


def _co_induction_bound(i_src, slots, access_block, blocks, by_addr, preds, dom, bases, cond_term):
    """When induction index i has NO bound of its own, a co-induction j in the same loop can still
    bound it: `for(j=0;j<100;j++){ table[i]=..; i++; }` -- the exit bounds j, not i, but i advances in
    LOCKSTEP with j (its step in the SAME block, so both step once per iteration), so i provably
    reaches init_i + step_i*(T-1) where T is j's constant trip count. Returns ('bounded', i_max, True)
    for the tightest such co-bound, or None. Sound: same-block steps guarantee equal advance counts,
    and `_induction_bound`'s single-exit gate excludes an early break that would stop short. Only j's
    CONSTANT bound (from a dominating `cmp j,const`) is used -- an input-bounded j is left to i's own
    input/unbounded paths."""
    sb = i_src.get("step_block")
    if sb is None or i_src.get("step", 0) <= 0:
        return None
    best = None
    for j_src in slots.values():
        if j_src is i_src or j_src.get("kind") != "induction" or not j_src.get("slot") \
                or j_src.get("step_block") != sb or j_src.get("step", 0) <= 0:
            continue                                      # not a lockstep co-counter
        chk = _induction_bound(blocks, by_addr, preds, access_block, j_src["slot"], dom, bases,
                               cond_term)
        if not (chk and chk[0] == "bounded"):
            continue
        m = (chk[1] - j_src["init"]) // j_src["step"]     # iterations the loop provably runs
        if m < 0:
            continue
        i_max = i_src["init"] + i_src["step"] * m
        if best is None or i_max < best:
            best = i_max
    return ("bounded", best, True) if best is not None else None


def _induction_verdict(check, base, scale, off, src):
    """Verdict for a LOOP INDUCTION index: the greatest index value the loop reaches (for a forward
    counter the loop's UPPER bound; for a DESCENDING counter the constant init, the first iteration's
    value -- `_descending_bound` supplies it as a ('bounded', init, True) check). 'bound' when that
    CONSTANT greatest value overruns a known-size array; 'unchecked' when the loop length is
    unvalidated input (the loop walks arbitrarily far). A variable non-input bound, or none, is
    undecidable (silent). A forward counter's index cannot be negative; a descending counter is only
    emitted with a non-negative init, so neither underflows."""
    if check is None or base[0] != "global" or not base[3] or scale <= 0:
        return None
    cap = base[3]
    if check[0] == "unchecked":
        return "unchecked", [max(1, cap // scale), -1]    # loop walks past the array (input length)
    if check[0] == "bounded":
        bound = check[1]
        if bound >= 0 and bound * scale + off + scale > cap:
            return "bound", [bound]
    return None


def _signed_imm(v):
    """A compare immediate read as a SIGNED counter bound: `int` indices are 32-bit, but a counter
    promoted to a 64-bit register is compared at pointer width, so both `cmp dword,0xffffffff` and
    `cmp rax,0xffffffffffffffff` mean -1. Values below the sign bit are returned unchanged."""
    if v >= 2 ** 63:
        return v - 2 ** 64
    if 2 ** 31 <= v < 2 ** 32:
        return v - 2 ** 32
    return v


# p(i, T): the branch is TAKEN when the signed counter i relates to the compare constant T this way.
# jns/js (and b.pl/b.mi, bpl/bmi) are sign tests whose T is the compare's constant (0 at -O0). Any
# mnemonic absent here leaves the exit relation unknown, so the descending counter is left unflagged.
_DESC_TAKEN = {
    "jge": lambda i, T: i >= T, "jnl": lambda i, T: i >= T, "jg": lambda i, T: i > T,
    "jnle": lambda i, T: i > T, "jle": lambda i, T: i <= T, "jng": lambda i, T: i <= T,
    "jl": lambda i, T: i < T, "jnge": lambda i, T: i < T, "jne": lambda i, T: i != T,
    "jnz": lambda i, T: i != T, "je": lambda i, T: i == T, "jz": lambda i, T: i == T,
    "jns": lambda i, T: i >= 0, "js": lambda i, T: i < 0,
    "b.ge": lambda i, T: i >= T, "b.gt": lambda i, T: i > T, "b.le": lambda i, T: i <= T,
    "b.lt": lambda i, T: i < T, "b.ne": lambda i, T: i != T, "b.eq": lambda i, T: i == T,
    "b.pl": lambda i, T: i >= 0, "b.mi": lambda i, T: i < 0,
    "bge": lambda i, T: i >= T, "bgt": lambda i, T: i > T, "ble": lambda i, T: i <= T,
    "blt": lambda i, T: i < T, "bne": lambda i, T: i != T, "beq": lambda i, T: i == T,
    "bpl": lambda i, T: i >= 0, "bmi": lambda i, T: i < 0,
}


_DESC_INPUT_PROBE = 1 << 30                                    # a large OOB index for the input-start case


def _descending_bound(blocks, by_addr, preds, access_block, dom, src, canon,
                      cmp_mnems, neg_cmp_mnems, load_mnems, store_mnems, counter_of, bases=None):
    """The verdict for a DESCENDING counter (`for(i=START;i>=0;i--) table[i]`, step<0) whose body
    provably runs at i=START, so the FIRST iteration stores table[START]. Two kinds of START:
      * a CONSTANT init -> ('bounded', init, True): the counter only decreases, so the greatest index
        it reaches is the init constant, and _induction_verdict flags it when that is out of range (the
        classic descending off-by-one);
      * an UNVALIDATED-INPUT init (`src['init_input']` = the input slot `n`) -> ('unchecked',): the
        first store is table[n] and n is attacker-controlled, so an unbounded n overruns -- the
        descending twin of the ascending `for(i=0;i<n;i++)` input-length overrun. Only when n has NO
        dominating bound (a `if(n<=K)` guard makes it safe -> silent, as in the ascending case; the
        input-slot detectors already dropped a re-clamped n), hence `bases` is required.
    None otherwise. The exit test is used ONLY to confirm the body runs at the START value:
      * a single-block self-loop (the `-O1` shape `table[i]=i; sub i,1; cmp i,-1; jne .`) is straight
        line -- the store runs each iteration before the terminal branch, so it runs at START;
      * otherwise the exit test must DOMINATE the access (a top/pre-access test), so on the first
        iteration its compared value is START, and the body runs iff the in-loop edge is taken for it.
    The input case probes a large index (an unbounded n reaches it), so only a down-counting loop whose
    continuation admits a large value (`i>=0`/`i>C`/`i!=C`), not an `i<C` upper test, is flagged.
    `counter_of(op)` is truthy when `op` directly names the counter (its slot memory operand, or its
    register); the slot form also follows the counter through a register loaded from the slot."""
    from . import bounds
    init, nslot = src.get("init"), src.get("init_input")
    if src.get("step", 0) >= 0 or (nslot is None and (init is None or init < 0)):
        return None
    succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
    ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, access_block, dom)
    if not ok or exit_src is None:
        return None
    if nslot is not None:                                      # input-start: n must be unbounded
        if bases is None or bounds.guard_bound(blocks, exit_src, nslot, bases=bases, dom=dom) is not None:
            return None
        probe, result = _DESC_INPUT_PROBE, ("unchecked",)
    else:
        probe, result = init, ("bounded", init, True)
    if access_block in (succ_map.get(access_block) or ()):     # single-block self-loop (bottom test)
        return result
    if exit_src == access_block or exit_src not in dom.get(access_block, ()):
        return None                                            # not a pre-access test -> not sound
    ins = (by_addr.get(exit_src) or {}).get("instructions") or []
    if not ins:
        return None
    mnem, ops = _ops((ins[-1].get("text") or "").split(";")[0].strip())
    pred = _DESC_TAKEN.get(mnem)
    if pred is None or not ops:
        return None
    if _naddr(ops[0]) not in {_naddr(a) for a in src.get("loop", ())}:
        return None                                            # taken edge must continue the loop
    counter_regs: set = set()
    T = None
    for i in ins[:-1]:
        m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
        if not o2:
            continue
        if (m2 in load_mnems or m2 in store_mnems) and len(o2) >= 2 and counter_of(o2[-1]):
            counter_regs.add(canon(o2[0].lower()))             # reg <-/-> slot: now holds the counter
            continue
        is_ctr = len(o2) >= 2 and _NUM.match(o2[1].lstrip("#")) \
            and (counter_of(o2[0]) or canon(o2[0].lower()) in counter_regs)
        if m2 in cmp_mnems and is_ctr:
            T = _signed_imm(int(o2[1].lstrip("#"), 0))
            continue
        if m2 in neg_cmp_mnems and is_ctr:                     # `cmn r,#k` compares r against -k
            T = -int(o2[1].lstrip("#"), 0)
            continue
        if canon(o2[0].lower()) in counter_regs:
            counter_regs.discard(canon(o2[0].lower()))         # overwritten: no longer the counter
    if T is None:
        return None
    return result if pred(probe, T) else None


def _rsp_slot_for_reg(texts, reg: str):
    """(`RSP`, disp) when `reg` holds `rsp + disp` (`lea rsi, [rsp + 0xc]`, the -O2 &local)."""
    for t in reversed(texts):
        mnem, ops = _ops(t.split(";")[0].strip())
        if not ops or _X86_CANON.get(ops[0].lower()) != _X86_CANON.get(reg):
            continue
        if mnem == "lea" and len(ops) == 2:
            s = _frame_slot(_mem_terms(ops[1]))
            return s if s and s[0] == "RSP" else None
        if mnem not in _NO_WRITE:
            return None
    return None


def _touches(instrs, slot, slot_names):
    """Does this block READ the index slot? (`lea` only takes its address -- the block that calls
    `read(fd, &i, 4)` and branches on read's return is not a check on i.)"""
    for i in instrs:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if mnem == "lea":
            continue
        for op in ops:
            if _frame_slot(_mem_terms(op, slot_names)) == slot:
                return True
    return False


def _ends_in_cond_jump(instrs):
    if not instrs:
        return False
    mnem, _ops_ = _ops((instrs[-1].get("text") or "").split(";")[0].strip())
    return mnem.startswith("j") and mnem != "jmp"


def _slot_check(blocks, site_block, slot, dom, slot_names):
    """What dominating checks prove about a frame-slot index at `site_block`: ("unchecked",), or
    ("bounded", bound, nonneg), or None when a dominating branch reads the index but cannot be
    evaluated (a variable bound, a validator call) -- the claim is then not made."""
    from . import bounds
    by_addr = {b.get("addr"): b for b in blocks}
    bases = ("RBP", "RSP")
    for d in dom.get(site_block, ()):
        if d == site_block:
            continue
        ins = (by_addr.get(d) or {}).get("instructions") or []
        if _ends_in_cond_jump(ins) and _touches(ins, slot, slot_names) and \
                bounds.branch_predicate(ins, slot, bases) is None:
            return None
    g = bounds.guard_bound(blocks, site_block, slot, bases=bases, dom=dom)
    if g is None:
        return ("unchecked",)
    return ("bounded", g["bound"], bool(g["nonneg"]))


# ---- register-held index across a merge (all ISAs) ---------------------------------------------
# An index kept in a register (never spilled) that reaches an access through a control-flow MERGE
# (`int r=0; if(k<N) r=t[k]; t[k]=1;` at -O2 -- the second access sits at a 2-predecessor join).
# The frame-slot path already handles merges, because its dominating-check analysis keys on a stable
# memory location; a register does not, since the index can be in r0 at the guard and r2 at the use
# and may be reassigned/poisoned in between. `_reg_bound` is a backward, edge-aware walk: the bound
# proven for the raw input value `src` arriving at a block is the MEET over its predecessors of
# (the bound carried into that predecessor, refined by the predecessor's terminating branch toward
# this block). It reads each predecessor's branch with the register that actually held `src` THERE
# (from the forward scan's origin/head maps, with COPY propagation covering intra-block copies), so
# the register-identity gap cannot silently drop a real bound (which would be a false positive).
_PRED_FLAG_WRITE = re.compile(r"->\s*reg:(CY|ZR|NG|OV):", re.I)


def _reg_variants(rname):
    """The register-name forms to seed the branch reader with. aarch64 compares the 32-bit `w` view
    of a 64-bit `x` index (`cmp w0,#9`), and _REG_FAMILY does not relate them, so try both; every
    other ISA's sub-register aliasing is already in _REG_FAMILY, so the canonical upper form suffices."""
    m = re.fullmatch(r"[xw](\d+)", (rname or "").lower())
    return (f"X{m.group(1)}", f"W{m.group(1)}") if m else ((rname or "").upper(),)


def _same_idx(a, b):
    """Two tracked register values are the SAME index: same scale, same offset, and the same input
    source OBJECT (not merely equal fields) -- so a merge joins only genuinely identical values."""
    return (isinstance(a, tuple) and isinstance(b, tuple) and len(a) >= 4 and len(b) >= 4
            and a[0] == "idx" and b[0] == "idx" and a[1] == b[1] and a[2] == b[2] and a[3] is b[3])


def _branch_pred_term(ins, slot, bases):
    """branch_predicate reading the block's TERMINATING branch, not an ARM predicated op's internal
    skip-CBRANCH (-O2 `movhi r0,#0` carries its own CBRANCH). A non-terminating instruction holding
    a CBRANCH is a predicated op: drop its effect so the real branch is read -- unless it
    conditionally writes a real condition flag, where dropping it could hide a bound, so bail."""
    from . import bounds
    if not ins:
        return None
    n = len(ins)
    out = []
    for j, i in enumerate(ins):
        pcs = i.get("pcode") or []
        if j != n - 1 and any((pc or "").startswith("CBRANCH") for pc in pcs):
            if any(_PRED_FLAG_WRITE.search(pc or "") for pc in pcs):
                return None
            out.append({"addr": i.get("addr"), "text": i.get("text"), "pcode": []})
        else:
            out.append(i)
    return bounds.branch_predicate(out, slot, bases)


def _branch_on_index(ins, seed_regs):
    """True if the block's TERMINATING branch condition depends (through P-Code dataflow) on a
    register holding the index. It separates an unreadable branch ON the index (a VARIABLE bound
    `if(i>=n)` -> undecidable, no claim) from a branch on an UNRELATED value (`if(n<=0)` guarding a
    loop whose body indexes with an untouched input -> no constraint on the index). Over-approximate
    (whole-taint, whole register family), the safe direction: a missed dependency could only turn an
    undecidable verdict into a claim, so taint is seeded generously and propagated through every op."""
    from .taint import _REG_FAMILY, _key, _parse
    if not ins:
        return False
    taint = set()
    for r in seed_regs:
        for nm in _reg_variants(r):
            taint.add(("reg", nm))
            taint.update(("reg", f) for f in _REG_FAMILY.get(nm, ()))
    n = len(ins)
    for j, i in enumerate(ins):
        for pc in i.get("pcode") or []:
            mnem, insk, outk, toks = _parse(pc)
            if mnem == "CBRANCH":
                if j == n - 1 and len(toks) >= 3 and _key(toks[2]) in taint:
                    return True                                # the terminating branch tests the index
                continue                                       # a predicated op's CBRANCH is not it
            if outk is not None:
                if any(k in taint for k in insk):
                    taint.add(outk)
                else:
                    taint.discard(outk)
    return False


def _meet_checks(paths):
    """The weakest guarantee over the paths reaching a merge, as a finding reads it: any path with
    NO upper bound makes the index unchecked (an out-of-bounds value reaches the access on that
    path); an undecidable path (None) blocks a claim unless another path is already unchecked; only
    when every path is bounded is the merge bounded, at the loosest (largest) of the bounds."""
    if not paths:
        return None
    if any(p == ("unchecked",) for p in paths):
        return ("unchecked",)
    if any(p is None for p in paths):
        return None
    return ("bounded", max(p[1] for p in paths), all(p[2] for p in paths))


def _reaches_without(by_addr, start, target, avoid):
    """Can control reach `target` from `start` WITHOUT passing through `avoid`? A forward CFG walk."""
    if start == target:
        return True
    seen = {avoid}
    stack = [start]
    while stack:
        n = stack.pop()
        if n == target:
            return True
        if n in seen:
            continue
        seen.add(n)
        stack.extend((by_addr.get(n) or {}).get("succ") or [])
    return False


def _edge_bound(src, pred, block, cx):
    """The upper bound `pred`'s terminating branch proves for `src` on the pred->block edge:
    ("bounded", b, nn), ("unchecked",) when it adds none (branch not on src, or the taken edge is
    the lower-bound side), or None when a branch on src cannot be read."""
    from . import bounds
    pblk = cx["by_addr"].get(pred)
    if pblk is None:
        return ("unchecked",)
    pins = pblk.get("instructions") or []
    last = _ops((pins[-1].get("text") or "").split(";")[0].strip())[0] if pins else ""
    if not pins or not cx["cond_term"](last):
        return ("unchecked",)                              # no terminating conditional branch
    reaching = cx["dom"].get(block, ())
    # Keep only successors that reach the site on a FORWARD path (not by looping back through `pred`).
    # In a loop `cmp i,9; jbe site; .. <latch> -> pred`, the latch dominates the site via the back
    # edge, so `_edge_pred_bound` would otherwise read BOTH edges as reaching the site and discard the
    # guard -- a false "unchecked" on a guarded access. The latch reaches the site only through `pred`,
    # so it is dropped here and the `jbe site` bound is honoured.
    succ = [s for s in (pblk.get("succ") or []) if _reaches_without(cx["by_addr"], s, block, pred)]
    cands = []                                             # (instruction slice, seed register)
    o = cx["origin"].get(id(src))
    if o is not None and o[0] == pred and len(o) >= 3 and o[2]:
        cands.append((pins[o[1] + 1:], o[2]))              # src defined in pred: seed its def reg
    for r, v in (cx["head"].get(pred) or {}).items():      # src flowed in: seed each head carrier
        if isinstance(v, tuple) and v and v[0] == "idx" and v[3] is src:
            cands.append((pins, r))
    if not cands:
        return None                                        # src live but no carrier found -> bail
    for after, rname in cands:
        for vr in _reg_variants(rname):
            got = _branch_pred_term(after, ("reg", vr), cx["bases"])
            if got is None:
                continue
            e = bounds._edge_pred_bound(got, succ, reaching, block)
            return ("bounded", e[0], bool(e[1])) if e else ("unchecked",)
    # the branch is not readable as a constant bound on the index. If it TESTS the index (a variable
    # bound `if(i>=n)`) the claim is withheld (undecidable, no false positive); if it tests an
    # UNRELATED value (`if(n<=0)` around a loop over an untouched input index) it adds no constraint.
    if any(_branch_on_index(after, [rname]) for after, rname in cands):
        return None
    return ("unchecked",)


def _reg_bound(src, block, cx, seen=None):
    """The upper bound proven for `src` where it is used as an index in `block`, held in a register.
    A backward walk (see the section note). A loop back edge returns None (the result there would
    depend on the walk's own chain, so it is not cached); a runaway walk is capped, also at None."""
    if seen is None:
        seen = frozenset()
        cx["_calls"] = 0
    if block in seen:
        return None                                        # a loop back edge -> undecidable
    cx["_calls"] += 1
    if cx["_calls"] > 4000:
        return None                                        # pathological CFG -> withhold the claim
    o = cx["origin"].get(id(src))
    if o is not None and o[0] == block:
        return ("unchecked",)                              # defined here, no branch before the use
    ps = cx["preds"].get(block, [])
    if not ps:
        return ("unchecked",)
    seen2 = seen | {block}
    paths = []
    for p in ps:
        tailp = cx["tail"].get(p)
        if tailp is None:                                  # predecessor not yet processed (back edge)
            paths.append(None)
            continue
        if not any(isinstance(v, tuple) and v and v[0] == "idx" and v[3] is src
                   and v[1] == 1 and v[2] == 0 for v in tailp.values()):
            paths.append(None)                             # pred does not carry the raw src out
            continue
        paths.append(_combine_checks(_reg_bound(src, p, cx, seen2),
                                     _edge_bound(src, p, block, cx)))
    return _meet_checks(paths)


def _index_verdict(check, base, scale, off):
    """(verdict, oob index values) for a check on an index into `base`, or None when in bounds or
    undecidable. `scale`/`off` describe the byte offset index*scale + off."""
    if check[0] == "unchecked":
        n = None
        if base[0] == "global" and base[3]:
            n = max(1, base[3] // max(scale, 1))
        return "unchecked", ([n, -1] if n else [-1])
    bound, nonneg = check[1], check[2]
    if not nonneg:
        return "signed", [-1]
    if off < 0:
        return None                                        # needs the exact lower bound
    if base[0] == "global" and base[3] and scale > 0:
        last = bound * scale + off + scale                 # one past the last byte touched
        if last > base[3]:
            return "bound", [bound]
    return None


_IDX_TITLES = {
    "unchecked": "Array index from input used without a bounds check",
    "signed": "Array index checked only from above (a negative index reaches the array)",
    "bound": "Array index bound admits an index past the end of the array",
}


_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")     # SysV integer argument order


def _param_slot_sources(ir, slot_names, entry):
    """Frame slots that hold an incoming integer ARGUMENT unmodified (the -O0 spill
    `mov dword [rbp - 0x14], edi` in the entry block), keyed (BASE, disp) -> source dict. Dropped,
    as for an input slot, when the slot is written anywhere else or its address is taken -- the
    function could then change the value before it indexes with it."""
    flat = _block_flat(ir)
    leas: dict = defaultdict(list)
    writes: dict = defaultdict(list)
    for (_b, _j, addr, body) in flat:
        mnem, ops = _ops(body)
        if not ops:
            continue
        if mnem == "lea" and len(ops) == 2:
            sl = _frame_slot(_mem_terms(ops[1], slot_names))
            if sl:
                leas[sl].append(_naddr(addr))
        elif mnem not in _NO_WRITE:
            sl = _frame_slot(_mem_terms(ops[0], slot_names))
            if sl:
                writes[sl].append(_naddr(addr))
    out = {}
    clobbered = set()                                     # arg registers already overwritten
    for (blk, _j, addr, body) in flat:
        if blk != entry:
            break
        mnem, ops = _ops(body)
        if mnem == "call":
            break
        src = _X86_CANON.get(ops[1].lower()) if mnem == "mov" and len(ops) == 2 else None
        sl = _frame_slot(_mem_terms(ops[0], slot_names)) if ops else None
        if sl and src in _ARG_REGS and src not in clobbered and \
                _mem_terms(ops[0], slot_names)[0] in ("dword", "qword", None):
            if not leas.get(sl) and writes.get(sl) == [_naddr(addr)]:
                k = _ARG_REGS.index(src)
                out[sl] = {"source": f"argument {k + 1}", "source_site": addr, "slot": sl,
                           "kind": "param", "param": k, "block": entry}
            continue
        if ops and _X86_CANON.get(ops[0].lower()) and mnem not in _NO_WRITE:
            clobbered.add(_X86_CANON[ops[0].lower()])
    return out


def _combine_checks(caller, callee):
    """Both checks hold at the access: the tighter upper bound, non-negative if either side
    proves it. None (undecidable) on either side stays undecidable."""
    if caller is None or callee is None:
        return None
    if caller[0] == "unchecked":
        return callee
    if callee[0] == "unchecked":
        return caller
    return ("bounded", min(caller[1], callee[1]), bool(caller[2] or callee[2]))


def _tail_resolver(ctx):
    """A `resolve_tail(operand) -> callee entry addr or None` for the current target. A tail call
    (x86 `jmp sym.inner`, ARM `b inner`) forwards a parameter at -O2 but the decompiler records NO
    call edge for it, so it is invisible through `targets` alone. Match the branch operand against
    the known function entries, by address or by name; a memory/computed/intra-function target is
    not a tail call and returns None."""
    func_entries = {_naddr(a) for a in ctx.func_irs}
    fn_by_name: dict = {}
    for f in (ctx.functions or []):
        nm, ad = getattr(f, "name", None), getattr(f, "addr", None)
        if nm and ad is not None:
            fn_by_name[normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", nm))] = _naddr(ad)

    def resolve_tail(operand):
        tok = (operand or "").strip()
        if not tok or re.search(r"[\[\]+*]", tok):            # a memory / computed jmp is not a tail call
            return None
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", tok):
            a = _naddr(tok)
            return a if a in func_entries else None
        a = fn_by_name.get(normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", tok)))
        return a if (a is not None and a in func_entries) else None

    return resolve_tail


def _x86_global_ptr_init(ctx, by_addr, dom, header, body, p):
    """Resolve a register's INITIAL value to a known-size global object (`lea p,[obj.table]` in a
    dominating preheader), as ('global', name, addr, sz), or None. Used by the walking-pointer
    detector; a bare address / unknown-size symbol is dropped."""
    g = None
    for d in sorted((x for x in dom.get(header, ()) if x != header and x not in body),
                    key=lambda x: len(dom.get(x, ()))):              # farthest dominator first (exec order)
        for i in (by_addr.get(d) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops or _X86_CANON.get(ops[0].lower()) != p:
                continue
            if mnem == "lea" and len(ops) == 2:
                t = _mem_terms(ops[1])
                gb = None
                if t and t[3]:
                    gb = _global_base(ctx, sym=t[3][0])
                elif t and not t[1] and t[2] >= 0x1000:
                    gb = _global_base(ctx, addr=t[2])
                g = ("global", gb[0], gb[1], gb[2]) if (gb and gb[1] is not None and gb[2]) else None
            else:
                g = None                                            # p redefined by something else
    return g


def _store_through_ptr_x86(mnem, ops, slot_names):
    """(ptr_reg, store_width) for an x86 store through a base pointer with NO index -- `mov [p],src`
    / `mov [p+disp],src` (not a frame slot) -- else None. The write a `-O2` walking-pointer copy loop
    makes each iteration."""
    if mnem != "mov" or len(ops) != 2:
        return None
    t = _mem_terms(ops[0], slot_names)
    if not t or len(t[1]) != 1 or t[1][0][1] != 1 or t[3] or t[1][0][0] in ("rbp", "rsp"):
        return None
    return (t[1][0][0], {"byte": 1, "word": 2, "dword": 4, "qword": 8}.get(t[0], 4))


def _x86_unbounded_walk(ctx, faddr, blocks, preds, succ_map, dom, by_addr, slot_names, out):
    """x86-64 `-O2` UNBOUNDED walking-pointer write: `for(..) *q++ = getchar()` becomes a pointer that
    walks a fixed global (`lea rbx,[table]; mov [rbx],eax; add rbx,4`) with the loop exit driven by an
    input-reading call (`call getc; cmp eax,-1; jne`), no counter and no bound -- so the write runs an
    input-controlled number of times and overruns the array. Flagged `unchecked`. Single-exit loop,
    an input-call-driven exit, a known-size global base, and p walked only by its one step are all
    required, so a bounded or non-input loop stays silent (no false positive)."""
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, header, dom)
        if not ok or exit_src is None:
            continue
        if not _exit_driven_by_input_call(by_addr.get(exit_src), ("rax",), _X86_CANON.get):
            continue
        steps: dict = defaultdict(list)
        stores: dict = {}
        writes: dict = defaultdict(int)
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                if not ops:
                    continue
                sw = _store_through_ptr_x86(mnem, ops, slot_names)
                if sw:
                    stores.setdefault(sw[0], (sw[1], i.get("addr")))
                dst = _X86_CANON.get(ops[0].lower())
                if dst is None or mnem in _NO_WRITE:
                    continue
                if mnem in ("add", "sub") and len(ops) == 2 and _NUM.match(ops[1]):
                    steps[dst].append(int(ops[1], 0) * (1 if mnem == "add" else -1))
                elif mnem in ("inc", "dec") and len(ops) == 1:
                    steps[dst].append(1 if mnem == "inc" else -1)
                else:
                    writes[dst] += 1
        for p, st in steps.items():
            if p not in stores or writes.get(p) or len(st) != 1 or st[0] <= 0:
                continue
            gbase = _x86_global_ptr_init(ctx, by_addr, dom, header, body, p)
            if gbase is None:
                continue
            width, site = stores[p]
            v = _index_verdict(("unchecked",), gbase, width, 0)
            if v is None:
                continue
            verdict, oob = v
            src = {"source": "a walking pointer", "source_site": site, "slot": None,
                   "slot_name": None, "kind": "walk"}
            out.append(_array_index_cand(faddr, site, gbase, width, 0, src, "write",
                                         ("unchecked",), verdict, oob))
            return                                                   # one walking-pointer finding/function


_RAM_STORE_RE = re.compile(r"->\s*ram:(0x[0-9a-fA-F]+|\d+):(\d+)\b")


def _x86_const_oob_stores(ctx, faddr, blocks, out):
    """A CONSTANT-ADDRESS store that writes past a known-size global array -- the x86 `-O1`/`-O2`
    fully-unrolled / vectorised overrun (`for(i=0;i<N;i++) t[i]=v` compiled to straight-line
    `movups xmmword [table+off],xmm` / `mov dword [table+off],c`), which carries no loop or index
    register for the induction path to read. A direct store to an absolute address shows in p-code as
    `<op> ... -> ram:A:W`; when A lands INSIDE a known-size object and the W-byte write crosses the
    object's st_size, it is a CWE-129 overrun -- a wide SIMD store straddling the array's end. A store
    whose START address is AT or PAST the object end is normally NOT attributed to it: the linked
    binary has lost the symbol+addend origin, so that address could belong to an ADJACENT global --
    attributing it would be a false positive. The ONE exception, handled here, is a store whose
    address lands PAST EVERY object AND every writable data section (`_global_base` returns None --
    the image's data boundary, e.g. `&table[10]` == `_end` when table is the last global): nothing
    valid can be there, so a store to it is unambiguously an overrun of the array whose end abuts it.
    A known symbol size is required. The aarch64 twin `_a64_const_oob_stores` reads the same overrun
    off an `adrp+add` base pointer instead, since aarch64 cannot express an absolute store in one op."""
    objs = _global_objects(ctx)
    for b in blocks:
        for i in b.get("instructions") or []:
            seen = set()
            for pc in i.get("pcode") or []:
                if not isinstance(pc, str):
                    continue
                m = _RAM_STORE_RE.search(pc)
                if not m:
                    continue
                addr, width = int(m.group(1), 0), int(m.group(2), 0)
                if width <= 0 or (addr, width) in seen:
                    continue
                seen.add((addr, width))
                g = _global_base(ctx, addr=addr)
                if g is None:
                    # past EVERY object and data section -> the image's data boundary. A store here
                    # overruns the array whose end abuts `addr` (exactly one such array; nothing valid
                    # sits past it, so no adjacent-global ambiguity -- the sound one-past scalar case).
                    ends = [(nm, a, sz) for nm, (a, sz) in objs.items() if sz and a + sz == addr]
                    if len(ends) != 1 or any(a2 == addr for a2, _s in objs.values()):
                        continue                            # not exactly one array ends here (ambiguous)
                    nm, a, sz = ends[0]
                    base = ("global", nm, a, sz)
                    chk = ("bounded", sz // width, True)
                    v = _index_verdict(chk, base, width, sz % width)
                    if v is None:
                        continue
                    verdict, oob = v
                    src = {"source": "a constant offset", "source_site": i.get("addr"),
                           "slot": None, "kind": "constant"}
                    out.append(_array_index_cand(faddr, i.get("addr"), base, width, sz % width,
                                                 src, "write", chk, verdict, oob))
                    continue
                if not (g[1] is not None and g[2]):            # resolved to a known-size object
                    continue
                eff = g[3]                                      # byte offset of the store START in it
                if eff < 0 or eff + width <= g[2]:              # start inside and no crossing -> in bounds
                    continue
                base = ("global", g[0], g[1], g[2])
                chk = ("bounded", eff // width, True)
                v = _index_verdict(chk, base, width, eff % width)
                if v is None:
                    continue
                verdict, oob = v
                src = {"source": "a constant offset", "source_site": i.get("addr"),
                       "slot": None, "kind": "constant"}
                out.append(_array_index_cand(faddr, i.get("addr"), base, width, eff % width,
                                             src, "write", chk, verdict, oob))


def _index_scan_function(ctx, faddr, blocks, targets, summaries, calls, out, resolve_tail=None):
    """Pass 1 of array_index over ONE function (see array_index)."""
    from . import bounds
    ir = {"blocks": blocks}
    frame = ctx.frames.get(faddr) or {}
    _vs, slot_names = _frame_vars(frame)
    entry = next((b.get("addr") for b in blocks if _naddr(b.get("addr")) == _naddr(faddr)),
                 blocks[0].get("addr"))
    slots = _index_slot_sources(ctx, ir, slot_names)
    input_slots = set(slots)                              # the unvalidated-input slots, for a loop bound
    for sl, src in _param_slot_sources(ir, slot_names, entry).items():
        slots.setdefault(sl, src)
    for sl, src in _induction_slots(ir, slot_names, input_slots).items():
        slots.setdefault(sl, src)
    dom = bounds.dominators(blocks)
    preds: dict = defaultdict(list)
    succ_map: dict = {}
    for b in blocks:
        succ_map[b.get("addr")] = tuple(b.get("succ") or ())
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    by_addr = {b.get("addr"): b for b in blocks}
    # Registers that are loop induction counters (the -O2 shape: the counter lives in a register, not
    # a stack slot). Seeded at each loop header below so the array accesses it indexes resolve; its
    # bound comes from the loop's own exit test (_induction_bound with exit_const/exit_input).
    reg_inductions = _induction_regs(blocks, preds, succ_map, dom, by_addr)
    # Every natural loop, so a loop-invariant array base held in a register (`lea rbx,[table]` hoisted
    # out of the loop) is carried into the loop blocks below: `tail` carries only idx values, so
    # without this the in-loop access `base[i]` cannot resolve its array (the loop-header-merge gap).
    all_loops = _reg_natural_loops(blocks, preds, succ_map, dom)
    loop_writes: dict = {}                                # header -> regs written anywhere in its loop
    block_in_loops: dict = defaultdict(list)              # block -> [loop header it belongs to]
    for h, body in all_loops.items():
        w = set()
        for la in body:
            block_in_loops[la].append(h)
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
                if m2 == "call":
                    w.update(_CALLER_SAVED)               # a call clobbers the caller-saved regs
                elif o2 and _X86_CANON.get(o2[0].lower()) and m2 not in _NO_WRITE:
                    w.add(_X86_CANON[o2[0].lower()])
        loop_writes[h] = w
    _attach_slot_loops(slots, all_loops, block_in_loops)  # slot inductions get their loop body
    # A value held in a REGISTER is followed within its block and into a block whose SOLE
    # predecessor computed it. origin: id(src) -> (block, index of the instruction after which
    # it holds); a parameter arrives before the entry block's first instruction.
    origin: dict = {}
    params = {}
    for k, r in enumerate(_ARG_REGS):
        params[r] = {"source": f"argument {k + 1}", "source_site": faddr, "slot": None,
                     "kind": "param", "param": k}
        origin[id(params[r])] = (entry, -1, r)            # (block, instr index, defining register)
    tail: dict = {}
    tail_all: dict = {}                                   # full end-of-block state, for base carry
    head: dict = {}
    cx = {"origin": origin, "tail": tail, "head": head, "preds": preds, "dom": dom,
          "by_addr": by_addr, "bases": ("RBP", "RSP"),
          "cond_term": lambda m: m.startswith("j") and m != "jmp"}

    def seed_induction(ba, seed):
        """Carry each loop-invariant array base into every block of a loop containing `ba` (`tail` is
        idx-only, so a base register `lea rcx,[table]` hoisted out of the loop is otherwise lost and
        the in-loop access cannot resolve its array), and seed a loop header's register counter(s) at
        their header value. A base is taken from the NEAREST dominating block that defines it (most
        dominators = closest); it reaches on every path and is not written in the loop, so it is safe
        to seed in any loop block regardless of block-processing order."""
        for h in block_in_loops.get(ba, ()):
            body = all_loops[h]
            written = loop_writes.get(h, set())
            for d in sorted((d for d in dom.get(h, ()) if d != h and d not in body and d in tail_all),
                            key=lambda x: -len(dom.get(x, ()))):
                for r, v in tail_all[d].items():
                    if v and v[0] in ("ga", "fa", "sa", "ptr") and r not in written and r not in seed:
                        seed[r] = v
        for r, src in (reg_inductions.get(ba) or {}).items():
            seed[r] = ("idx", 1, 0, src)                  # the counter at its header value (R0)

    def check_for(src, ba, pred):
        if src.get("kind") == "induction" and not src.get("slot"):   # a register-held loop counter
            if src.get("descending"):
                if src.get("init_input_reg"):
                    return _reg_input_start_bound(src, ba, head, cx, by_addr, dom, preds, blocks,
                                                  _X86_CANON.get)
                return _descending_bound(blocks, by_addr, preds, ba, dom, src, _X86_CANON.get,
                                         ("cmp",), (), (), (),
                                         lambda op: _X86_CANON.get(op.lower()) == src["reg"],
                                         ("RBP", "RSP"))
            c = _induction_bound(
                blocks, by_addr, preds, ba, ("reg", src["reg"]), dom, ("RBP", "RSP"),
                lambda m: m.startswith("j") and m != "jmp",
                exit_const=lambda eb: _x86_exit_const(eb, src), loop_body=src["loop"],
                exit_unbounded=lambda eb: _exit_driven_by_input_call(eb, ("rax",), _X86_CANON.get))
            if c is not None:
                return c
            return _reg_loop_input_bound(src, ba, head, cx, by_addr, dom, preds, blocks,
                                         _X86_CANON.get, {"cmp"})
        if src.get("slot"):
            if src["block"] != ba and src["block"] not in dom.get(ba, ()):
                return None                           # the value does not reach on every path
            if src.get("kind") == "induction":        # a loop counter: read the loop's own bound
                if src.get("descending"):
                    return _descending_bound(
                        blocks, by_addr, preds, ba, dom, src, _X86_CANON.get, ("cmp",), (),
                        ("mov", "movsxd", "movsx", "movzx"), (),
                        lambda op: _frame_slot(_mem_terms(op, slot_names)) == src["slot"],
                        ("RBP", "RSP"))
                b = _induction_bound(
                    blocks, by_addr, preds, ba, src["slot"], dom, ("RBP", "RSP"),
                    lambda m: m.startswith("j") and m != "jmp",
                    exit_input=lambda eb: _exit_input_slot(eb, src["slot"], input_slots, slot_names),
                    exit_unbounded=lambda eb: _exit_driven_by_input_call(eb, ("rax",), _X86_CANON.get),
                    exit_const=lambda eb: _slot_exit_const(
                        eb, src, lambda op: _frame_slot(_mem_terms(op, slot_names)), _X86_CANON.get,
                        ("jne", "jnz"), ("mov", "movsxd", "movsx", "movzx"), (), ("cmp",)))
                return b if b is not None else _co_induction_bound(
                    src, slots, ba, blocks, by_addr, preds, dom, ("RBP", "RSP"),
                    lambda m: m.startswith("j") and m != "jmp")
            return _slot_check(blocks, ba, src["slot"], dom, slot_names)
        if id(src) not in origin:
            return None
        c = _reg_bound(src, ba, cx)                   # backward edge-aware walk (handles merges)
        if c is None and src.get("kind") in _IND_INPUT_KINDS:
            # The index here IS a raw unvalidated input (the tracker resolved it to idx*1+0), but the
            # backward walk was withheld -- typically because the register is also decremented in a
            # SURROUNDING loop (the x86 -O2 input-start descending loop gcc 2x-unrolls, whose PEELED
            # first iteration `table[n]=..` is a direct input index). Fall back to the dominator-only
            # length bound: no dominating guard -> unchecked, a `if(n<=k)` constant guard -> its bound
            # (silent in range), a VARIABLE guard (`if(i>=n)`) -> withheld (None -> silent). Dominator-
            # only, so it never reads a non-dominating branch; never a false positive.
            return _length_bound(by_addr, ba, src, cx)
        return c

    for b in blocks:
        ba = b.get("addr")
        ins = b.get("instructions") or []
        seed, pred = {}, None
        ps = preds.get(ba, [])
        if ba == entry:
            seed = {r: ("idx", 1, 0, params[r]) for r in _ARG_REGS}
        elif len(ps) == 1 and ps[0] in tail and ps[0] != ba:
            pred = ps[0]
            seed = dict(tail[pred])
        else:
            proc = [p for p in ps if p in tail and p != ba]
            if proc and len(proc) == len([p for p in ps if p != ba]):
                for r, v in tail[proc[0]].items():        # a MERGE: carry a register common to all
                    if v and v[0] == "idx" and all(_same_idx(tail[p].get(r), v) for p in proc[1:]):
                        seed[r] = v
        seed_induction(ba, seed)                          # register loop counter + its array base
        head[ba] = dict(seed)
        tr = _IdxTracker(ctx, slots, slot_names, seed)
        for j, i in enumerate(ins):
            body = (i.get("text") or "").split(";")[0].strip()
            mnem, ops = _ops(body)
            rsrc = None
            if mnem == "call":
                if _norm_call(body) in _INT_PARSERS:
                    pre = [(x.get("text") or "") for x in ins[:j]]
                    if _addr_for_reg(pre, "rdi") is None and not _str_flag_for_reg(pre, "rdi"):
                        rsrc = {"source": _norm_call(body), "source_site": i.get("addr"),
                                "slot": None, "kind": "register"}
                        origin[id(rsrc)] = (ba, j, "rax")     # the parser result lands in rax
            # A `call`, or a TAIL `jmp <func>` (how -O2 forwards a parameter: `outer: jmp inner`),
            # that passes an input index as an argument, unscaled. Two kinds, both recorded so pass
            # 2 can chain them: a value the caller PARSED itself (kind != param) is an entry into
            # the cross-function join; the caller's OWN parameter forwarded on (kind == param) is a
            # middle edge -- following it is how a register-carried index crosses MORE THAN ONE edge.
            callee = None
            if mnem == "call":
                callee = targets.get(_naddr(i.get("addr")))
            elif mnem == "jmp" and ops and resolve_tail is not None:
                callee = resolve_tail(ops[0])                 # a tail call leaves `faddr` for callee
                if callee == _naddr(faddr):
                    callee = None                             # a self-loop jmp, not a tail call
            if callee is not None:
                passed = {}
                for k, r in enumerate(_ARG_REGS):
                    v = tr.st.get(r)
                    if v and v[0] == "idx" and v[1] == 1 and v[2] == 0:
                        passed[k] = (v[3], check_for(v[3], ba, pred))
                if passed:
                    calls.append((faddr, i.get("addr"), callee, passed))
            hit = tr.step(mnem, ops, reg_source=rsrc)
            if not hit:
                continue
            (_p, base, scale, off, src), access = hit
            check = check_for(src, ba, pred)
            if check is None:
                continue
            if src.get("kind") == "param":
                summaries[_naddr(faddr)].append((faddr, i.get("addr"), base, scale, off,
                                                 src["param"], access, check))
                continue
            v = (_induction_verdict(check, base, scale, off, src) if src.get("kind") == "induction"
                 else _index_verdict(check, base, scale, off))
            if v is None:
                continue
            verdict, oob = v
            out.append(_array_index_cand(faddr, i.get("addr"), base, scale, off, src, access,
                                         check, verdict, oob))
        tail[ba] = {r: v for r, v in tr.st.items() if v[0] == "idx"}
        tail_all[ba] = dict(tr.st)


# ---- aarch64 CWE-129 ---------------------------------------------------------------------------
# The x86 _IdxTracker (operand syntax, SysV registers, [base+idx*scale+disp]) does not fit aarch64,
# so this is a separate, conservative scanner for the commonest shape: an input/parameter integer,
# sign-extended, indexing a GLOBAL array with `str/ldr wN, [xBase, xIdx, lsl #s]`. The index arrives
# either SPILLED to a frame slot (-O0: `str w0,[var]; ldrsw xI,[var]`) or held in a REGISTER (-O2:
# the strtol result / a parameter in w0 used straight in `[xB, w0, sxtw #s]`), tracked across one
# block edge. The DOMINATING-CHECK analysis is reused unchanged -- bounds.guard_bound /
# branch_predicate / _edge_pred_bound work on P-Code, which is architecture-neutral (measured: they
# read `cmp wI,#9; b.gt` as signed and `b.hi` as unsigned correctly) -- with the aarch64 frame bases
# (SP, X29) and a stack-slot key ("SP", frame_offset) or a ("reg", NAME) key. The CROSS-FUNCTION
# join is wired: a parameter-indexed access is recorded (not emitted) and a `bl`/`blr` (or a -O2
# tail-call `b <func>`) that forwards an input/parameter argument is recorded, so the shared
# `_array_index_join` follows input across call edges exactly as on x86 -- a bare parameter alone is
# no longer a finding. The index is still carried at most one BLOCK edge WITHIN a function, so a
# deeper intra-function carry is silent not wrong, and anything the tracker cannot resolve is dropped.
_A64_ARG = ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
_A64_NO_IDX_WRITE = {"cmp", "cmn", "tst", "str", "strb", "strh", "stp", "stur", "b", "bl", "blr",
                     "ret", "nop", "cbz", "cbnz", "tbz", "tbnz"}


def _A64_COND_TERM(mnem):
    return mnem.startswith("b.") or mnem in ("cbz", "cbnz", "tbz", "tbnz")


def _a64_canon(reg):
    """The 64-bit name for an aarch64 register token (`w3`->`x3`, `wsp`/`sp`->`sp`), else the token."""
    r = (reg or "").lower()
    if r in ("sp", "wsp"):
        return "sp"
    m = re.fullmatch(r"[wx](\d+|zr)", r)
    return ("x" + m.group(1)) if m else r


def _a64_mem(op, names):
    """Classify an aarch64 memory operand: ('slot', offset, name) for a named frame local
    `[var_2ch]`; ('indexed', base, idx, scale) for an `[xB, xI, lsl #s]` / `[xB, wI, sxtw #s]` /
    `[xB, xI]` array access; ('base', reg, disp) for `[xN]` / `[xN, #imm]`; or None."""
    m = re.search(r"\[([^\]]*)\]", op or "")
    if not m:
        return None
    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
    if not parts:
        return None
    if len(parts) == 1:
        tok = parts[0]
        if names and tok in names:
            return ("slot", int(names[tok]), tok)
        if re.fullmatch(r"[wx]\d+|sp|wsp", tok.lower()):
            return ("base", _a64_canon(tok), 0)
        return None
    base = parts[0]
    if not re.fullmatch(r"[wx]\d+|sp|wsp", base.lower()):
        return None
    base = _a64_canon(base)
    second = parts[1]
    if second.startswith("#") or _NUM.match(second.lstrip("#")):
        return ("base", base, int(second.lstrip("#"), 0))          # [xN, #imm]
    if re.fullmatch(r"[wx]\d+", second.lower()):
        scale = 1
        if len(parts) >= 3:                                        # lsl #s / sxtw #s / uxtw #s
            s = re.search(r"(?:lsl|sxtw|uxtw|sxtx)\s*#?(0x[0-9a-fA-F]+|\d+)", parts[2].lower())
            if s:
                scale = 1 << int(s.group(1), 0)
            elif not re.search(r"(?:sxtw|uxtw|sxtx)\b", parts[2].lower()):
                return None                                        # an extend with no shift is x1
        return ("indexed", base, _a64_canon(second), scale)
    return None


def _a64_adrp_const(instr):
    """The page address an `adrp xN, _` materialises, read from its P-Code (`COPY const:C -> reg:xN`);
    the disassembly text's symbol is often a nearby reloc, so the P-Code constant is the truth."""
    for pc in instr.get("pcode", []) or []:
        m = re.match(r"COPY const:(0x[0-9a-fA-F]+|\d+):\d+ -> reg:(\w+)", pc)
        if m:
            return int(m.group(1), 0)
    return None


def _a64_index_slots(ctx, blocks, names, entry):
    """Frame-slot offset -> source dict, for a slot that holds a parsed input integer or an incoming
    PARAMETER, written exactly once and whose address is never taken (`add xN, sp/x29, #off`) -- so
    nothing can re-bound it unseen. Conservative: on any doubt the slot is dropped."""
    writes: dict = defaultdict(list)                               # offset -> [instr addr]
    taken = set()                                                  # offsets whose &addr escaped
    for b in blocks:
        for i in b.get("instructions") or []:
            body = (i.get("text") or "").split(";")[0].strip()
            mnem, ops = _ops(body)
            if not ops:
                continue
            if mnem.startswith("st"):                              # str/strb/strh/stp/stur
                mm = _a64_mem(ops[-1], names)
                if mm and mm[0] == "slot":
                    writes[mm[1]].append(_naddr(i.get("addr")))
            if mnem == "add" and len(ops) == 3 and ops[1].lower() in ("sp", "x29") \
                    and _NUM.match(ops[2].lstrip("#")):
                taken.add(int(ops[2].lstrip("#"), 0))              # add xN, sp, #off  == &slot
    out = {}
    # a parser result spilled: `bl <parser>` then `str w0, [slot]` within a few instructions
    for b in blocks:
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            body = (i.get("text") or "").split(";")[0].strip()
            mnem, ops = _ops(body)
            if mnem not in ("bl", "blr") or not ops:
                continue
            name = normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", ops[0]))
            if name not in _INT_PARSERS:
                continue
            for i2 in ins[j + 1:j + 4]:
                m2, o2 = _ops((i2.get("text") or "").split(";")[0].strip())
                if m2 == "str" and o2 and o2[0].lower() in ("w0", "x0"):
                    mm = _a64_mem(o2[-1], names)
                    if mm and mm[0] == "slot":
                        out[mm[1]] = {"source": name, "source_site": i.get("addr"),
                                      "slot": ("SP", mm[1]), "slot_name": mm[2], "kind": "parsed"}
                    break
                if m2 in ("bl", "blr"):
                    break
    # an incoming parameter spilled in the entry block: `str wK, [slot]`, arg reg not yet clobbered
    e = next((b for b in blocks if b.get("addr") == entry), blocks[0])
    clob = set()
    for i in e.get("instructions") or []:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if mnem in ("bl", "blr"):
            break
        if mnem == "str" and len(ops) == 2 and _a64_canon(ops[0]) in _A64_ARG \
                and _a64_canon(ops[0]) not in clob:
            mm = _a64_mem(ops[1], names)
            if mm and mm[0] == "slot" and mm[1] not in out:
                k = _A64_ARG.index(_a64_canon(ops[0]))
                out[mm[1]] = {"source": f"argument {k + 1}", "source_site": i.get("addr"),
                              "slot": ("SP", mm[1]), "slot_name": mm[2], "kind": "param", "param": k}
        if ops and re.fullmatch(r"[wx]\d+", ops[0].lower()) and mnem not in _A64_NO_IDX_WRITE:
            clob.add(_a64_canon(ops[0]))
    # keep only single-writer, address-never-taken slots
    return {o: s for o, s in out.items()
            if o not in taken and len(writes.get(o, [])) == 1}


def _a64_classify_store(ins, j, src_reg, off, names, input_slots=None):
    """Classify a `str <src_reg>, [slot@off]` at index j: ('init', c) for a constant initialiser
    (`str wzr` or a preceding `mov src,#c`), ('step', k) for a `ldr t,[slot]; add src,t,#k; str src`
    increment of the SAME slot, ('input', n_off) when src was just loaded from an unvalidated-INPUT
    slot (`ldr src,[n]; str src,[i]` -- the descending input-start counter `i=n`), or ('other',)."""
    src = _a64_canon(src_reg)
    if src == "xzr" or (src_reg or "").lower() in ("wzr", "xzr"):
        return ("init", 0)
    for k in range(j - 1, max(-1, j - 6), -1):            # the last definition of src before the store
        m, o = _ops((ins[k].get("text") or "").split(";")[0].strip())
        if not o or _a64_canon(o[0]) != src:
            continue
        if m == "mov" and len(o) == 2 and _NUM.match(o[1].lstrip("#")):
            return ("init", int(o[1].lstrip("#"), 0))
        if m in ("add", "sub") and len(o) == 3 and _NUM.match(o[2].lstrip("#")):
            tmp = _a64_canon(o[1])
            for k2 in range(k - 1, max(-1, k - 4), -1):   # tmp = load of the same slot
                m2, o2 = _ops((ins[k2].get("text") or "").split(";")[0].strip())
                if o2 and _a64_canon(o2[0]) == tmp and m2 in ("ldr", "ldrsw"):
                    mm = _a64_mem(o2[-1], names)
                    if mm and mm[0] == "slot" and mm[1] == off:
                        k0 = int(o[2].lstrip("#"), 0)
                        return ("step", k0 if m == "add" else -k0)   # `sub` -> DESCENDING counter
            return ("other",)
        if input_slots is not None and m in ("ldr", "ldrsw") and len(o) >= 2:
            mm = _a64_mem(o[-1], names)
            if mm and mm[0] == "slot" and mm[1] in input_slots:
                return ("input", mm[1])                  # i = n, a copy of an unvalidated-input slot
        return ("other",)
    return ("other",)


def _a64_reg_const_init(by_addr, dom, header, body, reg):
    """The non-negative constant `reg` holds on entry to an aarch64 loop, read from its single
    dominating preheader (`mov xD,#c` / `mov xD,wzr` as that block's last write to reg), or None.
    The aarch64 twin of `_reg_const_init`, used only for a DESCENDING counter whose bound is the
    init (an ascending reg counter takes its bound from the exit test and needs no init)."""
    pre = [d for d in dom.get(header, ()) if d != header and d not in body]
    if len(pre) != 1:
        return None
    init = None
    for i in (by_addr.get(pre[0]) or {}).get("instructions") or []:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops or _a64_canon(ops[0]) != reg:
            continue
        if mnem == "mov" and len(ops) == 2 and _NUM.match(ops[1].lstrip("#")):
            init = int(ops[1].lstrip("#"), 0)
        elif mnem == "mov" and len(ops) == 2 and ops[1].lower() in ("wzr", "xzr"):
            init = 0
        else:
            init = None                                   # an opaque write: value unknown from here
    return init


def _a64_induction_regs(blocks, preds, succ_map, dom, by_addr):
    """Registers that are LOOP INDUCTION VARIABLES held in a REGISTER on aarch64 (the `-O2` shape, e.g.
    `str w1,[x2,x1,lsl #2]; add x1,x1,#1; cmp w0,w1; b.gt`). A register qualifies iff it has EXACTLY
    ONE constant positive self-increment (`add xD,xD,#k`) in the loop and no other writer -- so inside
    the loop it only increments. The entry value is not required (the bound comes from the loop's exit
    test, not the init). Returns {header -> {reg: src}}. See `_induction_regs` (the x86 twin)."""
    out: dict = defaultdict(dict)
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        steps: dict = defaultdict(list)
        other: dict = defaultdict(int)
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                if not ops or not re.fullmatch(r"[wx]\d+", ops[0].lower()):
                    continue                              # not a write to a general register
                dst = _a64_canon(ops[0])
                if mnem in ("add", "sub") and len(ops) == 3 and _a64_canon(ops[1]) == dst \
                        and _NUM.match(ops[2].lstrip("#")):
                    steps[dst].append((int(ops[2].lstrip("#"), 0) * (1 if mnem == "add" else -1),
                                       i.get("addr")))
                elif mnem not in _A64_NO_IDX_WRITE:
                    other[dst] += 1
        for reg, st in steps.items():
            if other.get(reg) or len(st) != 1 or st[0][0] == 0:
                continue
            if st[0][0] < 0:                              # a DESCENDING counter: greatest index is the
                init = _a64_reg_const_init(by_addr, dom, header, body, reg)       # init (const or input)
                base = {"source": "loop counter", "source_site": st[0][1], "slot": None,
                        "slot_name": None, "kind": "induction", "reg": reg, "step": st[0][0],
                        "header": header, "loop": frozenset(body), "descending": True}
                if init is not None and init >= 0:
                    out[header][reg] = {**base, "init": init}
                else:                                     # init not a known constant: an input start is
                    out[header][reg] = {**base, "init": None, "init_input_reg": True}     # resolved later
                continue
            out[header][reg] = {"source": "loop counter", "source_site": st[0][1], "slot": None,
                                "slot_name": None, "kind": "induction", "reg": reg, "step": st[0][0],
                                "init": 0, "header": header, "loop": frozenset(body)}
    return out


def _a64_induction_slots(blocks, names, input_slots=None):
    """Frame slots that are LOOP INDUCTION VARIABLES on aarch64: one initialiser (constant `str wzr` /
    `mov w,#c; str w`, or a copy of an unvalidated-INPUT slot `ldr w,[n]; str w`) and one load-add-store
    step (`ldr w,[s]; add w,w,#k; str w,[s]`), &addr never taken, no other writer. Returned as index
    sources (kind 'induction'), same as the x86 detector. `input_slots` names the input slot offsets."""
    taken = set()
    stores: dict = defaultdict(list)                      # offset -> [(addr, slot_name, class, block)]
    for b in blocks:
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            if mnem == "add" and len(ops) == 3 and ops[1].lower() in ("sp", "x29") \
                    and _NUM.match(ops[2].lstrip("#")):
                taken.add(int(ops[2].lstrip("#"), 0))
            if mnem == "str" and len(ops) >= 2:
                mm = _a64_mem(ops[-1], names)
                if mm and mm[0] == "slot":
                    stores[mm[1]].append((i.get("addr"), mm[2],
                                          _a64_classify_store(ins, j, ops[0], mm[1], names, input_slots),
                                          b.get("addr")))
    out = {}
    for off, lst in stores.items():
        if off in taken:
            continue
        inits = [s for s in lst if s[2][0] == "init"]
        inputs = [s for s in lst if s[2][0] == "input"]
        steps = [s for s in lst if s[2][0] == "step"]
        if len(lst) == 2 and len(inputs) == 1 and len(steps) == 1 and steps[0][2][1] < 0:
            out[off] = {"source": "loop counter", "source_site": inputs[0][0], "slot": ("SP", off),
                        "slot_name": inputs[0][1], "kind": "induction", "init": None,
                        "step": steps[0][2][1], "step_block": steps[0][3],
                        "init_input": ("SP", inputs[0][2][1]), "descending": True}
        elif len(lst) == 2 and len(inits) == 1 and len(steps) == 1 \
                and inits[0][2][1] >= 0 and steps[0][2][1] != 0:
            out[off] = {"source": "loop counter", "source_site": inits[0][0], "slot": ("SP", off),
                        "slot_name": inits[0][1], "kind": "induction",
                        "init": inits[0][2][1], "step": steps[0][2][1], "step_block": steps[0][3]}
            if steps[0][2][1] < 0:                         # a DESCENDING counter: max index is the init
                out[off]["descending"] = True
    return out


def _a64_exit_input_slot(exit_blk, i_off, input_slots, names):
    """The INPUT slot the loop's exit compares the induction slot against (`i < n`) on aarch64, or
    None. aarch64 loads both into registers (`ldr wi,[i]; ldr wn,[n]; cmp wi,wn`), so the exit block
    reads the induction slot AND loads an input slot. `input_slots` (from `_a64_index_slots`) already
    drops a re-written/clamped n; the caller still checks n has no dominating bound."""
    ins = (exit_blk or {}).get("instructions") or []
    reads_i = False
    nslot = None
    has_cmp = False
    for i in ins:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops:
            continue
        if mnem in ("cmp", "cmn", "subs"):
            has_cmp = True
        if mnem in ("ldr", "ldrsw", "ldrsb", "ldrsh", "ldrb", "ldrh") and len(ops) >= 2:
            mm = _a64_mem(ops[-1], names)
            if mm and mm[0] == "slot":
                if mm[1] == i_off:
                    reads_i = True
                elif mm[1] in input_slots:
                    nslot = ("SP", mm[1])
    return nslot if (reads_i and has_cmp) else None


def _arm_slot_check(blocks, by_addr, site_block, slot, dom, bases, cond_term, touch_pred):
    """`_slot_check` for an ARM-family ISA: the P-Code bounds analysis with the ISA's frame bases
    and a (base, off) slot key -- a dominating branch that READS the slot but the evaluator cannot
    turn into a bound -> None (no claim). aarch64 uses ("SP", positive off); arm32 uses ("R11",
    negative off). `cond_term(mnem)` recognises the ISA's conditional branch; `touch_pred(text)`
    recognises an instruction that reads the slot."""
    from . import bounds
    # guard_bound is authoritative: a bound it finds is real, so trust it before the fallback guard
    # below (which only decides unchecked-vs-undecidable when no bound was found). Without this
    # order a block that both DEFINES and checks the index -- `str r0,[k]; cmp r0,#0; blt` on arm32
    # -O0, where the store makes branch_predicate over the whole block read nothing -- would be
    # called undecidable even though guard_bound correctly saw the bound.
    g = bounds.guard_bound(blocks, site_block, slot, bases=bases, dom=dom)
    if g is not None:
        return ("bounded", g["bound"], bool(g["nonneg"]))
    for d in dom.get(site_block, ()):
        if d == site_block:
            continue
        ins = (by_addr.get(d) or {}).get("instructions") or []
        if not ins:
            continue
        last = _ops((ins[-1].get("text") or "").split(";")[0].strip())[0]
        if cond_term(last) and any(touch_pred(i.get("text") or "") for i in ins) \
                and bounds.branch_predicate(ins, slot, bases) is None:
            return None                                   # a dominating branch reads it, unreadably
    return ("unchecked",)


def _index_record(summaries, out, faddr, site, base, scale, off, src, access, chk):
    """Route one array-index hit (shared by the aarch64 and arm32 scanners). A PARAMETER-sourced
    index goes to `summaries` for the cross-function join -- it is a finding only once input is shown
    to reach that parameter, combining the check at each edge. Any other source (self-parsed input)
    is a finding right here. An undecidable check (`chk` is None) is dropped, never guessed."""
    if chk is None:
        return
    if src.get("kind") == "param":
        summaries[_naddr(faddr)].append((faddr, site, base, scale, off, src["param"], access, chk))
        return
    v = (_induction_verdict(chk, base, scale, off, src) if src.get("kind") == "induction"
         else _index_verdict(chk, base, scale, off))
    if v is not None:
        verdict, oob = v
        out.append(_array_index_cand(faddr, site, base, scale, off, src, access, chk, verdict, oob))


def _record_forward(calls, reg, arg_regs, faddr, site, callee, check_for, ba, pred):
    """Record the input/parameter arguments a call or tail call forwards -- an UNSCALED index value
    (`("idx", 1, 0, src)`) live in an argument register, with the check the caller applies on the
    way -- as an edge for the cross-function join. Nothing live to forward records nothing."""
    passed = {}
    for k, r in enumerate(arg_regs):
        v = reg.get(r)
        if v and v[0] == "idx" and v[1] == 1 and v[2] == 0:
            passed[k] = (v[3], check_for(v[3], ba, pred, r))
    if passed:
        calls.append((faddr, site, callee, passed))


def _a64_store_width(mnem, regops):
    """The byte width an aarch64 store writes: strb/strh are 1/2; otherwise the stored register's
    view (w/s=4, x/d=8, q=16), doubled for a store-pair (`stp`). None when not a plain store."""
    if mnem in ("strb", "sturb"):
        return 1
    if mnem in ("strh", "sturh"):
        return 2
    regs = [o for o in regops if re.fullmatch(r"[wxsdq]\d+", (o or "").lower())]
    if not regs:
        return None
    per = {"w": 4, "s": 4, "x": 8, "d": 8, "q": 16}.get(regs[0][0].lower())
    if per is None:
        return None
    return per * (2 if mnem in ("stp", "stnp") else 1)


def _a64_const_oob_stores(ctx, faddr, blocks, out):
    """A CONSTANT-OFFSET store that writes past a known-size global array -- the `-O2` fully unrolled /
    vectorised overrun (`for(i=0;i<=10;i++) t[i]=i` becomes straight-line SIMD plus `str w1,[x0,#40]`
    into a 10-int array), which carries no loop or index register for the induction path to see.
    `adrp+add` gives the base pointer's absolute address; a store at `[base, #imm]` whose byte offset
    into the RESOLVED object plus the store width exceeds the object's st_size is a CWE-129 overrun.
    Straight-line within a block (the unrolled body has no branches); a known symbol size is required,
    so an opaque base or a size-0 symbol (a flexible array) stays silent -- never a false positive."""
    for b in blocks:
        gaddr: dict = {}                                  # reg -> absolute address of a global pointer
        for i in b.get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _a64_canon(ops[0])
            if mnem == "adrp":
                c = _a64_adrp_const(i)
                gaddr[dst] = c if c is not None else gaddr.pop(dst, None)
                continue
            if mnem == "add" and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                s = _a64_canon(ops[1])
                gaddr[dst] = gaddr[s] + int(ops[2].lstrip("#"), 0) if s in gaddr else gaddr.pop(dst, None)
                continue
            if mnem.startswith("st"):
                mm = _a64_mem(ops[-1], None)
                if mm and mm[0] == "base" and mm[1] in gaddr:
                    width = _a64_store_width(mnem, ops[:-1])
                    g = _global_base(ctx, addr=gaddr[mm[1]]) if width else None
                    if g and g[1] is not None and g[2]:   # resolved to a global with a known size
                        eff = g[3] + mm[2]                 # byte offset into the object
                        base = ("global", g[0], g[1], g[2])
                        v = _index_verdict(("bounded", eff // width, True), base, width, eff % width) \
                            if eff >= 0 else None
                        if v is not None:
                            verdict, oob = v
                            src = {"source": "a constant offset", "source_site": i.get("addr"),
                                   "slot": None, "kind": "constant"}
                            out.append(_array_index_cand(
                                faddr, i.get("addr"), base, width, eff % width, src, "write",
                                ("bounded", eff // width, True), verdict, oob))
                continue
            if dst and dst in gaddr and re.fullmatch(r"[wx]\d+", ops[0].lower()):
                gaddr.pop(dst, None)                       # any other write clobbers the pointer


def _a64_global_ptr_init(ctx, by_addr, dom, header, body, p):
    """A register's INITIAL value as a known-size global object (`adrp p,page; add p,p,#off`) in a
    dominating preheader, as ('global', name, addr, sz), or None."""
    g = None
    page: dict = {}
    for d in sorted((x for x in dom.get(header, ()) if x != header and x not in body),
                    key=lambda x: len(dom.get(x, ()))):
        for i in (by_addr.get(d) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _a64_canon(ops[0])
            if mnem == "adrp":
                c = _a64_adrp_const(i)
                page[dst] = c
                if dst == p:
                    g = None
            elif mnem == "add" and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")) \
                    and _a64_canon(ops[1]) in page and page[_a64_canon(ops[1])] is not None:
                gb = _global_base(ctx, addr=page[_a64_canon(ops[1])] + int(ops[2].lstrip("#"), 0))
                if dst == p:
                    g = ("global", gb[0], gb[1], gb[2]) if (gb and gb[1] is not None and gb[2]) else None
            elif dst == p and re.fullmatch(r"[wx]\d+", ops[0].lower()):
                g = None                                            # p redefined by something else
    return g


def _store_through_ptr_a64(mnem, ops):
    """(ptr_reg, stride, width) for an aarch64 POST-INDEX store `str REG,[p],#k` (p walks by k each
    iteration, storing through p) -- the `-O2` `*q++ = ...` walking write -- else None."""
    if not mnem.startswith("st") or mnem in ("stp", "stnp") or len(ops) != 3:
        return None
    m = re.fullmatch(r"\[([wx]\d+|sp)\]", ops[1].replace(" ", ""))
    if not m or not _NUM.match(ops[2].lstrip("#")):
        return None
    w = {"strb": 1, "sturb": 1, "strh": 2, "sturh": 2}.get(mnem,
                                                           4 if ops[0].lower().startswith("w") else 8)
    return (_a64_canon(m.group(1)), int(ops[2].lstrip("#"), 0), w)


def _a64_reg_written_in(body, by_addr, reg):
    """True if `reg` is the explicit destination of any non-store write in the loop body -- i.e. some
    write OTHER than the walking store's own implicit post-index writeback (whose operand-0 is the
    stored value, not the pointer). Such a write means it is not a clean one-step walk."""
    for la in body:
        for i in (by_addr.get(la) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if ops and re.fullmatch(r"[wx]\d+", ops[0].lower()) and _a64_canon(ops[0]) == reg \
                    and mnem not in _A64_NO_IDX_WRITE:
                return True
    return False


def _a64_unbounded_walk(ctx, faddr, blocks, preds, succ_map, dom, by_addr, out, call_names=None):
    """aarch64 `-O2` UNBOUNDED walking-pointer write: `adrp/add x19,table; str w0,[x19],#4` (post-index)
    with the loop exit driven by an input-reading call (`bl getc; cmn w0,#1; b.ne`), no counter, no
    bound -- an input-controlled overrun of the fixed array -> unchecked. Single-exit, input-call exit,
    a known-size global base, and p walked only by its one post-index step are all required."""
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, header, dom)
        if not ok or exit_src is None:
            continue
        if not _exit_driven_by_input_call(by_addr.get(exit_src), ("x0", "w0"), _a64_canon, call_names):
            continue
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                sw = _store_through_ptr_a64(mnem, ops)
                if sw is None or sw[1] <= 0 or _a64_reg_written_in(body, by_addr, sw[0]):
                    continue
                gbase = _a64_global_ptr_init(ctx, by_addr, dom, header, body, sw[0])
                if gbase is None:
                    continue
                v = _index_verdict(("unchecked",), gbase, sw[2], 0)
                if v is None:
                    continue
                verdict, oob = v
                src = {"source": "a walking pointer", "source_site": i.get("addr"), "slot": None,
                       "slot_name": None, "kind": "walk"}
                out.append(_array_index_cand(faddr, i.get("addr"), gbase, sw[2], 0, src, "write",
                                             ("unchecked",), verdict, oob))
                return


def _array_index_arm(ctx, summaries, calls, targets, resolve_tail, out):
    """aarch64 CWE-129, pass 1. Per function: an access indexed by self-parsed input is emitted
    directly; an access indexed by a PARAMETER is recorded in `summaries`, and a call (or tail call)
    forwarding an input/parameter value in `calls`, for the shared cross-function join."""
    from . import bounds
    # a `bl` target is a bare address on the ghidra backend, so resolve the callee NAME through the
    # call graph (as arm32 does) -- the input-reading-call exit test needs the name
    call_names = {_naddr(e.site_addr): normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "",
                                                        e.dst_name))
                  for e in (ctx.call_edges or []) if getattr(e, "dst_name", None)}
    for faddr, ir in ctx.func_irs.items():
        blocks = [b for b in ((ir or {}).get("blocks") or [])
                  if isinstance(b, dict) and b.get("addr")]
        if blocks and len(blocks) <= 2000:
            _a64_scan_function(ctx, faddr, blocks, summaries, calls, targets, resolve_tail, out,
                               call_names)
            _a64_const_oob_stores(ctx, faddr, blocks, out)
            preds: dict = defaultdict(list)
            succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
            for b in blocks:
                for sc in b.get("succ") or []:
                    preds[sc].append(b.get("addr"))
            _a64_unbounded_walk(ctx, faddr, blocks, preds, succ_map, bounds.dominators(blocks),
                                {b.get("addr"): b for b in blocks}, out, call_names)


def _has_pcode(blocks) -> bool:
    """Does this function carry P-Code? The dominating-check analysis is P-Code-based, so WITHOUT
    it `guard_bound` sees no guard and every indexed access would read as `unchecked` -- a false
    finding over a checked access. A backend that emits no P-Code for an ISA (measured: the native
    backend gives none for 32-bit ARM) must therefore make the scan SILENT, not blind."""
    return any((i.get("pcode") for b in blocks for i in (b.get("instructions") or [])))


def _a64_scan_function(ctx, faddr, blocks, summaries, calls, targets, resolve_tail, out,
                       call_names=None):
    """The aarch64 CWE-129 scan over ONE function (its own scope, so `check_for` binds cleanly).
    A self-parsed input index is emitted here; a parameter index goes to `summaries` and a
    forwarded argument to `calls`, both joined across call edges by `_array_index_join`."""
    from . import bounds
    if not _has_pcode(blocks):                            # no P-Code -> the check is invisible -> silent
        return
    frame = ctx.frames.get(faddr) or {}
    _vs, names = _frame_vars(frame)
    entry = next((b.get("addr") for b in blocks if _naddr(b.get("addr")) == _naddr(faddr)),
                 blocks[0].get("addr"))
    slots = _a64_index_slots(ctx, blocks, names, entry)
    a64_input_slots = {off for off, s in slots.items() if s.get("kind") in ("parsed", "pointer")}
    for off, src in _a64_induction_slots(blocks, names, a64_input_slots).items():
        slots.setdefault(off, src)
    dom = bounds.dominators(blocks)
    by_addr = {b.get("addr"): b for b in blocks}
    preds: dict = defaultdict(list)
    succ_map: dict = {}
    for b in blocks:
        succ_map[b.get("addr")] = tuple(b.get("succ") or ())
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    reg_inductions = _a64_induction_regs(blocks, preds, succ_map, dom, by_addr)   # -O2 register counters
    # every natural loop, so a hoisted loop-invariant array base (`adrp/add x1,table`) is carried into
    # its blocks below -- `tail` is idx-only, so otherwise the in-loop access cannot resolve its array
    all_loops = _reg_natural_loops(blocks, preds, succ_map, dom)
    loop_writes: dict = {}
    block_in_loops: dict = defaultdict(list)
    for h, body in all_loops.items():
        w = set()
        for la in body:
            block_in_loops[la].append(h)
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
                if m2 in ("bl", "blr"):
                    w.update(f"x{n}" for n in range(0, 18))   # a call clobbers x0-x17
                elif o2 and re.fullmatch(r"[wx]\d+", o2[0].lower()) and m2 not in _A64_NO_IDX_WRITE:
                    w.add(_a64_canon(o2[0]))
        loop_writes[h] = w
    _attach_slot_loops(slots, all_loops, block_in_loops)  # slot inductions get their loop body
    # A register-held index is followed within its block and into a block whose SOLE predecessor
    # defined it. origin: id(src) -> (block, instr index after which it holds); a parameter
    # arrives before the entry block. tail: block -> {reg: idx-value} live at the block end.
    origin: dict = {}
    params: dict = {}
    for k, r in enumerate(_A64_ARG):
        params[r] = {"source": f"argument {k + 1}", "source_site": faddr, "slot": None,
                     "slot_name": None, "kind": "param", "param": k}
        origin[id(params[r])] = (entry, -1, r)            # (block, instr index, defining register)
    tail: dict = {}
    tail_all: dict = {}
    head: dict = {}
    cx = {"origin": origin, "tail": tail, "head": head, "preds": preds, "dom": dom,
          "by_addr": by_addr, "bases": ("SP", "X29"), "cond_term": _A64_COND_TERM}

    def check_for(src, ba, pred, idx_reg):
        if src.get("kind") == "induction" and not src.get("slot"):   # a register-held loop counter
            if src.get("descending"):
                if src.get("init_input_reg"):
                    return _reg_input_start_bound(src, ba, head, cx, by_addr, dom, preds, blocks,
                                                  _a64_canon)
                return _descending_bound(blocks, by_addr, preds, ba, dom, src, _a64_canon,
                                         ("cmp", "subs"), ("cmn",), (), (),
                                         lambda op: _a64_canon(op) == src["reg"], ("SP", "X29"))
            c = _induction_bound(blocks, by_addr, preds, ba, ("reg", src["reg"]), dom, ("SP", "X29"),
                                 _A64_COND_TERM, loop_body=src["loop"],
                                 exit_const=lambda eb: _loop_exit_const(eb, src, _a64_canon, ("b.ne",)))
            if c is not None:
                return c
            return _reg_loop_input_bound(src, ba, head, cx, by_addr, dom, preds, blocks,
                                         _a64_canon, {"cmp", "cmn", "subs"})
        if src.get("slot"):
            if src.get("kind") == "induction":            # a loop counter: read the loop's own bound
                if src.get("descending"):
                    return _descending_bound(
                        blocks, by_addr, preds, ba, dom, src, _a64_canon, ("cmp", "subs"), ("cmn",),
                        ("ldr", "ldrsw", "ldrb", "ldrh", "ldrsb", "ldrsh"), ("str", "strb", "strh"),
                        lambda op: (lambda mm: bool(mm) and mm[0] == "slot"
                                    and ("SP", mm[1]) == src["slot"])(_a64_mem(op, names)),
                        ("SP", "X29"))
                b = _induction_bound(blocks, by_addr, preds, ba, ("SP", src["slot"][1]), dom,
                                     ("SP", "X29"), _A64_COND_TERM,
                                     exit_input=lambda eb: _a64_exit_input_slot(
                                         eb, src["slot"][1], a64_input_slots, names),
                                     exit_unbounded=lambda eb: _exit_driven_by_input_call(
                                         eb, ("x0", "w0"), _a64_canon, call_names),
                                     exit_const=lambda eb: _slot_exit_const(
                                         eb, src, lambda op: (lambda mm: ("SP", mm[1]) if mm
                                                              and mm[0] == "slot" else None)(
                                             _a64_mem(op, names)),
                                         _a64_canon, ("b.ne",),
                                         ("ldr", "ldrsw", "ldrb", "ldrh", "ldrsb", "ldrsh"),
                                         ("str", "strb", "strh"), ("cmp", "subs")))
                return b if b is not None else _co_induction_bound(
                    src, slots, ba, blocks, by_addr, preds, dom, ("SP", "X29"), _A64_COND_TERM)
            nm = src["slot_name"]
            return _arm_slot_check(blocks, by_addr, ba, ("SP", src["slot"][1]), dom, ("SP", "X29"),
                                   _A64_COND_TERM, lambda t: ("[" + nm) in t)
        if id(src) not in origin:
            return None
        return _reg_bound(src, ba, cx)                    # backward edge-aware walk (handles merges)

    def seed_induction(ba, reg):
        """Carry each loop-invariant array base (`adrp/add x2,table` hoisted out of the loop -- a
        ('ga',...) value `tail` does not carry) into every block of a loop containing `ba`, and seed a
        header's register counter(s). See the x86 twin in `_index_scan_function`."""
        for h in block_in_loops.get(ba, ()):
            body = all_loops[h]
            written = loop_writes.get(h, set())
            for d in sorted((d for d in dom.get(h, ()) if d != h and d not in body and d in tail_all),
                            key=lambda x: -len(dom.get(x, ()))):
                for r, v in tail_all[d].items():
                    if v and v[0] in ("ga", "sa") and r not in written and r not in reg:
                        reg[r] = v
        for r, src in (reg_inductions.get(ba) or {}).items():
            reg[r] = ("idx", 1, 0, src)

    for b in blocks:
        ba = b.get("addr")
        ps = preds.get(ba, [])
        reg: dict = {}
        pred = None
        if ba == entry:
            reg = {r: ("idx", 1, 0, params[r]) for r in _A64_ARG}
        elif len(ps) == 1 and ps[0] in tail and ps[0] != ba:
            pred = ps[0]
            reg = dict(tail[pred])
        else:
            proc = [p for p in ps if p in tail and p != ba]
            if proc and len(proc) == len([p for p in ps if p != ba]):
                for r, v in tail[proc[0]].items():        # a MERGE: carry a register common to all
                    if v and v[0] == "idx" and all(_same_idx(tail[p].get(r), v) for p in proc[1:]):
                        reg[r] = v
        seed_induction(ba, reg)                           # -O2 register loop counter + its array base
        head[ba] = dict(reg)
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _a64_canon(ops[0])
            if mnem == "b" and ops:
                # a tail call (`b inner` at -O2 forwards a parameter): the live argument registers
                # carry the forwarded value and the function ends here. A plain `b` to a block
                # within this function is NOT a tail call (resolve_tail returns None).
                callee = resolve_tail(ops[0])
                if callee is not None and callee != _naddr(faddr):
                    _record_forward(calls, reg, _A64_ARG, faddr, i.get("addr"), callee,
                                    check_for, ba, pred)
                continue
            if mnem in ("bl", "blr"):
                # record a forwarded index BEFORE the call clobbers the argument registers: an
                # input/parameter value in x0-x7 (unscaled) passed to a known callee is an edge of
                # the cross-function join (a parsed value seeds it; the function's own parameter
                # carries it onward). Resolve the callee through the call graph, falling back to the
                # direct branch target when the decompiler left the call edge out (measured: ghidra
                # drops the edge for some direct `bl`s, which silently broke the seed).
                callee = targets.get(_naddr(i.get("addr"))) or resolve_tail(ops[0] if ops else "")
                if callee is not None:
                    _record_forward(calls, reg, _A64_ARG, faddr, i.get("addr"), callee,
                                    check_for, ba, pred)
                name = (call_names or {}).get(_naddr(i.get("addr"))) \
                    or (normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", ops[0])) if ops else "")
                for r in list(reg):                   # a call clobbers x0-x18/x30; x19-x28 are preserved
                    m = re.fullmatch(r"x(\d+)", _a64_canon(r))
                    if not (m and 19 <= int(m.group(1)) <= 29):
                        reg.pop(r, None)
                if name in _INT_PARSERS:
                    rsrc = {"source": name, "source_site": i.get("addr"), "slot": None,
                            "slot_name": None, "kind": "register"}
                    origin[id(rsrc)] = (ba, j, "x0")  # the parsed value lands in w0/x0
                    reg["x0"] = ("idx", 1, 0, rsrc)
                continue
            if mnem == "adrp":
                c = _a64_adrp_const(i)
                reg[dst] = ("gapage", c) if c is not None else None
                continue
            if mnem == "add" and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                imm = int(ops[2].lstrip("#"), 0)
                sreg = _a64_canon(ops[1])
                if sreg in ("sp", "x29"):
                    reg[dst] = ("sa", "SP", imm)               # &local: a stack array base
                    continue
                v = reg.get(sreg)
                if v and v[0] == "gapage":
                    g = _global_base(ctx, addr=v[1] + imm)
                    reg[dst] = ("ga", g[1], g[0], g[2]) if (g and g[1] is not None) else None
                elif v and v[0] == "idx":
                    reg[dst] = ("idx", v[1], v[2] + imm, v[3])
                elif v and v[0] == "sa":
                    reg[dst] = ("sa", v[1], v[2] + imm)
                else:
                    reg[dst] = None
                continue
            if mnem in ("lsl", "lsls") and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                v = reg.get(_a64_canon(ops[1]))                # a stack array scales the index HERE
                sh = int(ops[2].lstrip("#"), 0)                # (`lsl x0,x0,#2`), not in the operand
                reg[dst] = ("idx", v[1] << sh, v[2] << sh, v[3]) if (v and v[0] == "idx") else None
                continue
            mm = _a64_mem(ops[-1], names)
            if mm and mm[0] == "indexed":                      # an array access
                store = mnem.startswith("st")
                # the base is whichever operand holds the array address; the other is the index. When
                # neither operand is shifted (`[x0, x1]`, the vectorised `str q,[off,base]` walk), EITHER
                # may be the base, so try both orderings -- the lsl form `[xB, xI, lsl #s]` pins the
                # index to the second operand, so only that ordering is tried.
                orders = [(mm[1], mm[2])] + ([(mm[2], mm[1])] if mm[3] == 1 else [])
                for bkey, ikey in orders:
                    base = ("sa", "SP", 0) if bkey in ("sp", "x29") else reg.get(bkey)
                    idx = reg.get(ikey)
                    if base and base[0] in ("ga", "sa") and idx and idx[0] == "idx":
                        scale, off = idx[1] * mm[3], idx[2] * mm[3]
                        abase = (("global", base[2], base[1], base[3]) if base[0] == "ga"
                                 else ("stack", base[1], base[2]))
                        _index_record(summaries, out, faddr, i.get("addr"), abase, scale, off, idx[3],
                                      "write" if store else "read", check_for(idx[3], ba, pred, ikey))
                        break
                if not store:
                    reg[dst] = None                            # a load result is array data
                continue
            if mnem in ("ldr", "ldrsw", "ldrsb", "ldrsh", "ldrb", "ldrh") and mm \
                    and mm[0] == "slot" and mm[1] in slots:
                reg[dst] = ("idx", 1, 0, slots[mm[1]])          # the index value, from its slot
                continue
            if mnem in ("mov", "sxtw", "sxtb", "sxth", "uxtw", "uxtb", "uxth") and len(ops) == 2 \
                    and re.fullmatch(r"[wx]\d+", ops[1].lower()):
                # a sign/zero extension of the index IS the index value used for the access (`sxtw
                # x0,w0` on a non-negative loop counter) -- carry the source's tracked value through
                reg[dst] = reg.get(_a64_canon(ops[1]))
                continue
            if mnem not in _A64_NO_IDX_WRITE and re.fullmatch(r"[wx]\d+", ops[0].lower()):
                reg[dst] = None                                # any other write clobbers it
        tail[ba] = {r: v for r, v in reg.items() if v and v[0] == "idx"}
        tail_all[ba] = dict(reg)


# ---- arm32 CWE-129 -----------------------------------------------------------------------------
# Same conservative shape as the aarch64 scanner, for 32-bit ARM. Two differences carry the weight:
# (1) the global base comes from a PC-relative LITERAL POOL (`ldr r3,[0xLIT]; add r3,pc,r3`), not an
# adrp, so the literal word is read from the image and added to the instruction's PC; (2) the frame
# base is fp/r11 with NEGATIVE slot offsets, so the check key is ("R11", off) with bases (SP, R11).
# The P-Code dominating-check analysis is reused unchanged. SOUNDNESS GUARD for -O2 ARM conditional
# execution (a bound enforced WITHOUT a branch edge the P-Code reader models): a predicated RETURN or
# branch (`cmp r0,#9; popls`/`bxhi lr`) or a predicated multi-register transfer still skips the whole
# function (`_arm32_pred_unsound`) -- silent, never a false finding. But a predicated single-dest DATA
# op (`movhi r0,#0`, the common `-O2` return-value clamp, or a predicated index CLAMP) no longer
# skips the function: its destination is poisoned (made undecidable) in-line, so a clamp of the index
# suppresses only that access while a genuinely-unchecked access elsewhere is still flagged -- the
# recall gcc's conditional execution used to cost. At -O0 the checks are plain `cmp;b.cond` branches.
# Like aarch64, it feeds the shared CROSS-FUNCTION join: a parameter-indexed access is recorded (not
# emitted) and a `bl`/`blx` forwarding an input/parameter argument is recorded, so input is followed
# into a callee that indexes with the forwarded parameter; a bare parameter alone is not a finding.
_ARM32_ARG = ("r0", "r1", "r2", "r3")
_ARM32_NO_IDX_WRITE = {"cmp", "cmn", "tst", "teq", "str", "strb", "strh", "stm", "stmdb", "push",
                       "b", "bl", "blx", "bx", "nop", "pop", "ret"}
_ARM32_CONDS = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt",
                "gt", "le")
_ARM32_PRED_RE = re.compile(
    r"^(ldr|ldrb|ldrh|str|strb|strh|mov|movw|movt|mvn|add|adc|sub|sbc|rsb|rsc|and|orr|eor|bic|"
    r"mul|lsl|lsr|asr|ror|pop|push|ldm|ldmia|stm|stmdb|bx|blx|cmp|cmn|tst|teq)("
    + "|".join(_ARM32_CONDS) + r")$")
_ARM32_BRANCH_RE = re.compile(r"^b(" + "|".join(_ARM32_CONDS) + r")$")
# Predicated ops whose effect the edge-based bound analysis cannot model: a predicated RETURN/branch
# (`bxhi lr`, `pophi {..,pc}`, `ldmiahi {..,pc}`) enforces a bound on the fall-through with NO block
# edge, and a predicated multi-register load/store writes several registers at once. Their presence
# forces the whole function to be skipped (silent, never wrong). A predicated single-dest DATA op
# (`movhi r0,#0`) is handled in-line instead -- its destination is poisoned (made undecidable), so a
# predicated clamp of the INDEX suppresses only that access while a predicated write to an unrelated
# register leaves a genuinely-unchecked access flaggable.
_ARM32_PRED_CF_BASE = {"bx", "blx", "pop", "push", "ldm", "ldmia", "stm", "stmdb"}


def _ARM32_COND_TERM(mnem):
    return bool(_ARM32_BRANCH_RE.fullmatch(mnem))


def _arm32_pred_unsound(mnem, ops):
    """True for a predicated op that defeats the edge-based bound analysis (see _ARM32_PRED_CF_BASE):
    a predicated branch/return, a predicated multi-register transfer, or a predicated write to pc."""
    m = _ARM32_PRED_RE.fullmatch(mnem or "")
    if not m:
        return False
    return m.group(1) in _ARM32_PRED_CF_BASE or any(_arm32_canon(o) == "pc" for o in (ops or ()))


def _arm32_canon(reg):
    r = (reg or "").lower()
    return "r11" if r in ("fp", "r11") else r


def _arm32_isreg(tok):
    return bool(re.fullmatch(r"r\d+|fp|sp|lr|pc", (tok or "").lower()))


def _word_at(ctx, vaddr, n=4):
    """The little-endian integer of `n` bytes at virtual address `vaddr` in an allocated, file-backed
    section of the image (a literal-pool word), or None."""
    v = _naddr(vaddr)
    if v is None:
        return None
    secs, data = _image_sections(ctx)
    if not data:
        return None
    for sec in secs:
        if not (sec["flags"] & 2) or sec["type"] == 8 or not sec["addr"]:
            continue
        if sec["addr"] <= v < sec["addr"] + sec["size"]:
            off = sec["offset"] + (v - sec["addr"])
            return int.from_bytes(data[off:off + n], "little") if off + n <= len(data) else None
    return None


def _arm32_mem(op, names):
    """Classify an arm32 memory operand: ('slot', off, name) for an fp/r11-relative local
    `[fp, #-8]`; ('indexed', base, idx, scale) for `[rB, rI, lsl #s]` / `[rB, rI]`; ('base', reg,
    disp) for `[rN]` / `[rN, #imm]`; or None. A literal-pool `ldr rN,[0xADDR]` is handled by the
    scanner, not here."""
    m = re.search(r"\[([^\]]*)\]", op or "")
    if not m:
        return None
    parts = [p.strip() for p in m.group(1).split(",") if p.strip()]
    if not parts:
        return None
    if len(parts) == 1:
        tok = parts[0]
        if names and tok in names:
            return ("slot", int(names[tok]), tok)
        if _arm32_isreg(tok):
            return ("base", _arm32_canon(tok), 0)
        return None
    base = parts[0]
    if not _arm32_isreg(base):
        return None
    base = _arm32_canon(base)
    second = parts[1].lstrip("#")
    if _NUM.match(second) or re.fullmatch(r"-(?:0x)?[0-9a-fA-F]+", second):
        disp = int(second, 0)
        return ("slot", disp, None) if base == "r11" else ("base", base, disp)
    if _arm32_isreg(parts[1]):
        scale = 1
        if len(parts) >= 3:
            s = re.search(r"lsl\s*#?(0x[0-9a-fA-F]+|\d+)", parts[2].lower())
            if s:
                scale = 1 << int(s.group(1), 0)
            else:
                return None
        return ("indexed", base, _arm32_canon(parts[1]), scale)
    return None


def _arm32_touch(disp):
    """An instruction that reads the fp/r11-relative slot at `disp` (for the unreadable-guard scan)."""
    def pred(t):
        for mm in re.finditer(r"\[(?:fp|r11)\s*,\s*#?(-?(?:0x)?[0-9a-fA-F]+)\]", t or ""):
            try:
                if int(mm.group(1), 0) == disp:
                    return True
            except ValueError:
                pass
        return False
    return pred


def _arm32_pcbase(instr):
    """The PC value an `add rN, pc, rM` uses, from its P-Code `INT_ADD const:<pc> const:<k>`."""
    for pc in instr.get("pcode", []) or []:
        m = re.match(r"INT_ADD const:(0x[0-9a-fA-F]+|\d+):\d+ const:(0x[0-9a-fA-F]+|\d+):\d+", pc)
        if m:
            return int(m.group(1), 0) + int(m.group(2), 0)
    return None


def _arm32_index_slots(ctx, blocks, names, entry, call_names):
    """Frame-slot offset -> source dict (a parser result or a parameter spilled to fp/r11-relative
    memory, single writer, address never taken)."""
    writes: dict = defaultdict(list)
    taken = set()
    for b in blocks:
        for i in b.get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            if mnem in ("str", "strb", "strh"):
                mm = _arm32_mem(ops[-1], names)
                if mm and mm[0] == "slot":
                    writes[mm[1]].append(_naddr(i.get("addr")))
            if mnem in ("add", "sub") and len(ops) == 3 and _arm32_canon(ops[1]) in ("r11", "sp") \
                    and _arm32_canon(ops[0]) not in ("r11", "sp") \
                    and _NUM.match(ops[2].lstrip("#")):
                # `add r3, fp, #-8` computes &local into a general register (address escapes); the
                # frame setup `sub sp, sp, #N` / `add fp, sp, #4` has a frame-register DESTINATION and
                # does NOT take a local's address -- excluding it kept the real param slot invisible.
                imm = int(ops[2].lstrip("#"), 0)
                taken.add(-imm if mnem == "sub" else imm)
    out = {}
    for b in blocks:
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if mnem not in ("bl", "blx") or not ops:
                continue
            name = call_names.get(_naddr(i.get("addr"))) \
                or normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", ops[0]))
            if name not in _INT_PARSERS:
                continue
            for i2 in ins[j + 1:j + 4]:
                m2, o2 = _ops((i2.get("text") or "").split(";")[0].strip())
                if m2 == "str" and o2 and _arm32_canon(o2[0]) == "r0":
                    mm = _arm32_mem(o2[-1], names)
                    if mm and mm[0] == "slot":
                        out[mm[1]] = {"source": name, "source_site": i.get("addr"),
                                      "slot": ("R11", mm[1]), "slot_name": mm[2], "kind": "parsed"}
                    break
                if m2 in ("bl", "blx"):
                    break
    e = next((b for b in blocks if b.get("addr") == entry), blocks[0])
    clob = set()
    for i in e.get("instructions") or []:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if mnem in ("bl", "blx"):
            break
        if mnem == "str" and len(ops) == 2 and _arm32_canon(ops[0]) in _ARM32_ARG \
                and _arm32_canon(ops[0]) not in clob:
            mm = _arm32_mem(ops[1], names)
            if mm and mm[0] == "slot" and mm[1] not in out:
                k = _ARM32_ARG.index(_arm32_canon(ops[0]))
                out[mm[1]] = {"source": f"argument {k + 1}", "source_site": i.get("addr"),
                              "slot": ("R11", mm[1]), "slot_name": mm[2], "kind": "param", "param": k}
        if ops and _arm32_isreg(ops[0]) and mnem not in _ARM32_NO_IDX_WRITE:
            clob.add(_arm32_canon(ops[0]))
    return {o: s for o, s in out.items() if o not in taken and len(writes.get(o, [])) == 1}


def _arm32_classify_store(ins, j, src_reg, off, names, input_slots=None):
    """Classify a `str <src_reg>, [slot@off]` at index j on arm32: ('init', c) for a `mov src,#c`
    initialiser, ('step', k) for a `ldr t,[slot]; add src,t,#k; str src` increment of the SAME slot,
    ('input', n_off) when src was just loaded from an unvalidated-INPUT slot (`ldr src,[n]; str src,[i]`
    -- the descending input-start counter `i=n`), or ('other',)."""
    src = _arm32_canon(src_reg)
    for k in range(j - 1, max(-1, j - 6), -1):
        m, o = _ops((ins[k].get("text") or "").split(";")[0].strip())
        if not o or _arm32_canon(o[0]) != src:
            continue
        if m in ("mov", "movw") and len(o) == 2 and _NUM.match(o[1].lstrip("#")):
            return ("init", int(o[1].lstrip("#"), 0))
        if m in ("add", "sub") and len(o) == 3 and _NUM.match(o[2].lstrip("#")):
            tmp = _arm32_canon(o[1])
            for k2 in range(k - 1, max(-1, k - 4), -1):
                m2, o2 = _ops((ins[k2].get("text") or "").split(";")[0].strip())
                if o2 and _arm32_canon(o2[0]) == tmp and m2 in ("ldr", "ldrsb", "ldrsh"):
                    mm = _arm32_mem(o2[-1], names)
                    if mm and mm[0] == "slot" and mm[1] == off:
                        k0 = int(o[2].lstrip("#"), 0)
                        return ("step", k0 if m == "add" else -k0)   # `sub` -> DESCENDING counter
            return ("other",)
        if input_slots is not None and m in ("ldr", "ldrsb", "ldrsh") and len(o) >= 2:
            mm = _arm32_mem(o[-1], names)
            if mm and mm[0] == "slot" and mm[1] in input_slots:
                return ("input", mm[1])                  # i = n, a copy of an unvalidated-input slot
        return ("other",)
    return ("other",)


def _arm32_induction_slots(blocks, names, input_slots=None):
    """arm32 LOOP INDUCTION VARIABLE slots: one initialiser (`mov r,#c; str r,[s]`, or a copy of an
    unvalidated-INPUT slot `ldr r,[n]; str r,[s]`) and one `ldr r,[s]; add r,r,#k; str r,[s]` step,
    &addr never taken, no other writer. Index sources (kind 'induction'), as the x86/aarch64 detectors.
    `input_slots` names the input slot offsets."""
    taken = set()
    stores: dict = defaultdict(list)
    for b in blocks:
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            if mnem in ("add", "sub") and len(ops) == 3 and _arm32_canon(ops[1]) in ("r11", "sp") \
                    and _arm32_canon(ops[0]) not in ("r11", "sp") and _NUM.match(ops[2].lstrip("#")):
                imm = int(ops[2].lstrip("#"), 0)
                taken.add(-imm if mnem == "sub" else imm)
            if mnem in ("str", "strb", "strh") and len(ops) >= 2:
                mm = _arm32_mem(ops[-1], names)
                if mm and mm[0] == "slot":
                    stores[mm[1]].append((i.get("addr"), mm[2],
                                          _arm32_classify_store(ins, j, ops[0], mm[1], names, input_slots),
                                          b.get("addr")))
    out = {}
    for off, lst in stores.items():
        if off in taken:
            continue
        inits = [s for s in lst if s[2][0] == "init"]
        inputs = [s for s in lst if s[2][0] == "input"]
        steps = [s for s in lst if s[2][0] == "step"]
        if len(lst) == 2 and len(inputs) == 1 and len(steps) == 1 and steps[0][2][1] < 0:
            out[off] = {"source": "loop counter", "source_site": inputs[0][0], "slot": ("R11", off),
                        "slot_name": inputs[0][1], "kind": "induction", "init": None,
                        "step": steps[0][2][1], "step_block": steps[0][3],
                        "init_input": ("R11", inputs[0][2][1]), "descending": True}
        elif len(lst) == 2 and len(inits) == 1 and len(steps) == 1 \
                and inits[0][2][1] >= 0 and steps[0][2][1] != 0:
            out[off] = {"source": "loop counter", "source_site": inits[0][0], "slot": ("R11", off),
                        "slot_name": inits[0][1], "kind": "induction",
                        "init": inits[0][2][1], "step": steps[0][2][1], "step_block": steps[0][3]}
            if steps[0][2][1] < 0:                         # a DESCENDING counter: max index is the init
                out[off]["descending"] = True
    return out


def _arm32_exit_input_slot(exit_blk, i_off, input_slots, names):
    """The INPUT slot the loop's exit compares the induction slot against (`i < n`) on arm32, or None
    -- the exit block reads the induction slot AND loads an input slot and has a `cmp`. `input_slots`
    already drops a re-written/clamped n; the caller still checks n has no dominating bound."""
    ins = (exit_blk or {}).get("instructions") or []
    reads_i = False
    nslot = None
    has_cmp = False
    for i in ins:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops:
            continue
        if mnem in ("cmp", "cmn", "subs"):
            has_cmp = True
        if mnem in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh") and len(ops) >= 2:
            mm = _arm32_mem(ops[-1], names)
            if mm and mm[0] == "slot":
                if mm[1] == i_off:
                    reads_i = True
                elif mm[1] in input_slots:
                    nslot = ("R11", mm[1])
    return nslot if (reads_i and has_cmp) else None


def _arm32_induction_regs(blocks, preds, succ_map, dom, by_addr):
    """Register loop counters on arm32 (the `-O2` shape): a register with EXACTLY ONE constant
    positive self-increment (`add rD,rD,#k`) in the loop and no other in-loop writer. Returns
    {header -> {reg: src}} (src carries reg/step/loop). See `_a64_induction_regs` (the aarch64 twin).
    The entry value is not required -- the bound comes from the loop's exit test, not the init."""
    out: dict = defaultdict(dict)
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        steps: dict = defaultdict(list)
        other: dict = defaultdict(int)
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                if not ops or not _arm32_isreg(ops[0]):
                    continue
                dst = _arm32_canon(ops[0])
                if mnem in ("add", "sub") and len(ops) == 3 and _arm32_canon(ops[1]) == dst \
                        and _NUM.match(ops[2].lstrip("#")):
                    steps[dst].append((int(ops[2].lstrip("#"), 0) * (1 if mnem == "add" else -1),
                                       i.get("addr")))
                elif mnem not in _ARM32_NO_IDX_WRITE:
                    other[dst] += 1
        for reg, st in steps.items():
            if other.get(reg) or len(st) != 1 or st[0][0] <= 0:
                continue
            out[header][reg] = {"source": "loop counter", "source_site": st[0][1], "slot": None,
                                "slot_name": None, "kind": "induction", "reg": reg, "step": st[0][0],
                                "init": 0, "header": header, "loop": frozenset(body)}
    return out


def _arm32_walk_store(mnem, ops):
    """(ptr_reg, stride, pre_index) for an arm32 WRITEBACK store that walks a pointer -- pre-index
    `str rX,[p,#k]!` or post-index `str rX,[p],#k` -- else None. These walk `p` by `k` bytes each
    iteration (the `-O2` form of `for(..) *q++ = ..`), so the array index is implicit in the walk."""
    if mnem not in ("str", "strb", "strh"):
        return None
    if len(ops) == 2 and ops[1].rstrip().endswith("]!"):
        m = re.match(r"\[\s*(r\d+|fp|sp|lr)\s*,\s*#?(-?(?:0x)?[0-9a-fA-F]+)\s*\]!$", ops[1].strip())
        if m:
            return (_arm32_canon(m.group(1)), int(m.group(2), 0), True)
    if len(ops) == 3 and re.fullmatch(r"\[\s*(r\d+|fp|sp|lr)\s*\]", ops[1].strip()) \
            and _NUM.match(ops[2].lstrip("#")):
        m = re.match(r"\[\s*(r\d+|fp|sp|lr)\s*\]", ops[1].strip())
        return (_arm32_canon(m.group(1)), int(ops[2].lstrip("#"), 0), False)
    return None


def _arm32_walk_base(ctx, by_addr, dom, header, body, p):
    """Resolve a walking pointer's INITIAL value to a global object: ('global', name, addr, sz) and
    the signed byte offset into it, or None. Re-simulates the literal-pool base build in the blocks
    that dominate the loop (`ldr p,[0xLIT]; add p,pc,p; sub p,p,#4` -> &table - 4), which the main
    scanner drops once it subtracts from a `ga`. A known symbol size is required (else None)."""
    val: dict = {}
    for d in sorted((x for x in dom.get(header, ()) if x != header and x not in body),
                    key=lambda x: len(dom.get(x, ()))):              # farthest dominator first (exec order)
        for i in (by_addr.get(d) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops or not _arm32_isreg(ops[0]):
                continue
            dst = _arm32_canon(ops[0])
            if mnem == "ldr" and len(ops) == 2 and re.fullmatch(r"\[(0x[0-9a-fA-F]+|\d+)\]",
                                                                ops[1].strip()):
                w = _word_at(ctx, int(ops[1].strip("[]"), 0))
                val[dst] = ("litoff", w) if w is not None else None
            elif mnem == "add" and len(ops) == 3 and ops[1].lower() == "pc":
                v = val.get(_arm32_canon(ops[2]))
                pcb = _arm32_pcbase(i)
                if v and v[0] == "litoff" and pcb is not None:
                    g = _global_base(ctx, addr=pcb + v[1])
                    val[dst] = ("ga", g[0], g[1], g[2], 0) if (g and g[1] is not None) else None
                else:
                    val[dst] = None
            elif mnem in ("add", "sub") and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                v = val.get(_arm32_canon(ops[1]))
                k = int(ops[2].lstrip("#"), 0) * (1 if mnem == "add" else -1)
                val[dst] = ("ga", v[1], v[2], v[3], v[4] + k) if (v and v[0] == "ga") else None
            else:
                val[dst] = None                                      # any other write clobbers it
    g = val.get(p)
    if g and g[0] == "ga" and g[2] is not None and g[3]:
        return ("global", g[1], g[2], g[3]), g[4]
    return None


def _arm32_const_init(by_addr, dom, header, body, reg):
    """The non-negative constant `reg` holds on entry to the loop, from its single dominating
    preheader (`mov reg, #c`), or None. arm32-specific (`_reg_const_init` reads x86 operands)."""
    pre = [d for d in dom.get(header, ()) if d != header and d not in body]
    if len(pre) != 1:
        return None
    init = None
    for i in (by_addr.get(pre[0]) or {}).get("instructions") or []:
        mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
        if not ops or _arm32_canon(ops[0]) != reg:
            continue
        init = int(ops[1].lstrip("#"), 0) if (mnem in ("mov", "movs") and len(ops) == 2
                                              and _NUM.match(ops[1].lstrip("#"))) else None
    return init


def _arm32_reg_written_in(body, by_addr, reg):
    """True if `reg` is the explicit destination of any instruction in the loop body. The walking
    pointer's own writeback is implicit (the store's dest operand is the stored VALUE, not the
    pointer), so a match here means some OTHER write reloads/recomputes the pointer -- not a clean
    walk, so the overrun is withheld."""
    for la in body:
        for i in (by_addr.get(la) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if ops and _arm32_isreg(ops[0]) and _arm32_canon(ops[0]) == reg \
                    and mnem not in _ARM32_NO_IDX_WRITE:
                return True
    return False


def _arm32_walking_pointer_loops(ctx, faddr, blocks, preds, succ_map, dom, by_addr, out):
    """arm32 `-O2` WALKING-POINTER loop overrun: gcc compiles `for(i=0;i<=10;i++) t[i]=i` into a
    pointer that walks the array (`str r3,[r2,#4]!`, r2 = &t - 4) with a separate counter giving the
    trip count (`cmp r3,#11; bne`). No index register appears in the store, so the induction path
    cannot see it; this pass links the pointer's stride and start to the counter's CONSTANT trip
    count and flags the overrun. The input-length form carries a predicated return (`pople`) and is
    already skipped by the caller's `_arm32_pred_unsound` gate -- so only the constant case is handled
    here (sound: an unprovable trip count yields no claim). step=1, stride=width, known init only."""
    for header, counters in _arm32_induction_regs(blocks, preds, succ_map, dom, by_addr).items():
        body = next(iter(counters.values()))["loop"]
        ok, exit_src = _access_loops_single_exit(blocks, preds, succ_map, header, dom)
        if not ok or exit_src is None:
            continue
        # the counter whose constant equality exit governs the loop
        rc, src, r0max = None, None, None
        for reg, s in counters.items():
            v = _loop_exit_const(by_addr.get(exit_src), s, _arm32_canon, ("bne",))
            if v is not None:
                rc, src, r0max = reg, s, v
                break
        if src is None or src["step"] != 1:                 # step 1 keeps the walk in lockstep
            continue
        init = _arm32_const_init(by_addr, dom, header, body, rc)
        if init is None:
            continue
        trips = (r0max - init) // src["step"] + 1           # iterations the loop runs
        if trips <= 0:
            continue
        seen = set()
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                w = _arm32_walk_store(mnem, ops)
                if w is None:
                    continue
                p, stride, pre = w
                width = {"strb": 1, "strh": 2}.get(mnem, 4)
                if stride != width or stride <= 0 or p in seen:
                    continue
                seen.add(p)
                if _arm32_reg_written_in(body, by_addr, p):  # p must be walked ONLY by the writeback
                    continue
                gb = _arm32_walk_base(ctx, by_addr, dom, header, body, p)
                if gb is None:
                    continue
                gbase, base_off = gb
                # the max byte offset the walk writes: pre-index advances before each store
                max_off = base_off + (trips if pre else trips - 1) * stride
                if max_off < 0:
                    continue
                verdict = _index_verdict(("bounded", max_off // stride, True), gbase, stride,
                                         max_off % stride)
                if verdict is None:
                    continue
                vd, oob = verdict
                isrc = {"source": "loop counter", "source_site": i.get("addr"), "slot": None,
                        "slot_name": None, "kind": "induction", "reg": rc}
                out.append(_array_index_cand(faddr, i.get("addr"), gbase, stride, max_off % stride,
                                             isrc, "write", ("bounded", max_off // stride, True),
                                             vd, oob))
                return                                       # one walking-pointer finding per function


def _arm32_desc_walk_trips(by_addr, dom, header, body, p):
    """(counter_reg, trips) for a single-block descending walk's VALUE counter -- the lone register
    with a `sub/subs rC,rC,#s` step (not the walking pointer p), a constant init in the dominating
    preheader, and a terminating `bne` whose exit value is read from a `cmn rC,#k` (-> -k), `cmp rC,#k`
    (-> k), or the flag-setting `subs` itself (-> 0). trips = (init - exit) // s. None when the counter,
    its init, or the trip count cannot be pinned (so an unprovable walk yields no claim)."""
    ins = (by_addr.get(header) or {}).get("instructions") or []
    steps: dict = defaultdict(list)
    for i in ins:
        m, o = _ops((i.get("text") or "").split(";")[0].strip())
        if m in ("sub", "subs") and len(o) == 3 and _arm32_isreg(o[0]) and _arm32_canon(o[0]) == p:
            return None                                     # p is stepped by a plain sub, not writeback
        if m in ("sub", "subs") and len(o) == 3 and _arm32_canon(o[0]) == _arm32_canon(o[1]) \
                and _NUM.match(o[2].lstrip("#")):
            steps[_arm32_canon(o[0])].append(int(o[2].lstrip("#"), 0))
    cands = [(r, s) for r, s in steps.items() if len(s) == 1 and s[0] > 0 and r != p]
    if len(cands) != 1:
        return None
    rc, s = cands[0][0], cands[0][1][0]
    init = _arm32_const_init(by_addr, dom, header, body, rc)
    if init is None or init < 0:
        return None
    exitv, step_sets_flags = None, False
    for i in ins:
        m, o = _ops((i.get("text") or "").split(";")[0].strip())
        if m == "cmn" and len(o) == 2 and _arm32_canon(o[0]) == rc and _NUM.match(o[1].lstrip("#")):
            exitv = -int(o[1].lstrip("#"), 0)
        elif m == "cmp" and len(o) == 2 and _arm32_canon(o[0]) == rc and _NUM.match(o[1].lstrip("#")):
            exitv = int(o[1].lstrip("#"), 0)
        elif m == "subs" and len(o) == 3 and _arm32_canon(o[0]) == rc:
            step_sets_flags = True
    if exitv is None and step_sets_flags:
        exitv = 0                                           # `subs rC,rC,#s; bne` exits when rC hits 0
    if exitv is None:
        return None
    trips = (init - exitv) // s
    return (rc, trips) if trips >= 1 else None


def _arm32_descending_walk(ctx, faddr, blocks, preds, succ_map, dom, by_addr, out):
    """arm32 `-O1`/`-O2` DESCENDING walking-pointer overrun: gcc compiles `for(i=C;i>=0;i--) t[i]=i`
    into a pointer that walks the array DOWN with PRE-decrement writeback (`str r3,[r2,#-4]!`, r2 =
    &t + (C+1)*stride), plus a value counter giving the trip count. The store carries no index
    register, so the induction path cannot see it. The walk writes `trips` elements ending at
    base_abs + trips*stride (the lowest), so THAT is the array's base -- resolved ABSOLUTELY (not via
    the literal's anchor symbol, which gcc may share with a neighbour: `&big` can be encoded `&table +
    0x128`, and trusting the anchor would wrongly blame `table`). The highest (first) store is
    base_abs + stride; when its offset in the resolved array plus the width exceeds the array's
    st_size the first iteration overruns. Flagged only for a single-block SELF-LOOP (the store runs
    before the loop's branch, so it always executes) whose pointer is walked ONLY by the writeback
    and whose start + trip count are both constant -- never a false positive."""
    seen_fn = set()
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        if len(body) != 1 or header not in body:            # single-block self-loop: the store, then
            continue                                        # the counter step + branch -- store runs 1st
        ok, _exit = _access_loops_single_exit(blocks, preds, succ_map, header, dom)
        if not ok:
            continue
        for i in (by_addr.get(header) or {}).get("instructions") or []:
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            w = _arm32_walk_store(mnem, ops)
            if w is None:
                continue
            p, stride, pre = w
            width = {"strb": 1, "strh": 2}.get(mnem, 4)
            if not pre or stride >= 0 or -stride != width or p in seen_fn:   # PRE-decrement, |stride|=w
                continue
            seen_fn.add(p)
            if _arm32_reg_written_in(body, by_addr, p):     # p recomputed elsewhere -> not a clean walk
                continue
            ct = _arm32_desc_walk_trips(by_addr, dom, header, body, p)
            gb = _arm32_walk_base(ctx, by_addr, dom, header, body, p)
            if ct is None or gb is None:
                continue
            _rc, trips = ct
            gbase, base_off = gb
            base_abs = gbase[2] + base_off                  # the pointer's value on loop entry
            arr_base = base_abs + trips * stride            # the LOWEST store == the array's own base
            obj = _global_base(ctx, addr=arr_base)          # resolve the TRUE array absolutely
            if not (obj and obj[1] is not None and obj[2]):
                continue
            top = (base_abs + stride) - obj[1]              # the highest (first) store's offset in it
            if top < 0:
                continue
            base = ("global", obj[0], obj[1], obj[2])
            verdict = _index_verdict(("bounded", top // width, True), base, width, top % width)
            if verdict is None:
                continue
            vd, oob = verdict
            isrc = {"source": "a descending walk", "source_site": i.get("addr"), "slot": None,
                    "slot_name": None, "kind": "constant"}
            out.append(_array_index_cand(faddr, i.get("addr"), base, width, top % width, isrc,
                                         "write", ("bounded", top // width, True), vd, oob))
            return                                           # one walking-pointer finding per function


def _arm32_predicated_descending_walk(ctx, faddr, blocks, out):
    """arm32 `-O2` descending walking-pointer overrun whose loop exits via a PREDICATED RETURN
    (`str r3,[r2,#-4]!; subs r3,r3,#1; bxcc lr; b .loop`). The decompiler drops the conditional-return
    edge, so the loop looks exitless and the function is skipped by the `_arm32_pred_unsound` gate --
    but the overrun is the FIRST (pre-decrement) store, which runs on iteration 1 regardless of the
    (invisible) exit. This pass runs BEFORE that gate, for this one shape only, and so must be
    self-contained and tightly gated: it bails unless the ONLY predicated op in the function is a
    `bx<cc>`/`blx<cc>` return (a predicated DATA op could feed the walk and is left to the gate). The
    array is resolved by TRIP COUNT absolutely (shared with `_arm32_descending_walk`), so the broken
    CFG and the shared anchor symbol never mislead it; nothing predicated feeds the walk, so the
    first-store overrun is sound. No single-exit / single-block requirement (the exit is invisible)."""
    saw_pret = False
    for b in blocks:
        for i in b.get("instructions") or []:
            m0 = _ops((i.get("text") or "").split(";")[0].strip())[0]
            mm = _ARM32_PRED_RE.fullmatch(m0 or "")
            if not mm:
                continue
            if mm.group(1) in ("bx", "blx"):
                saw_pret = True                           # a conditional return: the dropped-edge exit
            else:
                return                                    # any other predicated op -> too risky, bail
    if not saw_pret:
        return                                            # no predicated return -> the gated passes run
    from . import bounds
    preds: dict = defaultdict(list)
    succ_map: dict = {}
    by_addr = {b.get("addr"): b for b in blocks}
    for b in blocks:
        succ_map[b.get("addr")] = tuple(b.get("succ") or ())
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    dom = bounds.dominators(blocks)
    seen = set()
    for header, body in _reg_natural_loops(blocks, preds, succ_map, dom).items():
        for la in body:
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
                w = _arm32_walk_store(mnem, ops)
                if w is None:
                    continue
                p, stride, pre = w
                width = {"strb": 1, "strh": 2}.get(mnem, 4)
                if not pre or stride >= 0 or -stride != width or p in seen:   # PRE-decrement, |stride|=w
                    continue
                seen.add(p)
                if _arm32_reg_written_in(body, by_addr, p):
                    continue
                ct = _arm32_desc_walk_trips(by_addr, dom, header, body, p)
                gb = _arm32_walk_base(ctx, by_addr, dom, header, body, p)
                if ct is None or gb is None:
                    continue
                _rc, trips = ct
                gbase, base_off = gb
                base_abs = gbase[2] + base_off
                arr_base = base_abs + trips * stride            # the lowest store == the array's base
                obj = _global_base(ctx, addr=arr_base)          # resolve the TRUE array absolutely
                if not (obj and obj[1] is not None and obj[2]):
                    continue
                top = (base_abs + stride) - obj[1]              # the highest (first) store's offset
                if top < 0:
                    continue
                base = ("global", obj[0], obj[1], obj[2])
                verdict = _index_verdict(("bounded", top // width, True), base, width, top % width)
                if verdict is None:
                    continue
                vd, oob = verdict
                isrc = {"source": "a descending walk", "source_site": i.get("addr"), "slot": None,
                        "slot_name": None, "kind": "constant"}
                out.append(_array_index_cand(faddr, i.get("addr"), base, width, top % width, isrc,
                                             "write", ("bounded", top // width, True), vd, oob))
                return                                           # one walking-pointer finding per function


def _array_index_arm32(ctx, summaries, calls, targets, resolve_tail, out):
    """arm32 CWE-129, pass 1. As aarch64: a self-parsed input index is emitted directly; a parameter
    index is recorded in `summaries` and a forwarded argument (call or tail call) in `calls`, for
    the shared join."""
    # The ghidra backend (which emits the P-Code this ISA needs) renders a `bl` target as a raw
    # address, so the parser name is resolved through the call graph, not the disassembly text.
    call_names = {_naddr(e.site_addr): normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "",
                                                        e.dst_name))
                  for e in (ctx.call_edges or []) if getattr(e, "dst_name", None)}
    for faddr, ir in ctx.func_irs.items():
        blocks = [b for b in ((ir or {}).get("blocks") or [])
                  if isinstance(b, dict) and b.get("addr")]
        if blocks and len(blocks) <= 2000:
            _arm32_scan_function(ctx, faddr, blocks, summaries, calls, targets, resolve_tail, out,
                                 call_names)


def _arm32_scan_function(ctx, faddr, blocks, summaries, calls, targets, resolve_tail, out,
                         call_names):
    from . import bounds
    if not _has_pcode(blocks):                            # no P-Code -> the check is invisible
        return
    # A descending pre-decrement walking pointer whose loop exits via a predicated return (`bxcc lr`)
    # -- the decompiler drops that edge, so the gate below skips the function; this handles its
    # first-store overrun first, from the walk alone (no reliance on the broken CFG).
    _arm32_predicated_descending_walk(ctx, faddr, blocks, out)
    for b in blocks:                                      # unmodellable conditional execution
        for i in b.get("instructions") or []:
            m0, o0 = _ops((i.get("text") or "").split(";")[0].strip())
            if _arm32_pred_unsound(m0, o0):               # predicated return/branch / multi-reg -> skip
                return
    frame = ctx.frames.get(faddr) or {}
    _vs, names = _frame_vars(frame)
    entry = next((b.get("addr") for b in blocks if _naddr(b.get("addr")) == _naddr(faddr)),
                 blocks[0].get("addr"))
    slots = _arm32_index_slots(ctx, blocks, names, entry, call_names)
    arm32_input_slots = {off for off, s in slots.items() if s.get("kind") == "parsed"}
    for off, src in _arm32_induction_slots(blocks, names, arm32_input_slots).items():
        slots.setdefault(off, src)
    dom = bounds.dominators(blocks)
    by_addr = {b.get("addr"): b for b in blocks}
    preds: dict = defaultdict(list)
    succ_map: dict = {}
    for b in blocks:
        succ_map[b.get("addr")] = tuple(b.get("succ") or ())
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    # every natural loop, so a hoisted loop-invariant array base (`ldr/add r,pc,..` literal pool) is
    # carried into its blocks -- `tail` is idx-only, otherwise the in-loop access cannot resolve it
    all_loops = _reg_natural_loops(blocks, preds, succ_map, dom)
    loop_writes: dict = {}
    block_in_loops: dict = defaultdict(list)
    for h, body in all_loops.items():
        w = set()
        for la in body:
            block_in_loops[la].append(h)
            for i in (by_addr.get(la) or {}).get("instructions") or []:
                m2, o2 = _ops((i.get("text") or "").split(";")[0].strip())
                if m2 in ("bl", "blx"):
                    w.update(_ARM32_ARG)                  # a call clobbers r0-r3 (and ip); be safe
                    w.add("r12")
                elif o2 and _arm32_isreg(o2[0]) and m2 not in _ARM32_NO_IDX_WRITE:
                    w.add(_arm32_canon(o2[0]))
        loop_writes[h] = w
    _attach_slot_loops(slots, all_loops, block_in_loops)  # slot inductions get their loop body
    origin: dict = {}
    params: dict = {}
    for k, r in enumerate(_ARM32_ARG):
        params[r] = {"source": f"argument {k + 1}", "source_site": faddr, "slot": None,
                     "slot_name": None, "kind": "param", "param": k}
        origin[id(params[r])] = (entry, -1, r)            # (block, instr index, defining register)
    tail: dict = {}
    tail_all: dict = {}
    head: dict = {}
    cx = {"origin": origin, "tail": tail, "head": head, "preds": preds, "dom": dom,
          "by_addr": by_addr, "bases": ("SP", "R11"), "cond_term": _ARM32_COND_TERM}

    def seed_bases(ba, reg):
        """Carry each loop-invariant array base (`ldr r,[pc,..]; add r,pc,r` literal-pool &table,
        hoisted out of the loop) into every block of a loop containing `ba` -- `tail` is idx-only."""
        for h in block_in_loops.get(ba, ()):
            body = all_loops[h]
            written = loop_writes.get(h, set())
            for d in sorted((d for d in dom.get(h, ()) if d != h and d not in body and d in tail_all),
                            key=lambda x: -len(dom.get(x, ()))):
                for r, v in tail_all[d].items():
                    if v and v[0] in ("ga", "sa") and r not in written and r not in reg:
                        reg[r] = v

    def check_for(src, ba, pred, idx_reg):
        if src.get("slot"):
            if src.get("kind") == "induction":            # a loop counter: read the loop's own bound
                if src.get("descending"):
                    return _descending_bound(
                        blocks, by_addr, preds, ba, dom, src, _arm32_canon, ("cmp", "subs"), ("cmn",),
                        ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh"), ("str", "strb", "strh"),
                        lambda op: (lambda mm: bool(mm) and mm[0] == "slot"
                                    and ("R11", mm[1]) == src["slot"])(_arm32_mem(op, names)),
                        ("SP", "R11"))
                b = _induction_bound(blocks, by_addr, preds, ba, ("R11", src["slot"][1]), dom,
                                     ("SP", "R11"), _ARM32_COND_TERM,
                                     exit_input=lambda eb: _arm32_exit_input_slot(
                                         eb, src["slot"][1], arm32_input_slots, names),
                                     exit_unbounded=lambda eb: _exit_driven_by_input_call(
                                         eb, ("r0",), _arm32_canon, call_names),
                                     exit_const=lambda eb: _slot_exit_const(
                                         eb, src, lambda op: (lambda mm: ("R11", mm[1]) if mm
                                                              and mm[0] == "slot" else None)(
                                             _arm32_mem(op, names)),
                                         _arm32_canon, ("bne",),
                                         ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh"),
                                         ("str", "strb", "strh"), ("cmp", "subs")))
                return b if b is not None else _co_induction_bound(
                    src, slots, ba, blocks, by_addr, preds, dom, ("SP", "R11"), _ARM32_COND_TERM)
            return _arm_slot_check(blocks, by_addr, ba, ("R11", src["slot"][1]), dom, ("SP", "R11"),
                                   _ARM32_COND_TERM, _arm32_touch(src["slot"][1]))
        if id(src) not in origin:
            return None
        return _reg_bound(src, ba, cx)                    # backward edge-aware walk (handles merges)

    for b in blocks:
        ba = b.get("addr")
        ps = preds.get(ba, [])
        reg: dict = {}
        pred = None
        if ba == entry:
            reg = {r: ("idx", 1, 0, params[r]) for r in _ARM32_ARG}
        elif len(ps) == 1 and ps[0] in tail and ps[0] != ba:
            pred = ps[0]
            reg = dict(tail[pred])
        else:
            proc = [p for p in ps if p in tail and p != ba]
            if proc and len(proc) == len([p for p in ps if p != ba]):
                # a MERGE with every (non-self) predecessor processed: carry a register that holds
                # the SAME index value out of all of them (the backward walk computes its bound)
                for r, v in tail[proc[0]].items():
                    if v and v[0] == "idx" and all(_same_idx(tail[p].get(r), v) for p in proc[1:]):
                        reg[r] = v
        seed_bases(ba, reg)                               # loop-invariant array base carry
        head[ba] = dict(reg)
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _arm32_canon(ops[0])
            if _ARM32_PRED_RE.fullmatch(mnem):        # a predicated DATA op (control-flow already skipped)
                # its result is conditional: poison the destination so a predicated CLAMP of the index
                # makes that index undecidable (no false positive), and never read the op as an access
                if _arm32_isreg(ops[0]):
                    reg[dst] = None
                continue
            if mnem == "b" and ops:                   # a tail call forwards a parameter (see aarch64)
                callee = resolve_tail(ops[0])
                if callee is not None and callee != _naddr(faddr):
                    _record_forward(calls, reg, _ARM32_ARG, faddr, i.get("addr"), callee,
                                    check_for, ba, pred)
                continue
            if mnem in ("bl", "blx"):
                # record a forwarded index BEFORE the call clobbers r0-r3 (see the aarch64 scanner),
                # resolving the callee through the call graph with the direct branch target as a
                # fallback when the decompiler left the call edge out
                callee = targets.get(_naddr(i.get("addr"))) or resolve_tail(ops[0] if ops else "")
                if callee is not None:
                    _record_forward(calls, reg, _ARM32_ARG, faddr, i.get("addr"), callee,
                                    check_for, ba, pred)
                name = call_names.get(_naddr(i.get("addr"))) \
                    or normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "", ops[0]))
                for r in list(reg):                   # a call clobbers r0-r3/r12/lr; r4-r11 are preserved
                    m = re.fullmatch(r"r(\d+)", _arm32_canon(r))
                    if not (m and 4 <= int(m.group(1)) <= 11):
                        reg.pop(r, None)
                if name in _INT_PARSERS:
                    rsrc = {"source": name, "source_site": i.get("addr"), "slot": None,
                            "slot_name": None, "kind": "register"}
                    origin[id(rsrc)] = (ba, j, "r0")      # the parser result lands in r0
                    reg["r0"] = ("idx", 1, 0, rsrc)
                continue
            if mnem == "ldr" and len(ops) == 2 and re.fullmatch(r"\[(0x[0-9a-fA-F]+|\d+)\]",
                                                                ops[1].strip()):
                w = _word_at(ctx, int(ops[1].strip("[]"), 0))
                reg[dst] = ("litoff", w) if w is not None else None
                continue
            if mnem == "add" and len(ops) == 3 and ops[1].lower() == "pc":
                v = reg.get(_arm32_canon(ops[2]))
                pcb = _arm32_pcbase(i)
                if v and v[0] == "litoff" and pcb is not None:
                    g = _global_base(ctx, addr=pcb + v[1])
                    reg[dst] = ("ga", g[1], g[0], g[2]) if (g and g[1] is not None) else None
                else:
                    reg[dst] = None
                continue
            if mnem in ("lsl", "lsls") and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                v = reg.get(_arm32_canon(ops[1]))              # arm32 scales the index explicitly
                sh = int(ops[2].lstrip("#"), 0)
                reg[dst] = ("idx", v[1] << sh, v[2] << sh, v[3]) if (v and v[0] == "idx") else None
                continue
            if mnem in ("mov", "cpy") and len(ops) == 3:       # `mov rD, rS, lsl #s` inline shift
                m = re.search(r"lsl\s*#?(0x[0-9a-fA-F]+|\d+)", ops[2].lower())
                v = reg.get(_arm32_canon(ops[1]))
                sh = int(m.group(1), 0) if m else None
                reg[dst] = (("idx", v[1] << sh, v[2] << sh, v[3])
                            if (sh is not None and v and v[0] == "idx") else None)
                continue
            if mnem in ("add", "sub") and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                v = reg.get(_arm32_canon(ops[1]))
                d = int(ops[2].lstrip("#"), 0) * (1 if mnem == "add" else -1)
                if v and v[0] == "idx":
                    reg[dst] = ("idx", v[1], v[2] + d, v[3])
                elif v and v[0] == "ptr":
                    reg[dst] = ("ptr", v[1], v[2], v[3] + d, v[4])
                else:
                    reg[dst] = None
                continue
            if mnem == "add" and len(ops) >= 3 and _arm32_isreg(ops[1]) and _arm32_isreg(ops[2]):
                # `add rD, <frame base>, <idx>` (optionally `, lsl #s`): a stack array element pointer
                sh = 0
                if len(ops) >= 4:
                    m = re.search(r"lsl\s*#?(0x[0-9a-fA-F]+|\d+)", ops[3].lower())
                    sh = int(m.group(1), 0) if m else 0
                a, b2 = _arm32_canon(ops[1]), _arm32_canon(ops[2])
                fb = a if a in ("sp", "r11") else (b2 if b2 in ("sp", "r11") else None)
                iv = reg.get(b2) if a in ("sp", "r11") else reg.get(a)
                if fb and iv and iv[0] == "idx":
                    sb = ("stack", "R11" if fb == "r11" else "SP", 0)
                    reg[dst] = ("ptr", sb, iv[1] << sh, iv[2] << sh, iv[3])
                else:
                    reg[dst] = None
                continue
            mm = _arm32_mem(ops[-1], names)
            store = mnem in ("str", "strb", "strh")
            if mm and mm[0] == "indexed":
                base, idx = reg.get(mm[1]), reg.get(mm[2])
                if base and base[0] == "ga" and idx and idx[0] == "idx":
                    scale, off = idx[1] * mm[3], idx[2] * mm[3]
                    gbase = ("global", base[2], base[1], base[3])
                    _index_record(summaries, out, faddr, i.get("addr"), gbase, scale, off, idx[3],
                                  "write" if store else "read", check_for(idx[3], ba, pred, mm[2]))
                if not store:
                    reg[dst] = None
                continue
            if mm and mm[0] == "base" and reg.get(mm[1]) and reg[mm[1]][0] == "ptr":
                p = reg[mm[1]]                                 # a stack array element pointer + disp
                _index_record(summaries, out, faddr, i.get("addr"), p[1], p[2], p[3] + mm[2], p[4],
                              "write" if store else "read", check_for(p[4], ba, pred, mm[1]))
                if not store:
                    reg[dst] = None
                continue
            if mnem in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh") and mm and mm[0] == "slot" \
                    and mm[1] in slots:
                reg[dst] = ("idx", 1, 0, slots[mm[1]])
                continue
            if mnem in ("mov", "cpy") and len(ops) == 2 and _arm32_isreg(ops[1]):
                reg[dst] = reg.get(_arm32_canon(ops[1]))
                continue
            if mnem not in _ARM32_NO_IDX_WRITE and _arm32_isreg(ops[0]):
                reg[dst] = None
        tail[ba] = {r: v for r, v in reg.items() if v and v[0] == "idx"}
        tail_all[ba] = dict(reg)
    # -O2 walking-pointer loops (a pointer walks the array, a counter gives the trip count). Reached
    # only when the function passed the `_arm32_pred_unsound` gate above, so the input-length form
    # (which carries a predicated return) is already skipped -- the constant trip count is handled.
    succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
    _arm32_walking_pointer_loops(ctx, faddr, blocks, preds, succ_map, dom, by_addr, out)
    _arm32_descending_walk(ctx, faddr, blocks, preds, succ_map, dom, by_addr, out)


@register_detector
def array_index(ctx: DetectContext):
    """CWE-129, in two passes. Pass 1 walks every function and records (a) accesses indexed by an
    input value it obtained itself, (b) accesses indexed by one of its own PARAMETERS, with the
    check the function applies, and (c) every call that passes an input value as an argument,
    with the check the caller applies on the way. Pass 2 joins (b) and (c): an index parsed in
    `main` and handed to `set(i, v)`, which writes `table[i]`, is the commonest real shape and was
    invisible while the index had to be parsed in the function that used it. One call level --
    a parameter passed on again is not followed."""
    if not ctx.func_irs:
        return []
    from . import bounds
    out: list = []
    summaries: dict = defaultdict(list)    # callee addr -> [(cfaddr, site, base, scale, off, k, access, check)]
    calls: list = []                       # (caller, call site, callee addr, {k: (src, check)})
    targets = {_naddr(e.site_addr): _naddr(e.dst_addr) for e in (ctx.call_edges or [])
               if getattr(e, "dst_addr", None) and not getattr(e, "external", False)}
    resolve_tail = _tail_resolver(ctx)
    # aarch64 and arm32 feed the SAME two-structure model (summaries + calls) through their own
    # conservative pass-1 scanners, then share the ISA-neutral pass-2 join below. So a parameter
    # index is flagged on ARM exactly as on x86 -- only when input is shown to reach it, combining
    # the check at each call edge -- not merely because a bare parameter indexed an array.
    if _is_aarch64(ctx.arch) and ctx.bits == 64:
        _array_index_arm(ctx, summaries, calls, targets, resolve_tail, out)
        _array_index_join(summaries, calls, out)
        return out
    if _is_arm32(ctx.arch) and ctx.bits == 32:
        _array_index_arm32(ctx, summaries, calls, targets, resolve_tail, out)
        _array_index_join(summaries, calls, out)
        return out
    if not (_is_x86(ctx.arch) and ctx.bits == 64):
        return []
    for faddr, ir in ctx.func_irs.items():
        # the dominator / guard machinery keys every block by its address: a block without one
        # (a degenerate decompiler record) is dropped rather than allowed to sink the detector
        blocks = [b for b in ((ir or {}).get("blocks") or []) if isinstance(b, dict) and b.get("addr")]
        if not blocks or len(blocks) > 2000:
            continue
        _index_scan_function(ctx, faddr, blocks, targets, summaries, calls, out, resolve_tail)
        _x86_const_oob_stores(ctx, faddr, blocks, out)
        preds: dict = defaultdict(list)
        succ_map = {b.get("addr"): tuple(b.get("succ") or ()) for b in blocks}
        for b in blocks:
            for sc in b.get("succ") or []:
                preds[sc].append(b.get("addr"))
        _vs, slot_names = _frame_vars(ctx.frames.get(faddr) or {})
        _x86_unbounded_walk(ctx, faddr, blocks, preds, succ_map, bounds.dominators(blocks),
                            {b.get("addr"): b for b in blocks}, slot_names, out)
    _array_index_join(summaries, calls, out)
    return out


def _array_index_join(summaries, calls, out):
    """Pass 2 of array_index, SHARED by every ISA. An input value handed to a function that indexes
    with that parameter -- following a forwarded parameter across MORE THAN ONE call edge. Index the
    calls by callee and by the caller-PARAMETER each argument carries, then walk from every
    PARSED-input pass, combining the check at each edge, to the access that indexes the parameter at
    the end of the chain.

      main: i=atoi(argv[1]); f(i)   -->   f(p): g(p)   -->   g(q): table[q]

    `forwards[(func, param)]` = the calls that pass func's parameter `param` onward (to callee
    arg k', with the check func applies first); `summaries[func]` = the accesses func indexes with a
    parameter. A visited set and a depth bound keep a recursive/mutually-recursive call graph finite;
    the join stays silent (never a false finding) when any edge's check is undecidable, since
    `_combine_checks(None, ...)` is None. Reads only `summaries` and `calls` as pass 1 recorded them,
    so it is architecture-neutral -- x86, aarch64 and arm32 all drive it."""
    forwards: dict = defaultdict(list)
    seeds = []                                            # (caller, call_site, callee, k, src, check)
    for caller, call_site, callee, passed in calls:
        for k, (src, chk) in passed.items():
            if src.get("kind") == "param":
                # keyed by (normalised function addr, its parameter index) so the walk, which
                # arrives with a `_naddr`-normalised callee, matches it (summaries use `_naddr` too)
                forwards[(_naddr(caller), src["param"])].append((call_site, callee, k, chk))
            else:
                seeds.append((caller, call_site, callee, k, src, chk))

    def _emit(cfaddr, site, base, scale, off, access, check, src, chain):
        v = _index_verdict(check, base, scale, off)
        if v is None:
            return
        verdict, oob = v
        first = chain[0]
        via = dict(src, via={"caller": first[0], "call_site": first[1], "argument": first[2] + 1,
                             "hops": len(chain)})
        out.append(_array_index_cand(cfaddr, site, base, scale, off, via, access, check,
                                     verdict, oob))

    def _walk(func, param, check, src, chain, visited):
        if check is None or len(chain) > 6:               # undecidable edge, or too deep -> stop
            return
        if (func, param) in visited:                      # a cycle in the call graph -> stop
            return
        visited = visited | {(func, param)}
        for (cfaddr, site, base, scale, off, k, access, cchk) in summaries.get(func, ()):
            if k == param:
                _emit(cfaddr, site, base, scale, off, access, _combine_checks(check, cchk),
                      src, chain)
        for (call_site, callee, k, chk) in forwards.get((func, param), ()):
            _walk(callee, k, _combine_checks(check, chk), src, chain + [(func, call_site, k)],
                  visited)

    for caller, call_site, callee, k, src, chk in seeds:
        _walk(callee, k, chk, src, [(caller, call_site, k)], set())


def _array_index_cand(faddr, site, base, scale, off, src, access, check, verdict, oob):
    if base[0] == "global":
        name = base[1] or (f"data_{base[2]:x}" if base[2] is not None else "global")
        label = name
        where = (f"global array {name}" + (f" @ {base[2]:#x}" if base[2] is not None else "")
                 + (f" ({base[3]} bytes, {base[3] // scale} x {scale}-byte elements)"
                    if base[3] and scale else " (extent not in the symbol table)"))
        arr = {"kind": "global", "name": base[1], "addr": hex(base[2]) if base[2] is not None else None,
               "size": base[3], "elements": (base[3] // scale) if base[3] and scale else None,
               "element_size": scale}
    else:
        name = f"{base[1].lower()}{base[2]:+#x}"
        label = f"{faddr}:{name}"
        where = f"stack array at {name} ({scale}-byte elements; extent not asserted)"
        arr = {"kind": "stack", "frame_base": base[1].lower(), "frame_offset": base[2],
               "size": None, "elements": None, "element_size": scale}
    slot = src.get("slot")
    sname = src["source"] if " " in src["source"] else src["source"] + "()"
    constant = src.get("kind") == "constant"
    idx_from = (f"a constant offset emitted at {src['source_site']}" if constant else
                f"{sname} at {src['source_site']}"
                + (f", held in {slot[0].lower()}{slot[1]:+#x}" if slot else ""))
    via = src.get("via")
    if via:
        idx_from += (f", passed as argument {via['argument']} by the call at {via['call_site']} "
                     f"in {via['caller']}")
        if via.get("hops", 1) > 1:
            idx_from += f" and forwarded through {via['hops']} call(s) to this access"
    expr = f"index*{scale}" + (f"{off:+d}" if off else "")
    if verdict == "unchecked":
        why = "no dominating check bounds it from above on this path"
    elif verdict == "signed":
        why = (f"the only dominating check is a SIGNED upper bound (index <= {check[1]}) and "
               f"nothing excludes a negative index")
    else:
        why = (f"the dominating check admits index <= {check[1]}, past the array's "
               f"{arr['elements']} elements")
    origin = "is a compile-time constant" if constant else "comes from input"
    detail = (f"{access} of {where} at {site}: the index {origin} ({idx_from}) and {why}. "
              f"Address = base + {expr}. An index of {', '.join(str(x) for x in oob)} "
              f"{'writes' if access == 'write' else 'reads'} outside the array "
              f"(CWE-129). Static: the path to this access is not proven feasible.")
    data = {"array": arr, "index": {"source": src["source"], "source_site": src["source_site"],
                                    "slot": (f"{slot[0].lower()}{slot[1]:+#x}" if slot else None),
                                    "expr": expr, "element_offset": off,
                                    "via_call": via},
            "function": faddr, "site": site,
            "access": access, "check": {"verdict": verdict,
                                        "bound": check[1] if check[0] == "bounded" else None,
                                        "nonneg": check[2] if check[0] == "bounded" else False},
            "oob_index": oob}
    cand = _cand(
        "CWE-129", _IDX_TITLES[verdict], "high" if access == "write" else "medium", "array_index",
        [{"channel": "pattern", "detail": detail, "array_index": data}],
        function_addr=faddr, site_addr=site,
        site_detail=(f"{access} {name}[{expr}] from {sname}; {verdict}"
                     + (f" (bound {check[1]})" if check[0] == "bounded" else "")),
        dedup_key=f"CWE-129:array_index:{label}:{verdict}", confidence=0.5)
    return cand


# ---------------------------------------------------------------- format string (CWE-134) --------
# A variadic format function whose format is NOT a string literal AND that is called with zero
# format arguments -- `printf(buf)` where a correct call would be `printf("%s", buf)`. This is
# exactly GCC's `-Wformat-security` / `-Wformat=2` shape, and it is a security bug class on its own:
# if that run-time format is attacker-influenced the `%n`/`%s`/`%p` conversions give an arbitrary
# read and write, and even when it is not, a stray `%` corrupts output. It is reported precisely
# WITHOUT taint analysis because it rests on two STRUCTURAL facts, not an inferred dataflow:
#   (1) the format register is fed by a run-time value -- a pointer loaded from memory, or the
#       address of a stack buffer -- NOT the address of a `.rodata` constant string (a `lea` of a
#       `str.`/RIP-relative operand). This is what excludes the one false positive the naive
#       "non-literal format" rule produces: `printf(cond ? "a" : "b")` selects between two rodata
#       `lea`s, so it classifies as a literal and is never flagged.
#   (2) no format ARGUMENT register is set up in the call's argument window (the instructions since
#       the previous call). `printf("%s", buf)` writes rsi, so it is excluded; `printf(buf)` does
#       not, so it is the flagged shape.
# Deliberately NOT built the naive way (flagging every non-literal format) -- that fabricates FPs,
# which the precision rule forbids. The v* family (vprintf/vfprintf/...) is excluded: it always
# carries a va_list argument, so (2) never holds, and a `void log(const char*f,...){vfprintf(..,f,ap);}`
# wrapper -- the CORRECT pattern -- would otherwise be a huge FP source. Indeterminate provenance
# (format from a call return, a bare parameter, arithmetic) is skipped, not guessed: a false
# negative is acceptable, a fabricated finding is not. x86-64 only (the provenance scan is Intel).
_FMT_FUNCS = {                                   # name -> (format-arg register, the registers AFTER it)
    "printf":   ("rdi", ("rsi", "rdx", "rcx", "r8", "r9")),
    "fprintf":  ("rsi", ("rdx", "rcx", "r8", "r9")),
    "dprintf":  ("rsi", ("rdx", "rcx", "r8", "r9")),
    "sprintf":  ("rsi", ("rdx", "rcx", "r8", "r9")),
    "snprintf": ("rdx", ("rcx", "r8", "r9")),
    "syslog":   ("rsi", ("rdx", "rcx", "r8", "r9")),
}
_ARGREG_SUBS = {
    "rdi": {"rdi", "edi", "di", "dil"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdx": {"rdx", "edx", "dx", "dl"},
    "rcx": {"rcx", "ecx", "cx", "cl"},
    "r8":  {"r8", "r8d", "r8w", "r8b"},
    "r9":  {"r9", "r9d", "r9w", "r9b"},
}


def _fmt_source_class(texts, reg: str, slot_names=None):
    """Classify what feeds the format register `reg` at a printf-family call (scanning `texts`,
    the instructions before the call, newest definition wins, one reg-to-reg move hop allowed):

      'literal' -- the address of a constant string: `lea reg, str.x` / `lea reg,[rip+..]`. SAFE.
      'dynamic' -- a run-time value: a pointer loaded from memory (`mov reg,[..]`) or the address
                   of a stack buffer (`lea reg,[rbp-..]`/a named frame slot). The CWE-134 shape.
      None      -- indeterminate (reg set by a call return / a bare register / arithmetic / an
                   immediate address). NOT flagged -- precision over recall."""
    cur = reg
    for _ in range(2):                                # at most one mov hop, then the defining instr
        for t in reversed(texts):
            body = t.split(";")[0]
            m = re.match(r"\s*lea\s+" + re.escape(cur) + r"\s*,\s*(.+)$", body, re.I)
            if m:
                tgt = m.group(1)
                if _R2_STR_SYM.search(tgt) or "rip" in tgt.lower():
                    return "literal"                  # &"...": a constant rodata string
                if re.search(r"\brbp\b|\brsp\b", tgt, re.I):
                    return "dynamic"                  # &stack_buffer -> printf(local_buf)
                if slot_names:
                    mn = re.search(r"\[\s*(?:[a-z]+\s+)?([A-Za-z_][\w.]*)\s*\]", tgt)
                    if mn and mn.group(1) in slot_names:
                        return "dynamic"              # &named frame local
                return "literal"                      # unknown lea target -> assume const (no FP)
            if re.match(r"\s*mov\s+" + re.escape(cur) + r"\s*,\s*(?:[a-z]+\s+)?\[", body, re.I):
                return "dynamic"                      # pointer loaded from memory (a variable/global)
            mv = re.match(r"\s*mov\s+" + re.escape(cur) + r"\s*,\s*([a-z0-9]+)\s*$", body, re.I)
            if mv and mv.group(1).lower() in _X86_REGS:
                cur = mv.group(1).lower()
                break                                 # follow the move, re-scan for the new register
            if re.match(r"\s*(mov|movabs|lea|add|sub|xor|or|and|pop|imul|call)\s+"
                        + re.escape(cur) + r"\b", body, re.I):
                return None                           # defined by something we cannot call a literal
        else:
            return None
    return None


def _writes_arg_reg(texts, regs) -> bool:
    """True if any register in `regs` (or a sub-register of it) is a DESTINATION operand in
    `texts` -- i.e. a format argument was set up. Err toward True (a false 'has an argument' only
    costs a missed finding, never a fabricated one)."""
    subs = set()
    for r in regs:
        subs |= _ARGREG_SUBS[r]
    for t in texts:
        b = t.split(";")[0]
        m = re.match(r"\s*[a-z]+\s+([a-z0-9]+)\s*,", b, re.I)    # dest = first operand
        if m and m.group(1).lower() in subs:
            return True
    return False


@register_detector
def format_string(ctx: DetectContext):
    if not (_is_x86(ctx.arch) and ctx.bits == 64) or not ctx.func_irs:
        return []
    out = []
    for faddr, ir in ctx.func_irs.items():
        frame = ctx.frames.get(faddr) or {}
        _vs, slot_names = _frame_vars(frame)
        flat = [(i.get("addr"), (i.get("text") or ""))
                for b in _blocks_of(ir) for i in (b.get("instructions") or [])]
        texts = [t for _, t in flat]
        for idx, (addr, text) in enumerate(flat):
            name = _norm_call(text)
            if name not in _FMT_FUNCS:
                continue
            fmt_reg, following = _FMT_FUNCS[name]
            pre = texts[:idx]
            if _fmt_source_class(pre, fmt_reg, slot_names) != "dynamic":
                continue                              # literal or indeterminate -> not a bug we prove
            # the argument set-up window: instructions since the previous call. A written following
            # arg register means a format argument was passed -> printf(fmt, x), not printf(x).
            win = []
            for b in reversed(pre):
                if re.search(r"\bcall\b", b.split(";")[0], re.I):
                    break
                win.append(b)
            if _writes_arg_reg(win, following):
                continue
            out.append(_cand(
                "CWE-134",
                f"Non-literal format string with no arguments passed to {name}()",
                "high", "format_string",
                [{"channel": "pattern",
                  "detail": (f"{name}() at {addr} takes its format from a run-time value (not a "
                             f"string literal) and is called with no format arguments -- the GCC "
                             f"-Wformat-security shape. If that value is attacker-influenced the "
                             f"%n/%s/%p conversions yield an arbitrary read and write (CWE-134); "
                             f"the format's provenance is structural here, not taint-proven")}],
                function_addr=faddr, site_addr=addr,
                site_detail=f"{name}(<non-literal format>) with zero format arguments",
                dedup_key=f"CWE-134:format_string:{name}", confidence=0.5))
    return out


# ---------------------------- indirect call through a function pointer stored in an object field
# `call *[obj+off]` (or `mov r,[obj+off]; call r`) invokes a function pointer read from writable
# memory. When `obj` is a heap allocation whose contents an attacker can corrupt -- a UAF, a heap
# overflow, the bespoke-allocator bug in HTB auth-or-out (print_author calls author->fptr) -- that
# corruption redirects control flow directly, no ROP needed. This flags the SURFACE: an indirect
# call whose target is loaded from `[base+disp]` where `base` is itself a pointer read from memory
# (an object field), not a stack address (`rbp/rsp`) and not RIP-relative (that is the ordinary
# PLT/GOT indirect call). Reviewable inventory (one per function), lifted when the function also
# allocates (heap provenance is then likely). x86-64 only.
_GPREG = re.compile(r"^[re][a-z]{2}$|^r(8|9|1[0-5])[db]?$", re.I)
_ALLOCATORS = {"malloc", "calloc", "realloc", "reallocarray", "aligned_alloc", "memalign",
               "posix_memalign", "valloc", "strdup", "strndup", "xmalloc", "xcalloc", "g_malloc"}


def _reg_defined_by_mem_load(texts, reg):
    """The `[base(+disp)]` memory operand that last defined `reg`, as (base, disp_text, def_index),
    or None if `reg`'s most recent definition is not a plain memory load (a lea of a stack address,
    an immediate, a reg-to-reg move, or a call result). `def_index` is the position of the defining
    load in `texts`, so a caller can trace `base`'s own provenance from BEFORE that load."""
    for j in range(len(texts) - 1, -1, -1):
        body = texts[j].split(";")[0]
        if not re.match(r"\s*\S+\s+" + re.escape(reg) + r"\b", body, re.I):
            continue
        m = re.match(r"\s*mov\s+" + re.escape(reg) + r"\s*,\s*(?:qword\s+)?\[\s*([a-z0-9]+)\s*"
                     r"((?:[-+]\s*(?:0x[0-9a-f]+|\d+))?)\s*\]", body, re.I)
        return (m.group(1).lower(), (m.group(2) or "").replace(" ", ""), j) if m else None
    return None


@register_detector
def heap_fptr_call(ctx: DetectContext):
    if not (_is_x86(ctx.arch) and ctx.bits == 64) or not ctx.func_irs:
        return []
    # The called object is often allocated in a DIFFERENT function than the one that calls through
    # it (auth-or-out: add_author allocates, print_author calls author->fptr), so heap provenance is
    # a binary-wide signal: does the program use a heap allocator at all? Count the libc allocators,
    # any `*alloc*` routine (custom allocators like auth-or-out's ta_alloc/alloc_block), and the
    # mmap/brk backing calls -- so a bespoke allocator still reads as heap.
    def _is_alloc(name):
        n = normalize(name)
        return n in _ALLOCATORS or "alloc" in n or n in ("mmap", "mmap64", "sbrk", "brk")
    heap = any(_is_alloc(e.dst_name) for e in ctx.call_edges)
    out = []
    for faddr, ir in ctx.func_irs.items():
        flat = [(i.get("addr"), (i.get("text") or ""))
                for b in _blocks_of(ir) for i in (b.get("instructions") or [])]
        texts = [t for _, t in flat]
        seen_here = False
        for idx, (addr, text) in enumerate(flat):
            if seen_here:
                break                                     # one finding per function
            body = text.split(";")[0].strip()
            base = disp = None
            base_scope = idx                              # trace base's provenance from before here
            # call qword [base + disp]  -- indirect through memory
            m = re.match(r"call\s+(?:qword\s+)?\[\s*([a-z0-9]+)\s*"
                         r"((?:[-+]\s*(?:0x[0-9a-f]+|\d+))?)\s*\]$", body, re.I)
            if m:
                base, disp = m.group(1).lower(), (m.group(2) or "").replace(" ", "")
            else:
                # call reg  -- where reg was loaded from an object field [base+disp]
                mr = re.match(r"call\s+([a-z0-9]+)$", body, re.I)
                if mr and _GPREG.match(mr.group(1)):
                    ld = _reg_defined_by_mem_load(texts[:idx], mr.group(1).lower())
                    if ld:
                        base, disp, base_scope = ld[0], ld[1], ld[2]   # trace base before the load
            if base is None or base in ("rip", "rsp", "esp", "rbp", "ebp"):
                continue                                  # stack-local fptr or PLT/GOT: not this
            # the base must itself be a pointer read from memory (an object), not a stack address or
            # an incoming register -- otherwise it is a local function-pointer variable or an opaque
            # call, a different (lower-value) shape. Trace from BEFORE the fptr load, so a self
            # load (`mov rax,[rax+off]`) resolves the object pointer, not itself.
            if _reg_defined_by_mem_load(texts[:base_scope], base) is None:
                continue
            out.append(_cand(
                "CWE-822",
                "Indirect call through a function pointer in an object field "
                "(control-flow hijack surface)",
                "medium" if heap else "low", "heap_fptr_call",
                [{"channel": "pattern",
                  "detail": (f"call through [{base}{disp}] at {addr}: a function pointer read from "
                             f"an object field is invoked; if that object is corruptible "
                             f"({'the program uses a heap allocator' if heap else 'e.g. a UAF/overflow'})"
                             f" the call is a direct control-flow hijack")}],
                function_addr=faddr, site_addr=addr,
                site_detail=f"call [{base}{disp}] (object function pointer)",
                dedup_key="CWE-822:heap_fptr_call", confidence=0.45 if heap else 0.3))
            seen_here = True
    return out


# ------------------------------------------------------------- hard-coded secrets (string)
_AWS = re.compile(r"AKIA[0-9A-Z]{16}")
_PLACEHOLDERS = {"password", "secret", "changeme", "yourpassword", "xxxxxxxx",
                 "none", "null", "empty", "required", "optional", "unknown"}


def _secret(v: str):
    if not v:
        return None
    if "PRIVATE KEY" in v:
        return ("CWE-321", "high", "Hard-coded private key material")
    if _AWS.search(v):
        return ("CWE-798", "high", "Hard-coded AWS access key")
    m = _ASSIGNED.search(v)
    if m and _secretish(m.group("val")) and not _FMT.search(v):
        return ("CWE-798", "medium", "Possible hard-coded credential")
    return None


# A credential is a keyword BOUND TO A VALUE. Matching the keyword alone flagged ten strings in
# unzip -- "Enter password: ", "incorrect password", "-P p Use password p to decrypt files" --
# all of them messages ABOUT passwords, none of them a secret. That was two thirds of every
# finding reported for that binary.
_ASSIGNED = re.compile(
    r"""(?ix)
    (?:pass(?:wd|word)? | secret | token | api[_-]?key | auth[_-]?key | credential |
       access[_-]?key | private[_-]?key)
    ["']? \s* [:=] \s* ["']?
    (?P<val>[^\s"']+)
    """)
_TOKEN = re.compile(r"[A-Za-z0-9+/=_.-]+$")
# A printf template is a message, not a value: "[%s] %s password: " says nothing secret.
_FMT = re.compile(r"%[-#0 +']*[0-9]*(?:\.[0-9]+)?(?:hh|h|ll|l|L|q|j|z|t)?[diouxXeEfgGaAcsp]")


def _secretish(val: str) -> bool:
    """Does the bound value look like a secret rather than a word of prose or a placeholder?"""
    if not 6 <= len(val) <= 256:
        return False
    if val.startswith("-"):                       # a command-line option, not a value
        return False
    if val.lower() in _PLACEHOLDERS:
        return False
    # A long single-alphabet token is the commonest credential shape there is -- a hex API key
    # or a base64 blob has no mixed case and no punctuation at all.
    if len(val) >= 12 and _TOKEN.match(val):
        return True
    kinds = (any(c.islower() for c in val), any(c.isupper() for c in val),
             any(c.isdigit() for c in val), any(not c.isalnum() for c in val))
    return sum(kinds) >= 2                        # mixed case, digits or punctuation


@register_detector
def hardcoded_secrets(ctx: DetectContext):
    """Credentials built into the binary.

    A string the code REFERENCES is a different claim from a string that merely sits in the
    file: one is a credential the program uses, the other could be a sample, a message
    template or data that happens to look like a key. The reference is a second channel, so it
    corroborates -- without it this detector had none at all and a hard-coded credential could
    never leave `candidate`, which is why the eval corpus measured CWE-798 recall at 0.00 for
    the state the release gate scores.
    """
    out = []
    for s in ctx.strings:
        hit = _secret(s.value or "")
        if not hit:
            continue
        cwe, sev, title = hit
        evidence = [{"channel": "string", "detail": f"{(s.value or '')[:60]!r} @ {s.addr}"}]
        used = [x for x in (s.xrefs or []) if x]
        state, conf = "candidate", 0.5
        if used:
            state, conf = "corroborated", 0.7
            where = ", ".join(str(x) for x in used[:4]) + (" ..." if len(used) > 4 else "")
            evidence.append({"channel": "xref",
                             "detail": f"the code reads this string at {where}"})
        cand = _cand(cwe, title, sev, "hardcoded_secrets", evidence,
                     function_addr=None, site_addr=s.addr,
                     dedup_key=f"{cwe}:{s.addr}", confidence=conf)
        cand["state"] = state
        out.append(cand)
    return out


# ---------------------------------------------------------------- TOCTOU (CWE-367/CWE-362)
# Checking a path and then acting on it are two operations on a NAME, not on a file, and
# anything can change what the name refers to in between. The check-then-use pair in one
# function is the shape; the window is whatever runs between them.
# Distinct name from `_TOCTOU_CHECK`/`_TOCTOU_USE` above: same module globals would otherwise
# shadow the comprehensive sets `toctou_race` relies on, silently narrowing BOTH detectors.
_TOCTOU_CHECK_LEGACY = {"access", "stat", "lstat", "faccessat", "statx", "euidaccess", "eaccess"}
_TOCTOU_USE_LEGACY = {"open", "open64", "fopen", "fopen64", "freopen", "creat", "unlink", "remove",
                      "rename", "chmod", "chown", "truncate", "symlink", "link", "mkdir", "rmdir"}




# A credential is a credential whatever the substrate: this detector reads only strings,
# so it works on a jar's constant pool exactly as it works on an ELF's .rodata. The other
# detectors need call edges or mitigation flags, neither of which a JVM target has -- and
# `hardening` in particular would report "no PIE, no NX" about a runtime that has neither
# concept.
hardcoded_secrets.jvm_safe = True  # type: ignore[attr-defined]

@register_detector
def toctou(ctx: DetectContext):
    """A path checked with access()/stat() and then opened or modified in the same function.

    Deliberately reported as a candidate: this is reachability and ordering, not a proof that
    both calls name the same path. What makes it worth reporting anyway is that the safe form
    of this code does not exist -- the fix is to stop checking and handle the error from the
    use itself -- so the pair being present at all is the signal.
    """
    by_func: dict = defaultdict(list)
    for e in ctx.call_edges:
        n = normalize(e.dst_name)
        if n in _TOCTOU_CHECK_LEGACY or n in _TOCTOU_USE_LEGACY:
            by_func[e.src_addr].append((e.site_addr, n))
    out = []
    for faddr, calls in by_func.items():
        ordered = sorted(calls, key=lambda c: _addr_int(c[0]))
        checks = [c for c in ordered if c[1] in _TOCTOU_CHECK_LEGACY]
        if not checks:
            continue
        first = _addr_int(checks[0][0])
        uses = [c for c in ordered if c[1] in _TOCTOU_USE_LEGACY and _addr_int(c[0]) > first]
        if not uses:
            continue
        chk, use = checks[0], uses[0]
        out.append(_cand(
            "CWE-367", f"Check with {chk[1]}() then use with {use[1]}() (TOCTOU)", "medium",
            "toctou",
            [{"channel": "pattern",
              "detail": f"{chk[1]}() at {chk[0]} then {use[1]}() at {use[0]} in the same "
                        f"function -- the path can change in between"}],
            function_addr=faddr, site_addr=use[0],
            dedup_key=f"CWE-367:toctou:{faddr}", confidence=0.4))
    return out


def _addr_int(a) -> int:
    try:
        return int(a, 16) if isinstance(a, str) else int(a or 0)
    except (TypeError, ValueError):
        return 0


# ------------------------------------------------- weak crypto / RNG / temp files (rules)
_WEAK_CRYPTO = {
    "md5": ("CWE-328", "weak hash MD5"), "md4": ("CWE-328", "weak hash MD4"),
    "md2": ("CWE-328", "weak hash MD2"), "sha1": ("CWE-328", "weak hash SHA-1"),
    "des": ("CWE-327", "weak cipher DES"), "rc4": ("CWE-327", "weak cipher RC4"),
}
_WEAK_RANDOM = {"rand", "random", "srand", "srandom", "rand_r",
                "drand48", "lrand48", "mrand48", "erand48"}
_INSECURE_TMP = {"tmpnam", "tempnam", "mktemp"}   # mkstemp is safe, excluded


@register_detector
def weak_crypto(ctx: DetectContext):
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name).lower()
        if not n:
            continue
        for tok, (cwe, desc) in _WEAK_CRYPTO.items():
            if re.search(r"(^|_)" + tok + r"(_|$|[0-9])", n):   # token boundary, not substring
                call = normalize(e.dst_name)
                out.append(_cand(
                    cwe, f"Use of {desc}", "medium", "weak_crypto",
                    [{"channel": "pattern", "detail": f"call to {call}() at {e.site_addr}"}],
                    function_addr=e.src_addr, site_addr=e.site_addr,
                    dedup_key=f"{cwe}:crypto:{tok}", confidence=0.5))
                break
    return out


@register_detector
def weak_random(ctx: DetectContext):
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name).lower()
        if n in _WEAK_RANDOM:
            out.append(_cand(
                "CWE-330", "Use of an insecure/predictable PRNG", "medium", "weak_random",
                [{"channel": "pattern", "detail": f"call to {n}() at {e.site_addr}"}],
                function_addr=e.src_addr, site_addr=e.site_addr,
                dedup_key=f"CWE-330:{n}", confidence=0.4))
    return out


@register_detector
def insecure_tmp(ctx: DetectContext):
    out = []
    for e in ctx.call_edges:
        n = normalize(e.dst_name).lower()
        if n in _INSECURE_TMP:
            out.append(_cand(
                "CWE-377", f"Insecure temporary file via {n}()", "medium", "insecure_tmp",
                [{"channel": "pattern", "detail": f"call to {n}() at {e.site_addr}"}],
                function_addr=e.src_addr, site_addr=e.site_addr,
                dedup_key=f"CWE-377:{n}", confidence=0.5))
    return out


@register_detector
def hardening(ctx: DetectContext):
    """Missing binary mitigations (from triage) as protection-mechanism weaknesses."""
    m = ctx.mitigations or {}
    checks = [
        ("nx", "off", "Executable stack (NX disabled)", "medium", 0.5),
        ("canary", "off", "No stack canary (stack-smashing protection off)", "low", 0.4),
        ("pie", "off", "No PIE (position-dependent; ASLR limited)", "low", 0.4),
        ("relro", "off", "No RELRO (GOT is writable)", "low", 0.4),
        ("relro", "partial", "Partial RELRO (GOT partially writable)", "low", 0.3),
    ]
    out = []
    for key, bad, title, sev, conf in checks:
        if m.get(key) == bad:
            out.append(_cand("CWE-693", title, sev, "hardening",
                             [{"channel": "config", "detail": title}],
                             dedup_key=f"hardening:{key}:{bad}", confidence=conf))
    return out


def reaches_within(start, targets: set, callers: dict, depth: int = 4) -> bool:
    """Is `start` within `depth` call levels below any function in `targets`?

    Breadth-first, so every node is visited at its SHORTEST distance from `start`. The
    previous implementation was a depth-limited DFS sharing ONE `seen` set across the whole
    search: a node first reached with the budget nearly spent was marked visited and never
    re-explored along a shorter path that still had budget, so reachability that genuinely
    existed could be reported as absent. Whether it happened depended on the order a set
    iterated, which is why it never showed up as a reproducible failure -- the worst kind of
    wrong answer, since a missed source just looks like a finding that stayed `candidate`.
    """
    if start in targets:
        return True
    frontier = {start}
    seen = {start}
    for _ in range(depth):
        nxt: set = set()
        for node in frontier:
            nxt |= callers.get(node, set()) - seen
        if not nxt:
            return False
        if nxt & targets:
            return True
        seen |= nxt
        frontier = nxt
    return False


# ----------------------------------- input->sink reachability (approximate taint channel)
def correlate(cands: list, ctx: DetectContext) -> list:
    """Promote dangerous_api sinks that are reachable from an untrusted-input source over
    the call graph (candidate -> corroborated). Approximate: reachability, not data flow."""
    edges = ctx.call_edges
    source_fns = {e.src_addr for e in edges if normalize(e.dst_name) in SOURCES}
    # NB: the entry point is deliberately NOT a source here, even though argv/envp really do
    # arrive as main's parameters. This channel is REACHABILITY, not data flow, and every
    # function is reachable from main -- so seeding it promotes essentially every candidate
    # in any program that takes arguments, which is precision loss with no detection gain
    # (measured: CWE-134 precision 0.33 with it, 1.00 without). argv is modelled in the
    # data-flow channel instead (catalog.ENTRY_PARAM_SOURCES -> taint.analyze_program), which
    # tracks where the bytes actually go and catches these cases on its own.
    callers = defaultdict(set)          # callee entry -> {caller entries}
    for e in edges:
        if e.dst_addr:
            callers[e.dst_addr].add(e.src_addr)

    def reaches_source(fn_addr, depth=4):
        return reaches_within(fn_addr, source_fns, callers, depth)

    for c in cands:
        if c["detector"] == "dangerous_api" and c.get("api") in ADVISORY:
            continue                        # reachability cannot corroborate "verify this"
        if c["detector"] == "dangerous_api" and c.get("function_addr") \
                and reaches_source(c["function_addr"]):
            c["state"] = "corroborated"
            c["confidence"] = max(c["confidence"], 0.65)
            c["evidence"].append({"channel": "taint-reachability",
                                  "detail": "untrusted input reaches this sink (call graph)"})
    return cands
