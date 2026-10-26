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
            return ("idx",) + idx if idx else None
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


def _reg_check(pred_block, after_idx, regs, site_block, dom):
    """The same question for an index held in a REGISTER across the edge from its source block
    (`call strtol; cmp eax, 0xf; ja ...` -> the access in the successor)."""
    from . import bounds
    ins = pred_block.get("instructions") or []
    if not _ends_in_cond_jump(ins):
        return ("unchecked",)
    reaching = dom.get(site_block, ())
    after = ins[after_idx + 1:]
    for r in regs:
        got = bounds.branch_predicate(after, ("reg", r.upper()), ("RBP", "RSP"))
        if got is None:
            continue
        e = bounds._edge_pred_bound(got, pred_block.get("succ") or [], reaching, site_block)
        if e is None:
            return ("unchecked",)
        return ("bounded", e[0], bool(e[1]))
    return None                                            # the branch is not readable on the index


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


def _index_scan_function(ctx, faddr, blocks, targets, summaries, calls, out, resolve_tail=None):
    """Pass 1 of array_index over ONE function (see array_index)."""
    from . import bounds
    ir = {"blocks": blocks}
    frame = ctx.frames.get(faddr) or {}
    _vs, slot_names = _frame_vars(frame)
    entry = next((b.get("addr") for b in blocks if _naddr(b.get("addr")) == _naddr(faddr)),
                 blocks[0].get("addr"))
    slots = _index_slot_sources(ctx, ir, slot_names)
    for sl, src in _param_slot_sources(ir, slot_names, entry).items():
        slots.setdefault(sl, src)
    dom = bounds.dominators(blocks)
    preds: dict = defaultdict(list)
    for b in blocks:
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    by_addr = {b.get("addr"): b for b in blocks}
    # A value held in a REGISTER is followed within its block and into a block whose SOLE
    # predecessor computed it. origin: id(src) -> (block, index of the instruction after which
    # it holds); a parameter arrives before the entry block's first instruction.
    origin: dict = {}
    params = {}
    for k, r in enumerate(_ARG_REGS):
        params[r] = {"source": f"argument {k + 1}", "source_site": faddr, "slot": None,
                     "kind": "param", "param": k}
        origin[id(params[r])] = (entry, -1)
    tail: dict = {}

    def check_for(src, ba, pred):
        if src.get("slot"):
            if src["block"] != ba and src["block"] not in dom.get(ba, ()):
                return None                           # the value does not reach on every path
            return _slot_check(blocks, ba, src["slot"], dom, slot_names)
        o = origin.get(id(src))
        if o is None:
            return None
        if o[0] == ba:
            return ("unchecked",)                     # same block: no branch in between
        if pred is not None and o[0] == pred:
            regs = sorted((r for r, v in tail.get(pred, ({}, None))[0].items()
                           if v[3] is src and v[1] == 1 and v[2] == 0),
                          key=lambda r: r != "rax")
            return _reg_check(by_addr[pred], o[1], regs, ba, dom) if regs else None
        return None                                   # carried further than one edge

    for b in blocks:
        ba = b.get("addr")
        ins = b.get("instructions") or []
        seed, pred = {}, None
        ps = preds.get(ba, [])
        if ba == entry:
            seed = {r: ("idx", 1, 0, params[r]) for r in _ARG_REGS}
        elif len(ps) == 1 and ps[0] in tail and ps[0] != ba:
            pred = ps[0]
            seed = dict(tail[pred][0])
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
                        origin[id(rsrc)] = (ba, j)
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
            v = _index_verdict(check, base, scale, off)
            if v is None:
                continue
            verdict, oob = v
            out.append(_array_index_cand(faddr, i.get("addr"), base, scale, off, src, access,
                                         check, verdict, oob))
        live = {r: v for r, v in tr.st.items() if v[0] == "idx"}
        if live:
            tail[ba] = (live, None)


# ---- aarch64 CWE-129 ---------------------------------------------------------------------------
# The x86 _IdxTracker (operand syntax, SysV registers, [base+idx*scale+disp]) does not fit aarch64,
# so this is a separate, conservative scanner for the commonest shape: an input/parameter integer,
# sign-extended, indexing a GLOBAL array with `str/ldr wN, [xBase, xIdx, lsl #s]`. The index arrives
# either SPILLED to a frame slot (-O0: `str w0,[var]; ldrsw xI,[var]`) or held in a REGISTER (-O2:
# the strtol result / a parameter in w0 used straight in `[xB, w0, sxtw #s]`), tracked across one
# block edge. The DOMINATING-CHECK analysis is reused unchanged -- bounds.guard_bound /
# branch_predicate / _edge_pred_bound work on P-Code, which is architecture-neutral (measured: they
# read `cmp wI,#9; b.gt` as signed and `b.hi` as unsigned correctly) -- with the aarch64 frame bases
# (SP, X29) and a stack-slot key ("SP", frame_offset) or a ("reg", NAME) key. Single function (the
# cross-function join is not yet wired), global arrays, index carried at most one edge; anything the
# tracker cannot resolve is dropped, so a stack array, arm32, or a deeper carry is silent not wrong.
_A64_ARG = ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7")
_A64_NO_IDX_WRITE = {"cmp", "cmn", "tst", "str", "strb", "strh", "stp", "stur", "b", "bl", "blr",
                     "ret", "nop", "cbz", "cbnz", "tbz", "tbnz"}


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
            s = re.search(r"(?:lsl|sxtw|uxtw|sxtx)\s*#?(\d+)", parts[2].lower())
            if s:
                scale = 1 << int(s.group(1))
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


def _a64_slot_check(blocks, by_addr, site_block, slot_off, slot_name, dom):
    """`_slot_check` for aarch64: the P-Code bounds analysis with (SP, X29) bases and an ("SP", off)
    slot key -- an undecidable dominating branch that reads the slot -> None (no claim)."""
    from . import bounds
    slot, bases = ("SP", slot_off), ("SP", "X29")
    for d in dom.get(site_block, ()):
        if d == site_block:
            continue
        ins = (by_addr.get(d) or {}).get("instructions") or []
        if not ins:
            continue
        last = _ops((ins[-1].get("text") or "").split(";")[0].strip())[0]
        ends_cond = last.startswith("b.") or last in ("cbz", "cbnz", "tbz", "tbnz")
        touches = any(("[" + slot_name) in (i.get("text") or "") for i in ins)
        if ends_cond and touches and bounds.branch_predicate(ins, slot, bases) is None:
            return None
    g = bounds.guard_bound(blocks, site_block, slot, bases=bases, dom=dom)
    return ("unchecked",) if g is None else ("bounded", g["bound"], bool(g["nonneg"]))


def _a64_reg_check(pred_block, after_idx, idx_reg, site_block, dom):
    """`_reg_check` for aarch64: an index held in a REGISTER across the edge from the block that
    defined it (`bl strtol; cmp w0,#9; b.gt` / an incoming parameter checked before the access).
    `cmp;b.gt` is signed (a negative index still reaches), `cmp;b.hi` unsigned (proves non-negative)
    -- branch_predicate encodes which, and _edge_pred_bound maps it onto the taken edge."""
    from . import bounds
    ins = pred_block.get("instructions") or []
    if not ins:
        return ("unchecked",)
    last = _ops((ins[-1].get("text") or "").split(";")[0].strip())[0]
    if not (last.startswith("b.") or last in ("cbz", "cbnz", "tbz", "tbnz")):
        return ("unchecked",)
    reaching = dom.get(site_block, ())
    after = ins[after_idx + 1:]
    for name in ("X" + idx_reg[1:], "W" + idx_reg[1:]):            # the compare may name x0 or w0
        got = bounds.branch_predicate(after, ("reg", name), ("SP", "X29"))
        if got is None:
            continue
        e = bounds._edge_pred_bound(got, pred_block.get("succ") or [], reaching, site_block)
        return ("unchecked",) if e is None else ("bounded", e[0], bool(e[1]))
    return None                                                    # the branch is not on the index


def _array_index_arm(ctx, out):
    """aarch64 CWE-129 (single function). See the module note above."""
    for faddr, ir in ctx.func_irs.items():
        blocks = [b for b in ((ir or {}).get("blocks") or [])
                  if isinstance(b, dict) and b.get("addr")]
        if blocks and len(blocks) <= 2000:
            _a64_scan_function(ctx, faddr, blocks, out)


def _a64_scan_function(ctx, faddr, blocks, out):
    """The aarch64 CWE-129 scan over ONE function (its own scope, so `check_for` binds cleanly)."""
    from . import bounds
    frame = ctx.frames.get(faddr) or {}
    _vs, names = _frame_vars(frame)
    entry = next((b.get("addr") for b in blocks if _naddr(b.get("addr")) == _naddr(faddr)),
                 blocks[0].get("addr"))
    slots = _a64_index_slots(ctx, blocks, names, entry)
    dom = bounds.dominators(blocks)
    by_addr = {b.get("addr"): b for b in blocks}
    preds: dict = defaultdict(list)
    for b in blocks:
        for sc in b.get("succ") or []:
            preds[sc].append(b.get("addr"))
    # A register-held index is followed within its block and into a block whose SOLE predecessor
    # defined it. origin: id(src) -> (block, instr index after which it holds); a parameter
    # arrives before the entry block. tail: block -> {reg: idx-value} live at the block end.
    origin: dict = {}
    params: dict = {}
    for k, r in enumerate(_A64_ARG):
        params[r] = {"source": f"argument {k + 1}", "source_site": faddr, "slot": None,
                     "slot_name": None, "kind": "param", "param": k}
        origin[id(params[r])] = (entry, -1)
    tail: dict = {}

    def check_for(src, ba, pred, idx_reg):
        if src.get("slot"):
            return _a64_slot_check(blocks, by_addr, ba, src["slot"][1], src["slot_name"], dom)
        o = origin.get(id(src))
        if o is None:
            return None
        if o[0] == ba:
            return ("unchecked",)                     # same block: no branch between
        if pred is not None and o[0] == pred:
            return _a64_reg_check(by_addr[pred], o[1], idx_reg, ba, dom)
        return None                                   # carried further than one edge

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
        ins = b.get("instructions") or []
        for j, i in enumerate(ins):
            mnem, ops = _ops((i.get("text") or "").split(";")[0].strip())
            if not ops:
                continue
            dst = _a64_canon(ops[0])
            if mnem in ("bl", "blr"):
                name = normalize(re.sub(r"^(sym\.imp\.|sym\.|imp\.|\.)", "",
                                        ops[0])) if ops else ""
                for r in list(reg):                   # a call clobbers the caller-saved regs
                    reg.pop(r, None)
                if name in _INT_PARSERS:
                    rsrc = {"source": name, "source_site": i.get("addr"), "slot": None,
                            "slot_name": None, "kind": "register"}
                    origin[id(rsrc)] = (ba, j)
                    reg["x0"] = ("idx", 1, 0, rsrc)   # the parsed value, in w0/x0
                continue
            if mnem == "adrp":
                c = _a64_adrp_const(i)
                reg[dst] = ("gapage", c) if c is not None else None
                continue
            if mnem == "add" and len(ops) == 3 and _NUM.match(ops[2].lstrip("#")):
                v = reg.get(_a64_canon(ops[1]))
                imm = int(ops[2].lstrip("#"), 0)
                if v and v[0] == "gapage":
                    g = _global_base(ctx, addr=v[1] + imm)
                    reg[dst] = ("ga", g[1], g[0], g[2]) if (g and g[1] is not None) else None
                elif v and v[0] == "idx":
                    reg[dst] = ("idx", v[1], v[2] + imm, v[3])
                else:
                    reg[dst] = None
                continue
            mm = _a64_mem(ops[-1], names)
            if mm and mm[0] == "indexed":                      # an array access
                base, idx = reg.get(mm[1]), reg.get(mm[2])
                store = mnem.startswith("st")
                if base and base[0] == "ga" and idx and idx[0] == "idx":
                    scale, off = idx[1] * mm[3], idx[2] * mm[3]
                    gbase = ("global", base[2], base[1], base[3])
                    src = idx[3]
                    chk = check_for(src, ba, pred, mm[2])
                    v = _index_verdict(chk, gbase, scale, off) if chk else None
                    if v is not None:
                        verdict, oob = v
                        out.append(_array_index_cand(faddr, i.get("addr"), gbase, scale, off,
                                                     src, "write" if store else "read", chk,
                                                     verdict, oob))
                if not store:
                    reg[dst] = None                            # a load result is array data
                continue
            if mnem in ("ldr", "ldrsw", "ldrsb", "ldrsh", "ldrb", "ldrh") and mm \
                    and mm[0] == "slot" and mm[1] in slots:
                reg[dst] = ("idx", 1, 0, slots[mm[1]])          # the index value, from its slot
                continue
            if mnem == "mov" and len(ops) == 2 and re.fullmatch(r"[wx]\d+", ops[1].lower()):
                reg[dst] = reg.get(_a64_canon(ops[1]))
                continue
            if mnem not in _A64_NO_IDX_WRITE and re.fullmatch(r"[wx]\d+", ops[0].lower()):
                reg[dst] = None                                # any other write clobbers it
        tail[ba] = {r: v for r, v in reg.items() if v and v[0] == "idx"}


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
    out: list = []
    if _is_aarch64(ctx.arch) and ctx.bits == 64:
        _array_index_arm(ctx, out)       # a separate, conservative aarch64 scanner
        return out
    if not (_is_x86(ctx.arch) and ctx.bits == 64):
        return []
    summaries: dict = defaultdict(list)    # callee addr -> [(site, base, scale, off, k, access, check)]
    calls: list = []                       # (caller, call site, callee addr, {k: (src, check)})
    targets = {_naddr(e.site_addr): _naddr(e.dst_addr) for e in (ctx.call_edges or [])
               if getattr(e, "dst_addr", None) and not getattr(e, "external", False)}
    # Resolve a tail `jmp` operand to a function entry: the decompiler does not record a call edge
    # for a tail call, so a forwarded parameter at -O2 (`outer: jmp sym.inner`) is invisible through
    # `targets` alone. Match the operand against the known function entries, by name or by address.
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

    for faddr, ir in ctx.func_irs.items():
        # the dominator / guard machinery keys every block by its address: a block without one
        # (a degenerate decompiler record) is dropped rather than allowed to sink the detector
        blocks = [b for b in ((ir or {}).get("blocks") or []) if isinstance(b, dict) and b.get("addr")]
        if not blocks or len(blocks) > 2000:
            continue
        _index_scan_function(ctx, faddr, blocks, targets, summaries, calls, out, resolve_tail)
    # Pass 2: an input value handed to a function that indexes with that parameter -- following a
    # forwarded parameter across MORE THAN ONE call edge. Index the calls by callee and by the
    # caller-PARAMETER each argument carries, then walk from every PARSED-input pass, combining the
    # check at each edge, to the access that indexes the parameter at the end of the chain.
    #
    #   main: i=atoi(argv[1]); f(i)   -->   f(p): g(p)   -->   g(q): table[q]
    #
    # `forwards[(func, param)]` = the calls that pass func's parameter `param` onward (to callee
    # arg k', with the check func applies first); `summaries[func]` = the accesses func indexes
    # with a parameter. A visited set and a depth bound keep a recursive/mutually-recursive call
    # graph finite; the join stays silent (never a false finding) when any edge's check is
    # undecidable, since `_combine_checks(None, ...)` is None.
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
    return out


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
    idx_from = (f"{sname} at {src['source_site']}"
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
    detail = (f"{access} of {where} at {site}: the index comes from input ({idx_from}) and {why}. "
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
