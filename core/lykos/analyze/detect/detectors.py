"""Deterministic CWE detectors + call-graph reachability correlation (zero-AI).

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
_RUST_SINKS = (
    ("process..Command", "CWE-78", "high", "OS command execution (std::process::Command)"),
    ("Command..new", "CWE-78", "high", "OS command execution (std::process::Command::new)"),
    ("fs..read", "CWE-22", "medium", "file read with a runtime path (std::fs)"),
    ("File..open", "CWE-22", "medium", "file open with a runtime path (std::fs::File)"),
    ("File..create", "CWE-22", "medium", "file create with a runtime path"),
)
# Untrusted-input sources (call-graph reachability). Go: argv/env/flags, stdin readers, HTTP req.
_GO_SOURCES = ("os.Args", "os.Getenv", "flag._FlagSet_", "bufio._Reader_.Read", "bufio._Scanner_.",
               "http._Request_", "ioutil.ReadAll", "io.ReadAll", "os.Stdin")
_RUST_SOURCES = ("env..args", "env..var", "io..stdin", "read_line", "read_to_string")


@register_detector
def lang_sinks(ctx: DetectContext):
    tc = (ctx.toolchain or "").lower()
    # detect language from the toolchain hint, or fall back to the call graph (Go has runtime.*).
    is_go = tc == "go" or any("runtime." in (e.dst_name or "") for e in ctx.call_edges)
    is_rust = tc == "rust"
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
        bufs = [v for v in (frame.get("vars") or []) if v.get("is_buffer")]
        sinks = sinks_by_func.get(addr, [])
        if not bufs or not sinks:
            continue
        buf = min(bufs, key=lambda v: v.get("size", 1 << 30))   # tightest buffer = worst case
        # distance from the buffer to the saved return address in Ghidra frame coords
        ret_off = frame.get("ret_offset")
        off_to_ret = (ret_off - int(buf.get("offset", 0))) if ret_off is not None \
            else abs(int(buf.get("offset", 0))) + 8
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
                                 f"({buf.get('type')}, {buf.get('size')} B); ~{off_to_ret} "
                                 f"bytes from the buffer to the saved return address"),
                    dedup_key=f"CWE-121:stack_frame:{n}", confidence=0.55))
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
_SYM_WIDTH = re.compile(r"(\d+)(?:s|\[)")                      # a width in an r2 str. flag name


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
    cur = reg
    for _ in range(2):
        for t in reversed(texts):
            body = t.split(";")[0]
            m = re.match(r"\s*lea\s+" + re.escape(cur) + r"\s*,\s*(.+)$", body, re.I)
            if m:
                sym = _R2_STR_SYM.search(m.group(1))
                return sym.group(1) if sym else None
            mv = re.match(r"\s*mov\s+" + re.escape(cur) + r"\s*,\s*([a-z0-9]+)\s*$", body, re.I)
            if mv and mv.group(1).lower() in _X86_REGS:
                cur = mv.group(1).lower()
                break
            if re.match(r"\s*(mov|lea|add|sub|xor|pop)\s+" + re.escape(cur) + r"\b", body, re.I):
                return None
        else:
            return None
    return None


def _stack_slot_for_reg(texts, reg: str):
    """The rbp-relative slot (`-K`, an int) that `reg` holds the ADDRESS of at the end of `texts`,
    following one level of reg-to-reg move (`lea rax,[rbp-0x10]; mov rsi,rax`). None if `reg` is not
    a &frame-local at the call. Matches the -O0 argument set-up r2 emits."""
    cur = reg
    for _ in range(2):                                    # at most one mov hop then the lea
        for t in reversed(texts):
            body = t.split(";")[0]
            m = re.match(r"\s*lea\s+" + re.escape(cur) + r"\s*,\s*\[\s*rbp\s*-\s*(0x[0-9a-f]+|\d+)\s*\]",
                         body, re.I)
            if m:
                return -int(m.group(1), 0)
            mv = re.match(r"\s*mov\s+" + re.escape(cur) + r"\s*,\s*([a-z0-9]+)\s*$", body, re.I)
            if mv and mv.group(1).lower() in _X86_REGS:
                cur = mv.group(1).lower()
                break                                     # re-scan for the new source register
            if re.match(r"\s*(mov|lea|add|sub|xor|pop)\s+" + re.escape(cur) + r"\b", body, re.I):
                return None                               # reg was defined by something else
        else:
            return None
    return None


def _memset_size_for_slot(texts, slot: int):
    """Size of a `memset(&local, 0, IMM)` on `slot` earlier in the function (r2: `lea rax,[rbp-K];
    mov rdi,rax; mov edx,IMM; ...; call memset`). Gives the buffer size when the decompiler frame
    did not size the local. None if not found."""
    edx = None
    for t in texts:
        body = t.split(";")[0]
        m = re.match(r"\s*mov\s+(?:edx|rdx)\s*,\s*(0x[0-9a-f]+|\d+)\s*$", body, re.I)
        if m:
            edx = int(m.group(1), 0)
        if _norm_call(body) == "memset" and edx is not None:
            if _stack_slot_for_reg(texts[:texts.index(t)], "rdi") == slot:
                return edx
    return None


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
    if not real_widths:
        return []
    out = []
    for faddr, ir in ctx.func_irs.items():
        frame = ctx.frames.get(faddr) or {}
        vsize = {int(v.get("offset", 1)): int(v.get("size", 0))
                 for v in (frame.get("vars") or []) if v.get("offset") is not None}
        flat = [(i.get("addr"), (i.get("text") or ""))
                for b in ir.get("blocks", []) or [] for i in (b.get("instructions") or [])]
        texts = [t for _, t in flat]
        for idx, (addr, text) in enumerate(flat):
            variant = _norm_call(text)
            if variant not in _SCANF_VARIANTS:
                continue
            fmt_reg, buf_reg = _SCANF_VARIANTS[variant]
            pre = texts[:idx]
            # the format string flag feeding the format register -> its declared widths
            sym = _str_flag_for_reg(pre, fmt_reg)
            widths = {int(w) for w in _SYM_WIDTH.findall(sym)} & real_widths if sym else set()
            if not widths:
                continue
            slot = _stack_slot_for_reg(pre, buf_reg)
            if slot is None:
                continue
            size = vsize.get(slot) or _memset_size_for_slot(pre, slot)
            if not size:
                continue
            n = max(widths)
            if n + 1 <= size:                             # width + NUL fits -> genuinely safe
                continue
            off = "off-by-one NUL" if n + 1 == size + 1 and n == size else f"{n + 1 - size}-byte"
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
                for b in ir.get("blocks", []) or [] for i in (b.get("instructions") or [])]
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
_TOCTOU_CHECK = {"access", "stat", "lstat", "faccessat", "statx", "euidaccess", "eaccess"}
_TOCTOU_USE = {"open", "open64", "fopen", "fopen64", "freopen", "creat", "unlink", "remove",
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
        if n in _TOCTOU_CHECK or n in _TOCTOU_USE:
            by_func[e.src_addr].append((e.site_addr, n))
    out = []
    for faddr, calls in by_func.items():
        ordered = sorted(calls, key=lambda c: _addr_int(c[0]))
        checks = [c for c in ordered if c[1] in _TOCTOU_CHECK]
        if not checks:
            continue
        first = _addr_int(checks[0][0])
        uses = [c for c in ordered if c[1] in _TOCTOU_USE and _addr_int(c[0]) > first]
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
