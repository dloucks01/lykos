"""Root-cause analysis of a confirmed crash (Phase 6).

Turns a fault capture (registers, fault address, faulting-instruction bytes, backtrace, memory
maps -- from the ptrace helper or GDB) into a structured explanation: what kind of memory-
safety failure occurred, where, and how attacker input reached it. The dynamic fault is then
*sliced* against the static call graph and taint results to name the path from an input source
to the crash site. objdump, when present, disassembles the faulting instruction (read vs write
vs return); everything else is pure stdlib.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from ..detect.catalog import SOURCES, normalize

# arch (triage naming) -> objdump `-m` machine. NO DEFAULT: the old `.get(arch, "i386:x86-64")`
# decoded a MIPS/PPC/RISC-V fault's bytes as x86-64, and the garbage it printed decided read vs
# write -- or, when the bytes happened to be 0xc3, a `ret` and so a CRITICAL "stack-return-
# overwrite" on a target that has no such instruction. An arch we cannot decode is undecoded.
_OBJDUMP_MACH = {"x86-64": "i386:x86-64", "x86": "i386", "aarch64": "aarch64", "arm": "arm",
                 "mips": "mips", "mipsel": "mips", "riscv": "riscv:rv64",
                 "riscv64": "riscv:rv64", "ppc": "powerpc:common", "ppc64": "powerpc:common64",
                 "s390": "s390:64-bit", "loongarch": "loongarch64", "sh": "sh4",
                 "sparc": "sparc", "sparcv9": "sparc:v9", "m68k": "m68k"}
# Arches whose bytes are big-endian unless the capture says otherwise (objdump's binary input
# otherwise assumes little-endian, which decodes a big-endian MIPS word as a different insn).
_BIG_ENDIAN_DEFAULT = {"mips", "ppc", "ppc64", "s390", "sparc", "sparcv9", "m68k"}
# Per-arch cross objdump to fall back on when the host one is single-target.
_CROSS_OBJDUMP = {"aarch64": "aarch64-linux-gnu-objdump", "arm": "arm-linux-gnueabihf-objdump",
                  "mips": "mips-linux-gnu-objdump", "mipsel": "mipsel-linux-gnu-objdump",
                  "riscv": "riscv64-linux-gnu-objdump", "riscv64": "riscv64-linux-gnu-objdump",
                  "ppc": "powerpc-linux-gnu-objdump", "ppc64": "powerpc64-linux-gnu-objdump",
                  "s390": "s390x-linux-gnu-objdump", "loongarch": "loongarch64-linux-gnu-objdump",
                  "sh": "sh4-linux-gnu-objdump", "sparcv9": "sparc64-linux-gnu-objdump",
                  "m68k": "m68k-linux-gnu-objdump"}


def _to_int(x):
    try:
        return int(x, 0) if isinstance(x, str) else int(x)
    except (ValueError, TypeError):
        return None


def disasm_one(pc_bytes: bytes, arch: str, endianness: Optional[str] = None,
               thumb: bool = False):
    """Disassemble the first instruction in `pc_bytes` via objdump; None if unavailable, or if
    `arch` is one objdump is not asked to decode here (never guessed as x86)."""
    mach = _OBJDUMP_MACH.get(arch or "")
    if not pc_bytes or not mach:
        return None
    tools = [t for t in (shutil.which("objdump"), shutil.which(_CROSS_OBJDUMP.get(arch, "") or
                                                               "\0")) if t]
    if not tools:
        return None
    opts = []
    if arch in ("x86-64", "x86"):
        opts = ["-M", "intel"]
    elif arch == "arm" and thumb:
        opts = ["-M", "force-thumb"]
    big = (endianness == "big") or (endianness is None and arch in _BIG_ENDIAN_DEFAULT)
    if arch not in ("x86-64", "x86"):
        opts.append("-EB" if big else "-EL")
    fd, path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pc_bytes)
        for tool in tools:
            try:
                r = subprocess.run([tool, "-D", "-b", "binary", "-m", mach, *opts, path],
                                   capture_output=True, text=True, timeout=10, check=False)
            except (OSError, subprocess.SubprocessError):
                continue
            for line in r.stdout.splitlines():
                s = line.strip()
                parts = s.split("\t")
                if len(parts) >= 3 and parts[0].rstrip().endswith(":"):
                    # x86 objdump separates mnemonic and operands with spaces, the RISC
                    # back ends with a TAB -- taking parts[2] alone kept `str` and dropped
                    # `w1, [x0]`, the half that names the memory operand.
                    ins = " ".join(" ".join(parts[2:]).split())
                    if ins and not ins.startswith("(bad)"):
                        return ins
                    break
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return None


def mapping_for(maps, addr):
    if addr is None:
        return None
    for m in maps or []:
        if m["start"] <= addr < m["end"]:
            return m
    return None


def _fn_ranges(functions):
    out = []
    for f in functions:
        fa = _to_int(f.addr)
        if fa is None:
            continue
        size = f.size or 1
        out.append((fa, fa + size, f))
    out.sort()
    return out


def _fn_at(ranges, addr):
    for lo, hi, f in ranges:
        if lo <= addr < hi:
            return f
    return None


def module_base(maps, target_path):
    """Runtime load base of the target's OWN module."""
    if not maps or not target_path:
        return 0
    want = os.path.basename(target_path)
    starts = [m["start"] for m in maps
              if m.get("path") and os.path.basename(m["path"]) == want]
    return min(starts) if starts else 0


def _is_entry_name(name: str) -> bool:
    """True for the disassembler's name of the ELF entry point. Ghidra calls it `entry`/`_start`;
    rizin AND radare2 both call it `entry0` (and would use `entry1`... for extra entries) -- which
    the old `in ("entry","start")` check missed, so `image_base` returned None and PIE targets
    rebased NOTHING, silently killing crash attribution on every position-independent binary. The
    dotted decoys rizin also emits -- `entry.init0`, `entry.fini0` -- are the libc init/fini
    thunks, NOT the entry, so they are excluded (they contain a `.`)."""
    nm = (name or "").lstrip("_").lower()
    if "." in nm:
        return False
    return nm == "start" or nm == "entry" or (nm.startswith("entry") and nm[5:].isdigit())


def image_base(functions, elf_entry):
    """The address the DECOMPILER placed file offset 0 at, or None if it cannot be derived.

    Ghidra rebases a position-independent image -- 0x100000 for ET_DYN on this toolchain --
    so a runtime address minus its load base is a FILE OFFSET, not a decompiler address. That
    is derived here rather than assumed: the ELF header gives the entry point as a file vaddr
    and the function table gives the same function's decompiler address, and the difference
    between them is the base. Guessing it (rounding the lowest function down to a boundary)
    would resolve frames to the wrong functions whenever the guess was off.
    """
    if elf_entry is None:
        return None
    for f in functions:
        if _is_entry_name(f.name or ""):
            a = _to_int(f.addr)
            if a is not None and a >= elf_entry:
                return a - elf_entry
    return None


def rebase_delta(maps, target_path, functions, elf_entry):
    """How much to subtract from a runtime address to get a decompiler address.

    0 for a non-PIE image (the two coincide) and None when it cannot be established, in which
    case frames are matched absolutely and a PIE target simply resolves nothing -- which is
    what it did before, and is at least honest.
    """
    rb = module_base(maps, target_path)
    ib = image_base(functions, elf_entry)
    if not rb or ib is None:
        return None
    return rb - ib


def symbolize(addr, maps, ranges, target_path, delta=None):
    m = mapping_for(maps, addr)
    module = os.path.basename(m["path"]) if (m and m["path"]) else (
        "[anon]" if m else "??")
    entry = {"addr": addr, "module": module,
             "offset": (addr - m["start"]) if m else None, "symbol": None}
    # Absolute match (no-PIE) -- but only for an address that is not POSITIVELY in some other
    # module. A frame in libc, a [heap]/[stack] page or the vdso that happens to fall inside the
    # decompiler's address range (a rebased PIE image at 0x100000, a 32-bit guest layout) was
    # named after a target function it has nothing to do with.
    foreign = False
    if m and m.get("path") and target_path:
        mp = str(m["path"])
        if mp.endswith(" (deleted)"):
            mp = mp[:-len(" (deleted)")]
        foreign = mp.startswith("[") or os.path.basename(mp) != os.path.basename(target_path)
    f = None if foreign else _fn_at(ranges, addr)
    static = addr
    if f is None and delta and module == os.path.basename(target_path or ""):
        f = _fn_at(ranges, addr - delta)          # PIE: rebase into the decompiler's image
        if f is not None:
            static = addr - delta
    if f is not None:
        entry["symbol"] = f.name or f"sub_{f.addr}"
        entry["func_addr"] = f.addr
        entry["static_addr"] = static
    return entry


# Widest call encoding across the supported ISAs (m68k `jsr` reaches 6 bytes; SuperH's return
# address clears a delay slot), so a return address sits within this much of its call.
_CALL_WINDOW = 16
# Weakest to strongest. The distinction is the whole point: being in the same function as a
# crash is proximity, while faulting inside the call a finding names is a demonstration.
_TIERS = ("crash-function", "on-stack", "fault-site")


def attribute(frames, findings, sites_by_finding=None):
    """Which static findings does this crash actually demonstrate, and at which site?

    A verified PoC used to land as an orphan row keyed on the signal, next to an undifferen-
    tiated pile of static findings -- on jhead, one "out-of-bounds read" beside 38 unknown
    copy sites, several in the very function the fault was in, with nothing joining them.
    The backtrace already says which calls were executing; this reads it.

    Strength is graded and only the top tier is a proof:
      fault-site     the faulting PC is inside the call this site makes -- the sink itself
                     faulted, so the finding is demonstrated
      on-stack       that call was somewhere on the stack, so the site is on the crash path
      crash-function the site merely sits in a function the stack runs through

    Every tier NAMES THE SITE. Findings are deduped at defect grain -- one CWE-120 row covers
    twenty memcpy sites -- so "this defect occurs in a function on the stack" is close to
    vacuous on its own; which occurrence is the whole content of the claim.
    """
    by_finding = sites_by_finding or {}
    occ_of, sites = {}, []
    for f in findings:
        occ = [o for o in (by_finding.get(f.id) or []) if o.get("site_addr")]
        if not occ and f.site_addr:
            occ = [{"function_addr": f.function_addr, "site_addr": f.site_addr}]
        occ_of[f.id] = occ
        for o in occ:
            sa = _to_int(o.get("site_addr"))
            if sa is not None:
                sites.append((sa, f, o))
    fn_addrs = {_to_int(fr.get("func_addr")) for fr in frames}
    fn_addrs.discard(None)
    sym_of = {_to_int(fr.get("func_addr")): fr.get("symbol") for fr in frames
              if fr.get("func_addr")}
    best: dict = {}

    def where(o):
        fa, sa = _to_int(o.get("function_addr")), _to_int(o.get("site_addr"))
        name = sym_of.get(fa) or (f"0x{fa:x}" if fa is not None else "?")
        return f"0x{sa:x} in {name}" if sa is not None else name

    def offer(f, tier, detail, occ):
        cur = best.get(f.id)
        if cur is None or _TIERS.index(tier) > _TIERS.index(cur["tier"]):
            best[f.id] = {"finding": f, "tier": tier, "detail": detail,
                          "site": (occ or {}).get("site_addr"),
                          "function_addr": (occ or {}).get("function_addr")}

    for f in findings:
        for o in occ_of.get(f.id, ()):
            if _to_int(o.get("function_addr")) in fn_addrs:
                offer(f, "crash-function",
                      f"a site of this defect ({where(o)}) sits in a function on the crashing "
                      f"call stack -- proximity, not proof", o)
                break

    # The faulting instruction IS a recorded site. This is the only match available to a
    # finding that is not a call -- an out-of-bounds read is a `mov`, and matching return
    # addresses to call sites can never reach it. It is also the strongest match there is:
    # not "the call that faulted" but "the instruction that faulted".
    if frames and frames[0].get("fault_pc"):
        pc = frames[0].get("static_addr")
        if pc is not None:
            for sa, f, o in sites:
                if sa == pc:
                    offer(f, "fault-site",
                          f"the faulting instruction IS this site ({where(o)})",
                          o)

    # Frame 0 is the faulting instruction; every later frame is a RETURN address, which sits
    # just past the call it came from. That is what ties a frame to a recorded call site.
    returns = frames[1:] if (frames and frames[0].get("fault_pc")) else frames
    for depth, fr in enumerate(returns):
        ra = fr.get("static_addr")
        if ra is None:
            continue
        near = [t for t in sites if 0 < ra - t[0] <= _CALL_WINDOW]
        if not near:
            continue
        sa, f, o = max(near, key=lambda t: t[0])   # closest call before the return address
        if depth == 0:
            offer(f, "fault-site",
                  f"the fault occurred inside the call this finding names at {where(o)}",
                  o)
        else:
            offer(f, "on-stack",
                  f"the call at {where(o)} was on the stack when the fault occurred",
                  o)
    return sorted(best.values(), key=lambda a: -_TIERS.index(a["tier"]))


_X86_PREFIXES = frozenset({"rep", "repe", "repz", "repne", "repnz", "lock", "bnd", "notrack",
                           "data16", "addr32", "xacquire", "xrelease", "cs", "ds", "es", "fs",
                           "gs", "ss", "{vex}", "{vex3}", "{evex}"})
# Instructions whose memory operand is only READ even when it is written first (Intel order).
_X86_READ_ONLY = frozenset({"cmp", "test", "bt", "ptest", "vptest", "ucomiss", "ucomisd",
                            "comiss", "comisd", "vucomiss", "vucomisd", "vcomiss", "vcomisd",
                            "cmpsb", "cmpsw", "cmpsd", "cmpsq", "cmps", "scas", "scasb", "scasw",
                            "scasd", "scasq", "push", "call", "jmp", "ljmp", "lcall", "bound",
                            "verr", "verw", "lgdt", "lidt", "lldt", "ltr", "lmsw", "outs",
                            "outsb", "outsw", "outsd", "ldmxcsr", "vldmxcsr", "mul", "div",
                            "idiv", "clflush", "clflushopt", "clwb", "prefetch", "prefetchw",
                            "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta"})
# One-operand instructions that WRITE their memory operand (the rest -- fld, fadd, push, call,
# mul, div, jmp, ... -- read it). `fld QWORD PTR [rax]` was a "write" because its only operand
# "is the destination", and so was `call QWORD PTR [rax+8]`.
_X86_SINGLE_WRITE = frozenset({"inc", "dec", "not", "neg", "pop", "fst", "fstp", "fist", "fistp",
                               "fisttp", "fbstp", "fnstcw", "fstcw", "fnstsw", "fstsw",
                               "fnstenv", "fstenv", "fnsave", "fsave", "fxsave", "fxsave64",
                               "xsave", "xsave64", "xsaveopt", "xsavec", "xsaves", "stmxcsr",
                               "vstmxcsr", "sgdt", "sidt", "sldt", "str", "smsw", "cmpxchg8b",
                               "cmpxchg16b", "stos", "stosb", "stosw", "stosd", "stosq", "movs",
                               "movsb", "movsw", "movsq", "ins", "insb", "insw", "insd"})


def _x86_access(disasm: str) -> Optional[str]:
    toks = disasm.replace(",", " , ").split()
    while toks and toks[0].lower() in _X86_PREFIXES:
        toks = toks[1:]
    if not toks:
        return None
    mnem = toks[0].lower()
    ops = [o.strip() for o in " ".join(toks[1:]).replace(" , ", ",").split(",") if o.strip()]
    if not any("[" in o for o in ops):
        # No explicit memory operand: only the implicit STACK accesses can fault here.
        if mnem in ("push", "pushf", "pushfq", "pushfd", "call", "enter"):
            return "write"
        if mnem in ("pop", "popf", "popfq", "popfd", "leave"):
            return "read"
        return None                                   # direction is not in the instruction
    if mnem in _X86_READ_ONLY or mnem.startswith(("j", "loop", "fld", "fild", "fxrstor",
                                                  "xrstor", "frstor", "fldenv", "fldcw")):
        return "read"
    if mnem in ("xchg", "xadd", "cmpxchg"):
        return "write"                                # always writes its memory operand
    if len(ops) == 1:
        if mnem in _X86_SINGLE_WRITE or mnem.startswith("set"):
            return "write"
        return "read"
    return "write" if "[" in ops[0] else "read"


# RISC ISAs name the direction in the MNEMONIC (the register operand comes first for a store as
# well as a load), so `str w1, [x0]` -- a STORE -- read as a load under the x86 "is the first
# operand memory?" rule, and every cross-arch out-of-bounds write was filed as CWE-125.
_RISC_STORE_PREFIX = {
    "aarch64": ("st", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
                "swp", "cas"),
    "arm": ("st", "push", "vst", "vpush", "swp"),
    "ppc": ("st", "dcbz"), "ppc64": ("st", "dcbz"),
    "loongarch": ("st", "fst", "sc.", "am"),
    "sparc": ("st", "swap", "cas", "ldstub"), "sparcv9": ("st", "swap", "cas", "ldstub"),
}
_RISC_LOAD_PREFIX = {
    "aarch64": ("ld", "prfm"), "arm": ("ld", "pop", "vld", "vpop"),
    "ppc": ("l",), "ppc64": ("l",), "loongarch": ("ld", "fld", "ll."),
    "sparc": ("ld",), "sparcv9": ("ld",),
}
_MIPS_STORES = frozenset({"sb", "sh", "sw", "sd", "swl", "swr", "sdl", "sdr", "sc", "scd",
                          "swc1", "sdc1", "swc2", "sdc2", "swxc1", "sdxc1", "suxc1", "sq"})
_MIPS_LOADS = frozenset({"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "lwl", "lwr", "ldl", "ldr",
                         "ll", "lld", "lwc1", "ldc1", "lwc2", "ldc2", "lwxc1", "ldxc1", "luxc1"})
_RISCV_STORES = ("sb", "sh", "sw", "sd", "sq", "c.sw", "c.sd", "c.swsp", "c.sdsp", "fsw", "fsd",
                 "fsq", "c.fsw", "c.fsd", "c.fswsp", "c.fsdsp", "sc.", "amo")
_RISCV_LOADS = ("lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "c.lw", "c.ld", "c.lwsp", "c.ldsp",
                "flw", "fld", "flq", "c.flw", "c.fld", "c.flwsp", "c.fldsp", "lr.")
_S390_WRITES = frozenset({"mvc", "mvi", "mviy", "mvhi", "mvghi", "mvhhi", "xc", "oc", "nc", "ni",
                          "oi", "xi", "niy", "oiy", "xiy", "mvcle", "mvst"})


def _access_kind(disasm, arch: Optional[str] = None) -> Optional[str]:
    """"read" / "write" for the memory access the faulting instruction makes, or None when the
    instruction (or its absence) does not say. None is an answer: it must not be filed as a read."""
    if not disasm:
        return None
    text = str(disasm).strip()
    mnem = text.split(None, 1)[0].lower() if text else ""
    rest = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
    a = (arch or "").lower()
    if a in ("", "x86-64", "x86", "amd64", "i386"):
        if not a and mnem in ("str", "stp", "stur", "strb", "strh") and "," in rest:
            return "write"                            # an arch-less aarch64/arm store
        return _x86_access(text)
    if a in ("mips", "mipsel", "mips64"):
        m = mnem.rstrip(".")
        return "write" if m in _MIPS_STORES else ("read" if m in _MIPS_LOADS else None)
    if a in ("riscv", "riscv64"):
        if mnem.startswith(_RISCV_STORES):
            return "write"
        return "read" if mnem.startswith(_RISCV_LOADS) else None
    if a in ("s390", "s390x"):
        if mnem in _S390_WRITES or mnem.startswith("st"):
            return "write"
        return "read" if mnem.startswith(("l", "c", "ic", "tm")) and "(" in rest else None
    if a in ("sh", "m68k"):
        # MIT/SuperH order: the DESTINATION is the last operand; `@` marks memory
        ops = [o.strip() for o in rest.split(",") if o.strip()]
        if not ops or not any("@" in o for o in ops):
            return None
        if mnem.startswith(("tst", "cmp", "btst", "pea", "jmp", "jsr", "lea", "bra")):
            return "read"
        if len(ops) == 1:
            return "write" if mnem.startswith(("clr", "neg", "not", "s", "add", "sub", "mov",
                                               "fmov")) else "read"
        return "write" if "@" in ops[-1] else "read"
    stores = _RISC_STORE_PREFIX.get(a)
    if stores is not None:
        if mnem.startswith(stores):
            return "write"
        if mnem.startswith(_RISC_LOAD_PREFIX.get(a, ())):
            return "read"
    return None


def _is_memory_write(disasm, arch: Optional[str] = None):
    """True when the faulting instruction STORES to memory (see `_access_kind`)."""
    return _access_kind(disasm, arch) == "write"


# A deliberate trap: an assertion, `__builtin_trap`, a compiler-inserted check (clang CFI,
# -fsanitize-trap, Rust's abort) -- not "execution reached corrupted code". Reading `ud2` as
# illegal-instruction rated it EXPLOITABLE ("bad control-flow target") on every such abort.
_TRAP_MNEMONICS = frozenset({"ud2", "ud1", "ud0", "udf", "brk", "int3", "bkpt", "trap",
                             "unimp", "c.unimp", "break", "illtrap", "tw", "td", "trapa"})


# AddressSanitizer/UBSan bug class -> (CWE, severity). The sanitizer names the exact defect a
# bare SIGABRT cannot; for the source-code path this is the difference between "aborted by a
# runtime check" and "heap-buffer-overflow at parser.c:88".
_ASAN_CWE = {
    "heap-buffer-overflow": ("CWE-122", "critical"),
    "stack-buffer-overflow": ("CWE-121", "critical"),
    "global-buffer-overflow": ("CWE-787", "high"),
    "dynamic-stack-buffer-overflow": ("CWE-121", "critical"),
    "heap-use-after-free": ("CWE-416", "critical"),
    "stack-use-after-return": ("CWE-562", "high"),
    "stack-use-after-scope": ("CWE-562", "high"),
    "use-after-poison": ("CWE-416", "high"),
    "double-free": ("CWE-415", "high"),
    "alloc-dealloc-mismatch": ("CWE-762", "medium"),
    "attempting-free-on-address": ("CWE-590", "high"),
    "bad-free": ("CWE-590", "high"),
    "negative-size-param": ("CWE-1284", "medium"),
    "SEGV": ("CWE-476", "high"),
    # NOT memory corruption. A library that believes a size field in its input allocates what the
    # input asked for, and ASan reports that as its own class -- which was absent here, so the
    # fallback called it CWE-119 at HIGH: a denial of service reported as a write primitive. It is
    # a real defect (libtiff and libjpeg both carry CVEs for it) and it is a different one.
    "allocation-size-too-big": ("CWE-789", "medium"),
    "out-of-memory": ("CWE-400", "medium"),
}

#: ASan's class name does NOT say which way the access went: `heap-buffer-overflow` is reported
#: for a one-byte READ past the end and for a wild WRITE alike, and the table above resolved both
#: to CWE-122 "heap-based buffer overflow" at severity CRITICAL. A read is not a write: it
#: discloses or crashes, it does not corrupt, and calling it critical spends the reader's
#: attention on the wrong finding. The report DOES state the direction ("READ of size 1 at ..."),
#: so where it does, the class is resolved by it. Where it does not, the entry above stands --
#: the same rule the UBSan table follows for the check that cannot distinguish them.
_ASAN_BY_ACCESS = {
    ("heap-buffer-overflow", "write"): ("CWE-122", "critical"),
    ("heap-buffer-overflow", "read"): ("CWE-125", "high"),
    ("stack-buffer-overflow", "write"): ("CWE-121", "critical"),
    ("stack-buffer-overflow", "read"): ("CWE-125", "high"),
    ("dynamic-stack-buffer-overflow", "write"): ("CWE-121", "critical"),
    ("dynamic-stack-buffer-overflow", "read"): ("CWE-125", "high"),
    ("global-buffer-overflow", "write"): ("CWE-787", "high"),
    ("global-buffer-overflow", "read"): ("CWE-125", "high"),
    ("stack-buffer-underflow", "write"): ("CWE-787", "critical"),
    ("stack-buffer-underflow", "read"): ("CWE-125", "high"),
    ("heap-use-after-free", "write"): ("CWE-416", "critical"),
    ("heap-use-after-free", "read"): ("CWE-416", "high"),
}

# UndefinedBehaviorSanitizer names the exact check that fired in its "runtime error:" line, so the
# report carries the bug class already -- classifying every one of them as CWE-758 ("reliance on
# undefined behaviour") threw that away and reported an out-of-bounds array write as a vague
# medium. Matched in order, first hit wins; anything unrecognised still falls back to CWE-758.
_UBSAN_CWE = (
    # An out-of-bounds array access. UBSan does not say whether it was a read or a write, so this
    # stays at the bounds PARENT class rather than claiming CWE-125/CWE-787 it cannot distinguish.
    (r"\bindex\b.*\bout of bounds\b", "array-index-out-of-bounds", "CWE-119", "high"),
    (r"\bvariable length array bound\b", "vla-bound-not-positive", "CWE-129", "medium"),
    (r"\b(?:signed|unsigned) integer overflow\b", "integer-overflow", "CWE-190", "high"),
    (r"\bnegation of .* cannot be represented\b", "integer-overflow", "CWE-190", "medium"),
    (r"\bimplicit conversion from type\b", "integer-truncation", "CWE-197", "medium"),
    (r"\bdivision by zero\b", "divide-by-zero", "CWE-369", "medium"),
    (r"\b(?:member access within|member call on|load of|store to|applying .* to|"
     r"binding reference to|applying zero offset to)\s*(?:misaligned address|null pointer)",
     "null-pointer-dereference", "CWE-476", "high"),
    (r"\bshift exponent\b", "bad-shift", "CWE-1335", "medium"),
    (r"\bpointer index expression .* overflowed\b", "pointer-overflow", "CWE-823", "medium"),
    (r"\bnot a valid value for type\b", "invalid-value-load", "CWE-704", "medium"),
    (r"\bthrough pointer to incorrect function type\b", "function-type-mismatch",
     "CWE-686", "medium"),
    (r"\bexecution reached the end of a value-returning function\b", "missing-return",
     "CWE-758", "low"),
)


def _classify_ubsan(msg: str):
    """(class, cwe, severity) for a UBSan 'runtime error: ...' message."""
    import re
    for pat, bug, cwe, sev in _UBSAN_CWE:
        if re.search(pat, msg, re.I):
            return bug, cwe, sev
    return "undefined-behavior", "CWE-758", "medium"

# Tokens that can follow "AddressSanitizer:" in a non-defect line (setup/runtime failures, not
# bugs in the target). Belt-and-braces alongside the colon requirement in parse_asan_report.
_ASAN_NONBUG = frozenset({"failed", "out", "hard", "requested", "cannot", "unable", "shadow",
                          "nested", "ignoring", "while", "thread", "internal", "atos"})

#: Classes ASan words as a SENTENCE. The token regex takes the first word-like thing after the
#: colon, which for these is English prose -- and two of those words are in the denylist above, so
#: the report was not merely mislabelled but DROPPED. Measured: `attempting double-free on 0x...`
#: came out as class `attempting` carrying CWE-119, and `requested allocation size 0x8000...
#: exceeds maximum supported size` matched `requested`, which the denylist removes, so
#: `parse_asan_report` returned None and a reachable, CVE-bearing defect class produced NO FINDING
#: AT ALL -- the very outcome the comment on `allocation-size-too-big` below says it fixed, by an
#: entry nothing could ever reach.
_ASAN_SENTENCE = (
    (re.compile(r"AddressSanitizer:\s*attempting double-free"), "double-free"),
    (re.compile(r"AddressSanitizer:\s*attempting free on address"), "bad-free"),
    (re.compile(r"AddressSanitizer:\s*requested allocation size 0x[0-9a-f]+.*?exceeds maximum"),
     "allocation-size-too-big"),
    # A looser second pass for the same class: the exact wording of this line has moved across
    # clang releases ("exceeds maximum supported size", "exceeds the maximum"), and matching
    # neither is how this report came to be dropped in the first place.
    (re.compile(r"AddressSanitizer:\s*(?:requested )?allocation size .*?exceeds (?:maximum|the)"),
     "allocation-size-too-big"),
)
#: How each sentence class reads in the finding's detail line.
_SENTENCE_DETAIL = {
    "bad-free": "free of an address that was never allocated",
    "allocation-size-too-big": "allocation of an attacker-sized region refused by the allocator",
}


#: Stack frames that belong to the REPORTING machinery and not to the defect: the sanitizer
#: runtimes, their interceptors and libFuzzer's own driver.
_RUNTIME_FRAME = re.compile(
    r"(?:ubsan|asan|msan|tsan|lsan|hwasan|sanitizer|interception)_"
    r"|compiler-rt/|(?:^|/)Fuzzer[A-Za-z]*\.cpp$")
#: The glibc path `abort()` raises through. glibc ships file names (`./nptl/pthread_kill.c`), so
#: without this the first frame "naming a real source file" is the abort path on every build that
#: halts on error. Matched on the DIRECTORY as well as the name, because a project is entitled to
#: its own `signal.c` or `abort.c` and a frame in one of those is a frame in the target.
_LIBC_RAISE = re.compile(
    r"(?:^|/)(?:nptl|sysdeps|stdlib|signal|csu)/(?:[^/]+/)*[^/]*"
    r"(?:pthread_kill|pthread_sigqueue|raise|abort|sigaction|sigsuspend)[^/]*\.c$")


def _is_runtime_frame(path: str) -> bool:
    """Is this stack frame the machinery that REPORTED the fault rather than the fault's site?"""
    return bool(_RUNTIME_FRAME.search(path) or _LIBC_RAISE.search(path))


def _ubsan_site(t: str) -> Optional[str]:
    """The source location UBSan itself names, from its report line or its summary."""
    fm = re.search(r"^(\S+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+):\d+: runtime error:", t, re.M)
    if fm is None:
        fm = re.search(r"SUMMARY:\s*UndefinedBehaviorSanitizer:\s*\S+\s+"
                       r"(\S+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)", t)
    return f"{fm.group(1).split('/')[-1]}:{fm.group(2)}" if fm else None


#: Where the object was freed, and where it was allocated. A lifetime defect has THREE locations
#: -- the use, the free and the allocation -- and a report that names only the use tells whoever
#: reads it the one thing they can already see from the stack. ASan prints both sections; the
#: allocator frame inside each has no file:line, so the first frame that does is the project's.
_ASAN_FREED_BY = re.compile(r"^freed by thread .*? here:$", re.M)
_ASAN_ALLOCED_BY = re.compile(r"^(?:previously )?allocated by thread .*? here:$", re.M)
#: A sanitizer stack frame that names a source file. The address and the `in` are OPTIONAL
#: because ThreadSanitizer omits both -- it writes `#0 bump /src/race.c:6:66 (race+0xea472)` where
#: ASan writes `#1 0x5a in main /src/x.c:12`. Requiring the ASan shape meant a data race had no
#: site at all: not the two racing lines, and not even one **[measured]**.
_ASAN_FRAME = re.compile(
    r"#\d+ (?:0x[0-9a-f]+ in )?\S+ ([^\s:]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)")


def _section_site(t: str, header: re.Pattern) -> Optional[str]:
    """The first project source location in the stack under `header`, or None."""
    m = header.search(t or "")
    if m is None:
        return None
    # The section ends at the next blank line; ASan separates them with one.
    tail = t[m.end():]
    end = tail.find("\n\n")
    for fm in _ASAN_FRAME.finditer(tail if end < 0 else tail[:end]):
        if _is_runtime_frame(fm.group(1)):
            continue
        return f"{fm.group(1).split('/')[-1]}:{fm.group(2)}"
    return None


def parse_asan_report(text: str) -> Optional[dict]:
    """Turn an AddressSanitizer / UBSan report into a classification, with the source location
    when the build was symbolized. Returns None when the text carries no sanitizer report."""
    import re
    t = text or ""
    # A real bug line is `ERROR: AddressSanitizer: <class>` or `SUMMARY: AddressSanitizer:
    # <class>` -- the colon after "AddressSanitizer" is what separates a defect report from a
    # runtime *setup failure* like "AddressSanitizer failed to allocate ..." (no colon), which a
    # too-small address-space limit produces and which is NOT a finding. Requiring the colon,
    # plus a denylist for the odd non-bug token, keeps those out of the classification.
    m = re.search(r"(?:ERROR|SUMMARY):\s*AddressSanitizer:\s*([a-z][a-z0-9-]+)", t)
    # Some classes are stated as a SENTENCE rather than as a token, and the token regex above
    # then picks the first word of English prose. Matched before it, so the class is the defect.
    sentence = next((cls for rx, cls in _ASAN_SENTENCE if rx.search(t)), None)
    if sentence:
        m = None
    # MemorySanitizer reports the one class ASan/UBSan cannot: a READ of memory that was never
    # initialized (CWE-457). It needs its own -fsanitize=memory build (clang, mutually exclusive
    # with ASan), so this fires only when such a binary is detonated -- see compile_source_msan.
    msan = re.search(r"(?:ERROR|SUMMARY):\s*MemorySanitizer:\s*(use-of-uninitialized-value)", t)
    # ThreadSanitizer reports a data race (CWE-362) -- a concurrency class none of the other
    # sanitizers see; it needs its own -fsanitize=thread build (see compile_source_tsan).
    tsan = re.search(r"(?:WARNING|ERROR|SUMMARY):\s*ThreadSanitizer:\s*(data race|"
                     r"heap-use-after-free|thread leak|lock-order-inversion|"
                     r"destroy of a locked mutex|signal-unsafe call)", t)
    # LeakSanitizer (standalone, or inside an ASan build) reports a memory leak (CWE-401).
    lsan = re.search(r"(?:ERROR|SUMMARY):\s*LeakSanitizer:\s*detected memory leaks", t) or \
        re.search(r"(?:Direct|Indirect) leak of \d+ byte", t)
    ub = re.search(r"runtime error:\s*(.+)", t)
    if m and m.group(1) in _ASAN_NONBUG:
        m = None
    if not m and not msan and not tsan and not lsan and not ub and not sentence:
        return None
    if sentence:
        bug = sentence
        cwe, sev = _ASAN_CWE[bug]
        detail = f"AddressSanitizer: {_SENTENCE_DETAIL.get(bug, bug.replace('-', ' '))}"
        who = "AddressSanitizer"
    elif msan:
        bug = "use-of-uninitialized-value"
        cwe, sev = ("CWE-457", "medium")
        detail = "MemorySanitizer: use of uninitialized value"
        who = "MemorySanitizer"
    elif tsan:
        bug = tsan.group(1).replace(" ", "-")
        cwe, sev = (("CWE-416", "high") if bug == "heap-use-after-free" else ("CWE-362", "high"))
        detail = f"ThreadSanitizer: {tsan.group(1)}"
        who = "ThreadSanitizer"
    elif lsan:
        bug = "memory-leak"
        cwe, sev = ("CWE-401", "low")
        detail = "LeakSanitizer: detected memory leak"
        who = "LeakSanitizer"
    elif m:
        bug = m.group(1)
        cwe, sev = _ASAN_CWE.get(bug, ("CWE-119", "high"))
        detail = f"AddressSanitizer: {bug.replace('-', ' ')}"
        who = "AddressSanitizer"
    else:
        msg = ub.group(1).strip()
        bug, cwe, sev = _classify_ubsan(msg)
        detail = f"UndefinedBehaviorSanitizer: {msg[:120]}"
        who = "UndefinedBehaviorSanitizer"
    # WHERE THE DEFECT IS. UBSan states it in its own report line, and that beats any stack walk:
    # a build that aborts on error hands libFuzzer a deadly signal, and the stack libFuzzer then
    # prints begins in the REPORTING machinery rather than in the library. Measured on expat
    # 2.1.0: the left-shift fault at `xmltok_impl.c:694` was filed, keyed and deduped as
    # `pthread_kill.c:43` -- the glibc file `abort()` raises from, which ships source names like
    # any other. That is not merely a wrong label: the site is the DEDUP KEY for a sanitizer
    # defect, so every UBSan fault in a campaign collapsed into one finding at one glibc line.
    src = _ubsan_site(t) if ub and not (m or msan or tsan or lsan) else None
    if src is None:
        for fm in _ASAN_FRAME.finditer(t):
            if _is_runtime_frame(fm.group(1)):
                continue                                 # the reporting machinery, not the bug
            src = f"{fm.group(1).split('/')[-1]}:{fm.group(2)}"
            break
    # A report whose stack held nothing but runtime frames, or none at all: a recovered UBSan
    # verdict (`-fsanitize-recover`, or a tool that captured only the summary) prints no stack.
    if src is None:
        src = _ubsan_site(t)
    # WHICH sanitizer said so. Nothing set this, and `libfuzzer_stage` reads it with
    # `cls.get("sanitizer", "AddressSanitizer")` -- so every UBSan and ThreadSanitizer finding
    # ever filed claimed AddressSanitizer in its evidence **[measured]**. It is also the only
    # honest way to tell TSan's `heap-use-after-free` from ASan's: same class name, different
    # evidence, and only one of them has an offset inside a freed chunk to reason about.
    out = {"class": bug, "cwe": cwe, "severity": sev, "sanitizer": who,
           "detail": detail + (f" at {src}" if src else ""), "source": src}
    out.update(_access_detail(t))
    out.update(_quantity_detail(t, bug))
    if tsan:
        out.update(_tsan_detail(t))
    if msan:
        # WHETHER IT ESCAPED. The class is one name for two defects an operator must triage
        # differently, and only the report can tell them apart -- see `_msan_detail`.
        out.update(_msan_detail(t))
        if out.get("escape_bytes") is not None:
            out["cwe"], out["severity"] = "CWE-200", "high"
            out["detail"] = (f"MemorySanitizer: {out.get('escape_bytes')} bytes of "
                             f"{out.get('origin') or 'uninitialised'} memory reached "
                             f"`{out.get('escape_fn')}`"
                             + (f" at {src}" if src else ""))
    refined = _ASAN_BY_ACCESS.get((bug, out.get("access") or ""))
    if refined:
        out["cwe"], out["severity"] = refined
        out["detail"] = (f"AddressSanitizer: {bug.replace('-', ' ')} "
                         f"({out['access'].upper()} of size {out.get('access_size')})"
                         + (f" at {src}" if src else ""))
    return out


#: `READ of size 4 at 0x...` -- the access that faulted. ASan states the DIRECTION and WIDTH of
#: the access, which no register capture can recover on a sanitizer build: the process aborts
#: inside the ASan runtime, so the fault-time pc belongs to the reporting machinery and not to
#: the instruction that went out of bounds.
_ASAN_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+) at 0x([0-9a-f]+)")
#: `0x... is located 5 bytes after 20-byte region [0x..,0x..)`. Clang 21 writes "after"/"before";
#: older releases wrote "to the right of"/"to the left of". Both are accepted because a parser
#: that silently matches neither reports an overflow with no magnitude, which reads as if the
#: tool looked and found nothing to say.
#: A LIFETIME defect words it "is located 5 bytes inside of 128-byte region" -- with an `of` the
#: overflow wording does not have. Without it, every use-after-free and double-free reported no
#: distance and no region size **[measured]**, which are the two numbers the primitive verdict for
#: that class turns on: WHICH field of the stale object is touched, and HOW BIG the freed chunk is.
_ASAN_REGION = re.compile(
    r"is located (\d+) bytes (after|before|inside|to the right of|to the left of)(?: of)?\s*"
    r"(\d+)-byte region")
_SIDE = {"after": "after", "to the right of": "after",
         "before": "before", "to the left of": "before", "inside": "inside"}


#: The NUMBER each quantity-shaped class is about, with what to call it and the limit it broke.
#: These classes describe no access -- there is no distance past an object and no offset inside a
#: dead one -- so neither the out-of-bounds verdict nor the lifetime verdict has anything to say
#: about them. What their report does state is a MAGNITUDE, and whether the attacker chooses it is
#: the one question that separates "this input happened to do it" from "the input decides".
#: (class, what the number is, how to read it, how to read the SECOND number, what that one is).
#: The second number is not always a limit -- for a leak it is the object count -- so it carries
#: its own name rather than being printed as a bound the first one exceeded.
_QUANTITIES = (
    ("allocation-size-too-big", "requested allocation size",
     re.compile(r"requested allocation size (0x[0-9a-f]+|\d+)"),
     re.compile(r"exceeds maximum supported size of (0x[0-9a-f]+|\d+)"), "allocator maximum"),
    ("out-of-memory", "allocation size",
     re.compile(r"allocat\w* (?:of )?(0x[0-9a-f]+|\d+) bytes"), None, ""),
    ("negative-size-param", "size argument",
     re.compile(r"negative-size-param:\s*\(size=(-?\d+)\)"), None, ""),
    ("memory-leak", "leaked bytes",
     re.compile(r"(?:Direct|Indirect) leak of (\d+) byte"),
     re.compile(r"in (\d+) object"), "objects"),
    ("array-index-out-of-bounds", "index",
     re.compile(r"\bindex (-?\d+) out of bounds"),
     re.compile(r"out of bounds for type '[^']*\[(\d+)\]"), "array bound"),
    ("bad-shift", "shift exponent",
     re.compile(r"shift exponent (-?\d+)"), re.compile(r"for (\d+)-bit type"), "type width"),
)


def _int(text: str | None):
    if text is None:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _quantity_detail(t: str, bug: str) -> dict:
    """The magnitude a quantity-shaped report states, and the limit it exceeded.

    One field name for every class (`quantity`), because the verdict asks the same question of
    all of them -- does it move when the input moves -- and only the WORDING differs.
    """
    for cls, name, rx, limit_rx, limit_name in _QUANTITIES:
        if cls != bug:
            continue
        m = rx.search(t or "")
        if m is None:
            return {}
        out = {"quantity": _int(m.group(1)), "quantity_name": name}
        if limit_rx is not None:
            lm = limit_rx.search(t or "")
            if lm:
                out["quantity_limit"] = _int(lm.group(1))
                out["quantity_limit_name"] = limit_name
        return out
    return {}


#: What a ThreadSanitizer report states that nothing was reading: the two (or more) accesses that
#: race, where each one is, and what the memory IS. A race has no single site -- naming only the
#: first frame describes half of it, and the half it names is whichever thread the detector
#: happened to see second.
_TSAN_ACCESS = re.compile(
    r"^\s*(?:Previous\s+)?(read|write|atomic read|atomic write)(?:\s+of size (\d+))?"
    r".*?by (?:thread|main thread)", re.M | re.I)
_TSAN_LOCATION = re.compile(r"^\s*Location is ([^\n]+?)\s*$", re.M)


def _tsan_detail(t: str) -> dict:
    """The accesses, their sites and the racing object, from a ThreadSanitizer report."""
    out: dict = {}
    accesses, sites = [], []
    for m in _TSAN_ACCESS.finditer(t or ""):
        accesses.append(m.group(1).lower())
        # The first project frame BELOW this header is where that access happened. The sections
        # are separated by a blank line, exactly like ASan's free/alloc stacks.
        tail = (t or "")[m.end():]
        end = tail.find("\n\n")
        site = None
        for fm in _ASAN_FRAME.finditer(tail if end < 0 else tail[:end]):
            if _is_runtime_frame(fm.group(1)):
                continue
            site = f"{fm.group(1).split('/')[-1]}:{fm.group(2)}"
            break
        sites.append(site)
    if accesses:
        out["accesses"] = accesses[:4]
        out["race_sites"] = sites[:4]
    lm = _TSAN_LOCATION.search(t or "")
    if lm:
        out["location"] = lm.group(1)[:160]
    return out


#: What a MemorySanitizer report states, and what each line is worth.
#:
#: `Uninitialized bytes in write at offset 0 inside [0x7ffe..., 128)` is the line that matters
#: most, and it is printed only when the undefined bytes reached an INTERCEPTOR -- a write, a
#: send, a printf. That is the difference between CWE-457 (the program used a value it never
#: initialised: real, internal, nothing escaped) and CWE-200 (stack or heap residue left the
#: process), and MSan draws it by observation rather than by inference. It is printed BEFORE the
#: `WARNING:` line **[measured, clang 21]**, so anything that scans only the text after the
#: warning misses the one distinction the class turns on. Clang 21 names the interceptor `write`;
#: older releases write `__interceptor_write`, so the prefix is stripped rather than required.
_MSAN_ESCAPE = re.compile(
    r"Uninitialized bytes in (\S+?) at offset (\d+) inside \[0x[0-9a-f]+,\s*(\d+)\)")
#: Where the undefined value CAME FROM, which `-fsanitize-memory-track-origins` exists to say and
#: which decides what the residue IS: a dead stack frame holds the previous call's locals (so, on
#: a program that reads input into one, the attacker's own bytes), a recycled heap chunk holds a
#: previously freed object. The variable's name comes free and is the thing a maintainer fixes.
_MSAN_ORIGIN_STACK = re.compile(
    r"Uninitialized value was created by an allocation of '([^']*)' in the stack frame")
_MSAN_ORIGIN_HEAP = re.compile(r"Uninitialized value was created by a heap allocation")
_MSAN_ORIGIN_HDR = re.compile(r"^\s*Uninitialized value was created by .*$", re.M)


def _msan_detail(t: str) -> dict:
    """Whether the undefined value ESCAPED, how much of it, and where it came from.

    Three facts, all of them in the report text and none of them anywhere else. Without this the
    class arrives as a bare `use-of-uninitialized-value` and every one of them looks alike: the
    branch on an uninitialised flag that never leaves the process reads exactly like 128 bytes of
    a dead stack frame going out on a socket.
    """
    out: dict = {}
    t = t or ""
    m = _MSAN_ESCAPE.search(t)
    if m:
        out["escape_fn"] = m.group(1).replace("__interceptor_", "")[:64]
        out["escape_offset"] = int(m.group(2))
        # The size of the buffer handed to the output call. It BOUNDS the disclosure rather than
        # measuring it: MSan says these bytes are undefined from `offset` on, not how many of
        # them are, so this is reported as the volume that reached the output and read as such.
        out["escape_bytes"] = int(m.group(3))
    sm = _MSAN_ORIGIN_STACK.search(t)
    if sm:
        out["origin"] = "stack"
        out["origin_var"] = sm.group(1)[:64]
    elif _MSAN_ORIGIN_HEAP.search(t):
        out["origin"] = "heap"
    site = _section_site(t, _MSAN_ORIGIN_HDR)
    if site:
        # NOT the use site. A report that names only where the value was USED sends whoever has
        # to fix it to the line that reads the variable, when the line to change is the one that
        # declared or allocated it without an initialiser.
        out["origin_site"] = site
    return out


def _access_detail(t: str) -> dict:
    """The magnitude of a sanitizer-reported out-of-bounds access: which way, how wide, how far
    past the end, and how big the object was. This is the only place that information exists --
    it is in the report text and nowhere else -- and it is what decides whether the defect is an
    information disclosure, a corruption, or a one-byte nudge off the end."""
    out: dict = {}
    m = _ASAN_ACCESS.search(t or "")
    if m:
        out["access"] = m.group(1).lower()
        out["access_size"] = int(m.group(2))
        out["access_addr"] = int(m.group(3), 16)
    r = _ASAN_REGION.search(t or "")
    if r:
        out["distance"] = int(r.group(1))
        out["side"] = _SIDE.get(r.group(2), r.group(2))
        out["region_size"] = int(r.group(3))
    for key, header in (("freed_at", _ASAN_FREED_BY), ("allocated_at", _ASAN_ALLOCED_BY)):
        site = _section_site(t, header)
        if site:
            out[key] = site
    return out


def classify(cap, disasm):
    sig = cap.get("signal_name")
    pc = cap.get("pc")
    fault = cap.get("fault_addr")
    maps = cap.get("maps") or []
    pc_map = mapping_for(maps, pc)
    # only conclude "hijack" when we actually have maps and the PC is not in an exec region;
    # with no map info we cannot claim non-executability, so fall through to signal analysis.
    if maps and pc is not None and not (pc_map and "x" in pc_map.get("perms", "")):
        return {"class": "control-flow-hijack", "cwe": "CWE-787", "severity": "critical",
                "detail": f"program counter 0x{(pc or 0):x} is not in executable memory "
                          "(attacker-controlled execution transfer)"}
    # No maps (a gdbstub capture), but si_addr == pc: the fault was the INSTRUCTION FETCH --
    # execution was transferred to an address that cannot be executed. That is the same verdict
    # the maps branch reaches, from the one fact a stub capture does carry.
    if not maps and pc is not None and fault is not None and fault == pc \
            and sig in ("SIGSEGV", "SIGBUS"):
        if pc < 0x1000:
            return {"class": "null-pointer-dereference", "cwe": "CWE-476", "severity": "medium",
                    "detail": f"call/jump through a NULL function pointer (pc 0x{pc:x})"}
        return {"class": "control-flow-hijack", "cwe": "CWE-787", "severity": "critical",
                "detail": f"instruction fetch faulted at pc 0x{pc:x} "
                          "(execution transferred to a non-executable address)"}
    if sig == "SIGABRT":
        return {"class": "detected-corruption-abort", "cwe": "CWE-787", "severity": "high",
                "detail": "process aborted by a runtime integrity check "
                          "(stack canary / _FORTIFY_SOURCE / heap consistency)"}
    if sig == "SIGFPE":
        return {"class": "arithmetic-exception", "cwe": "CWE-369", "severity": "high",
                "detail": "arithmetic fault (divide-by-zero or INT_MIN/-1)"}
    mnem0 = (disasm or "").split()[0].lower() if disasm else ""
    if sig == "SIGTRAP" or (sig == "SIGILL" and mnem0 in _TRAP_MNEMONICS):
        return {"class": "reachable-assertion", "cwe": "CWE-617", "severity": "medium",
                "detail": "the program executed a deliberate trap instruction"
                          + (f" (`{disasm}`)" if disasm else "")
                          + " -- an assertion, unreachable() or a compiler-inserted check fired; "
                            "the defect behind it is not visible from the trap itself"}
    if sig == "SIGILL":
        return {"class": "illegal-instruction", "cwe": "CWE-119", "severity": "high",
                "detail": "illegal instruction (corrupted code or control flow)"}

    # STACK EXHAUSTION, before any bounds verdict. A fault immediately BELOW the [stack] mapping
    # is the guard page the kernel keeps there, and the thing that walks into it is a stack that
    # has grown as far as the rlimit allows -- uncontrolled recursion (CWE-674), a denial of
    # service. Reading it as an out-of-bounds write is wrong twice over: the address is not one
    # the attacker placed (it is wherever the stack happened to end) and there is no primitive to
    # chain, so the lead sends a reader looking for a write they cannot have. Measured on a
    # recursion fixture whose depth comes from the input: `root_cause/CWE-787`, "invalid write",
    # severity high. The window is deliberately narrow -- a page or two below the mapping -- and
    # an ordinary wild write lands nowhere near it.
    stack_map = next((m for m in maps if "[stack]" in (m.get("path") or "")), None)
    if fault is not None and stack_map and 0 <= (int(stack_map["start"]) - fault) <= 0x10000:
        return {"class": "stack-exhaustion", "cwe": "CWE-674", "severity": "high",
                "detail": f"fault at 0x{fault:x}, just below the stack mapping at "
                          f"0x{int(stack_map['start']):x}: the stack grew into its guard page "
                          "(uncontrolled recursion / unbounded stack allocation). The faulting "
                          "address is where the stack ended, not an address the input chose, so "
                          "this is a denial of service and not a write primitive."}

    mnem = (disasm or "").split()[0] if disasm else ""
    if mnem in ("ret", "retq", "retn"):
        return {"class": "stack-return-overwrite", "cwe": "CWE-121", "severity": "critical",
                "detail": "fault at a function return: the saved return address was "
                          "overwritten (stack-based buffer overflow)"}
    kind = _access_kind(disasm, cap.get("arch"))
    if fault is not None and fault < 0x1000:
        return {"class": "null-pointer-dereference", "cwe": "CWE-476", "severity": "medium",
                "detail": f"{kind or 'access'} through a NULL/near-NULL pointer "
                          f"(fault at 0x{fault:x})"}
    if kind is None:
        # Neither the instruction nor its absence says which way the access went (no objdump,
        # an ISA we do not decode, an unreadable pc, a gdbstub capture). Calling that a READ
        # filed every such crash as CWE-125 and rated it PROBABLY_NOT_EXPLOITABLE -- a write
        # understated by default. Say what is known: an invalid access, direction unknown.
        where = f" at 0x{fault:x}" if fault is not None else " (fault address not captured)"
        return {"class": "invalid-memory-access", "cwe": "CWE-119", "severity": "high",
                "detail": f"invalid memory access{where}; access direction unknown"
                          + (f" (`{disasm}`)" if disasm else "")}
    is_write = kind == "write"
    cwe = "CWE-787" if is_write else "CWE-125"
    return {"class": f"out-of-bounds-{kind}", "cwe": cwe, "severity": "high",
            "detail": (f"invalid {kind} at 0x{fault:x}" if fault is not None
                       else f"invalid {kind} (fault address not captured)")
                      + (f" via `{disasm}`" if disasm else "")}


def _callgraph_path(call_edges, sources_callers, crash_fn_addr, maxdepth=8):
    """Shortest forward call path from any source-calling function to the crash function."""
    from collections import deque
    succ = {}
    for e in call_edges:
        sa, da = _to_int(e.src_addr), _to_int(e.dst_addr)
        if sa is not None and da is not None:
            succ.setdefault(sa, set()).add(da)
    target = _to_int(crash_fn_addr)
    seen = set()
    q = deque((s, [s]) for s in sources_callers)
    while q:
        node, path = q.popleft()
        if node == target:
            return path
        if node in seen or len(path) > maxdepth:
            continue
        seen.add(node)
        for nxt in succ.get(node, ()):
            q.append((nxt, path + [nxt]))
    return None


def attribution_upsert(f, a, signal_name):
    """The finding row an attribution produces. Pure -- the caller owns the DAO.

    Only `fault-site` promotes: the fault happened inside the call the finding names, so the
    crash IS that finding. The weaker tiers attach the evidence and leave the state alone,
    because being near a crash is not being the crash.
    """
    proven = a["tier"] == "fault-site"
    # Mark the SITE, not just the defect: a 99-site finding with one proven occurrence must
    # not render like one where all 99 are proven.
    # `attribute()` returns "site"; the slice serialises it as "site_addr". Accept both, or
    # the promotion lands on the finding and never reaches the occurrence it proved.
    sa = a.get("site") or a.get("site_addr")
    site = {"function_addr": a.get("function_addr"), "site_addr": sa,
            "site_verdict": "proven" if proven else a["tier"],
            "site_state": "poc-backed" if proven else None,
            "site_confidence": 0.97 if proven else None} if sa else {}
    return {
        **site,
        "dedup_key": f.dedup_key, "cwe": f.cwe, "severity": f.severity,
        # Its OWN channel: a promotion from a reproduced crash must not overwrite what the
        # static detector says, and must not be undone when that detector next re-runs.
        "channel": "crash-attribution",
        "detector": f.detector,          # upsert rewrites detector on merge; keep the original
        "state": "poc-backed" if proven else f.state,
        "confidence": 0.97 if proven else f.confidence,
        "evidence": [{"channel": "crash-attribution",
                      "detail": f"{a['detail']} -- reproduced {signal_name} crash"}]}


def build_slice(cap, functions, call_edges, findings, maps, target_path,
                sites_by_finding=None, elf_entry=None):
    ranges = _fn_ranges(functions)
    delta = rebase_delta(maps, target_path, functions, elf_entry)
    pc = cap.get("pc")
    chain = [pc] + list(cap.get("backtrace") or [])
    frames = [symbolize(a, maps, ranges, target_path, delta) for a in chain if a is not None]
    if pc is not None and frames:
        frames[0]["fault_pc"] = True              # the rest are return addresses
    crash_fn = next((fr for fr in frames if fr.get("func_addr")), None)

    sources_callers = {_to_int(e.src_addr) for e in call_edges
                       if normalize(e.dst_name) in SOURCES and _to_int(e.src_addr) is not None}
    path = None
    tainted = False
    if crash_fn:
        path = _callgraph_path(call_edges, sources_callers, crash_fn["func_addr"])
        for f in findings:
            if f.function_addr == crash_fn["func_addr"] and any(
                    (e.get("channel") if isinstance(e, dict) else "") .startswith("taint")
                    for e in (f.evidence or [])):
                tainted = True
    addr_to_name = {}
    for lo, _hi, fn in ranges:
        addr_to_name[lo] = fn.name or f"sub_{fn.addr}"
    named_path = [{"addr": hex(a), "symbol": addr_to_name.get(a)} for a in (path or [])]
    attributed = attribute(frames, findings, sites_by_finding)
    return {"backtrace": frames, "crash_function": crash_fn,
            "source_path": named_path, "input_tainted": tainted,
            "reachable_from_source": bool(path),
            "attributed": [{"finding_id": a["finding"].id, "tier": a["tier"],
                            "detail": a["detail"], "site_addr": a["site"],
                            "function_addr": a.get("function_addr"),
                            "title": a["finding"].title,
                            "cwe": a["finding"].cwe} for a in attributed]}


def analyze(cap, functions, call_edges, findings, target_path, arch,
            sites_by_finding=None, elf_entry=None):
    from . import exploitability
    try:
        pcb = bytes.fromhex(cap.get("pc_bytes") or "")
    except ValueError:
        pcb = b""
    cap = dict(cap)
    cap.setdefault("arch", arch)
    # A gdbstub capture decodes its own faulting instruction (it alone knows the guest's
    # endianness and Thumb state) and hands it over as `insn`.
    disasm = disasm_one(pcb, arch, cap.get("endianness"), bool(cap.get("thumb"))) \
        or cap.get("insn")
    verdict = classify(cap, disasm)
    exploit = exploitability.rate(cap, verdict)
    sl = build_slice(cap, functions, call_edges, findings, cap.get("maps") or [], target_path,
                     sites_by_finding, elf_entry)
    summary = _summary(verdict, sl, cap, disasm)
    return {"signal": cap.get("signal_name"), "pc": cap.get("pc"),
            "fault_addr": cap.get("fault_addr"), "faulting_instruction": disasm,
            "classification": verdict, "exploitability": exploit, "slice": sl,
            "summary": summary}


def _summary(verdict, sl, cap, disasm):
    where = ""
    cf = sl.get("crash_function")
    if cf and cf.get("symbol"):
        where = f" in {cf['symbol']}"
    elif cf:
        where = f" in {cf['module']}+0x{cf['offset']:x}"
    reach = ""
    if sl.get("source_path"):
        names = [p["symbol"] or p["addr"] for p in sl["source_path"]]
        reach = " reached from untrusted input via " + " -> ".join(names)
    tail = f"; faulting instruction `{disasm}`" if disasm else ""
    return (f"{verdict['class']} ({verdict['cwe']}){where}: {verdict['detail']}{reach}{tail}")
