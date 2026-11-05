"""T2 (doc 46) -- emulated single-function harness (the executor half).

Drive ONE function of a userland x86-64 ELF directly under unicorn: map the image, set up a
stack, place the fuzzed input in a scratch buffer, set the arguments per the SysV ABI (rdi=&buf,
rsi=len for an `f(buf,len)` parser), run from the function's entry to a sentinel return, and
report whether it FAULTED (a memory-safety bug reached without running the whole program) plus the
basic blocks it covered (feedback for the fuzz loop, T2 part two).

This is the "binary libFuzzer" primitive behind doc 46: it reaches a parser buried inside a daemon
without starting the daemon. First increment = the executor + a crash/coverage oracle; it does not
yet stub libc (so it targets functions whose faulting path needs no external call -- an OOB index,
a wild-pointer deref, a manual copy loop), and the fuzz loop + libc stubs + ladder hand-off are the
next increments. Pure-Python, no persistent-mode afl (so it is testable off the cold container).
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

_log = __import__("logging").getLogger(__name__)

_PAGE = 0x1000
# A high, out-of-the-way layout so it never collides with a (no-PIE) image mapped at 0x400000.
_STACK_TOP = 0x7F0000000000
_STACK_SZ = 0x200000                 # 2 MiB stack
_INPUT_ADDR = 0x0000AA0000000000     # where the fuzzed buffer is placed
_INPUT_SZ = 0x100000                 # 1 MiB input window (mapped; input written at the base)
_SENTINEL = 0x0000BB0000000000       # the fake return address; reaching it = a clean return
_HEAP_ADDR = 0x0000CC0000000000      # bump-allocator region for the malloc/calloc/realloc stubs
_HEAP_SZ = 0x1000000                 # 16 MiB heap
_TLS_ADDR = 0x0000DD0000000000       # a fake TLS block so `fs:[0x28]` (the stack canary) is valid
_TLS_BELOW = 0x10000                 # mapped each side of the thread pointer (static TLS)
_MAX_INSNS = 2_000_000               # per-segment instruction runaway guard
#: libc stubs that only READ their arguments -- a fault inside one is an over-READ (CWE-125), not a
#: write. Everything else (memset/strcpy dest, unknown) is treated as a write, as before.
_READ_ONLY_STUBS = frozenset({
    "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp",
    "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk", "strtok", "atoi", "atol",
    "atoll", "strtol", "strtoul", "strtoll", "puts", "fputs", "printf", "fprintf", "__printf_chk",
    "__fprintf_chk", "perror", "putchar", "putc"})
_MAX_CALLS = 200_000                 # external-call runaway guard
#: The libc routines `_emulate_libc` models exactly. In a STATIC binary these are stubbed by name
#: (symbol table / IFUNC name / the function table's FLIRT name) so its own malloc/free go through
#: the redzone heap rather than glibc's allocator running on syscalls the emulator does not have.
_MODELLED = frozenset({
    "memcpy", "memmove", "__memcpy_chk", "__memmove_chk", "mempcpy", "memset", "__memset_chk",
    "strlen", "strcpy", "__strcpy_chk", "stpcpy", "strncpy", "__strncpy_chk", "strcat",
    "__strcat_chk", "strcmp", "strncmp", "memcmp", "malloc", "calloc", "realloc", "free", "cfree",
    "__stack_chk_fail", "puts", "putchar", "fflush", "setvbuf", "fprintf", "printf", "fwrite",
    "fputs", "putc", "perror", "__printf_chk", "__fprintf_chk"})
# T5 oracle (doc 46): a single allocation this large, requested by a parser we fed a SMALL fuzzed
# input, is an attacker-controlled allocation size -- CWE-789 (unbounded allocation) / CWE-400 DoS.
# A legitimate parser does not malloc 64 MiB off a few KB of input; a `malloc(len_field)` with the
# length under the attacker's control does.
_HUGE_ALLOC = 0x4000000              # 64 MiB


@dataclass
class HarnessResult:
    crashed: bool = False
    returned: bool = False           # reached the sentinel = the function returned cleanly
    fault_addr: Optional[int] = None  # the address it faulted accessing (si_addr-like)
    fault_pc: Optional[int] = None    # where it was executing when it faulted
    access: str = ""                 # "read" | "write" | "fetch"
    blocks: set = field(default_factory=set)   # basic-block start addresses reached (coverage)
    huge_alloc: Optional[int] = None  # T5: an attacker-controlled allocation SIZE (CWE-789 DoS)
    seq_index: Optional[int] = None   # T6: which message in a driven sequence faulted
    note: str = ""
    # A stub handed the function a NULL that the REAL call would not have (an unknown external
    # stubbed to 0, the harness's own 16 MiB heap running out). A NULL-page fault after that is the
    # harness's doing, not the input's -- see _drive_messages.
    artifact_null: bool = False
    # The redzone heap's verdict on a heap fault: "heap-buffer-overflow" | "heap-use-after-free" |
    # "double-free" | "invalid-free" ("" for a non-heap fault), and a one-line description of the
    # chunk involved ("3 bytes right of a 16-byte chunk allocated at call site 0x401234").
    heap_kind: str = ""
    heap_detail: str = ""


def available() -> bool:
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:                                    # noqa: BLE001
        return False


# R_X86_64_* relocation types the loader applies.
_R_64, _R_GLOB_DAT, _R_JUMP_SLOT, _R_RELATIVE = 1, 6, 7, 8
_MAX_RELOCS = 2_000_000              # pathological-table guard
#: Where a PIE runs in the emulator: the base Linux itself uses with ASLR off. Results are
#: translated back to the decompiler's coordinates (run_function's `load_base`).
_PIE_BASE = 0x555555554000
#: Synthetic entry points for imported functions reached through a GOT slot rather than a PLT stub
#: (`-fno-plt`, `__libc_start_main`): each slot is pointed at one, and reaching it runs the same
#: libc emulation a PLT call gets. Without them every such call jumped to 0 and "faulted".
_STUB_ADDR = 0x0000EE0000000000
_PLANS: "OrderedDict" = OrderedDict()   # id(data) -> (data, plan); see _load_plan


def _load_plan(data: bytes) -> dict:
    """How to lay the image out in the emulator -- which pages to map, the RELOCATED bytes to
    write there, the import stubs and the PLT map -- computed once per image and reused by every
    execution of a campaign.

    A PIE runs where a loader puts it, with its dynamic relocations applied. The emulator used to
    map it at its link address (0) without relocating it, which broke three ways, all measured:
      * the Ghidra backend rebases a PIE (0x100000 on this toolchain), so every function it named
        lay outside the mapped image -- the first instruction "faulted", and the harness filed a
        high-severity control-flow corruption for every function it drove, harmless ones included;
      * an lld-linked PIE leaves RELATIVE slots zero (GNU ld happens to pre-fill them), so pointer
        tables and vtables read as NULL;
      * lld puts .rodata in the first page, which the loader-at-0 had to unmap so a NULL deref
        would still fault -- so every string literal read "faulted" as an out-of-bounds read."""
    key = id(data)
    hit = _PLANS.get(key)
    if hit is not None and hit[0] is data:
        _PLANS.move_to_end(key)
        return hit[1]
    plan = _build_plan(data)
    _PLANS[key] = (data, plan)                           # holding `data` keeps its id unique
    while len(_PLANS) > 4:
        _PLANS.popitem(last=False)
    return plan


def _build_plan(data: bytes) -> dict:
    import struct
    if data[:4] != b"\x7fELF" or len(data) < 64:
        raise ValueError("not an ELF")
    machine = _machine(data)
    if machine is None:
        raise ValueError("the harness drives little-endian x86-64 and aarch64 ELF64 images")
    _R_64, _R_GLOB_DAT, _R_JUMP_SLOT, _R_RELATIVE = _RELOCS[machine]
    en = "<" if data[5] == 1 else ">"
    e_type = struct.unpack_from(en + "H", data, 0x10)[0]
    base = _PIE_BASE if e_type == 3 else 0
    e_phoff = struct.unpack_from(en + "Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 0x36)
    loads, dyn = [], None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from(en + "II", data, off)
        p_offset, p_vaddr, _pa, p_filesz, p_memsz = struct.unpack_from(en + "QQQQQ", data, off + 8)
        if p_type == 1:                                  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
        elif p_type == 2:                                # PT_DYNAMIC
            dyn = (p_offset, p_filesz)
    if not loads:
        raise ValueError("no PT_LOAD segments to map")
    images = [bytearray(data[o:o + fs]) for (_v, o, fs, _m, _f) in loads]
    extra: list = []                                     # slots past a segment's file bytes (.bss)
    stubs: dict = {}                                     # import name -> synthetic entry

    def file_off(va: int, n: int = 8):
        for v, o, fs, _m, _f in loads:
            if v <= va and va + n <= v + fs:
                return o + (va - v)
        return None

    def put(va: int, value: int) -> None:
        blob = struct.pack(en + "Q", value & 0xFFFFFFFFFFFFFFFF)
        for i, (v, _o, fs, _m, _f) in enumerate(loads):
            if v <= va and va + 8 <= v + fs:
                images[i][va - v:va - v + 8] = blob
                return
        extra.append((base + va, blob))

    def slot(va: int) -> int:
        o = file_off(va)
        return struct.unpack_from(en + "Q", data, o)[0] if o is not None else 0

    applied = 0
    tags: dict = {}
    if dyn is not None:
        o, sz = dyn
        for k in range(0, max(0, min(sz, len(data) - o) - 15), 16):
            t, v = struct.unpack_from(en + "qQ", data, o + k)
            if t == 0:
                break
            tags.setdefault(t, v)
    symtab = file_off(tags[6], 24) if 6 in tags else None
    strtab = file_off(tags[5], 1) if 5 in tags else None

    def sym(idx: int):
        """(defined, value, is_function, is_weak, name) of dynamic symbol `idx`, or None."""
        if symtab is None:
            return None
        so = symtab + idx * 24
        if so + 24 > len(data):
            return None
        st_name, st_info = struct.unpack_from(en + "IB", data, so)
        shndx = struct.unpack_from(en + "H", data, so + 6)[0]
        value = struct.unpack_from(en + "Q", data, so + 8)[0]
        name = ""
        if strtab is not None and st_name:
            a = strtab + st_name
            name = data[a:data.find(b"\x00", a)].decode("latin-1", "ignore")
        return (shndx != 0, value, (st_info & 0xF) in (0, 2, 10), (st_info >> 4) == 2, name)

    tables = [(tags.get(7), tags.get(8, 0))]             # DT_RELA / DT_RELASZ
    if tags.get(20, 7) == 7:                             # DT_PLTREL is RELA on x86-64
        tables.append((tags.get(23), tags.get(2, 0)))    # DT_JMPREL / DT_PLTRELSZ
    for va, size in tables:
        ro = file_off(va, max(24, size)) if va else None
        if ro is None:
            continue
        for k in range(0, size - 23, 24):
            if applied >= _MAX_RELOCS:
                break
            r_off, r_info, r_add = struct.unpack_from(en + "QQq", data, ro + k)
            typ, sidx = r_info & 0xFFFFFFFF, r_info >> 32
            if typ == _R_RELATIVE:
                if e_type == 3:
                    put(r_off, base + r_add)
            elif typ in (_R_64, _R_GLOB_DAT, _R_JUMP_SLOT):
                s = sym(sidx) if sidx else None
                if s is None:
                    continue
                defined, value, is_fn, weak, name = s
                if defined and value:
                    if e_type == 3:
                        put(r_off, base + value + (r_add if typ == _R_64 else 0))
                elif typ == _R_JUMP_SLOT:
                    cur = slot(r_off)                    # lazy slot -> its own PLT stub
                    if cur and e_type == 3:
                        put(r_off, cur + base)
                elif is_fn and name and not weak:
                    # An import reached through its GOT slot: point it at a synthetic entry. A
                    # weak one stays 0 -- the loader leaves an absent weak symbol NULL, and code
                    # tests for that (`if (__gmon_start__) ...`).
                    if name not in stubs:
                        stubs[name] = _STUB_ADDR + 16 * len(stubs)
                    put(r_off, stubs[name] + (r_add if typ == _R_64 else 0))
                else:
                    continue
            else:
                continue                                 # IRELATIVE/TLS/...: not modelled
            applied += 1
    # DT_RELR (packed relative): the slot already holds the link-time value; add the base.
    rv, rsz = tags.get(36), tags.get(35, 0)
    ro = file_off(rv, max(8, rsz)) if rv else None
    if ro is not None and e_type == 3:
        where = 0
        for k in range(0, rsz - 7, 8):
            ent = struct.unpack_from(en + "Q", data, ro + k)[0]
            if not ent & 1:
                where = ent
                put(where, slot(where) + base)
                where += 8
            else:
                for bit in range(63):
                    if (ent >> (bit + 1)) & 1:
                        put(where + bit * 8, slot(where + bit * 8) + base)
                where += 63 * 8
            applied += 1
            if applied >= _MAX_RELOCS:
                break
    # IFUNC slots (a static glibc binary's memcpy/strlen/...): what the startup would write there.
    # A slot whose routine the stubs model goes to that stub (so the redzone checks see the call);
    # any other goes to the implementation its resolver picks. Without this every such call
    # jumped to the on-disk slot value -- 0.
    from .. import ifunc as _ifunc
    irel = _ifunc.irelative_relocs(data)
    static_names: dict = {}
    if irel:
        names, impls = _ifunc.slot_names(data), _ifunc.resolve(data)
        for slot_va, _res in irel:
            nm = names.get(slot_va)
            if nm in _MODELLED:
                if nm not in stubs:
                    stubs[nm] = _STUB_ADDR + 16 * len(stubs)
                put(slot_va, stubs[nm])
            elif slot_va in impls:
                put(slot_va, base + impls[slot_va])
    if _ifunc.is_static(data):
        static_names = {base + va: nm for va, nm in _ifunc.func_symbols(data, _MODELLED).items()}
    regions, writes = [], []
    lo_img, hi_img = None, None
    for (v, _o, fs, ms, _fl), img in zip(loads, images):
        lo = (base + v) & ~(_PAGE - 1)
        hi = (base + v + max(ms, fs) + _PAGE - 1) & ~(_PAGE - 1)
        lo_img = lo if lo_img is None else min(lo_img, lo)
        hi_img = hi if hi_img is None else max(hi_img, hi)
        regions.append((lo, max(_PAGE, hi - lo)))
        if img:
            writes.append((base + v, bytes(img)))
    if stubs:
        size = (16 * len(stubs) + _PAGE - 1) & ~(_PAGE - 1)
        regions.append((_STUB_ADDR, size))
        writes.append((_STUB_ADDR, b"\xc3" * size))     # `ret`: never runs (the hook stops first)
    plt = {base + a: n for a, n in _plt_map(data, machine).items()}
    plt.update(static_names)
    plt.update({a: n for n, a in stubs.items()})
    return {"machine": machine, "e_type": e_type, "base": base, "span": (lo_img, hi_img),
            "regions": regions,
            "writes": writes + extra, "relocations": applied, "stubs": len(stubs), "plt": plt}


def _map_segments(uc, data: bytes) -> dict:
    """Map the ELF's PT_LOAD segments into the emulator (page-aligned, RWX for simplicity): a PIE
    at _PIE_BASE with its dynamic relocations applied, plus the import stubs. Returns the plan."""
    from unicorn import UC_PROT_ALL
    plan = _load_plan(data)
    for lo, size in plan["regions"]:
        _map_gaps(uc, lo, size, UC_PROT_ALL)
    for addr, blob in plan["writes"]:
        uc.mem_write(addr, blob)
    return plan


def _map_gaps(uc, base: int, size: int, prot) -> None:
    """Map [base, base+size) except what is already mapped. Two PT_LOADs commonly share a page
    (one ends and the next begins inside it); mapping the second whole failed on the overlap, the
    failure was swallowed, and every OTHER page of that segment stayed unmapped -- the mem_write
    that followed then failed and the whole harness setup was abandoned."""
    end = base + size
    cur = base
    for b, e, _p in sorted(uc.mem_regions()):
        if e < cur or b >= end:
            continue
        if b > cur:
            uc.mem_map(cur, b - cur, prot)
        cur = max(cur, e + 1)
        if cur >= end:
            return
    if cur < end:
        uc.mem_map(cur, end - cur, prot)


def _sections(data: bytes) -> dict:
    """{name: (sh_addr, sh_offset, sh_size, sh_link, sh_entsize)} for an x86-64 ELF, stdlib only."""
    import struct
    en = "<"
    e_shoff = struct.unpack_from(en + "Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(en + "HHH", data, 0x3A)
    def _hdr(i):
        o = e_shoff + i * e_shentsize
        name, typ = struct.unpack_from(en + "II", data, o)
        flags, addr, off, size = struct.unpack_from(en + "QQQQ", data, o + 8)
        link, info = struct.unpack_from(en + "II", data, o + 40)
        align, entsz = struct.unpack_from(en + "QQ", data, o + 48)
        return {"name": name, "type": typ, "addr": addr, "off": off, "size": size,
                "link": link, "entsize": entsz}
    hdrs = [_hdr(i) for i in range(e_shnum)]
    strtab = hdrs[e_shstrndx]
    out = {}
    for h in hdrs:
        n = data[strtab["off"] + h["name"]:data.find(b"\x00", strtab["off"] + h["name"])].decode(
            "latin-1", "ignore")
        out[n] = h
    return out


def _plt_map(data: bytes, machine: str = "x86-64") -> dict:
    """{stub_addr: symbol_name} for every JUMP_SLOT in the PLT -- the externals a function calls.

    Maps the i-th .rela.plt JUMP_SLOT's symbol to BOTH the classic `.plt[i+1]` stub and the
    `.plt.sec[i]` stub (modern CF-protected binaries CALL the latter), so whichever the function
    actually targets, the hook fires. Best-effort; an unusual layout just yields fewer entries.
    """
    import struct
    try:
        secs = _sections(data)
    except Exception:                                    # noqa: BLE001
        return {}
    rela = secs.get(".rela.plt")
    dynsym = secs.get(".dynsym")
    dynstr = secs.get(".dynstr")
    if not (rela and dynsym and dynstr):
        return {}
    en = "<"
    names = []
    try:
        n = rela["size"] // 24
        for i in range(n):
            r_info = struct.unpack_from(en + "Q", data, rela["off"] + i * 24 + 8)[0]
            sym = r_info >> 32
            st_name = struct.unpack_from(en + "I", data, dynsym["off"] + sym * 24)[0]
            s = dynstr["off"] + st_name
            names.append(data[s:data.find(b"\x00", s)].decode("latin-1", "ignore"))
    except Exception:                                    # noqa: BLE001
        return {}
    out: dict = {}
    plt = secs.get(".plt")
    pltsec = secs.get(".plt.sec")
    for i, nm in enumerate(names):
        if not nm:
            continue
        if machine == "aarch64":
            if plt and plt["addr"]:
                out[plt["addr"] + 32 + i * 16] = nm      # PLT0 is 32 bytes, entries 16
            continue
        if plt and plt["addr"]:
            out[plt["addr"] + (i + 1) * 16] = nm         # classic: .plt[0] is the resolver
        if pltsec and pltsec["addr"]:
            out[pltsec["addr"] + i * 16] = nm            # CF-protected call target
    return out


_NULL_PAGE = 0x1000
# Above this no real allocator can succeed either, so a NULL for it is genuine, not an artifact.
_IMPOSSIBLE_ALLOC = 1 << 40


_EM = {62: "x86-64", 183: "aarch64"}
#: (R_64/ABS64, GLOB_DAT, JUMP_SLOT, RELATIVE) per machine
_RELOCS = {"x86-64": (1, 6, 7, 8), "aarch64": (257, 1025, 1026, 1027)}


def _machine(data: bytes) -> Optional[str]:
    """'x86-64' / 'aarch64' for a little-endian ELF64 image the harness drives, else None."""
    import struct
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    return _EM.get(struct.unpack_from("<H", data, 18)[0])


class _Arch:
    """What differs between the ISAs the harness drives: registers, how a call reaches the
    sentinel and how an emulated libc routine returns, where the call site is, syscalls, TLS."""

    def __init__(self, machine: str):
        self.machine = machine
        if machine == "x86-64":
            from unicorn import UC_ARCH_X86, UC_MODE_64
            from unicorn import x86_const as c
            self.uc_args = (UC_ARCH_X86, UC_MODE_64)
            self.args = (c.UC_X86_REG_RDI, c.UC_X86_REG_RSI, c.UC_X86_REG_RDX, c.UC_X86_REG_RCX)
            self.ret, self.sp, self.pc, self.lr = (c.UC_X86_REG_RAX, c.UC_X86_REG_RSP,
                                                   c.UC_X86_REG_RIP, None)
            self.sys_nr = c.UC_X86_REG_RAX
            # write, read, exit/exit_group, getpid/gettid, mmap, brk
            self.nr = {"write": 1, "read": 0, "exit": (60, 231), "pid": (39, 186), "mmap": 9,
                       "brk": 12}
            self._c = c
        elif machine == "aarch64":
            from unicorn import UC_ARCH_ARM64, UC_MODE_ARM
            from unicorn import arm64_const as c
            self.uc_args = (UC_ARCH_ARM64, UC_MODE_ARM)
            self.args = (c.UC_ARM64_REG_X0, c.UC_ARM64_REG_X1, c.UC_ARM64_REG_X2,
                         c.UC_ARM64_REG_X3)
            self.ret, self.sp, self.pc, self.lr = (c.UC_ARM64_REG_X0, c.UC_ARM64_REG_SP,
                                                   c.UC_ARM64_REG_PC, c.UC_ARM64_REG_X30)
            self.sys_nr = c.UC_ARM64_REG_X8
            self.nr = {"write": 64, "read": 63, "exit": (93, 94), "pid": (172, 178), "mmap": 222,
                       "brk": 214}
            self._c = c
        else:
            raise ValueError(f"no harness model for {machine}")

    def new_uc(self):
        from unicorn import Uc
        uc = Uc(*self.uc_args)
        if self.machine == "aarch64":
            try:                                         # FP/SIMD on (memcpy & co. use q-regs)
                uc.reg_write(self._c.UC_ARM64_REG_CPACR_EL1, 0x300000)
            except Exception:                            # noqa: BLE001 -- already on in this build
                pass
        return uc

    def set_tls(self, uc) -> None:
        if self.machine == "x86-64":
            # A real function reads its stack canary from `fs:[0x28]`: point FS at a fake TLS
            # block with a fixed canary there, so the read succeeds and setup/return values match
            # (no spurious __stack_chk_fail).
            uc.reg_write(self._c.UC_X86_REG_FS_BASE, _TLS_ADDR)
            uc.mem_write(_TLS_ADDR + 0x28, b"\x11\x22\x33\x44\x55\x66\x77\x00")
        else:
            # aarch64 keeps its canary in a global (__stack_chk_guard); TPIDR_EL0 is the thread
            # pointer static TLS hangs off
            uc.reg_write(self._c.UC_ARM64_REG_TPIDR_EL0, _TLS_ADDR)

    def enter(self, uc) -> None:
        """Fresh stack whose return lands on the sentinel."""
        if self.lr is None:
            sp = ((_STACK_TOP - 0x1000) & ~0xF) - 8
            uc.mem_write(sp, _SENTINEL.to_bytes(8, "little"))  # `ret` lands here
        else:
            sp = (_STACK_TOP - 0x1000) & ~0xF
            uc.reg_write(self.lr, _SENTINEL)
        uc.reg_write(self.sp, sp)

    def stub_return(self, uc) -> Optional[int]:
        """Where an emulated external returns to (popping it on x86), or None for a bad stack."""
        from unicorn import UcError
        if self.lr is not None:
            return uc.reg_read(self.lr)
        rsp = uc.reg_read(self.sp)
        try:
            ret = int.from_bytes(uc.mem_read(rsp, 8), "little")
        except UcError:
            return None
        uc.reg_write(self.sp, rsp + 8)
        return ret

    def call_site(self, uc, retaddr: int) -> Optional[int]:
        """The call instruction that reached the stub, when it is a direct one (x86 `call rel32`,
        aarch64 `bl` / `blr`): the caller's site, so two faulting calls to the same libc routine
        stay distinct."""
        from unicorn import UcError
        try:
            if self.lr is None:
                return retaddr - 5 if retaddr >= 5 and uc.mem_read(retaddr - 5, 1)[0] == 0xE8 else None
            w = int.from_bytes(uc.mem_read(retaddr - 4, 4), "little")
            return retaddr - 4 if ((w & 0xFC000000) == 0x94000000
                                   or (w & 0xFFFFFC1F) == 0xD63F0000) else None
        except UcError:
            return None

    def hook_syscalls(self, uc, handler) -> None:
        """`handler(uc)` on every syscall instruction (x86 `syscall`, aarch64 `svc #0`)."""
        from unicorn import UC_HOOK_INSN, UC_HOOK_INTR
        if self.machine == "x86-64":
            uc.hook_add(UC_HOOK_INSN, lambda u, _d: handler(u), None, 1, 0,
                        self._c.UC_X86_INS_SYSCALL)
        else:
            uc.hook_add(UC_HOOK_INTR, lambda u, intno, _d: handler(u) if intno == 2 else None)


class _StubFault(Exception):
    """A libc stub's argument span is (partly) unmapped: the real call would fault here."""

    def __init__(self, access: str, addr: int, kind: str = "", detail: str = ""):
        super().__init__(f"{access} fault at {addr:#x}")
        self.access, self.addr, self.kind, self.detail = access, addr, kind, detail


#: Poisoned bytes between two chunks (both sides of every allocation). An overflow that skips the
#: whole redzone and lands inside the NEXT live chunk is invisible to it, as with ASan.
_REDZONE = 32


class _Heap:
    """The harness's malloc: an ASan-style REDZONE + QUARANTINE allocator over the emulator heap.

    Every chunk is 16-aligned and surrounded by `_REDZONE` poisoned bytes; a freed chunk is never
    handed out again (bump allocation = permanent quarantine). `check` says whether a span lies
    wholly inside ONE live chunk. The emulated code's heap loads/stores are checked by a memory
    hook over the heap range (_drive_messages) and the libc stubs check their own spans -- so a
    one-byte heap overflow, a read of freed memory, a double free and a free of a non-chunk
    pointer all become faults, where the old bump allocator let them run silently into the next
    chunk. Sound by construction: only memory the program never obtained from malloc is poisoned.
    """

    def __init__(self):
        self.next = _HEAP_ADDR + _REDZONE
        self.starts: list = []                 # chunk user-starts, ascending (bump order)
        self.chunks: dict = {}                 # start -> [size, live, alloc_site, free_site]
        self.site: Optional[int] = None        # call site of the stub being emulated

    def alloc(self, n: int) -> int:
        """User pointer for an n-byte chunk, or 0 when the harness heap is exhausted."""
        p = (self.next + 15) & ~15
        span = (max(int(n), 1) + 15) & ~15
        if p + span + _REDZONE > _HEAP_ADDR + _HEAP_SZ:
            return 0
        self.next = p + span + _REDZONE
        self.starts.append(p)
        self.chunks[p] = [int(n), True, self.site, None]
        return p

    def _owner(self, addr: int):
        import bisect
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.starts[i] if i >= 0 else None

    def check(self, addr: int, n: int, access: str):
        """None when [addr, addr+n) is inside one live chunk (or not on the heap at all); else
        (kind, detail) naming the violation."""
        hi = _HEAP_ADDR + _HEAP_SZ
        if n <= 0 or addr + n <= _HEAP_ADDR or addr >= hi:
            return None
        start = self._owner(addr)
        if start is not None:
            size, live, asite, fsite = self.chunks[start]
            if addr < start + size:
                if not live:
                    return ("heap-use-after-free",
                            f"{access} {addr - start} bytes into a freed {size}-byte chunk"
                            + (f" (freed at {fsite:#x})" if fsite else ""))
                if addr + n <= start + size:
                    return None
                if access == "read" and n >= 16:
                    # a vector load that STARTS inside the chunk: SSE2 strlen/strchr/memchr read
                    # whole 16-byte blocks past a string's end by design (glibc's own code, run
                    # natively in a static binary). Compiled C does not do this.
                    return None
                return ("heap-buffer-overflow",
                        f"{access} of {n} at {addr - start}: {addr + n - start - size} byte(s) "
                        f"past a {size}-byte chunk" + (f" allocated at {asite:#x}" if asite else ""))
            # past this chunk's end: right of it, or left of the next one -- name the nearer
            import bisect
            j = bisect.bisect_right(self.starts, addr)
            nxt = self.starts[j] if j < len(self.starts) else None
            if nxt is not None and nxt - (addr + n) < addr - (start + size):
                nsize, _l, nas, _f = self.chunks[nxt]
                return ("heap-buffer-overflow",
                        f"{access} {nxt - addr} byte(s) left of a {nsize}-byte chunk"
                        + (f" allocated at {nas:#x}" if nas else ""))
            return ("heap-buffer-overflow",
                    f"{access} {addr - start - size} byte(s) right of a {size}-byte chunk"
                    + (f" allocated at {asite:#x}" if asite else ""))
        nxt = self.starts[0] if self.starts else None
        if nxt is not None:
            return ("heap-buffer-overflow",
                    f"{access} {nxt - addr} byte(s) left of a {self.chunks[nxt][0]}-byte chunk")
        return ("heap-buffer-overflow", f"{access} of heap memory never allocated")

    def free(self, p: int):
        """None for a valid free (or free(NULL)); else (kind, detail)."""
        if p == 0:
            return None
        c = self.chunks.get(p)
        if c is None:
            owner = self._owner(p)
            inside = owner is not None and p < owner + self.chunks[owner][0]
            return ("invalid-free", f"free({p:#x}): "
                    + (f"{p - owner} bytes into a {self.chunks[owner][0]}-byte chunk"
                       if inside else "not a pointer malloc returned"))
        if not c[1]:
            return ("double-free", f"free({p:#x}) of a {c[0]}-byte chunk already freed"
                    + (f" at {c[3]:#x}" if c[3] else ""))
        c[1], c[3] = False, self.site
        return None


def _first_unmapped(uc, addr: int, n: int) -> Optional[int]:
    """First address in [addr, addr+n) that is NOT mapped, or None when the whole span is.

    Checked BEFORE a stub touches memory: an attacker-controlled length (memcpy(dst, src, -1))
    made `uc.mem_read(src, n)` try to allocate n bytes on the HOST first -- a MemoryError/
    OverflowError, not a UcError, which escaped the stub, aborted the whole fuzz campaign for the
    function, and lost every crash it had already found."""
    if n <= 0:
        return None
    regions = sorted((b, e) for b, e, _perm in uc.mem_regions())
    cur, end = addr, addr + n
    while cur < end:
        hit = next(((b, e) for b, e in regions if b <= cur <= e), None)
        if hit is None:
            return cur
        cur = hit[1] + 1
    return None


def _emulate_libc(uc, name, res, heap, regs, call_site: Optional[int] = None) -> None:
    """Emulate one external libc call: read args from registers, operate on emulator memory, set
    the return value in rax. A memory op on a bad pointer (e.g. memcpy to an unmapped dst) raises
    and is recorded as a CRASH -- which is exactly the bug we are hunting. An unknown external is
    best-effort (rax=0) and recorded, so a wrong result is visible rather than silent."""
    from unicorn import UcError
    RDI, RSI, RDX, RCX, RAX, _RIP = regs
    a0, a1, a2 = uc.reg_read(RDI), uc.reg_read(RSI), uc.reg_read(RDX)
    nm = name.split("@")[0]                              # strip @GLIBC_x.y versioning

    def _set(v):
        uc.reg_write(RAX, v & 0xFFFFFFFFFFFFFFFF)

    def _cstr(addr, cap=0x10000):
        out = bytearray()
        while len(out) < cap:
            try:
                b = uc.mem_read(addr + len(out), 1)[0]
            except UcError:
                raise _StubFault("read", addr + len(out)) from None
            _heap_guard(addr + len(out), 1, "read")
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _rd(addr, n):
        bad = _first_unmapped(uc, addr, n)
        if bad is not None:
            raise _StubFault("read", bad)
        _heap_guard(addr, n, "read")
        return bytes(uc.mem_read(addr, n)) if n > 0 else b""

    def _wr(addr, blob):
        bad = _first_unmapped(uc, addr, len(blob))
        if bad is not None:
            raise _StubFault("write", bad)
        _heap_guard(addr, len(blob), "write")
        if blob:
            uc.mem_write(addr, blob)

    def _wr_fill(addr, byte, n):
        bad = _first_unmapped(uc, addr, n)          # checked BEFORE building n bytes on the host
        if bad is not None:
            raise _StubFault("write", bad)
        _heap_guard(addr, n, "write")
        if n > 0:
            uc.mem_write(addr, bytes([byte]) * n)

    def _alloc(n):
        n = int(n)                                       # malloc(0) is a unique 0-byte chunk
        if n >= _IMPOSSIBLE_ALLOC:
            return 0                                     # the real malloc fails too
        p = heap.alloc(n)
        if not p:
            res.artifact_null = True                     # the HARNESS heap ran out, not the target's
        return p

    def _heap_guard(addr, n, access):
        v = heap.check(addr, n, access)
        if v is not None:
            raise _StubFault(access, addr, *v)

    heap.site = call_site
    try:
        if nm in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk", "mempcpy"):
            _wr(a0, _rd(a1, a2))                         # source checked first: an over-read is a READ
            _set(a0 + a2 if nm == "mempcpy" else a0)
        elif nm in ("memset", "__memset_chk"):
            _wr_fill(a0, a1 & 0xFF, a2)
            _set(a0)
        elif nm == "strlen":
            _set(len(_cstr(a0)))
        elif nm in ("strcpy", "__strcpy_chk", "stpcpy"):
            s = _cstr(a1)
            _wr(a0, s + b"\x00")
            _set(a0 + len(s) if nm == "stpcpy" else a0)
        elif nm in ("strncpy", "__strncpy_chk"):
            s = _cstr(a1)[:a2]
            _wr(a0, s)
            _wr_fill(a0 + len(s), 0, a2 - len(s))
            _set(a0)
        elif nm in ("strcat", "__strcat_chk"):
            d, s = _cstr(a0), _cstr(a1)
            _wr(a0 + len(d), s + b"\x00")
            _set(a0)
        elif nm == "strcmp":
            _set(0 if _cstr(a0) == _cstr(a1) else 1)
        elif nm == "strncmp":
            _set(0 if _cstr(a0)[:a2] == _cstr(a1)[:a2] else 1)
        elif nm == "memcmp":
            _set(0 if _rd(a0, a2) == _rd(a1, a2) else 1)
        elif nm == "malloc":
            if a0 >= _HUGE_ALLOC and res.huge_alloc is None:
                res.huge_alloc = int(a0)                 # T5: attacker-controlled allocation size
            _set(_alloc(a0))
        elif nm == "calloc":
            n = a0 * a1                                  # true product (no C wraparound in the stub)
            if n >= _HUGE_ALLOC and res.huge_alloc is None:
                res.huge_alloc = int(n)                  # a huge count*size the input drove
            p = _alloc(n)
            if p and n:
                uc.mem_write(p, b"\x00" * n)
            _set(p)
        elif nm == "realloc":
            if a1 >= _HUGE_ALLOC and res.huge_alloc is None:
                res.huge_alloc = int(a1)
            if a0 and a0 not in heap.chunks:
                v = heap.free(a0)                        # realloc of a non-chunk: invalid free
                if v is not None:
                    raise _StubFault("free", a0, *v)
            old = heap.chunks.get(a0) if a0 else None
            if old is not None and not old[1]:
                raise _StubFault("free", a0, "double-free",
                                 f"realloc({a0:#x}) of a {old[0]}-byte chunk already freed")
            if a0 and not a1:
                heap.free(a0)                            # realloc(p, 0) frees p
                _set(0)
            else:
                p = _alloc(a1)
                if p and old is not None:
                    keep = min(old[0], int(a1))
                    if keep:
                        uc.mem_write(p, bytes(uc.mem_read(a0, keep)))
                if p and a0:
                    heap.free(a0)                        # moved: the old block is now freed memory
                _set(p)
        elif nm in ("free", "cfree"):
            v = heap.free(a0)
            if v is not None:
                raise _StubFault("free", a0, *v)
            _set(0)
        elif nm == "__stack_chk_fail":
            # the stack canary tripped: a stack-buffer overflow was DETECTED.
            res.crashed = True
            res.access = "write"
            res.note = (res.note + "; " if res.note else "") + "stack canary (__stack_chk_fail)"
            _set(0)
        elif nm in ("puts", "putchar", "fflush", "setvbuf", "fprintf", "printf", "fwrite",
                    "fputs", "putc", "perror", "__printf_chk", "__fprintf_chk", "write"):
            _set(0)                                      # output: no-op
        else:
            res.note = (res.note + "; " if res.note else "") + f"stubbed-unknown:{nm}"
            res.artifact_null = True                     # rax=0 is OUR answer, not the callee's
            _set(0)
    except _StubFault as f:
        # the precise side: a memcpy/strcpy SOURCE over-read is a READ (CWE-125), not the write
        # the destination side would be; and the faulting address is known.
        res.crashed = True
        res.access = f.access
        res.fault_addr = f.addr
        res.heap_kind, res.heap_detail = f.kind, f.detail
        if res.fault_pc is None:
            res.fault_pc = call_site
        res.note = (res.note + "; " if res.note else "") + f"fault in {nm}()"
    except (MemoryError, OverflowError, ValueError) as e:
        # a host-side failure of the stub itself is the HARNESS's limit, not a target fault
        res.note = (res.note + "; " if res.note else "") + f"stub {nm} failed on host: {e!r}"[:200]
        _set(0)
    except UcError:
        res.crashed = True
        if res.fault_pc is None:
            res.fault_pc = call_site
        # A fault INSIDE a libc stub that only READS its arguments (strlen/strcmp/memcmp/... over an
        # attacker-controlled pointer that over-reads unmapped memory) is a CWE-125 out-of-bounds
        # READ -- hardcoding "write" filed it as a CWE-787 out-of-bounds WRITE (wrong CWE, wrong
        # remediation, wrong exploit primitive). Write-side stubs (memset/strcpy dest) keep "write".
        res.access = "read" if nm in _READ_ONLY_STUBS else "write"
        res.note = (res.note + "; " if res.note else "") + f"fault in {nm}()"


def _setup(elf_bytes: bytes, res: HarnessResult):
    """Create the emulator for the image's ISA, map the ELF (a PIE at _PIE_BASE, relocated) +
    stack/input/heap/sentinel/TLS. Returns (uc, plan, heap, arch) or None (res.note set)."""
    from unicorn import UC_PROT_ALL
    machine = _machine(elf_bytes)
    if machine is None:
        res.note = "not a little-endian x86-64 / aarch64 ELF64 image"
        return None
    arch = _Arch(machine)
    uc = arch.new_uc()
    try:
        plan = _map_segments(uc, elf_bytes)
        uc.mem_map(_STACK_TOP - _STACK_SZ, _STACK_SZ, UC_PROT_ALL)
        uc.mem_map(_INPUT_ADDR, _INPUT_SZ, UC_PROT_ALL)
        uc.mem_map(_SENTINEL & ~(_PAGE - 1), _PAGE, UC_PROT_ALL)
        uc.mem_map(_HEAP_ADDR, _HEAP_SZ, UC_PROT_ALL)    # for the malloc/calloc/realloc stubs
        # fake TLS: x86's canary at fs:[0x28] and a static glibc's TLS variables below the thread
        # pointer (x86 variant II) or above it (aarch64 variant I)
        uc.mem_map(_TLS_ADDR - _TLS_BELOW, 2 * _TLS_BELOW, UC_PROT_ALL)
    except Exception as e:                               # noqa: BLE001
        res.note = f"map failed: {e}"
        return None
    arch.set_tls(uc)
    return uc, plan, _Heap(), arch


def _drive_messages(uc, func_addr: int, messages, res: HarnessResult, plt, heap, *,
                    arg_shape: str, max_insns: int, arch: Optional["_Arch"] = None) -> HarnessResult:
    """Call `func_addr` once per message, IN ORDER, reusing ONE emulator state so globals (.bss/
    .data) and the heap persist between calls -- this is what lets a sequence reach a state a
    single call cannot (T6). Each call gets a fresh stack + input buffer; coverage accumulates
    across the whole sequence. The sequence stops at the first call that faults or ends abnormally;
    `res.seq_index` records which message that was."""
    import time as _time

    from unicorn import (
        UC_HOOK_BLOCK,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_MEM_WRITE,
        UcError,
    )
    arch = arch or _Arch("x86-64")
    PC, RET = arch.pc, arch.ret
    pending = {"name": None}
    deadline = {"t": 0.0}

    def _on_block(uc_, addr, size, _ud):
        res.blocks.add(addr)
        nm = plt.get(addr)
        if nm is not None:                               # a call into the PLT: emulate the external
            pending["name"] = nm
            uc_.emu_stop()
        elif _time.time() > deadline["t"]:
            res.note = "wall-clock budget"
            uc_.emu_stop()

    def _on_unmapped(uc_, access, addr, size, value, _ud):
        res.crashed = True
        res.fault_addr = addr
        res.fault_pc = uc_.reg_read(PC)
        res.access = {19: "read", 20: "write", 21: "fetch"}.get(access, str(access))
        return False

    def _on_heap(uc_, access, addr, size, value, _ud):
        # the redzone check for the EMULATED code's own heap loads/stores (the stubs check theirs)
        if res.crashed:
            return
        acc = "write" if access == UC_MEM_WRITE else "read"
        v = heap.check(addr, size, acc)
        if v is not None:
            res.crashed = True
            res.fault_addr = addr
            res.fault_pc = uc_.reg_read(PC)
            res.access = acc
            res.heap_kind, res.heap_detail = v
            uc_.emu_stop()

    nrs = arch.nr

    def _on_syscall(uc_):
        # libc code that runs natively (a static binary) issues real syscalls. Unhooked, unicorn
        # treats x86 `syscall` as a no-op that leaves rax = the syscall number: brk "returned" 12
        # and glibc's malloc then used address 12 as its heap. Model the harmless ones; fail the
        # rest honestly and mark the result a harness artifact (a later NULL fault is not the
        # input's).
        nr = uc_.reg_read(arch.sys_nr)
        a2 = uc_.reg_read(arch.args[2])
        if nr == nrs["write"]:                            # write: all of it
            ret = a2
        elif nr == nrs["read"]:                           # read: EOF
            ret = 0
        elif nr in nrs["exit"]:                           # exit / exit_group: a clean end
            res.returned = True
            res.note = (res.note + "; " if res.note else "") + "exit()"
            uc_.emu_stop()
            return
        elif nr in nrs["pid"]:                            # getpid / gettid
            ret = 4242
        else:                                             # brk/mmap/open/...: not available
            ret = -12 if nr == nrs["mmap"] else (0 if nr == nrs["brk"] else -38)
            res.artifact_null = True
            if f"syscall:{nr}" not in res.note:
                res.note = (res.note + "; " if res.note else "") + f"syscall:{nr} failed"
        uc_.reg_write(RET, ret & 0xFFFFFFFFFFFFFFFF)

    arch.hook_syscalls(uc, _on_syscall)
    uc.hook_add(UC_HOOK_BLOCK, _on_block)
    uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, _on_heap,
                begin=_HEAP_ADDR, end=_HEAP_ADDR + _HEAP_SZ - 1)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                | UC_HOOK_MEM_FETCH_UNMAPPED, _on_unmapped)
    regs = (*arch.args, RET, PC)

    for idx, msg in enumerate(messages):
        buf = bytes(msg)[:_INPUT_SZ]
        uc.mem_write(_INPUT_ADDR, b"\x00" * min(_INPUT_SZ, len(buf) + 8))  # clear stale tail
        uc.mem_write(_INPUT_ADDR, buf)
        arch.enter(uc)
        uc.reg_write(arch.args[0], _INPUT_ADDR)
        if arg_shape == "ptr_len":
            uc.reg_write(arch.args[1], len(buf))
        res.returned = False
        res.note = ""                                     # per-call; a prior clean call left it empty
        deadline["t"] = _time.time() + 10.0               # wall-clock runaway guard, per call
        cur = func_addr
        calls = 0
        while True:
            pending["name"] = None
            try:
                uc.emu_start(cur, _SENTINEL, count=max_insns)
            except UcError:
                if not res.crashed and pending["name"] is None:
                    res.note = res.note or "emulation error (unsupported instruction)"
                    res.fault_pc = uc.reg_read(PC)
                break
            if res.crashed:
                break
            if pending["name"] is None:
                # no pending external -> reached the sentinel (clean return) or a budget stop
                if uc.reg_read(PC) in (_SENTINEL, 0) and not res.note:
                    res.returned = True
                break
            calls += 1
            if calls > _MAX_CALLS:
                res.note = "too many external calls"
                break
            # simulate the call's callee: take the return address, emulate the libc func, resume.
            retaddr = arch.stub_return(uc)
            if retaddr is None:
                res.note = "bad stack at external call"
                break
            _emulate_libc(uc, pending["name"], res, heap, regs,
                          call_site=arch.call_site(uc, retaddr))
            if res.crashed:
                break
            cur = retaddr
        if res.crashed and res.access == "fetch" and res.fault_addr == func_addr:
            # The function's own entry is not mapped: the address and the loaded image disagree
            # (a decompiler base the loader was not given). Nothing the input did; never a fault.
            res.crashed = False
            res.note = (res.note + "; " if res.note else "") + (
                f"function entry {func_addr:#x} is not in the loaded image -- address/image "
                "mismatch, not a fault")
            break
        if (res.crashed and res.artifact_null and res.fault_addr is not None
                and res.fault_addr < _NULL_PAGE):
            # A NULL-page fault after a stub returned a NULL the real callee would not have
            # (an unknown external stubbed to 0, the harness heap exhausted). `getenv()` -> 0 ->
            # `strlen(NULL)` faulted in EVERY run and was filed as a high-severity CWE-125 in the
            # target -- the harness's own artifact, not something the input did.
            res.crashed = False
            res.note = (res.note + "; " if res.note else "") + (
                "NULL-page fault after a harness stub returned NULL -- harness artifact, "
                "not attributed to the input")
            break
        if res.crashed:
            res.seq_index = idx
            break
        if res.note:                                      # abnormal end (budget / bad stack / error)
            break
    return res


def _shift_for(plan: dict, load_base: int) -> int:
    """Emulator address minus decompiler address. 0 for a fixed-address executable."""
    return plan["base"] - load_base if plan["e_type"] == 3 else 0


def _to_decompiler(res: HarnessResult, plan: dict, shift: int) -> HarnessResult:
    """Report addresses inside the image in the decompiler's coordinates (what the function table,
    the finding sites and the crash dedup keys use). Addresses outside it -- the input buffer, the
    heap, a wild pointer -- are runtime values and stay as they are."""
    if not shift:
        return res
    lo, hi = plan["span"]

    def back(a):
        return a - shift if (a is not None and lo <= a < hi) else a
    res.fault_pc = back(res.fault_pc)
    res.fault_addr = back(res.fault_addr)
    res.blocks = {back(b) for b in res.blocks}
    return res


def run_function(elf_bytes: bytes, func_addr: int, input_bytes: bytes, *,
                 arg_shape: str = "ptr_len", max_insns: int = _MAX_INSNS,
                 load_base: int = 0, stub_names: Optional[dict] = None) -> HarnessResult:
    """Execute ONE function with `input_bytes` as its buffer argument; report fault + coverage.

    `arg_shape`: "ptr_len" -> rdi=&input, rsi=len; "ptr" -> rdi=&input. Reaching the sentinel
    return means the function returned cleanly; an access to unmapped memory means it faulted
    (a memory-safety bug reached by driving this one function). A single-message `run_sequence`.

    `load_base`: where the DECOMPILER placed a PIE (0 for the native backend, 0x100000 for
    Ghidra). `func_addr` is in those coordinates and so is every address reported back.
    """
    return run_sequence(elf_bytes, func_addr, [input_bytes], arg_shape=arg_shape,
                        max_insns=max_insns, load_base=load_base, stub_names=stub_names)


def run_sequence(elf_bytes: bytes, func_addr: int, messages, *,
                 arg_shape: str = "ptr_len", max_insns: int = _MAX_INSNS,
                 load_base: int = 0, stub_names: Optional[dict] = None) -> HarnessResult:
    """Drive a stateful function with a SEQUENCE of messages in one emulator state (T6).

    A dispatch-style parser transitions between states as it consumes messages; a bug can live in
    a state only reachable after a specific prefix (e.g. after a HELLO then an AUTH). Each message
    is a fresh call with its own stack and input buffer, but globals and the heap carry over, so a
    later call sees the state the earlier calls established. Coverage is cumulative; the result's
    `seq_index` says which message faulted. With a single message this is exactly `run_function`.
    `load_base` as for run_function."""
    res = HarnessResult()
    if not messages:
        res.note = "empty sequence"
        return res
    setup = _setup(elf_bytes, res)
    if setup is None:
        return res
    uc, plan, heap, arch = setup
    shift = _shift_for(plan, load_base)
    plt = plan["plt"]
    if stub_names:
        # names the caller recovered for a stripped static binary (FLIRT / behaviour): only the
        # routines the stubs model exactly, and only where the image has no import of its own
        extra = {a + shift: n for a, n in stub_names.items() if n in _MODELLED}
        if extra:
            plt = {**extra, **plt}
    _drive_messages(uc, func_addr + shift, list(messages), res, plt, heap,
                    arg_shape=arg_shape, max_insns=max_insns, arch=arch)
    return _to_decompiler(res, plan, shift)
