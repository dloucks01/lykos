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
_MAX_INSNS = 2_000_000               # per-segment instruction runaway guard
#: libc stubs that only READ their arguments -- a fault inside one is an over-READ (CWE-125), not a
#: write. Everything else (memset/strcpy dest, unknown) is treated as a write, as before.
_READ_ONLY_STUBS = frozenset({
    "strlen", "strnlen", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp",
    "strchr", "strrchr", "strstr", "strspn", "strcspn", "strpbrk", "strtok", "atoi", "atol",
    "atoll", "strtol", "strtoul", "strtoll", "puts", "fputs", "printf", "fprintf", "__printf_chk",
    "__fprintf_chk", "perror", "putchar", "putc"})
_MAX_CALLS = 200_000                 # external-call runaway guard
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
    if data[4] != 2:
        raise ValueError("harness executor is x86-64 only for now")
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
    plt = {base + a: n for a, n in _plt_map(data).items()}
    plt.update({a: n for n, a in stubs.items()})
    return {"e_type": e_type, "base": base, "span": (lo_img, hi_img), "regions": regions,
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


def _plt_map(data: bytes) -> dict:
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
        if plt and plt["addr"]:
            out[plt["addr"] + (i + 1) * 16] = nm         # classic: .plt[0] is the resolver
        if pltsec and pltsec["addr"]:
            out[pltsec["addr"] + i * 16] = nm            # CF-protected call target
    return out


_NULL_PAGE = 0x1000
# Above this no real allocator can succeed either, so a NULL for it is genuine, not an artifact.
_IMPOSSIBLE_ALLOC = 1 << 40


class _StubFault(Exception):
    """A libc stub's argument span is (partly) unmapped: the real call would fault here."""

    def __init__(self, access: str, addr: int):
        super().__init__(f"{access} fault at {addr:#x}")
        self.access, self.addr = access, addr


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
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _rd(addr, n):
        bad = _first_unmapped(uc, addr, n)
        if bad is not None:
            raise _StubFault("read", bad)
        return bytes(uc.mem_read(addr, n)) if n > 0 else b""

    def _wr(addr, blob):
        bad = _first_unmapped(uc, addr, len(blob))
        if bad is not None:
            raise _StubFault("write", bad)
        if blob:
            uc.mem_write(addr, blob)

    def _wr_fill(addr, byte, n):
        bad = _first_unmapped(uc, addr, n)          # checked BEFORE building n bytes on the host
        if bad is not None:
            raise _StubFault("write", bad)
        if n > 0:
            uc.mem_write(addr, bytes([byte]) * n)

    def _alloc(n):
        n = int(n)
        if n == 0:
            n = 16                                       # glibc: malloc(0) is a unique minimum chunk
        n = (n + 15) & ~15
        if n <= 0 or heap["next"] + n > _HEAP_ADDR + _HEAP_SZ:
            if n < _IMPOSSIBLE_ALLOC:
                res.artifact_null = True                 # the HARNESS heap ran out, not the target's
            return 0
        p = heap["next"]
        heap["next"] += n
        return p

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
                uc.mem_write(p, b"\x00" * ((n + 15) & ~15))
            _set(p)
        elif nm == "realloc":
            if a1 >= _HUGE_ALLOC and res.huge_alloc is None:
                res.huge_alloc = int(a1)
            _set(_alloc(a1) if a1 else 0)                # fresh block, best-effort (no copy)
        elif nm in ("free",):
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
    """Create the emulator, map the ELF (a PIE at _PIE_BASE, relocated) + stack/input/heap/
    sentinel/TLS, set the fake stack canary. Returns (uc, plan, heap) on success or None (with
    res.note set) on a mapping failure."""
    from unicorn import UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, Uc
    from unicorn.x86_const import UC_X86_REG_FS_BASE
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    try:
        plan = _map_segments(uc, elf_bytes)
        uc.mem_map(_STACK_TOP - _STACK_SZ, _STACK_SZ, UC_PROT_ALL)
        uc.mem_map(_INPUT_ADDR, _INPUT_SZ, UC_PROT_ALL)
        uc.mem_map(_SENTINEL & ~(_PAGE - 1), _PAGE, UC_PROT_ALL)
        uc.mem_map(_HEAP_ADDR, _HEAP_SZ, UC_PROT_ALL)    # for the malloc/calloc/realloc stubs
        uc.mem_map(_TLS_ADDR, _PAGE, UC_PROT_ALL)        # fake TLS so the stack canary read works
    except Exception as e:                               # noqa: BLE001
        res.note = f"map failed: {e}"
        return None
    # A real function reads its stack canary from `fs:[0x28]`. Point FS at a fake TLS block with a
    # fixed canary there, so the read succeeds and the setup/return values match (no spurious
    # __stack_chk_fail). Without this every canary-protected function faults at 0x28 on entry.
    uc.reg_write(UC_X86_REG_FS_BASE, _TLS_ADDR)
    uc.mem_write(_TLS_ADDR + 0x28, b"\x11\x22\x33\x44\x55\x66\x77\x00")
    return uc, plan, {"next": _HEAP_ADDR}


def _drive_messages(uc, func_addr: int, messages, res: HarnessResult, plt, heap, *,
                    arg_shape: str, max_insns: int) -> HarnessResult:
    """Call `func_addr` once per message, IN ORDER, reusing ONE emulator state so globals (.bss/
    .data) and the heap persist between calls -- this is what lets a sequence reach a state a
    single call cannot (T6). Each call gets a fresh stack + input buffer; coverage accumulates
    across the whole sequence. The sequence stops at the first call that faults or ends abnormally;
    `res.seq_index` records which message that was."""
    import time as _time

    from unicorn import (
        UC_HOOK_BLOCK,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UcError,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )
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
        res.fault_pc = uc_.reg_read(UC_X86_REG_RIP)
        res.access = {19: "read", 20: "write", 21: "fetch"}.get(access, str(access))
        return False

    uc.hook_add(UC_HOOK_BLOCK, _on_block)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                | UC_HOOK_MEM_FETCH_UNMAPPED, _on_unmapped)

    for idx, msg in enumerate(messages):
        buf = bytes(msg)[:_INPUT_SZ]
        uc.mem_write(_INPUT_ADDR, b"\x00" * min(_INPUT_SZ, len(buf) + 8))  # clear stale tail
        uc.mem_write(_INPUT_ADDR, buf)
        sp = ((_STACK_TOP - 0x1000) & ~0xF) - 8
        uc.mem_write(sp, _SENTINEL.to_bytes(8, "little"))  # sentinel return: `ret` lands here
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RDI, _INPUT_ADDR)
        if arg_shape == "ptr_len":
            uc.reg_write(UC_X86_REG_RSI, len(buf))
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
                    res.fault_pc = uc.reg_read(UC_X86_REG_RIP)
                break
            if res.crashed:
                break
            if pending["name"] is None:
                # no pending external -> reached the sentinel (clean return) or a budget stop
                if uc.reg_read(UC_X86_REG_RIP) in (_SENTINEL, 0) and not res.note:
                    res.returned = True
                break
            calls += 1
            if calls > _MAX_CALLS:
                res.note = "too many external calls"
                break
            # simulate the `call`'s callee: pop the return address, emulate the libc func, resume.
            rsp = uc.reg_read(UC_X86_REG_RSP)
            try:
                retaddr = int.from_bytes(uc.mem_read(rsp, 8), "little")
            except UcError:
                res.note = "bad stack at external call"
                break
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            # the CALL instruction that reached this stub, when it is a plain `call rel32` (E8):
            # the caller's site, so two faulting calls to the same libc routine stay distinct
            site = None
            try:
                if retaddr >= 5 and uc.mem_read(retaddr - 5, 1)[0] == 0xE8:
                    site = retaddr - 5
            except UcError:
                site = None
            _emulate_libc(uc, pending["name"], res, heap,
                          (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                           UC_X86_REG_RAX, UC_X86_REG_RIP), call_site=site)
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
                 load_base: int = 0) -> HarnessResult:
    """Execute ONE function with `input_bytes` as its buffer argument; report fault + coverage.

    `arg_shape`: "ptr_len" -> rdi=&input, rsi=len; "ptr" -> rdi=&input. Reaching the sentinel
    return means the function returned cleanly; an access to unmapped memory means it faulted
    (a memory-safety bug reached by driving this one function). A single-message `run_sequence`.

    `load_base`: where the DECOMPILER placed a PIE (0 for the native backend, 0x100000 for
    Ghidra). `func_addr` is in those coordinates and so is every address reported back.
    """
    return run_sequence(elf_bytes, func_addr, [input_bytes], arg_shape=arg_shape,
                        max_insns=max_insns, load_base=load_base)


def run_sequence(elf_bytes: bytes, func_addr: int, messages, *,
                 arg_shape: str = "ptr_len", max_insns: int = _MAX_INSNS,
                 load_base: int = 0) -> HarnessResult:
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
    uc, plan, heap = setup
    shift = _shift_for(plan, load_base)
    _drive_messages(uc, func_addr + shift, list(messages), res, plan["plt"], heap,
                    arg_shape=arg_shape, max_insns=max_insns)
    return _to_decompiler(res, plan, shift)
