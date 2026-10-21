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

from dataclasses import dataclass, field
from typing import Optional

from ... import observe
from ..elf import parse as parse_elf

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
_MAX_CALLS = 200_000                 # external-call runaway guard


@dataclass
class HarnessResult:
    crashed: bool = False
    returned: bool = False           # reached the sentinel = the function returned cleanly
    fault_addr: Optional[int] = None  # the address it faulted accessing (si_addr-like)
    fault_pc: Optional[int] = None    # where it was executing when it faulted
    access: str = ""                 # "read" | "write" | "fetch"
    blocks: set = field(default_factory=set)   # basic-block start addresses reached (coverage)
    note: str = ""


def available() -> bool:
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:                                    # noqa: BLE001
        return False


def _map_segments(uc, data: bytes) -> None:
    """Map the ELF's PT_LOAD segments into the emulator (page-aligned, RWX for simplicity)."""
    from unicorn import UC_PROT_ALL
    info = parse_elf(data)
    loaded = 0
    for s in getattr(info, "segments", None) or []:
        # elf.parse may not expose segments; fall back to the section/program-header walk below.
        pass
    # Walk program headers directly (stdlib struct) -- elf.parse focuses on sections/dynamic.
    import struct
    if data[:4] != b"\x7fELF" or len(data) < 64:
        raise ValueError("not an ELF")
    is64 = data[4] == 2
    en = "<" if data[5] == 1 else ">"
    if not is64:
        raise ValueError("harness executor is x86-64 only for now")
    e_phoff = struct.unpack_from(en + "Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(en + "I", data, off)[0]
        if p_type != 1:                                  # PT_LOAD
            continue
        p_offset = struct.unpack_from(en + "Q", data, off + 8)[0]
        p_vaddr = struct.unpack_from(en + "Q", data, off + 16)[0]
        p_filesz = struct.unpack_from(en + "Q", data, off + 32)[0]
        p_memsz = struct.unpack_from(en + "Q", data, off + 40)[0]
        base = p_vaddr & ~(_PAGE - 1)
        end = (p_vaddr + p_memsz + _PAGE - 1) & ~(_PAGE - 1)
        try:
            uc.mem_map(base, max(_PAGE, end - base), UC_PROT_ALL)
        except Exception:                                # noqa: BLE001 -- overlap: already mapped
            observe.absorbed(_log, "segment overlap, continuing")
        seg = data[p_offset:p_offset + p_filesz]
        if seg:
            uc.mem_write(p_vaddr, seg)
        loaded += 1
    if not loaded:
        raise ValueError("no PT_LOAD segments to map")


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


def _emulate_libc(uc, name, res, heap, regs) -> None:
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
            b = uc.mem_read(addr + len(out), 1)[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _alloc(n):
        n = (int(n) + 15) & ~15
        if n <= 0 or heap["next"] + n > _HEAP_ADDR + _HEAP_SZ:
            return 0
        p = heap["next"]
        heap["next"] += n
        return p

    try:
        if nm in ("memcpy", "memmove", "__memcpy_chk", "__memmove_chk", "mempcpy"):
            uc.mem_write(a0, bytes(uc.mem_read(a1, a2)))
            _set(a0 + a2 if nm == "mempcpy" else a0)
        elif nm in ("memset", "__memset_chk"):
            uc.mem_write(a0, bytes([a1 & 0xFF]) * a2)
            _set(a0)
        elif nm == "strlen":
            _set(len(_cstr(a0)))
        elif nm in ("strcpy", "__strcpy_chk", "stpcpy"):
            s = _cstr(a1)
            uc.mem_write(a0, s + b"\x00")
            _set(a0 + len(s) if nm == "stpcpy" else a0)
        elif nm in ("strncpy", "__strncpy_chk"):
            s = _cstr(a1)[:a2]
            uc.mem_write(a0, s + b"\x00" * (a2 - len(s)))
            _set(a0)
        elif nm in ("strcat", "__strcat_chk"):
            d, s = _cstr(a0), _cstr(a1)
            uc.mem_write(a0 + len(d), s + b"\x00")
            _set(a0)
        elif nm == "strcmp":
            _set(0 if _cstr(a0) == _cstr(a1) else 1)
        elif nm == "strncmp":
            _set(0 if _cstr(a0)[:a2] == _cstr(a1)[:a2] else 1)
        elif nm == "memcmp":
            _set(0 if bytes(uc.mem_read(a0, a2)) == bytes(uc.mem_read(a1, a2)) else 1)
        elif nm == "malloc":
            _set(_alloc(a0))
        elif nm == "calloc":
            n = a0 * a1
            p = _alloc(n)
            if p:
                uc.mem_write(p, b"\x00" * ((n + 15) & ~15))
            _set(p)
        elif nm == "realloc":
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
            _set(0)
    except UcError:
        res.crashed = True
        res.access = "write"
        res.note = (res.note + "; " if res.note else "") + f"fault in {nm}()"


def run_function(elf_bytes: bytes, func_addr: int, input_bytes: bytes, *,
                 arg_shape: str = "ptr_len", max_insns: int = _MAX_INSNS) -> HarnessResult:
    """Execute ONE function with `input_bytes` as its buffer argument; report fault + coverage.

    `arg_shape`: "ptr_len" -> rdi=&input, rsi=len; "ptr" -> rdi=&input. Reaching the sentinel
    return means the function returned cleanly; an access to unmapped memory means it faulted
    (a memory-safety bug reached by driving this one function).
    """
    import time as _time
    from unicorn import (UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_MEM_FETCH_UNMAPPED,
                         UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_64,
                         UC_PROT_ALL, Uc, UcError)
    from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDI,
                                   UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSI,
                                   UC_X86_REG_RSP)
    res = HarnessResult()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    try:
        _map_segments(uc, elf_bytes)
        uc.mem_map(_STACK_TOP - _STACK_SZ, _STACK_SZ, UC_PROT_ALL)
        uc.mem_map(_INPUT_ADDR, _INPUT_SZ, UC_PROT_ALL)
        uc.mem_map(_SENTINEL & ~(_PAGE - 1), _PAGE, UC_PROT_ALL)
        uc.mem_map(_HEAP_ADDR, _HEAP_SZ, UC_PROT_ALL)    # for the malloc/calloc/realloc stubs
        uc.mem_map(_TLS_ADDR, _PAGE, UC_PROT_ALL)        # fake TLS so the stack canary read works
    except Exception as e:                               # noqa: BLE001
        res.note = f"map failed: {e}"
        return res
    # A real function reads its stack canary from `fs:[0x28]`. Point FS at a fake TLS block with a
    # fixed canary there, so the read succeeds and the setup/return values match (no spurious
    # __stack_chk_fail). Without this every canary-protected function faults at 0x28 on entry.
    from unicorn.x86_const import UC_X86_REG_FS_BASE
    uc.reg_write(UC_X86_REG_FS_BASE, _TLS_ADDR)
    uc.mem_write(_TLS_ADDR + 0x28, b"\x11\x22\x33\x44\x55\x66\x77\x00")
    buf = input_bytes[:_INPUT_SZ]
    uc.mem_write(_INPUT_ADDR, buf)
    sp = ((_STACK_TOP - 0x1000) & ~0xF) - 8
    uc.mem_write(sp, _SENTINEL.to_bytes(8, "little"))    # sentinel return: `ret` lands here
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RDI, _INPUT_ADDR)
    if arg_shape == "ptr_len":
        uc.reg_write(UC_X86_REG_RSI, len(buf))

    plt = _plt_map(elf_bytes)
    heap = {"next": _HEAP_ADDR}
    pending = {"name": None}
    deadline = _time.time() + 10.0                       # wall-clock runaway guard

    def _on_block(uc_, addr, size, _ud):
        res.blocks.add(addr)
        nm = plt.get(addr)
        if nm is not None:                               # a call into the PLT: emulate the external
            pending["name"] = nm
            uc_.emu_stop()
        elif _time.time() > deadline:
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
            # stopped with no pending external -> reached the sentinel (clean return) or a budget stop
            if uc.reg_read(UC_X86_REG_RIP) in (_SENTINEL, 0) and not res.note:
                res.returned = True
            break
        calls += 1
        if calls > _MAX_CALLS:
            res.note = "too many external calls"
            break
        # simulate the `call`'s callee: pop the return address, emulate the libc function, resume.
        rsp = uc.reg_read(UC_X86_REG_RSP)
        try:
            retaddr = int.from_bytes(uc.mem_read(rsp, 8), "little")
        except UcError:
            res.note = "bad stack at external call"
            break
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        _emulate_libc(uc, pending["name"], res, heap,
                      (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                       UC_X86_REG_RAX, UC_X86_REG_RIP))
        if res.crashed:
            break
        cur = retaddr
    return res
