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
_MAX_INSNS = 2_000_000               # runaway guard


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


def run_function(elf_bytes: bytes, func_addr: int, input_bytes: bytes, *,
                 arg_shape: str = "ptr_len", max_insns: int = _MAX_INSNS) -> HarnessResult:
    """Execute ONE function with `input_bytes` as its buffer argument; report fault + coverage.

    `arg_shape`: "ptr_len" -> rdi=&input, rsi=len; "ptr" -> rdi=&input. Reaching the sentinel
    return means the function returned cleanly; an access to unmapped memory means it faulted
    (a memory-safety bug reached by driving this one function).
    """
    from unicorn import (UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_MEM_FETCH_UNMAPPED,
                         UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_64,
                         UC_PROT_ALL, Uc, UcError)
    from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_RSI,
                                   UC_X86_REG_RSP)
    res = HarnessResult()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    try:
        _map_segments(uc, elf_bytes)
        uc.mem_map(_STACK_TOP - _STACK_SZ, _STACK_SZ, UC_PROT_ALL)
        uc.mem_map(_INPUT_ADDR, _INPUT_SZ, UC_PROT_ALL)
        uc.mem_map(_SENTINEL & ~(_PAGE - 1), _PAGE, UC_PROT_ALL)
    except Exception as e:                               # noqa: BLE001
        res.note = f"map failed: {e}"
        return res
    # input buffer
    buf = input_bytes[:_INPUT_SZ]
    uc.mem_write(_INPUT_ADDR, buf)
    # stack: 16-byte aligned, with the sentinel return address at the top so `ret` lands there.
    sp = (_STACK_TOP - 0x1000) & ~0xF
    sp -= 8
    uc.mem_write(sp, _SENTINEL.to_bytes(8, "little"))
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RDI, _INPUT_ADDR)
    if arg_shape == "ptr_len":
        uc.reg_write(UC_X86_REG_RSI, len(buf))

    def _on_block(uc_, addr, size, _ud):
        res.blocks.add(addr)

    def _on_unmapped(uc_, access, addr, size, value, _ud):
        res.crashed = True
        res.fault_addr = addr
        res.fault_pc = uc_.reg_read(UC_X86_REG_RIP)
        # unicorn's *_UNMAPPED access codes: 19 read, 20 write, 21 fetch.
        res.access = {19: "read", 20: "write", 21: "fetch"}.get(access, str(access))
        return False                                     # do not retry -> emu_stop with error

    uc.hook_add(UC_HOOK_BLOCK, _on_block)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                | UC_HOOK_MEM_FETCH_UNMAPPED, _on_unmapped)
    try:
        uc.emu_start(func_addr, _SENTINEL, count=max_insns)
        # Reaching the sentinel stops at _SENTINEL with no error: a clean return.
        if not res.crashed:
            res.returned = True
    except UcError:
        if not res.crashed:                              # an error that was not our unmapped hook
            res.note = "emulation error (unsupported instruction or external call)"
            res.fault_pc = uc.reg_read(UC_X86_REG_RIP)
    return res
