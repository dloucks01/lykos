"""Semantic (emulation-based) gadget discovery.

The pattern-matching gadget finders (`rop.find_*`) recognise TEXTBOOK gadget shapes by byte decode:
`pop rdi; ret`, `ldp x1,x2,[sp]; ... ; ret`, `mv a0,sS; jr sB`. They miss register-control gadgets
that reach the same EFFECT through a non-canonical instruction sequence -- which is exactly why
argument-register control (setting a1/a2 for an execve syscall) read as "gadget-blocked" on the RISC
load-store arches: no `ldp`-style instruction loads the argument registers, so the matcher finds
nothing, even though sequences that LEAVE a1 set from the stack exist.

This module instead EMULATES each short instruction window that ends in a return (via Unicorn) from
a sentinel register + stack state, and records what each GPR BECOMES: zeroed, loaded from the
attacker-controlled stack (and from which slot), or copied from another controllable register. A
gadget that sets a1 from the stack is thus found by its observable effect, whatever instructions
produce it -- the semantic-gadget approach (angrop / ropper's semantic mode / Q / PSHAPE), done with
a real CPU emulator so the effect is measured, not inferred.

SOUNDNESS. Emulation OBSERVES the effect; it never asserts an exploit. A chain built from these
gadgets is still confirmed end-to-end by the qemu detonation + negative control, exactly as the
pattern-matched chains are -- so a mis-emulated gadget costs one failed detonation, never a false
result.

OPTIONAL. Unicorn and Capstone are externals (like the fuzzers' afl); they are imported LAZILY, so
this module imports under a stdlib-only core and simply reports nothing where they are absent -- the
pattern finders stand. `available()` says whether the engine can run on this host.
"""
from __future__ import annotations

import importlib
import importlib.util
from dataclasses import dataclass, field
from typing import Callable

# Tag the initial state so a final register value reveals its PROVENANCE. The tags sit in the
# non-canonical high bits so they never collide with a plausible small constant a gadget might load.
_STACK_TAG = 0x5A5A_5A00_0000_0000
_REG_TAG = 0x4242_4200_0000_0000
_TAG_MASK = 0xFFFF_FF00_0000_0000


def available() -> bool:
    """True when Unicorn + Capstone are importable (the engine can run here)."""
    return (importlib.util.find_spec("unicorn") is not None
            and importlib.util.find_spec("capstone") is not None)


@dataclass
class _ArchCfg:
    name: str
    uc_arch: str                 # attribute name on the unicorn module, e.g. "UC_ARCH_RISCV"
    uc_mode: str                 # e.g. "UC_MODE_RISCV64"
    cs_arch: str                 # attribute name on capstone, e.g. "CS_ARCH_RISCV"
    cs_mode: str                 # e.g. "CS_MODE_RISCV64|CS_MODE_RISCVC"
    word: int
    const_mod: str               # unicorn per-arch const submodule, e.g. "riscv_const"
    gpr: dict                    # reg-name -> reg-const attribute name in const_mod (e.g. "UC_RISCV_REG_X11")
    sp: str                      # stack-pointer reg name (key into gpr)
    ret_reg: str                 # the register a `ret` branches to (ra/x30/lr); None for stack-pop arches
    pc: str                      # pc reg-const attribute name in const_mod
    all_gpr: list = field(default_factory=list)   # every GPR to seed (names into gpr)
    is_ret: Callable = None      # (bytes, i) -> ret byte-length or None
    endian: str = "little"


# ---- RISC-V 64 -----------------------------------------------------------------------------------
# a0..a7 = x10..x17, ra = x1, sp = x2. `ret` = jalr x0,0(ra) = 0x00008067; `c.jr ra` = 0x8082.
def _riscv64_is_ret(data: bytes, i: int):
    if i + 4 <= len(data) and int.from_bytes(data[i:i + 4], "little") == 0x00008067:
        return 4
    if i + 2 <= len(data) and int.from_bytes(data[i:i + 2], "little") == 0x8082:
        return 2
    return None


def _riscv64_cfg() -> _ArchCfg:
    gpr = {f"x{i}": f"UC_RISCV_REG_X{i}" for i in range(32)}
    names = {"a0": "x10", "a1": "x11", "a2": "x12", "a3": "x13", "a4": "x14", "a5": "x15",
             "a6": "x16", "a7": "x17", "ra": "x1", "sp": "x2"}
    gpr.update({k: gpr[v] for k, v in names.items()})
    return _ArchCfg(
        name="riscv64", uc_arch="UC_ARCH_RISCV", uc_mode="UC_MODE_RISCV64",
        cs_arch="CS_ARCH_RISCV", cs_mode="CS_MODE_RISCV64|CS_MODE_RISCVC", word=8,
        const_mod="riscv_const", gpr=gpr, sp="sp", ret_reg="ra", pc="UC_RISCV_REG_PC",
        all_gpr=[f"x{i}" for i in range(1, 32)], is_ret=_riscv64_is_ret)


_ARCHS = {"riscv64": _riscv64_cfg, "riscv": _riscv64_cfg}


def arch_supported(arch: str) -> bool:
    return (arch or "").lower() in _ARCHS


# --------------------------------------------------------------------------------------------------
_CODE_BASE = 0x1_0000_0000
_STK_BASE = 0x2_0000_0000
_STK_SIZE = 0x1_0000
_SP0 = _STK_BASE + 0x800            # start sp mid-stack, headroom below and above


def _classify(val: int, own_idx: int):
    """Describe a final register value by provenance: zero / stack@<sp-offset> / reg:x<k> / None.
    A value equal to the register's OWN input tag means it was left UNCHANGED -- not control -- so
    that returns None (the caller only wants registers the gadget actually sets)."""
    if val == 0:
        return "zero"
    if (val & _TAG_MASK) == _STACK_TAG:
        return f"stack@{val & 0xFFFF}"            # byte offset from the gadget's entry sp
    if (val & _TAG_MASK) == _REG_TAG:
        # A CLEAN copy leaves the input tag intact: low bits == a valid GPR index. Arithmetic on a
        # tagged register (`addi a0, sX, imm`) perturbs the low bits (giving e.g. "x108"), which is a
        # derived value, not a controllable copy -- report only the clean copies.
        k = val & (~_TAG_MASK & 0xFFFFFFFFFFFFFFFF)
        if k <= 31 and k != own_idx:
            return f"reg:x{k}"
    return None


def find_reg_control_gadgets(data: bytes, arch: str, *, want=("a1", "a2"), segments=None,
                             max_insns: int = 6, max_results: int = 64, scan_cap: int = 200000):
    """Emulate short windows ending in a return and return the gadgets that CONTROL any `want`
    register (zero it, load it from the attacker stack, or copy it from another GPR).

    `data` is the image bytes; `segments` is an optional list of (file_off, size, vaddr) EXECUTABLE
    ranges (default: scan `data` as one range at vaddr 0). Each result is
    {"va", "len", "insns", "effects": {regname: "zero"|"stack@<off>"|"reg:x<k>"}} -- `va` is the
    gadget entry, and for a `stack@N` effect the overflow places the desired value N bytes past the
    gadget's entry sp. Returns [] when Unicorn/Capstone are unavailable or the arch is unsupported."""
    cfg_fn = _ARCHS.get((arch or "").lower())
    if cfg_fn is None or not available():
        return []
    import capstone as cs
    import unicorn as uc
    cfg = cfg_fn()

    rc = importlib.import_module("unicorn." + cfg.const_mod)       # per-arch register constants
    md = cs.Cs(getattr(cs, cfg.cs_arch), _mode(cfg.cs_mode, cs))
    md.detail = False
    segs = segments if segments is not None else [(0, len(data), 0)]

    _uc_arch, _uc_mode = getattr(uc, cfg.uc_arch), _mode(cfg.uc_mode, uc)
    _hook_code = getattr(uc, "UC_HOOK_CODE")
    _reg = {name: getattr(rc, cfg.gpr[name]) for name in set(cfg.gpr)}
    want_regs = [w for w in want if w in cfg.gpr]
    _own = {w: int(cfg.gpr[w].rsplit("_X", 1)[1]) for w in want_regs}   # each want-reg's GPR index
    _stack = b"".join((_STACK_TAG | off).to_bytes(8, "little") for off in range(0, 0x1000, 8))
    results, seen = [], set()
    scanned = 0

    def _emu(window: bytes, rl: int):
        """Emulate the gadget body in a FRESH, isolated emulator and STOP right before its return,
        returning the register state at that point. A fresh Uc per gadget is deliberate: reusing one
        across thousands of gadgets let faults/stores leave state that silently killed every later
        emulation (the scan then found only the first handful). Stopping AT the ret (a code hook)
        reads the effect regardless of what the return does -- so an epilogue that restores ra from
        the stack (`ld ra,X(sp); ret`, the common chainable shape) is handled, not rejected. A fault
        in the body (an unmapped load/branch) aborts before the ret, so the gadget is rejected."""
        reached = [False]
        stop_at = _CODE_BASE + len(window) - rl                   # the ret instruction's address

        def _hook(uc_, address, size, user):
            if address == stop_at:
                reached[0] = True
                uc_.emu_stop()
        try:
            mu = uc.Uc(_uc_arch, _uc_mode)
            mu.mem_map(_CODE_BASE, 0x1000)
            mu.mem_map(_STK_BASE, _STK_SIZE)
            mu.mem_write(_CODE_BASE, window.ljust(0x1000, b"\x00"))
            mu.mem_write(_SP0, _stack)                            # stack sentinels: tag | byte-offset
            for i in range(1, 32):
                name = f"x{i}"
                if name in _reg:
                    mu.reg_write(_reg[name], _REG_TAG | i)
            mu.reg_write(_reg[cfg.sp], _SP0)
            mu.hook_add(_hook_code, _hook)
            mu.emu_start(_CODE_BASE, _CODE_BASE + len(window), count=max_insns + 4)
        except uc.UcError:
            pass
        if not reached[0]:                                        # body faulted before the return
            return None
        return {w: mu.reg_read(_reg[w]) for w in want_regs}

    for off, size, vaddr in segs:
        seg = data[off:off + size]
        # Linear disassembly gives CANONICAL instruction boundaries, so a gadget entry is a real
        # instruction start -- not a byte offset that happens to decode cleanly (which would skip the
        # instruction that actually sets the register). Each ret in the stream is a gadget tail; the
        # gadget is the k instructions preceding it, entered at a true boundary.
        insns = _disasm_stream(md, seg)
        for j, ins in enumerate(insns):
            rl = cfg.is_ret(seg, ins.address)
            if rl is None or rl != ins.size:
                continue
            ret_end = ins.address + rl
            best = None                                           # (entry_off, effects) richest found
            for k in range(1, max_insns + 1):
                if j - k < 0:
                    break
                entry = insns[j - k].address
                regs = _emu(seg[entry:ret_end], rl)
                scanned += 1
                if regs is None:
                    continue
                eff = {}
                for r in want_regs:
                    c = _classify(regs[r], _own[r])
                    if c is not None:
                        eff[r] = c
                if eff and (best is None or len(eff) > len(best[1])):
                    best = (entry, eff, k + 1)
            if best:
                va = vaddr + best[0]
                if va not in seen:
                    seen.add(va)
                    results.append({"va": va, "insns": best[2], "effects": best[1]})
                    if len(results) >= max_results:
                        return results
            if scanned >= scan_cap:
                return results
    return results


def _disasm_stream(md, seg: bytes):
    """Linearly disassemble `seg`, RESYNCING past undecodable bytes (the ELF header at the start of
    an R+X PT_LOAD, embedded data, padding) -- capstone's own disasm stops dead at the first bad
    byte, which on a real image yields almost nothing. Returns the instruction list; code regions
    decode correctly, data regions are skipped a half-word at a time."""
    out = []
    pos, n = 0, len(seg)
    while pos < n:
        advanced = pos
        for ins in md.disasm(seg[pos:], pos):
            out.append(ins)
            advanced = ins.address + ins.size
        pos = advanced + 2 if advanced == pos else advanced       # resync past a bad half-word
    return out


def _mode(expr: str, module):
    """OR the named mode constants (e.g. "CS_MODE_RISCV64|CS_MODE_RISCVC") off `module`."""
    val = 0
    for p in expr.split("|"):
        val |= getattr(module, p.strip())
    return val
