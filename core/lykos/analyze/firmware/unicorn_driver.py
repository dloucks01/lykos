#!/usr/bin/env python3
"""Standalone multi-architecture Unicorn firmware-rehosting driver (Phase 8, doc 17.5).

Run by a Unicorn-capable interpreter (NOT imported by the stdlib-based Lykos core):

    <unicorn_python> unicorn_driver.py <spec.json> <out.json>

Rehosts a bare-metal / RTOS firmware blob WITHOUT a board model (unlike QEMU, which needs one
that rarely exists for custom hardware): map the image + RAM, model the peripheral space, start
at the entry, and run bounded. This is the Fuzzware/P2IM approach and it is why we use Unicorn,
not QEMU -- it is exactly the aarch64 / VxWorks case where a QEMU machine does not exist.

MMIO modeling is access-pattern aware, deterministically:
  * a read inside a STATUS-POLL loop (the firmware spins waiting on a ready/busy bit) is
    auto-satisfied -- we cycle 0xFFFFFFFF / 0x0 / an incrementing counter until the loop exits,
    then cache the value that worked for that read site, so init gets PAST the poll instead of
    hanging (naive fuzz-every-read never does).
  * a LIVE-INPUT read (not in a stuck loop) returns the next bytes of the fuzz stream.
A write or instruction fetch to unmapped memory is a genuine fault (memory corruption / control-
flow hijack); a read to a wild address outside RAM and the MMIO window is a fault too on arches
with a defined map (Cortex-M), while generic arches model unmapped reads lazily to make progress.

Architectures: arm (+ cortex-m Thumb), aarch64, mips/mipsel/mips64(+el), ppc/ppc64, riscv32/64.
Always writes a JSON result, even on failure.
"""
import base64
import json
import random
import struct
import sys

try:
    import unicorn
    from unicorn import (
        UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS, UC_ARCH_PPC, UC_ARCH_RISCV,
        UC_HOOK_BLOCK, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_PROT, UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_PROT, UC_MEM_WRITE_UNMAPPED,
        UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_MIPS32, UC_MODE_MIPS64,
        UC_MODE_PPC32, UC_MODE_RISCV32, UC_MODE_RISCV64,
        UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN,
        Uc, UcError,
    )
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0
    from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0,
                                     UC_ARM64_REG_X30)
    from unicorn.mips_const import (UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_V0,
                                    UC_MIPS_REG_RA)
    from unicorn.ppc_const import UC_PPC_REG_PC, UC_PPC_REG_1, UC_PPC_REG_3, UC_PPC_REG_LR
    from unicorn.riscv_const import (UC_RISCV_REG_PC, UC_RISCV_REG_SP, UC_RISCV_REG_A0,
                                     UC_RISCV_REG_RA)
    try:
        from unicorn import UC_MODE_PPC64
    except Exception:
        UC_MODE_PPC64 = UC_MODE_PPC32
    HAVE = True
    IMPORT_ERR = ""
except Exception as e:  # pragma: no cover - exercised only where unicorn is absent
    HAVE = False
    IMPORT_ERR = repr(e)


# name -> architecture config. `cortex_m` = reads SP/entry from the reset vector table and has a
# defined MMIO map (reads elsewhere are wild-read faults); the generic arches model unmapped
# reads lazily. `big` sets big-endian. pc/sp are the Unicorn register ids.
def _arch_table():
    be = UC_MODE_BIG_ENDIAN
    le = UC_MODE_LITTLE_ENDIAN
    CM_MMIO = [(0x40000000, 0x20000000), (0xE0000000, 0x00100000)]
    return {
        "cortex-m": dict(uc=UC_ARCH_ARM, mode=UC_MODE_THUMB | le, pc=UC_ARM_REG_PC,
                         sp=UC_ARM_REG_SP, thumb=True, cortex_m=True, bits=32,
                         ram=(0x20000000, 0x00100000), mmio=CM_MMIO),
        "arm": dict(uc=UC_ARCH_ARM, mode=UC_MODE_ARM | le, pc=UC_ARM_REG_PC, sp=UC_ARM_REG_SP,
                    thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "armbe": dict(uc=UC_ARCH_ARM, mode=UC_MODE_ARM | be, pc=UC_ARM_REG_PC, sp=UC_ARM_REG_SP,
                      thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "aarch64": dict(uc=UC_ARCH_ARM64, mode=UC_MODE_ARM | le, pc=UC_ARM64_REG_PC,
                        sp=UC_ARM64_REG_SP, thumb=False, cortex_m=False, bits=64,
                        ram=None, mmio=None),
        "mips": dict(uc=UC_ARCH_MIPS, mode=UC_MODE_MIPS32 | be, pc=UC_MIPS_REG_PC,
                     sp=UC_MIPS_REG_SP, thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "mipsel": dict(uc=UC_ARCH_MIPS, mode=UC_MODE_MIPS32 | le, pc=UC_MIPS_REG_PC,
                       sp=UC_MIPS_REG_SP, thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "mips64": dict(uc=UC_ARCH_MIPS, mode=UC_MODE_MIPS64 | be, pc=UC_MIPS_REG_PC,
                       sp=UC_MIPS_REG_SP, thumb=False, cortex_m=False, bits=64, ram=None, mmio=None),
        "mips64el": dict(uc=UC_ARCH_MIPS, mode=UC_MODE_MIPS64 | le, pc=UC_MIPS_REG_PC,
                         sp=UC_MIPS_REG_SP, thumb=False, cortex_m=False, bits=64, ram=None, mmio=None),
        "ppc": dict(uc=UC_ARCH_PPC, mode=UC_MODE_PPC32 | be, pc=UC_PPC_REG_PC, sp=UC_PPC_REG_1,
                    thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "ppc64": dict(uc=UC_ARCH_PPC, mode=UC_MODE_PPC64 | be, pc=UC_PPC_REG_PC, sp=UC_PPC_REG_1,
                      thumb=False, cortex_m=False, bits=64, ram=None, mmio=None),
        "riscv": dict(uc=UC_ARCH_RISCV, mode=UC_MODE_RISCV32 | le, pc=UC_RISCV_REG_PC,
                      sp=UC_RISCV_REG_SP, thumb=False, cortex_m=False, bits=32, ram=None, mmio=None),
        "riscv64": dict(uc=UC_ARCH_RISCV, mode=UC_MODE_RISCV64 | le, pc=UC_RISCV_REG_PC,
                        sp=UC_RISCV_REG_SP, thumb=False, cortex_m=False, bits=64, ram=None, mmio=None),
    }


# the driver arch keys, as a plain set so arch resolution needs no Unicorn import.
_ARCH_NAMES = {"cortex-m", "arm", "armbe", "aarch64", "mips", "mipsel", "mips64", "mips64el",
               "ppc", "ppc64", "riscv", "riscv64"}


# canonical lykos arch name (+ endianness/bits) -> driver arch key.
def _resolve_arch(spec):
    name = (spec.get("arch") or "").lower()
    if name in ("cortex-m", "cortexm") or spec.get("sub") == "cortex-m":
        return "cortex-m"
    end = (spec.get("endianness") or "little").lower()
    bits = int(spec.get("bits") or 32)
    if name in ("arm", "thumb"):
        return "armbe" if end == "big" else "arm"
    if name in ("aarch64", "arm64"):
        return "aarch64"
    if name in ("mips", "mips32"):
        return ("mips64" if bits == 64 else "mips") if end == "big" else \
               ("mips64el" if bits == 64 else "mipsel")
    if name in ("mips64",):
        return "mips64" if end == "big" else "mips64el"
    if name in ("ppc", "powerpc"):
        return "ppc64" if bits == 64 else "ppc"
    if name in ("ppc64", "powerpc64"):
        return "ppc64"
    if name in ("riscv", "riscv32"):
        return "riscv64" if bits == 64 else "riscv"
    if name in ("riscv64",):
        return "riscv64"
    return name if name in _ARCH_NAMES else None


_PAGE = 0x1000
_STUCK = 48          # blocks without progress before we treat an MMIO read as a status poll


def _satisfy_values():
    """Deterministic value-set search for a stuck status-poll MMIO read. The poll-breaker tries
    these in order and keeps whichever advances the firmware (a new block appears), caching it
    per read site. Covers the common gate shapes without a datasheet or symbolic solver:
    all-bits-set / clear (ready/busy flags), each single bit (wait-for-bit-N), small counters,
    and common magic/status bytes (0x55/0xAA/0xFF ping-pong, 0x80 MSB). Full SMT solving of an
    arbitrary compare constant is the deeper symbolic tier."""
    vals = [0xFFFFFFFFFFFFFFFF, 0x0]
    vals += [1 << n for n in range(32)]                  # single-bit: wait-for-bit-N
    vals += [0x55, 0xAA, 0xFF, 0x80, 0x55AA, 0xAA55, 0x5555, 0xA5A5]  # common magic/status
    vals += [1, 2, 3, 0x10, 0x100, 0x7FFFFFFF]           # small counters / sign edge
    seen, out = set(), []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


_SATISFY = _satisfy_values()


def _ret_ra(cfg):
    """(return-value register, return-address register) for the arch, or (None, None). Used to
    intercept a known function (HAL/libc/delay) and return from it on the host."""
    a = cfg["uc"]
    if a == UC_ARCH_ARM:
        return UC_ARM_REG_R0, UC_ARM_REG_LR
    if a == UC_ARCH_ARM64:
        return UC_ARM64_REG_X0, UC_ARM64_REG_X30
    if a == UC_ARCH_MIPS:
        return UC_MIPS_REG_V0, UC_MIPS_REG_RA
    if a == UC_ARCH_PPC:
        return UC_PPC_REG_3, UC_PPC_REG_LR
    if a == UC_ARCH_RISCV:
        return UC_RISCV_REG_A0, UC_RISCV_REG_RA
    return None, None


def _kind(access):
    if access in (UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT):
        return "write"
    if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
        return "fetch"
    if access in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT):
        return "read"
    return "unknown"


def _in(addr, size, lo, hi):
    return lo <= addr and addr + size <= hi


def run_once(cfg, blob, base, sp, entry, fuzz, budget, handlers=None):
    be = bool(cfg["mode"] & UC_MODE_BIG_ENDIAN)
    endc = ">" if be else "<"
    uc = Uc(cfg["uc"], cfg["mode"])
    flash_size = max(0x10000, (len(blob) + 0xFFF) & ~0xFFF)
    uc.mem_map(base, flash_size)
    uc.mem_write(base, blob)
    # a scratch RAM region: the arch default, else a window straddling the image base.
    ram_lo, ram_sz = (cfg["ram"] if cfg["ram"] else (max(0, base - 0x200000) & ~0xFFF, 0x400000))
    # Tighten Cortex-M RAM to the initial stack top. vector[0] (the SP) is `_estack` -- the top of
    # RAM -- under the universal CMSIS/GCC startup convention. A stack-buffer overflow writes UP
    # past the stack top; with the whole SRAM region mapped it stays mapped and silently corrupts,
    # so the fault only shows up later (if at all) as a wild jump. Mapping RAM only up to SP turns
    # the overflow itself into a direct unmapped-WRITE fault (CWE-787) at the overflowing store.
    # .data/.bss/heap all live below SP, so nothing legitimate is cut off. Guarded to a sane SP
    # inside the default window and a non-tiny resulting size.
    if cfg["cortex_m"] and sp and ram_lo < sp <= ram_lo + ram_sz:
        tight = ((sp - ram_lo) + 0xFFF) & ~0xFFF
        if tight >= 0x800:
            ram_sz = tight
    try:
        uc.mem_map(ram_lo, ram_sz)
    except UcError:
        ram_lo, ram_sz = 0, 0
    mmio = cfg["mmio"]
    if mmio:
        for s, sz in mmio:
            uc.mem_map(s, sz)

    # Interrupt dispatch (Cortex-M): when the firmware is deeply stuck in a wait-for-interrupt
    # spin (nothing the MMIO poll-breaker can help), fire a vector-table handler as a subroutine
    # -- save thread PC/LR, set LR to a mapped SENTINEL, jump to the handler; when it returns to
    # SENTINEL, restore the thread. This reaches interrupt-driven code (a very common blocker)
    # without faithful exception semantics.
    SENTINEL = 0x04000000
    irq_handlers = []
    if cfg["cortex_m"]:
        try:
            uc.mem_map(SENTINEL, _PAGE)
            uc.mem_write(SENTINEL, b"\xFE\xE7")        # b . safety net
        except UcError:
            pass
        # vector[0]=SP, vector[1]=Reset (the entry, not an interrupt); IRQ/exception handlers are
        # vector[2..]. Collect the distinct Thumb handlers in flash, excluding the entry itself.
        seen_h = set()
        entry_h = (entry & ~1)
        for i in range(2, min(len(blob) // 4, 128)):
            v = struct.unpack_from("<I", blob, 4 * i)[0]
            h = v & ~1
            if v & 1 and base <= h < base + flash_size and h != entry_h and h not in seen_h:
                seen_h.add(h)
                irq_handlers.append(h)

    # HAL/known-function handlers: {entry_addr: action}. An operator (or the lykos core's
    # signature matcher) supplies the addresses of recognised library functions and we run them
    # on the host instead of emulating -- "skip" (return immediately), "ret0"/"ret1" (set the
    # return value and return). This is the HALucinator mechanism; the signature DB that finds
    # the addresses is populated separately.
    hmap = {(int(a, 0) if isinstance(a, str) else int(a)) & ~1: str(act)
            for a, act in (handlers or {}).items()}
    ret_reg, ra_reg = _ret_ra(cfg)

    blocks = set()
    st = {"i": 0, "fault": None, "since_new": 0, "stuck": False, "trial": 0,
          "pending": None, "cache": {}, "polls": 0, "wr": 0, "wr_seen": 0,
          "irq_i": 0, "in_isr": False, "saved": None, "fires": 0, "resume": None, "handled": 0}
    _IRQ_STUCK = _STUCK * 3
    _MAX_FIRES = 16

    def _read_model(uc, addr, size, pc):
        # cached satisfying value for a known status-poll site
        if pc in st["cache"]:
            v = st["cache"][pc]
        elif st["stuck"]:
            v = _SATISFY[st["trial"] % len(_SATISFY)]
            st["pending"] = (pc, v)
            st["trial"] += 1
            st["polls"] += 1
        else:
            chunk = (fuzz[st["i"]:st["i"] + size] + b"\x00" * size)[:size]
            st["i"] += size
            try:
                uc.mem_write(addr, chunk)
            except UcError:
                pass
            return
        data = struct.pack(endc + "Q", v & 0xFFFFFFFFFFFFFFFF)
        data = data[-size:] if be else data[:size]
        try:
            uc.mem_write(addr, data)
        except UcError:
            pass

    def hb(uc, addr, size, ud):
        # intercept a known function: run it on the host and return to the caller instead of
        # emulating its body (skip a delay/HAL_Init, return 0/1 from a probe).
        if hmap and ra_reg is not None and (addr & ~1) in hmap and not st["in_isr"]:
            act = hmap[addr & ~1]
            if act in ("ret0", "ret1") and ret_reg is not None:
                uc.reg_write(ret_reg, 1 if act == "ret1" else 0)
            st["handled"] += 1
            st["resume"] = uc.reg_read(ra_reg)       # return to the caller
            uc.emu_stop()
            return
        # returned from a fired interrupt -> restore the thread context and resume there.
        # (PC changes from a block hook do not reliably redirect Unicorn, so we stop and the
        # outer loop restarts at st["resume"].)
        if st["in_isr"] and (addr & ~1) == SENTINEL:
            s = st["saved"] or {}
            for reg, val in s.items():
                uc.reg_write(reg, val)
            st["in_isr"] = False
            st["saved"] = None
            st["since_new"] = 0
            st["resume"] = s.get(UC_ARM_REG_PC)
            uc.emu_stop()
            return
        if addr not in blocks:
            blocks.add(addr)
            st["since_new"] = 0
            st["wr_seen"] = st["wr"]
            if st["stuck"] and st["pending"]:        # the poll-satisfying value just made progress
                st["cache"][st["pending"][0]] = st["pending"][1]
            st["stuck"] = False
            st["pending"] = None
            st["trial"] = 0
            return
        st["since_new"] += 1
        # A loop that is WRITING memory is making real progress even with no NEW coverage: startup
        # .bss-zeroing/memcpy (a real RTOS image zeroes KBs of RAM before main) or an MMIO
        # receive-copy. Treat memory-write progress as progress -- reset the stuck window -- so we
        # neither poll-break nor (worse) fire an interrupt into a mid-init loop and derail it
        # before it ever reaches application code. A pure read-spin (MMIO poll or idle wait) does
        # not write, so it still escalates: poll-break for an MMIO read, interrupt for a true idle.
        if st["wr"] != st["wr_seen"]:
            st["wr_seen"] = st["wr"]
            st["since_new"] = 0
            st["stuck"] = False
            return
        if st["since_new"] > _STUCK:
            st["stuck"] = True
        # deeply stuck and genuinely idle (no write progress): fire the next interrupt handler.
        if (irq_handlers and not st["in_isr"] and st["fires"] < _MAX_FIRES
                and st["since_new"] > _IRQ_STUCK):
            h = irq_handlers[st["irq_i"] % len(irq_handlers)]
            st["irq_i"] += 1
            st["fires"] += 1
            st["saved"] = {UC_ARM_REG_PC: uc.reg_read(UC_ARM_REG_PC),
                           UC_ARM_REG_LR: uc.reg_read(UC_ARM_REG_LR)}
            st["in_isr"] = True
            st["since_new"] = 0
            uc.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
            st["resume"] = h | 1                      # restart at the handler (see note above)
            uc.emu_stop()

    def hmr_defined(uc, access, addr, size, value, ud):   # read inside a defined MMIO window
        _read_model(uc, addr, size, uc.reg_read(cfg["pc"]))

    def hmr_lazy(uc, access, addr, size, value, ud):      # generic: model any unmapped READ
        page = addr & ~(_PAGE - 1)
        try:
            uc.mem_map(page, _PAGE)
        except UcError:
            pass
        _read_model(uc, addr, size, uc.reg_read(cfg["pc"]))
        return True                                       # retry the access now that it's mapped

    def hbad(uc, access, addr, size, value, ud):          # bad write / fetch = genuine fault
        st["fault"] = {"addr": addr, "access": int(access),
                       "pc": uc.reg_read(cfg["pc"]), "kind": _kind(access)}
        return False

    def hw(uc, access, addr, size, value, ud):        # count mapped writes = the firmware is progressing
        st["wr"] += 1

    uc.hook_add(UC_HOOK_BLOCK, hb)
    uc.hook_add(UC_HOOK_MEM_WRITE, hw)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hbad)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hbad)
    if mmio:
        for s, sz in mmio:
            uc.hook_add(UC_HOOK_MEM_READ, hmr_defined, begin=s, end=s + sz)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hbad)      # wild read = fault (defined map)
    else:
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hmr_lazy)  # model all unmapped reads

    uc.reg_write(cfg["sp"], sp)
    # `until` must be an address the firmware never executes -- NOT 0, which equals a generic
    # arch's entry (base 0) and makes emu_start stop before the first instruction. count bounds it.
    until = 0xFFFFFFFFFFFFFFFC if cfg["bits"] == 64 else 0xFFFFFFFC
    halt = "budget"
    pc = (entry | 1) if cfg["thumb"] else entry
    # Emulate in segments: a hook that fires/returns an interrupt sets st["resume"] and stops;
    # we restart there. Restarts are bounded by the interrupt-fire cap, so this terminates.
    for _segment in range(_MAX_FIRES * 2 + 2):
        st["resume"] = None
        try:
            uc.emu_start(pc, until, count=budget)
        except UcError as e:
            halt = "fault"
            if st["fault"] is None:               # a UcError our mem hooks did not classify
                try:
                    fpc = uc.reg_read(cfg["pc"])
                except Exception:
                    fpc = 0
                st["fault"] = {"addr": fpc, "pc": fpc, "kind": "invalid", "error": str(e)}
            break
        if st["fault"]:
            break
        if st["resume"] is not None:
            pc = st["resume"]
            continue
        break                                     # natural end (count exhausted / until hit)
    if st["fault"]:
        halt = "fault"
    return {"nblocks": len(blocks), "blocks": sorted(hex(b) for b in blocks)[:200],
            "halt": halt, "fault": st["fault"], "consumed": st["i"],
            "polls_satisfied": len(st["cache"]), "irq_fires": st["fires"],
            "handled_calls": st["handled"]}


def _mutate(data, rng):
    d = bytearray(data or b"\x00")
    for _ in range(rng.randint(1, 6)):
        op = rng.randint(0, 4)
        if op == 0 and d:
            d[rng.randrange(len(d))] = rng.getrandbits(8)
        elif op == 1:
            d.append(rng.getrandbits(8))
        elif op == 2 and len(d) > 1:
            del d[rng.randrange(len(d))]
        elif op == 3 and d:
            d[rng.randrange(len(d))] = rng.choice([0x00, 0xFF, 0x7F, 0x80, 0x2A, 0x01])
        else:
            d += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 8)))
    return bytes(d[:256])


def fuzz(cfg, blob, base, sp, entry, budget, seeds, max_iters, rng_seed, handlers=None):
    rng = random.Random(rng_seed)
    corpus = [base64.b64decode(s) for s in seeds] or [b"\x00" * 16]
    corpus.append(bytes(rng.getrandbits(8) for _ in range(16)))
    covered = set()
    crash = None
    iters = 0
    best_polls = 0
    for _ in range(max_iters):
        iters += 1
        data = _mutate(rng.choice(corpus), rng)
        r = run_once(cfg, blob, base, sp, entry, data, budget, handlers=handlers)
        best_polls = max(best_polls, r.get("polls_satisfied", 0))
        new = set(r["blocks"]) - covered
        if new:
            covered |= new
            corpus.append(data)
        if r["fault"]:
            crash = {"fuzz_b64": base64.b64encode(data).decode(), "fault": r["fault"],
                     "nblocks": r["nblocks"], "consumed": r["consumed"]}
            break
    return {"iters": iters, "coverage": len(covered), "crash": crash,
            "polls_satisfied": best_polls}


def _vector_table(blob):
    sp = struct.unpack_from("<I", blob, 0)[0]
    entry = struct.unpack_from("<I", blob, 4)[0] & ~1
    return sp, entry


def main():
    spec = json.load(open(sys.argv[1]))
    archkey = _resolve_arch(spec) if HAVE else None
    out = {"ok": False, "unicorn_available": HAVE, "arch": archkey or spec.get("arch")}
    if not HAVE:
        out["error"] = "unicorn not importable: " + IMPORT_ERR
    elif archkey is None:
        out["error"] = "unsupported arch for rehosting: " + repr(spec.get("arch"))
    else:
        try:
            cfg = _arch_table()[archkey]
            blob = open(spec["blob"], "rb").read()
            base = int(spec.get("base") if spec.get("base") is not None else 0x08000000)
            if cfg["cortex_m"]:
                vsp, ventry = _vector_table(blob)
                sp = int(spec["sp"]) if spec.get("sp") is not None else vsp
                entry = int(spec["entry"]) if spec.get("entry") is not None else ventry
            else:
                # generic: entry defaults to the image base; SP to the top of a scratch stack.
                entry = int(spec["entry"]) if spec.get("entry") is not None else base
                sp = int(spec["sp"]) if spec.get("sp") is not None else (base + 0x100000)
            budget = int(spec.get("budget", 20000))
            out["unicorn_version"] = unicorn.__version__
            out["arch"] = archkey
            out["entry"] = hex(entry)
            out["sp"] = hex(sp)
            handlers = spec.get("handlers") or {}
            if spec.get("mode") == "fuzz":
                out["fuzz"] = fuzz(cfg, blob, base, sp, entry, budget,
                                   spec.get("seeds", []), int(spec.get("max_iters", 200)),
                                   int(spec.get("seed", 1337)), handlers=handlers)
            else:
                fz = base64.b64decode(spec["fuzz_b64"]) if spec.get("fuzz_b64") else b""
                out["run"] = run_once(cfg, blob, base, sp, entry, fz, budget, handlers=handlers)
            out["ok"] = True
        except Exception as e:
            out["error"] = repr(e)
    json.dump(out, open(sys.argv[2], "w"))


if __name__ == "__main__":
    main()
