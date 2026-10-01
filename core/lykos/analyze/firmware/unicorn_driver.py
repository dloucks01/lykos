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
        UC_HOOK_BLOCK, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_PROT, UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_PROT, UC_MEM_WRITE_UNMAPPED,
        UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_MIPS32, UC_MODE_MIPS64,
        UC_MODE_PPC32, UC_MODE_RISCV32, UC_MODE_RISCV64,
        UC_MODE_BIG_ENDIAN, UC_MODE_LITTLE_ENDIAN,
        Uc, UcError,
    )
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP
    from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_SP
    from unicorn.ppc_const import UC_PPC_REG_PC, UC_PPC_REG_1
    from unicorn.riscv_const import UC_RISCV_REG_PC, UC_RISCV_REG_SP
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
_SATISFY = [0xFFFFFFFFFFFFFFFF, 0x0, 0x1, 0x2, 0x3]   # try: all-set, clear, small counters


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


def run_once(cfg, blob, base, sp, entry, fuzz, budget):
    be = bool(cfg["mode"] & UC_MODE_BIG_ENDIAN)
    endc = ">" if be else "<"
    uc = Uc(cfg["uc"], cfg["mode"])
    flash_size = max(0x10000, (len(blob) + 0xFFF) & ~0xFFF)
    uc.mem_map(base, flash_size)
    uc.mem_write(base, blob)
    # a scratch RAM region: the arch default, else a window straddling the image base.
    ram_lo, ram_sz = (cfg["ram"] if cfg["ram"] else (max(0, base - 0x200000) & ~0xFFF, 0x400000))
    try:
        uc.mem_map(ram_lo, ram_sz)
    except UcError:
        ram_lo, ram_sz = 0, 0
    mmio = cfg["mmio"]
    if mmio:
        for s, sz in mmio:
            uc.mem_map(s, sz)

    blocks = set()
    st = {"i": 0, "fault": None, "since_new": 0, "stuck": False, "trial": 0,
          "pending": None, "cache": {}, "polls": 0}

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
        if addr not in blocks:
            blocks.add(addr)
            st["since_new"] = 0
            if st["stuck"] and st["pending"]:        # the poll-satisfying value just made progress
                st["cache"][st["pending"][0]] = st["pending"][1]
            st["stuck"] = False
            st["pending"] = None
            st["trial"] = 0
        else:
            st["since_new"] += 1
            if st["since_new"] > _STUCK:
                st["stuck"] = True

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

    uc.hook_add(UC_HOOK_BLOCK, hb)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hbad)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hbad)
    if mmio:
        for s, sz in mmio:
            uc.hook_add(UC_HOOK_MEM_READ, hmr_defined, begin=s, end=s + sz)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hbad)      # wild read = fault (defined map)
    else:
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hmr_lazy)  # model all unmapped reads

    uc.reg_write(cfg["sp"], sp)
    start = (entry | 1) if cfg["thumb"] else entry
    # `until` must be an address the firmware never executes -- NOT 0, which equals a generic
    # arch's entry (base 0) and makes emu_start stop before the first instruction. count bounds it.
    until = 0xFFFFFFFFFFFFFFFC if cfg["bits"] == 64 else 0xFFFFFFFC
    halt = "budget"
    try:
        uc.emu_start(start, until, count=budget)
    except UcError as e:
        halt = "fault"
        if st["fault"] is None:                   # a UcError our mem hooks did not classify
            try:
                pc = uc.reg_read(cfg["pc"])
            except Exception:
                pc = 0
            st["fault"] = {"addr": pc, "pc": pc, "kind": "invalid", "error": str(e)}
    if st["fault"]:
        halt = "fault"
    return {"nblocks": len(blocks), "blocks": sorted(hex(b) for b in blocks)[:200],
            "halt": halt, "fault": st["fault"], "consumed": st["i"],
            "polls_satisfied": len(st["cache"])}


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


def fuzz(cfg, blob, base, sp, entry, budget, seeds, max_iters, rng_seed):
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
        r = run_once(cfg, blob, base, sp, entry, data, budget)
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
            if spec.get("mode") == "fuzz":
                out["fuzz"] = fuzz(cfg, blob, base, sp, entry, budget,
                                   spec.get("seeds", []), int(spec.get("max_iters", 200)),
                                   int(spec.get("seed", 1337)))
            else:
                fz = base64.b64decode(spec["fuzz_b64"]) if spec.get("fuzz_b64") else b""
                out["run"] = run_once(cfg, blob, base, sp, entry, fz, budget)
            out["ok"] = True
        except Exception as e:
            out["error"] = repr(e)
    json.dump(out, open(sys.argv[2], "w"))


if __name__ == "__main__":
    main()
