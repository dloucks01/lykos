#!/usr/bin/env python3
"""Standalone Unicorn firmware-rehosting driver (Phase 8, doc 17.5).

Run by a Unicorn-capable interpreter (NOT imported by the stdlib-only Lykos core):

    <unicorn_python> unicorn_driver.py <spec.json> <out.json>

Partial single-task rehosting of an ARM Cortex-M blob (the lowest rung of doc 17.5's
fidelity ladder): map flash + SRAM, model the peripheral space Fuzzware-style -- every MMIO
read returns the next bytes of a fuzz stream -- start at the reset vector, and run bounded.
A memory access outside flash/SRAM/peripherals is a genuine fault (a firmware memory-safety
bug). `mode:"fuzz"` mutates the MMIO stream (coverage-greedy) to drive the firmware into a
fault and returns the crashing stream.

Always writes a JSON result, even on failure, so the core reports a message not a traceback.
"""
import base64
import json
import random
import sys

try:
    import unicorn
    from unicorn import (
        UC_ARCH_ARM,
        UC_HOOK_BLOCK,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_UNMAPPED,
        UC_MEM_FETCH_PROT,
        UC_MEM_FETCH_UNMAPPED,
        UC_MEM_READ_PROT,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_PROT,
        UC_MEM_WRITE_UNMAPPED,
        UC_MODE_THUMB,
        Uc,
        UcError,
    )
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP
    HAVE = True
    IMPORT_ERR = ""
except Exception as e:  # pragma: no cover - exercised only where unicorn is absent
    HAVE = False
    IMPORT_ERR = repr(e)

# ARM Cortex-M peripheral windows modelled by the fuzz stream (start, size)
PERIPH = [(0x40000000, 0x20000000), (0xE0000000, 0x00100000)]
SRAM = (0x20000000, 0x00100000)


def _kind(access):
    if access in (UC_MEM_WRITE_UNMAPPED, UC_MEM_WRITE_PROT):
        return "write"
    if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
        return "fetch"
    if access in (UC_MEM_READ_UNMAPPED, UC_MEM_READ_PROT):
        return "read"
    return "unknown"


def _pad(chunk, size):
    return (chunk + b"\x00" * size)[:size]


def run_once(blob, base, sp, entry, fuzz, budget):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    flash_size = max(0x10000, (len(blob) + 0xFFF) & ~0xFFF)
    uc.mem_map(base, flash_size)
    uc.mem_write(base, blob)
    uc.mem_map(*SRAM)
    for s, sz in PERIPH:
        uc.mem_map(s, sz)

    blocks = set()
    st = {"i": 0, "fault": None}

    def hb(uc, addr, size, ud):
        blocks.add(addr)

    def hmr(uc, access, addr, size, value, ud):        # peripheral read -> fuzz byte(s)
        chunk = _pad(fuzz[st["i"]:st["i"] + size], size)
        st["i"] += size
        uc.mem_write(addr, chunk)

    def hbad(uc, access, addr, size, value, ud):       # non-peripheral invalid access = fault
        st["fault"] = {"addr": addr, "access": int(access), "pc": uc.reg_read(UC_ARM_REG_PC),
                       "kind": _kind(access)}
        return False

    uc.hook_add(UC_HOOK_BLOCK, hb)
    for s, sz in PERIPH:
        uc.hook_add(UC_HOOK_MEM_READ, hmr, begin=s, end=s + sz)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hbad)
    uc.reg_write(UC_ARM_REG_SP, sp)

    halt = "budget"
    try:
        uc.emu_start(entry | 1, 0, count=budget)     # bit0 = Thumb (Cortex-M is Thumb-only)
    except UcError:
        halt = "fault"
    if st["fault"]:
        halt = "fault"
    return {"nblocks": len(blocks), "blocks": sorted(hex(b) for b in blocks)[:200],
            "halt": halt, "fault": st["fault"], "consumed": st["i"]}


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


def fuzz(blob, base, sp, entry, budget, seeds, max_iters, rng_seed):
    rng = random.Random(rng_seed)
    corpus = [base64.b64decode(s) for s in seeds] or [b"\x00" * 16]
    corpus.append(bytes(rng.getrandbits(8) for _ in range(16)))
    covered = set()
    crash = None
    iters = 0
    for _ in range(max_iters):
        iters += 1
        data = _mutate(rng.choice(corpus), rng)
        r = run_once(blob, base, sp, entry, data, budget)
        new = set(r["blocks"]) - covered
        if new:
            covered |= new
            corpus.append(data)
        if r["fault"]:
            crash = {"fuzz_b64": base64.b64encode(data).decode(), "fault": r["fault"],
                     "nblocks": r["nblocks"], "consumed": r["consumed"]}
            break
    return {"iters": iters, "coverage": len(covered), "crash": crash}


def main():
    spec = json.load(open(sys.argv[1]))
    out = {"ok": False, "unicorn_available": HAVE, "arch": "cortex-m"}
    if not HAVE:
        out["error"] = "unicorn not importable: " + IMPORT_ERR
    else:
        try:
            import struct
            blob = open(spec["blob"], "rb").read()
            base = int(spec.get("base", 0x08000000))
            sp = int(spec["sp"]) if spec.get("sp") is not None \
                else struct.unpack_from("<I", blob, 0)[0]
            entry = int(spec["entry"]) if spec.get("entry") is not None \
                else struct.unpack_from("<I", blob, 4)[0] & ~1
            budget = int(spec.get("budget", 20000))
            out["unicorn_version"] = unicorn.__version__
            out["entry"] = hex(entry)
            out["sp"] = hex(sp)
            if spec.get("mode") == "fuzz":
                out["fuzz"] = fuzz(blob, base, sp, entry, budget,
                                   spec.get("seeds", []), int(spec.get("max_iters", 200)),
                                   int(spec.get("seed", 1337)))
            else:
                fz = base64.b64decode(spec["fuzz_b64"]) if spec.get("fuzz_b64") else b""
                out["run"] = run_once(blob, base, sp, entry, fz, budget)
            out["ok"] = True
        except Exception as e:
            out["error"] = repr(e)
    json.dump(out, open(sys.argv[2], "w"))


if __name__ == "__main__":
    main()
