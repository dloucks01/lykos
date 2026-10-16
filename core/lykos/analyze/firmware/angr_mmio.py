#!/usr/bin/env python3
"""Standalone angr MMIO-value oracle for firmware rehosting (the symbolic tier of doc 17.5).

Run by an angr-capable interpreter (NOT imported by the stdlib-based Lykos core):

    <angr_python> angr_mmio.py <spec.json> <out.json>

The deterministic (SMT, not AI) answer to "what value should a peripheral read return?": load
the firmware blob, start at the entry with every peripheral (MMIO) read a FRESH SYMBOLIC value,
and let angr explore. For the deepest paths it finds, concretise the MMIO reads IN ORDER into a
byte stream -- a "seed" the fast Unicorn driver replays to reach the same code (and then fuzz /
catch faults from there). This solves gates the deterministic value-set search cannot (an
arbitrary compare constant), without a datasheet.

Bounded (step/state/time caps) and always writes a JSON result, even on failure, so a flaky or
unsupported target degrades to "no seeds" rather than a traceback.
"""
import base64
import json
import sys

# ---------------------------------------------------------------------------------- absorbed
# This driver runs as a standalone script under a different interpreter (the parent copies it to
# a scratch dir), so `lykos.observe` is not importable here. The counter still has to reach the
# parent, because a silently-skipped step in a tracer is exactly what turns a real crash into
# "no crash observed" -- so absorbed steps ride home in the JSON result and the parent folds
# them into its own counter. See observe.absorbed_remote.
_ABSORBED: list = []


def _absorbed(what):
    """Record a deliberately-absorbed failure, with the live exception's repr."""
    import sys as _sys
    exc = _sys.exc_info()[1]
    _ABSORBED.append({"what": what, "exc": repr(exc)[:200]})


try:
    import angr
    import archinfo
    import claripy
    HAVE = True
    IMPORT_ERR = ""
except Exception as e:  # pragma: no cover
    HAVE = False
    IMPORT_ERR = repr(e)

# lykos arch key -> (archinfo arch, thumb). Only the arches angr handles well as a flat blob.
_ARCH = {
    "cortex-m": ("ARMCortexM", True),
    "arm": ("ARMEL", False),
    "armbe": ("ARMEB", False),
    "aarch64": ("AARCH64", False),
    "mips": ("MIPS32", False),        # endianness set below
    "mipsel": ("MIPS32", False),
    "ppc": ("PPC32", False),
}
_MMIO = [(0x40000000, 0x60000000), (0xE0000000, 0xE0100000)]   # default ARM peripheral space


def _arch_obj(key, endian):
    name, thumb = _ARCH[key]
    end = "Iend_BE" if endian == "big" else "Iend_LE"
    if name == "MIPS32":
        return archinfo.ArchMIPS32(endness=("Iend_BE" if key == "mips" else "Iend_LE")), thumb
    try:
        return archinfo.arch_from_id(name, endness=end), thumb
    except Exception:
        _absorbed("falling back")
        return archinfo.arch_from_id(name), thumb


def run(spec):
    key = spec.get("arch")
    if key not in _ARCH:
        return {"ok": True, "supported": False, "seeds": [], "coverage": 0,
                "note": f"angr oracle does not model {key!r} as a flat blob"}
    with open(spec["blob"], "rb") as _f:
        blob = _f.read()
    base = int(spec.get("base", 0x08000000))
    entry = int(spec["entry"]) if spec.get("entry") is not None else base
    steps = int(spec.get("steps", 160))
    max_active = int(spec.get("max_active", 24))
    arch, thumb = _arch_obj(key, spec.get("endianness", "little"))

    proj = angr.load_shellcode(blob, arch, start_offset=0, load_address=base,
                               thumb=thumb, selfmodifying_code=False)
    opts = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    start = (entry | 1) if thumb else entry        # Thumb needs bit0 set or angr mis-decodes
    state = proj.factory.blank_state(addr=start, add_options=opts)
    try:
        state.regs.sp = int(spec.get("sp")) if spec.get("sp") is not None else (base + 0x100000)
    except Exception:
        _absorbed("continuing")

    # every MMIO read becomes a fresh, ordered symbolic value; we log them to reconstruct the
    # byte stream a path needs.
    counter = {"n": 0}

    def _is_mmio(addr):
        try:
            a = state.solver.eval(addr)
        except Exception:
            _absorbed("answering no")
            return False
        return any(lo <= a < hi for lo, hi in _MMIO)

    def on_read(st):
        addr = st.inspect.mem_read_address
        length = st.inspect.mem_read_length or 4
        try:
            concrete = st.solver.eval(addr)
        except Exception:
            _absorbed("returning early")
            return
        if not any(lo <= concrete < hi for lo, hi in _MMIO):
            return
        n = counter["n"]
        counter["n"] += 1
        sym = claripy.BVS(f"mmio_{n}", int(length) * 8)
        st.inspect.mem_read_expr = sym
        prior = st.globals["mmio"] if "mmio" in st.globals else []
        st.globals["mmio"] = prior + [(n, sym, int(length))]

    state.inspect.b("mem_read", when=angr.BP_AFTER, action=on_read)

    simgr = proj.factory.simulation_manager(state)
    reached = set()
    for _ in range(steps):
        if not simgr.active:
            break
        simgr.step()
        for s in simgr.active:
            for a in s.history.bbl_addrs:
                reached.add(a)
        if len(simgr.active) > max_active:                 # bound state explosion
            simgr.active[:] = simgr.active[:max_active]

    # build seeds from the states that got deepest: concretise their MMIO reads in order.
    cand = sorted(list(simgr.active) + list(simgr.deadended),
                  key=lambda s: len(s.history.bbl_addrs), reverse=True)[:6]
    seeds = []
    for s in cand:
        reads = s.globals.get("mmio", [])
        if not reads:
            continue
        stream = b""
        for _n, sym, length in sorted(reads, key=lambda r: r[0]):
            try:
                v = s.solver.eval(sym)
            except Exception:
                _absorbed("keeping the default")
                v = 0
            stream += int(v).to_bytes(int(length), "big" if spec.get("endianness") == "big" else "little")
        if stream:
            seeds.append(base64.b64encode(stream).decode())
    # de-dupe seeds
    seeds = list(dict.fromkeys(seeds))[:6]
    return {"ok": True, "supported": True, "seeds": seeds, "coverage": len(reached),
            "angr_version": angr.__version__}


def main():
    with open(sys.argv[1]) as _f:
        spec = json.load(_f)
    out = {"ok": False, "angr_available": HAVE, "seeds": []}
    if not HAVE:
        out["error"] = "angr not importable: " + IMPORT_ERR
    else:
        try:
            out.update(run(spec))
        except Exception as e:
            out["error"] = repr(e)
    with open(sys.argv[2], "w") as _f:    # explicit close: this driver is killed on timeout and
        out["absorbed"] = _ABSORBED
        json.dump(out, _f)                # a handle the GC never reached leaves partial JSON


if __name__ == "__main__":
    main()
