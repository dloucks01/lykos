#!/usr/bin/env python3
"""Standalone angr concolic/symbolic-execution driver (Phase 6).

Run by an angr-capable interpreter (NOT imported by the stdlib-based Lykos core):

    <angr_python> angr_driver.py <spec.json> <out.json>

spec.json:
  binary       path to the target
  input_mode   "stdin" | "arg" | "file"
  input_size   symbolic input length in bytes
  targets      ["0x..."] sink addresses to reach (find=); may be empty for coverage mode
  avoid        ["0x..."] addresses to avoid (optional)
  seeds        [base64,...] concrete inputs to preconstrain (concolic / hybrid seeding)
  max_seconds  wall-clock budget
  max_states   cap on simultaneously-active states (state-explosion guard)
  num_find     stop after this many target-reaching states

out.json:
  ok, angr_version, generated:[{input_b64, reached, from_seed}], reached_targets:[...],
  stats:{...}, note, error
  drained   True iff the search hit a natural fixpoint (no active/deferred/spilled/errored
            states left) -- the only condition under which "did not reach target X" licenses an
            UNREACHABLE claim for X (T3 reachability certificate).
  cutoff    True iff the search was stopped early (deadline / SIGALRM / state-cap / step-cap);
            a cut-off search that missed a target proves nothing about reachability.

Deterministic and offline. Always writes a JSON result, even on failure, so the core can
report a clear message rather than a stack trace.
"""
import base64
import json
import sys
import time


def _int(a):
    try:
        return int(a, 16) if str(a).lower().startswith("0x") else int(a)
    except (ValueError, TypeError):
        return None


def _write(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


# lykos arch string -> archinfo/angr arch name for the blob backend.
_ARCH = {
    "x86-64": "AMD64", "x86_64": "AMD64", "amd64": "AMD64", "x64": "AMD64",
    "x86": "X86", "i386": "X86", "i686": "X86",
    "arm": "ARMEL", "armel": "ARMEL", "armhf": "ARMHF", "thumb": "ARMEL",
    "aarch64": "AARCH64", "arm64": "AARCH64",
    "mips": "MIPS32", "mipsel": "MIPS32", "mips64": "MIPS64",
    "ppc": "PPC32", "powerpc": "PPC32", "ppc64": "PPC64",
    "riscv": "RISCV64", "riscv64": "RISCV64", "sparc": "SPARC",
}


def _load_project(angr, spec, binary):
    """Open the binary with angr, falling back to the raw 'blob' loader when CLE has no backend
    for it (a firmware image or headerless dump). Without this a non-ELF target raised
    CLECompatibilityError and took the whole concolic stage down; the blob backend loads any bytes
    at a base address for the given architecture so exploration can still proceed."""
    try:
        return angr.Project(binary, auto_load_libs=False)
    except Exception as first:                               # noqa: BLE001
        arch = _ARCH.get(str(spec.get("arch", "")).lower())
        if not arch:
            raise first
        base = spec.get("base_addr")
        main_opts = {"backend": "blob", "arch": arch}
        if isinstance(base, int):
            main_opts["base_addr"] = base
        entry = spec.get("entry")
        if isinstance(entry, int):
            main_opts["entry_point"] = entry
        return angr.Project(binary, auto_load_libs=False, main_opts=main_opts)


def main(spec_path, out_path):
    with open(spec_path) as _f:
        spec = json.load(_f)
    result = {"ok": False, "generated": [], "reached_targets": [], "stats": {}, "note": None}
    try:
        import logging

        import angr
        import claripy
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)
        result["angr_version"] = getattr(angr, "__version__", "?")
    except Exception as e:                                   # noqa: BLE001
        result["error"] = "angr import failed: %s" % e
        _write(out_path, result)
        return 2

    try:
        binary = spec["binary"]
        mode = spec.get("input_mode", "stdin")
        size = int(spec.get("input_size", 64))
        targets = [t for t in (_int(x) for x in spec.get("targets", [])) if t is not None]
        avoid = [t for t in (_int(x) for x in spec.get("avoid", [])) if t is not None]
        seeds = [base64.b64decode(s) for s in spec.get("seeds", [])]
        max_seconds = float(spec.get("max_seconds", 120))
        max_states = int(spec.get("max_states", 800))
        num_find = int(spec.get("num_find", 6))

        proj = _load_project(angr, spec, binary)
        symbytes = claripy.BVS("lykos_input", 8 * size)
        extras = {angr.options.LAZY_SOLVES}

        def _stdin_state():
            # The stdin SimFile model varies across angr versions -- a plain `SimFile` passed as
            # `stdin=` raised a TypeError ("can't handle sim file") on one bundle's angr, which took
            # the whole concolic lane down for that target. Try the SimFile, then a SimFileStream,
            # then a plain state with angr's own default symbolic stdin. The capability is preserved
            # (exploration still runs); only the explicit input binding is given up in the last
            # fallback, and `preconstrain` is already guarded. A lane that degrades beats a lane that
            # disappears.
            try:
                sf = angr.SimFile("stdin", content=symbytes, size=size)
                return proj.factory.full_init_state(stdin=sf, add_options=extras)
            except Exception:                                # noqa: BLE001
                pass
            try:
                sfs = angr.SimFileStream(name="stdin", content=symbytes, size=size)
                return proj.factory.full_init_state(stdin=sfs, add_options=extras)
            except Exception:                                # noqa: BLE001
                return proj.factory.full_init_state(add_options=extras)

        def make_state(preconstrain=None):
            if mode == "arg":
                st = proj.factory.full_init_state(
                    args=[binary, symbytes], add_options=extras)
            elif mode == "file":
                sf = angr.SimFile("lykos_input_file", content=symbytes, size=size)
                st = proj.factory.full_init_state(
                    args=[binary, "/lykos_input"], add_options=extras)
                st.fs.insert("/lykos_input", sf)
            else:                                            # stdin
                st = _stdin_state()
            if preconstrain is not None:
                try:
                    for i, byte in enumerate(preconstrain[:size]):
                        st.solver.add(symbytes.get_byte(i) == byte)
                except Exception:                            # noqa: BLE001
                    pass
            return st

        # concolic/hybrid: one preconstrained state per seed, plus a fully-symbolic state
        states = [make_state(s) for s in seeds[:8]]
        states.append(make_state())
        simgr = proj.factory.simulation_manager(states, save_unconstrained=True)

        deadline = time.time() + max_seconds
        steps = {"n": 0}
        timed_out = {"v": False}                             # the soft deadline fired during stepping

        def step_func(lsm):
            steps["n"] += 1
            if time.time() > deadline:
                timed_out["v"] = True
                lsm.move(from_stash="active", to_stash="deferred")
            if len(lsm.active) > max_states:
                lsm.split(from_stash="active", limit=max_states, to_stash="spilled")
            return lsm

        # Hard wall-clock guard. step_func honors the deadline BETWEEN steps, but a single step can
        # get stuck (a huge basic block, a slow solver query) and never return -- then the parent's
        # subprocess timeout SIGKILLs us and every input found so far is lost. A SIGALRM converts
        # that into a clean break: we stop exploring and dump whatever states we already have.
        class _Deadline(Exception):
            pass

        def _alarm(signum, frame):
            raise _Deadline()

        result["incomplete"] = False
        try:
            import signal
            signal.signal(signal.SIGALRM, _alarm)
            # a little past the soft deadline so step_func's graceful stop runs first
            signal.alarm(max(1, int(max_seconds) + 5))
        except Exception:                                    # noqa: BLE001 -- no SIGALRM on this OS
            signal = None
        try:
            if targets:
                simgr.explore(find=targets, avoid=avoid or None, num_find=num_find,
                              step_func=step_func)
            else:
                while simgr.active and time.time() < deadline and steps["n"] < 2000:
                    simgr.step(step_func=step_func)
        except _Deadline:
            result["incomplete"] = True                      # dump partial results below
        finally:
            if signal is not None:
                try:
                    signal.alarm(0)
                except Exception:                            # noqa: BLE001
                    pass

        def dump_input(st, from_seed):
            try:
                if mode == "stdin":
                    data = st.posix.dumps(0)
                elif mode == "arg":
                    data = st.solver.eval(symbytes, cast_to=bytes)
                else:
                    data = st.solver.eval(symbytes, cast_to=bytes)
                return {"input_b64": base64.b64encode(data[:size]).decode(),
                        "from_seed": from_seed}
            except Exception:                                # noqa: BLE001
                return None

        reached = set()
        for st in simgr.stashes.get("found", []):
            g = dump_input(st, False)
            if g:
                g["reached"] = "0x%x" % st.addr
                reached.add(g["reached"])
                result["generated"].append(g)
        # unconstrained states = hijacked instruction pointer -> strong crash candidates
        for st in simgr.stashes.get("unconstrained", [])[:num_find]:
            g = dump_input(st, False)
            if g:
                g["reached"] = "unconstrained-ip"
                result["generated"].append(g)
        # a few deadended inputs become new corpus seeds for the fuzzer (hybrid handoff)
        for st in simgr.deadended[:max(0, num_find - len(result["generated"]))]:
            g = dump_input(st, False)
            if g:
                g["reached"] = None
                result["generated"].append(g)

        result["reached_targets"] = sorted(reached)
        # Reachability-certificate soundness (T3): distinguish a search that reached a NATURAL
        # FIXPOINT -- every path found/avoided/deadended, nothing left to explore -- from one that
        # was CUT OFF (deadline, SIGALRM, state-cap spill, step-cap, or any errored path). Only a
        # drained search licenses an "unreachable" claim for a target we did not reach; a cut-off
        # search that missed a target proves nothing. `errored > 0` also forfeits the claim: an
        # errored path is indeterminate, not a dead end.
        deferred = len(simgr.stashes.get("deferred", []))
        spilled = len(simgr.stashes.get("spilled", []))
        errored = len(getattr(simgr, "errored", []) or [])
        step_cap_hit = (not targets) and steps["n"] >= 2000 and len(simgr.active) > 0
        leftover = len(simgr.active) + deferred + spilled
        cutoff = bool(result.get("incomplete")) or timed_out["v"] or step_cap_hit
        result["cutoff"] = cutoff
        result["drained"] = (leftover == 0) and (errored == 0) and not cutoff
        result["stats"] = {
            "steps": steps["n"], "found": len(simgr.stashes.get("found", [])),
            "unconstrained": len(simgr.stashes.get("unconstrained", [])),
            "deadended": len(simgr.deadended), "active": len(simgr.active),
            "deferred": deferred, "spilled": spilled, "errored": errored,
            "elapsed_s": round(time.time() - (deadline - max_seconds), 2)}
        result["ok"] = True
        _write(out_path, result)
        return 0
    except Exception as e:                                   # noqa: BLE001
        import traceback
        result["error"] = "%s: %s" % (type(e).__name__, e)
        result["traceback"] = traceback.format_exc()[-1500:]
        _write(out_path, result)
        return 3


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: angr_driver.py <spec.json> <out.json>", file=sys.stderr)
        sys.exit(64)
    sys.exit(main(sys.argv[1], sys.argv[2]))
