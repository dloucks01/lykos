#!/usr/bin/env python3
"""Standalone angr concolic/symbolic-execution driver (Phase 6).

Run by an angr-capable interpreter (NOT imported by the stdlib-only Lykos core):

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


def main(spec_path, out_path):
    spec = json.load(open(spec_path))
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

        proj = angr.Project(binary, auto_load_libs=False)
        symbytes = claripy.BVS("lykos_input", 8 * size)
        extras = {angr.options.LAZY_SOLVES}

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
                sf = angr.SimFile("stdin", content=symbytes, size=size)
                st = proj.factory.full_init_state(stdin=sf, add_options=extras)
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

        def step_func(lsm):
            steps["n"] += 1
            if time.time() > deadline:
                lsm.move(from_stash="active", to_stash="deferred")
            if len(lsm.active) > max_states:
                lsm.split(from_stash="active", limit=max_states, to_stash="spilled")
            return lsm

        if targets:
            simgr.explore(find=targets, avoid=avoid or None, num_find=num_find,
                          step_func=step_func)
        else:
            while simgr.active and time.time() < deadline and steps["n"] < 2000:
                simgr.step(step_func=step_func)

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
        result["stats"] = {
            "steps": steps["n"], "found": len(simgr.stashes.get("found", [])),
            "unconstrained": len(simgr.stashes.get("unconstrained", [])),
            "deadended": len(simgr.deadended), "active": len(simgr.active),
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
