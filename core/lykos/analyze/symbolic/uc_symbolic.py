"""Under-constrained symbolic execution of a single function -- discovery for code no harness drives.

A function is entered in ISOLATION (angr call_state, symbolic args, symbolic-filled lazy memory), so a
function the fuzzer never reaches is still examined. The sound, low-false-positive signal is a
DATA-dependent unconstrained instruction pointer: symbolic data the function READ reaches control flow
(a control-hijack candidate). A PC controlled only by an argument register (a passed callback) is NOT
flagged. See angr_driver._run_uc for the gate.

HONEST CONTRACT: under-constrained isolation assumes the function's arguments are attacker-reachable
and unconstrained, which is unsound for a CONFIRMATION -- real callers may guarantee what UC does not.
So a UC result is only ever a `candidate` with that caveat stated; it never claims a proven bug. It is
a DISCOVERY aid that widens coverage to undriven code; the confirmation ladder (a concrete input that
faults under a sanitizer with a negative control) remains the only thing that proves a finding.
"""
from __future__ import annotations

from . import concolic as _concolic


def uc_scan_function(binary, fn, *, load_libs=None, timeout: int = 60, ctx=None) -> dict:
    """Run UC symbolic execution on one function. `fn` is a symbol name or a hex address; `load_libs`
    force-loads the project's own .so (a shared build whose parser lives in a library). Returns the
    driver's `uc` dict: {function, reached, unconstrained, data_to_pc, hijackable, witness_vars, ...},
    or {reached: False, reason} when angr is unavailable / the explore could not run."""
    py = _concolic.locate_angr_python()
    if py is None:
        return {"reached": False, "reason": "angr unavailable"}
    spec = {"binary": str(binary), "input_mode": "uc", "uc_fn": str(fn),
            "max_seconds": int(timeout)}
    if load_libs:
        spec["load_libs"] = list(load_libs)
    try:
        res = _concolic.run_explore(py, spec, ctx=ctx, timeout=timeout + 10)
    except Exception as e:                                   # noqa: BLE001 -- a stuck/failed explore
        return {"reached": False, "reason": f"uc explore failed: {e}"}
    uc = res.get("uc")
    if not uc:
        return {"reached": False, "reason": res.get("error") or "no uc result"}
    uc["cutoff"] = bool(res.get("cutoff"))
    return uc
