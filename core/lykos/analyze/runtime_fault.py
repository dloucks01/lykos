"""One answer to "what does this uncaught exception mean", across every managed runtime.

A native crash is a signal; on the JVM and under CPython the equivalent is an uncaught
exception, and each runtime has its own vocabulary for the same defects (`IndexError` and
`ArrayIndexOutOfBoundsException` are one bug class). The per-runtime tables live next to their
parsers -- `jvm.EXCEPTION_CWE`, `pyc.EXCEPTION_CWE` -- because that is where the evidence for
each mapping is. This is the lookup the SHARED stages use, so a crash finding does not have to
know which runtime produced it.

Why not just chain the two `cwe_for_exception` helpers: each ends in a catch-all for a name
shaped like its own runtime's exceptions (`*Error`, `*Exception`), so whichever ran first would
swallow the other's specific names -- `IndexError` would come back CWE-248 "unknown JVM fault"
instead of CWE-129. Both SPECIFIC tables are consulted before either fallback.
"""
from __future__ import annotations

from typing import Optional

_JVM_FATAL = "JVM-FATAL-"
_PY_FATAL = "PY-FATAL-"


def managed_fault(name: str) -> Optional[tuple[str, str, str]]:
    """(cwe, severity, runtime) for an uncaught managed-runtime fault, else None.

    `runtime` is a phrase for a finding title ("the JVM", "CPython"), so the report says which
    interpreter actually observed the fault rather than implying a native crash.
    """
    if not name:
        return None
    from . import jvm, pyc, wasm
    # A wasm trap is already classified by the engine's own message, which names the defect;
    # the signal-shaped name just carries it out of the sandbox.
    hit = wasm.cwe_for_trap(name)
    if hit:
        return (hit[0], hit[1], "the WebAssembly engine")
    # The runtime ITSELF dying is the one managed result that really is memory corruption.
    if name.startswith(_JVM_FATAL):
        return ("CWE-119", "critical", "the JVM")
    if name.startswith(_PY_FATAL):
        return ("CWE-119", "critical", "CPython")
    hit = jvm.EXCEPTION_CWE.get(name)
    if hit:
        return (hit[0], hit[1], "the JVM")
    hit = pyc.EXCEPTION_CWE.get(name)
    if hit:
        return (hit[0], hit[1], "CPython")
    if name in pyc.NOT_A_FAULT:
        return None                      # SystemExit is a deliberate exit, not a defect
    if name.endswith(("Exception", "Error", "Throwable")):
        # Unknown, but unmistakably a managed-runtime exception. CWE-248 at a middling
        # severity is the honest answer; inheriting the native default would badge it critical
        # memory corruption on a runtime that has none.
        return ("CWE-248", "medium", "a managed runtime")
    return None
