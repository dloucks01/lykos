"""One answer to "what does this uncaught exception mean", across every managed runtime.

A native crash is a signal; on the JVM, under CPython, in a wasm engine and under the CLR the
equivalent is an uncaught exception or a trap, and each runtime has its own vocabulary for the
same defects (`IndexError`, `ArrayIndexOutOfBoundsException` and `IndexOutOfRangeException` are
one bug class). The per-runtime tables live next to their parsers -- `jvm.EXCEPTION_CWE`,
`pyc.EXCEPTION_CWE`, `dotnet.EXCEPTION_CWE`, `wasm.TRAP_CWE` -- because that is where the
evidence for each mapping is. This is the lookup the SHARED stages use, so a crash finding does
not have to know which runtime produced it.

Why not just chain the per-runtime `cwe_for_exception` helpers: each ends in a catch-all for a
name shaped like its own runtime's exceptions (`*Error`, `*Exception`), so whichever ran first
would swallow the other's specific names -- `IndexError` would come back CWE-248 "unknown JVM
fault" instead of CWE-129. Every SPECIFIC table is consulted before any fallback.

Why `file_type` is worth passing: the JVM and CLR tables genuinely share names --
`IOException`, `ArithmeticException`, `SecurityException`, `FileNotFoundException` all exist on
both. They agree on the CWE, so a name-only lookup gets the weakness right, but it would
attribute a .NET fault to "the JVM" in the finding title. Given the target's file_type the
right table is consulted first and the attribution is correct.
"""
from __future__ import annotations

from typing import Optional

_JVM_FATAL = "JVM-FATAL-"
_PY_FATAL = "PY-FATAL-"
_CLR_FATAL = "CLR-FATAL-"

#: The exception-table runtimes, in the order consulted when no file_type narrows it down.
#: `_table` owns the phrase for each, so there is one place a runtime is named.
_RUNTIMES = ("jvm", "cpython", "clr")


def _table(kind: str):
    """(EXCEPTION_CWE, phrase) for a runtime key, or (None, None)."""
    from . import dotnet, jvm, pyc
    if kind == "jvm":
        return jvm.EXCEPTION_CWE, "the JVM"
    if kind == "cpython":
        return pyc.EXCEPTION_CWE, "CPython"
    if kind == "clr":
        return dotnet.EXCEPTION_CWE, "the CLR"
    return None, None


def _runtime_key(file_type: Optional[str]) -> Optional[str]:
    """The runtime key for a file_type, via the one substrate table.

    `wasm` is absent from `_RUNTIMES` on purpose: a trap is classified by the engine's own
    message before any table is consulted, so there is no wasm exception table to prefer.
    """
    from . import substrate
    key = substrate.managed_kind(file_type)
    return key if key in _RUNTIMES else None


def managed_fault(name: str, file_type: Optional[str] = None):
    """(cwe, severity, runtime) for an uncaught managed-runtime fault, else None.

    `runtime` is a phrase for a finding title ("the JVM", "CPython", "the CLR"), so the report
    says which runtime actually observed the fault rather than implying a native crash.
    `file_type`, when known, decides which table is authoritative for a name two runtimes share.
    """
    if not name:
        return None
    from . import dotnet, pyc, wasm
    # A wasm trap is already classified by the engine's own message, which names the defect;
    # the signal-shaped name just carries it out of the sandbox.
    hit = wasm.cwe_for_trap(name)
    if hit:
        return (hit[0], hit[1], "the WebAssembly engine")
    # The runtime ITSELF dying is the one managed result that really is memory corruption.
    for prefix, phrase in ((_JVM_FATAL, "the JVM"), (_PY_FATAL, "CPython"),
                           (_CLR_FATAL, "the CLR")):
        if name.startswith(prefix):
            return ("CWE-119", "critical", phrase)
    # A .NET name may arrive fully qualified (`System.IndexOutOfRangeException`).
    short = name.rsplit(".", 1)[-1]
    # The target's own runtime first, so a name two runtimes share is attributed correctly.
    preferred = _runtime_key(file_type)
    order = ([preferred] + [k for k in _RUNTIMES if k != preferred]) if preferred \
        else list(_RUNTIMES)
    for kind in order:
        tbl, phrase = _table(kind)
        if not tbl:
            continue
        hit = tbl.get(name) or tbl.get(short)
        if hit:
            return (hit[0], hit[1], phrase)
    if short in pyc.NOT_A_FAULT or short in dotnet.NOT_A_FAULT:
        return None                      # SystemExit / a cancellation is not a defect
    if name.endswith(("Exception", "Error", "Throwable")):
        # Unknown, but unmistakably a managed-runtime exception. CWE-248 at a middling
        # severity is the honest answer; inheriting the native default would badge it critical
        # memory corruption on a runtime that has none.
        _, phrase = _table(preferred) if preferred else (None, None)
        return ("CWE-248", "medium", phrase or "a managed runtime")
    return None
