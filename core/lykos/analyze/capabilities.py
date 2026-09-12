"""Which stages apply to THIS target, and why the rest do not.

The GUI was substrate-blind while the engine was substrate-aware: `file_type` appeared
nowhere in index.html, so an ELF, a PE, a jar and a firmware image all rendered the same
twenty-two controls. Clicking the wrong one cost a Ghidra run that ended in
`FileNotFoundError`, or an AFL++ campaign that completed having executed nothing.

The fix is not for the GUI to learn the rules -- that just puts a second copy of them
somewhere they will drift. Every rule below is either the stage's OWN gate, imported, or a
fact the stage itself reports. Where a stage decides at runtime on something we cannot know
in advance (is this a Cortex-M image? is there a second component to taint across?), it is
reported AVAILABLE and allowed to decline for itself. Guessing "unavailable" and being wrong
is the worse error: it hides a capability that works, and the operator has no way to discover
the mistake.
"""
from __future__ import annotations

from typing import Optional

# The three questions the workbench asks, in the order the evidence-first pipeline answers
# them. `feed` is not a group of stages but of INPUTS -- how the target is invoked and what it
# is given -- which is the step that decides whether any of the rest can work at all, and
# which used to be the second of twenty-two controls in one panel.
FEED, FIND, PROVE = "feed", "find", "prove"

GROUPS = (
    (FEED, "Feed", "how the target is invoked and what it is given"),
    (FIND, "Find", "discover a defect -- by execution, or statically"),
    (PROVE, "Prove", "demonstrate it: explain, package, escalate"),
)

# stage -> (group, label, one-line purpose)
STAGES: dict = {
    "dynamic_run":          (FEED,  "Run once", "one execution, to see the target work"),
    "fuzz":                 (FIND,  "Fuzz", "black-box mutation; works on every substrate"),
    "coverage_fuzz":        (FIND,  "Coverage fuzz", "AFL++ edge feedback -- the biggest "
                                                     "lever when it can run"),
    "directed_fuzz":        (FIND,  "Directed fuzz", "bias execs toward known sink sites"),
    "boundary_fuzz":        (FIND,  "Boundary fuzz", "drive an IPC or protocol boundary"),
    "concolic":             (FIND,  "Concolic", "solve for inputs that reach new paths"),
    "disassemble":          (FIND,  "Decompile", "recover functions and the call graph"),
    "detect_cwe":           (FIND,  "Detect CWE", "static findings, ranked below anything run"),
    "cve_scan":             (FIND,  "CVE scan", "known-vulnerable components"),
    "extract_secrets":      (FIND,  "Extract secrets", "recover compared-against values"),
    "dynamic_taint":        (FIND,  "Dynamic taint", "watch input reach a sink at runtime"),
    "heap_check":           (FIND,  "Heap check", "guard-page allocator under LD_PRELOAD"),
    "behavior_trace":       (FIND,  "Behaviour trace", "syscalls, exec, network, anti-debug"),
    "debug_monitor":        (FIND,  "Runtime monitor", "break on dangerous calls, live"),
    "synthesize_poc":       (FIND,  "Synthesize PoC", "derive the overflow from the frame; "
                                                      "no execution"),
    "synthesize_injection": (FIND,  "Injection PoC", "confirm a command/format injection"),
    "synthesize_secret":    (FIND,  "Secret PoC", "package a recovered credential"),
    "root_cause":           (PROVE, "Root cause", "name the faulting function and the CWE"),
    "build_poc":            (PROVE, "Build PoC", "a verified, shareable reproducer (L1)"),
    "poc_primitive":        (PROVE, "IP control", "does the crash control the instruction "
                                                  "pointer? (L2)"),
    "build_exploit":        (PROVE, "Exploit", "redirect execution to a chosen function (L3)"),
    "multi_debug":          (PROVE, "Multi-process", "follow fork/exec and blame the child"),
}

_JVM = ("jar", "class")


def _why_unavailable(stage: str, target) -> Optional[str]:
    """The stage's own reason, or None when it can run (or decides at runtime)."""
    ftype = (target.file_type or "").lower()
    arch = getattr(target, "arch", None)
    linking = (getattr(target, "linking", None) or "").lower()

    if stage == "coverage_fuzz":
        from .fuzz.coverage import _unsupported  # the stage's gate, imported
        return _unsupported(target)

    if stage == "disassemble" and ftype in _JVM:
        return ("a Java target has no machine code to decompile -- its classes, strings and "
                "every method it calls are already in the constant pool, which detect_cwe "
                "reads directly.")

    if stage in ("poc_primitive", "build_exploit") and ftype in _JVM:
        return ("the JVM checks every array access and owns the instruction pointer, so "
                "control-flow hijack is not a claim this runtime can support. L1 (a verified, "
                "reproducible fault) is the ceiling for Java, and that is the runtime, not a "
                "gap to be closed.")

    if stage == "heap_check":
        from .dynamic import sandbox
        host = sandbox.host_arch()
        if ftype in _JVM:
            return "the JVM manages its own heap; the LD_PRELOAD guard-page allocator does " \
                   "not apply."
        if arch and host and arch != host:
            return (f"heap check is native-arch only (target {arch}, host {host}); a per-arch "
                    f"shim under qemu is future work.")
        if linking == "static":
            return ("this target is statically linked, so the LD_PRELOAD guard-page allocator "
                    "never loads -- nothing would be checked, which is not the same as "
                    "nothing found.")

    if stage == "multi_debug":
        from .debug import gdb
        from .dynamic import sandbox
        host = sandbox.host_arch()
        if arch and host and arch != host:
            return f"follow-fork debugging needs native execution (target {arch}, host {host})."
        if gdb.locate_gdb(None) is None:
            return "follow-fork multi-process debugging requires gdb, which is not installed."

    if stage in ("dynamic_taint", "debug_monitor", "concolic") and ftype in _JVM:
        return ("this channel works on machine code (P-Code / ptrace / angr); a Java target "
                "has none. The constant pool gives detect_cwe the same call inventory "
                "directly.")

    return None


def for_target(target, *, plan=None, done=()) -> dict:
    """{group: [ {stage, label, purpose, available, why, planned, done} ]} for one target.

    `plan` is `advise()`'s ordered plan, which decides what is RECOMMENDED; this decides what
    is POSSIBLE. They are different questions and the panel shows both: a recommended stage is
    highlighted, an impossible one is disabled with its reason, and everything else is simply
    available.
    """
    planned = {p["stage"]: i for i, p in enumerate(plan or [])}
    out: dict = {g: [] for g, _, _ in GROUPS}
    for stage, (group, label, purpose) in STAGES.items():
        why = _why_unavailable(stage, target)
        out[group].append({
            "stage": stage, "label": label, "purpose": purpose,
            "available": why is None, "why": why,
            "planned": planned.get(stage), "done": stage in set(done),
        })
    for g in out:
        # recommended first, then available, then the rest -- so the next thing to do is the
        # first thing on screen
        out[g].sort(key=lambda s: (s["planned"] is None, s["planned"] or 0,
                                   not s["available"], s["label"]))
    return out


def unavailable_summary(target) -> list:
    """Just the stage names that cannot run here -- for the target header badge."""
    return sorted(s for s in STAGES if _why_unavailable(s, target))
