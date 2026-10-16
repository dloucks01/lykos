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

from . import substrate  # the ONE table of what each file_type can be run on

# The three questions the workbench asks, in the order the evidence-first pipeline answers
# them. `feed` is not a group of stages but of INPUTS -- how the target is invoked and what it
# is given -- which is the step that decides whether any of the rest can work at all, and
# which used to be the second of twenty-two controls in one panel.
FEED, FIND, PROVE = "feed", "find", "prove"

# --------------------------------------------------------------------------- whose fault is it
# A capability that RAN and refused is reporting one of two completely different things, and
# until now they printed identically:
#
#   libfuzzer  no source for this target (libFuzzer needs C/C++ source to build a harness)
#   libfuzzer  libFuzzer build failed: 'tiffio.h' file not found
#
# The first is the tool knowing its own limits on this target. The second is OUR defect, and it
# means the run is INCOMPLETE for a reason the operator can have fixed -- which is exactly what
# they need to know before they read "0 crashes" as a result. `real_corpus_gate.py` has
# classified these since it was written; keeping its lists there alone meant the operator never
# saw the distinction the gate was built around.
#
# Each entry below is a substring of a note a stage really emitted, so these lists are evidence,
# not imagination. Order matters: BOUNDARY, then NOT_APPLICABLE, then OURS.

#: A capability boundary stated honestly, however much the wording resembles a defect.
#: `mem_oracle` saying "memcheck is a host-architecture dynamic translator and cannot run a
#: non-host-architecture target" is the tool knowing what it is, and calling that our fault
#: would train everyone to ignore the signal.
DECLINE_BOUNDARY = (
    "host-architecture", "host architecture", "cannot run a non-host",
    "incompatible with afl", "shadow memory", "only supports", "x86-64 only",
    "x86-64 native only", "needs native", "no gdbstub", "not supported for this",
    "cross-arch", "the clr owns", "owns the instruction pointer",
    # Emitted wherever a per-arch map (GDB argument registers, a shim ABI) is the obstacle
    # rather than the format. `foreign_cpu_reason` is the canonical sentence for the pure
    # arch case and already matches on "host architecture"; these are the sites where the
    # arch question is entangled with a second one and the phrase is written by hand.
    "native-arch only",
)
#: A decline that describes the TARGET, not us.
DECLINE_TARGET = (
    "no source for this target", "no archived source tree", "no ipc channel",
    "nothing here reads the environment", "no distinct custom allocator",
    "no matched cve", "no heap", "not applicable", "the clr", "managed",
    "no primitive", "needs params", "no crash", "not fuzzed under afl",
    "supply the", "params.", "no fixed-size global", "no named custom allocator",
    "does not terminate",
    # `build_exploit` on a target nothing crashed: "cyclic pattern did not fault on any channel;
    # run fuzz/L2 first". It is the same statement as "no crash" -- there is nothing to escalate
    # -- and it went unclassified on six of the ten foreign-architecture binaries in the first
    # cross-arch sweep, where no campaign found a crash in busybox to escalate.
    "did not fault",
)
#: A decline whose reason is OURS. Every one of these has been a real defect.
DECLINE_OURS = (
    "build failed", "did not compile", "file not found", "no such file",
    "undefined reference", "could not build", "failed to build", "not installed",
    "no clang", "loader refused", "did not link", "no harness",
)


def classify_decline(note: str) -> str:
    """"target" (its nature), "ours" (our defect) or "unknown" (nobody has classified it yet).

    "unknown" is deliberately visible rather than silently lumped with "target": an unclassified
    decline is one nobody has looked at, and the operator deciding whether to trust a null result
    should be told that much.
    """
    low = (note or "").lower()
    for s in DECLINE_BOUNDARY:
        if s in low:
            return "target"
    for s in DECLINE_TARGET:
        if s in low:
            return "target"
    for s in DECLINE_OURS:
        if s in low:
            return "ours"
    return "unknown"

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
    "mem_oracle":           (FIND,  "Uninitialised memory", "shadow memory: reads of undefined "
                                                           "bytes, and the disclosure when they "
                                                           "reach the output"),
    "behavior_trace":       (FIND,  "Behaviour trace", "syscalls, exec, network, anti-debug"),
    "debug_monitor":        (FIND,  "Runtime monitor", "break on dangerous calls, live"),
    "synthesize_poc":       (FIND,  "Synthesize PoC", "derive the overflow from the frame, "
                                                      "then detonate once -- no fuzzing"),
    "synthesize_injection": (FIND,  "Injection PoC", "confirm a command/format injection"),
    "synthesize_secret":    (FIND,  "Secret PoC", "package a recovered credential"),
    "root_cause":           (PROVE, "Root cause", "name the faulting function and the CWE"),
    "build_poc":            (PROVE, "Build PoC", "a verified, shareable reproducer (L1)"),
    "poc_primitive":        (PROVE, "IP control", "does the crash control the instruction "
                                                  "pointer? (L2)"),
    "build_exploit":        (PROVE, "Exploit", "redirect execution to a chosen function (L3)"),
    "multi_debug":          (PROVE, "Multi-process", "follow fork/exec and blame the child"),
    # Firmware. Both are launchable controls in the workbench and both were missing from this
    # table, so `for_target` never returned them: the panel could not rank them, and could not
    # disable them with a reason either. They decide at runtime (is there a filesystem to carve?
    # is there a Cortex-M vector table?), so per this module's rule they report AVAILABLE on any
    # substrate that could hold machine code and decline for themselves.
    "firmware_carve":       (FEED,  "Carve firmware", "pull the real binaries out of an image "
                                                      "and register each as its own target"),
    "firmware_rehost":      (FEED,  "Rehost firmware", "emulate the core and model the "
                                                       "peripherals so a bare-metal image runs"),
}



def _why_unavailable(stage: str, target) -> Optional[str]:
    """The stage's own reason, or None when it can run (or decides at runtime)."""
    ftype = (target.file_type or "").lower()
    arch = getattr(target, "arch", None)
    linking = (getattr(target, "linking", None) or "").lower()

    if stage == "coverage_fuzz":
        from .fuzz.coverage import _unsupported  # the stage's gate, imported
        return _unsupported(target)

    if stage == "disassemble":
        # Asked of the one substrate table, not of a jar/class list: .pyc, .wasm and a .NET
        # assembly have no machine code either, and the operator was being offered Decompile
        # on all three with no reason given.
        why = substrate.no_machine_code_reason(ftype)
        if why:
            return why

    if stage in ("poc_primitive", "build_exploit"):
        # The honest-ceiling message used to be told for jar/class ONLY, so .pyc, .wasm and
        # .NET targets were offered IP control and Exploit with no explanation at all -- the
        # exact "learn by waiting for a decline" failure this module exists to prevent.
        why = substrate.no_ip_control_reason(ftype)
        if why:
            return why

    if stage in ("firmware_carve", "firmware_rehost"):
        # Known in advance, and only this: a jar/class/.pyc/.wasm/.NET assembly is an artefact of
        # a managed runtime, never a flashed image. Everything else -- ELF, PE, Mach-O, raw blob,
        # firmware -- is left available, because whether an image actually carries a filesystem
        # or a reset vector is something only the stage can answer by looking.
        managed = substrate.managed_runtime(ftype)
        if managed:
            return (f"a firmware image is flashed machine code; this target is an artefact of "
                    f"{managed}, so there is nothing to carve or rehost.")

    if stage == "heap_check":
        from .dynamic import sandbox
        host = sandbox.host_arch()
        managed = substrate.managed_runtime(ftype)
        if managed:
            return (f"{managed} manages its own heap; the LD_PRELOAD guard-page allocator "
                    f"does not apply.")
        if ftype and ftype != "elf":
            # The stage says this itself at runtime; the map did not know, so the workbench
            # offered Heap check on a Windows PE and the operator learned by waiting for a
            # decline. Same shape as the jar case, one substrate over.
            return (f"the guard-page heap checker is a Linux/ELF LD_PRELOAD shim and cannot "
                    f"load into a {ftype.upper()} image -- nothing would be checked, which is "
                    f"not the same as nothing found.")
        why = substrate.foreign_cpu_reason(arch, ftype, host, "the guard-page heap checker")
        if why:
            return why + " A per-arch shim under qemu is future work."
        if linking == "static":
            return ("this target is statically linked, so the LD_PRELOAD guard-page allocator "
                    "never loads -- nothing would be checked, which is not the same as "
                    "nothing found.")

    if stage == "mem_oracle":
        from .dynamic import memoracle
        from .dynamic import sandbox as _sb
        sub = substrate.of(ftype)
        if sub.backend != substrate.NATIVE:
            return (f"memcheck is a host-architecture dynamic translator and cannot run a "
                    f"{(ftype or 'non-native').upper()} target.")
        host = _sb.host_arch()
        if substrate.foreign_cpu(arch, ftype, host):
            return (f"memcheck runs the target natively (target {arch}, host {host}); a "
                    f"cross-arch shadow-memory oracle is not available here.")
        if memoracle.valgrind_bin() is None:
            return "uninitialised-memory detection needs valgrind, which is not installed."

    if stage == "multi_debug":
        from .debug import gdb
        from .dynamic import sandbox
        host = sandbox.host_arch()
        # The substrate reason comes FIRST: a managed target's `arch` is its runtime's name, so
        # the comparison below told the operator "needs native execution (target cil)" -- true
        # by accident, and it named the wrong obstacle.
        why = substrate.native_only_reason(ftype, "follow-fork multi-process debugging")
        if why:
            return why
        if substrate.foreign_cpu(arch, ftype, host):
            return f"follow-fork debugging needs native execution (target {arch}, host {host})."
        if gdb.locate_gdb(None) is None:
            return "follow-fork multi-process debugging requires gdb, which is not installed."

    if stage in ("dynamic_taint", "debug_monitor", "concolic"):
        managed = substrate.managed_runtime(ftype)
        if managed:
            return (f"this channel works on machine code (P-Code / ptrace / angr) and a target "
                    f"that runs on {managed} has none. Its metadata gives detect_cwe the same "
                    f"call inventory directly.")

    if stage == "dynamic_taint" and ftype and ftype != "elf":
        return f"dynamic taint runs Linux ELF only (this target is {ftype.upper()})."

    # These two DO cover Windows: behaviour tracing and the runtime monitor both have Wine
    # relay paths. Everything else -- Mach-O, a raw image -- has no substrate to run on, which
    # is the stages' own wording.
    if stage in ("behavior_trace", "debug_monitor") and ftype not in ("elf", "pe", ""):
        return f"no execution substrate for a {ftype.upper()} image here (ELF and PE only)."

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
