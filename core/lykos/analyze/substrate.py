"""One table of what each `file_type` can be executed on, and everything that follows.

This exists because the question "what can I do with this file_type?" used to be answered in
SEVEN unsynchronised places: `triage` (the advisory), `dynamic.sandbox.run` (the exec dispatch),
`dynamic.sandbox.run_batch` (the batch refusal), `orchestrate._FOREIGN_SUBSTRATE_TYPES` (AFL
applicability and stage order), `debug.stage._MANAGED_FILE_TYPES` (the managed root-cause path),
`fuzz.coverage._unsupported` (the AFL gate, also imported by the capability map) and
`capabilities._JVM` (the proxy for "a managed runtime").

Adding a format meant editing all seven, and nothing failed loudly when one was missed. The
symptom was always the same and always the worst one this tool can produce: **a substrate that
cannot run the target reporting a CLEAN verdict.** That happened four separate times -- a .class
was never executed and the campaign called it clean; .pyc and .wasm the same; a .NET assembly was
dispatched to wine, which cannot run managed code, and reported `crashed=False` with no note.

So the rules live here once, keyed by file_type, and the seven call sites ask this module. A new
format is a row in `SUBSTRATES` plus a magic sniffer in `sandbox`; forget the row and the target
is reported UNRUNNABLE (the safe direction), never clean.

`execs_per_sec` is MEASURED on this platform, not guessed, and is what decides stage ORDER: a
cheap certain single-detonation stage must not queue behind a campaign that will spend the whole
budget to manage eleven executions a second.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# backend identifiers -- what actually executes the image
NATIVE = "native"            # the host CPU, under bwrap+rlimits
QEMU = "qemu"                # a foreign ARCH on the host, qemu-user
WINE = "wine"                # a Windows PE
JVM = "jvm"                  # a JVM target (.class/.jar)
CPYTHON = "cpython"          # CPython bytecode (.pyc)
WASM = "wasm"                # a WebAssembly module, under node
CLR = "clr"                  # a .NET assembly, under `dotnet`
REHOST = "rehost"            # a bare-metal image, emulated by the firmware rehoster
NONE = None                  # nothing on this host can run it


@dataclass(frozen=True)
class Substrate:
    """What executes this file_type, and what that substrate can and cannot support."""

    backend: Optional[str]
    #: Human name of the managed runtime that owns the instruction pointer, else None.
    #: Non-None is the single authority for "a defect here is an uncaught exception or a trap,
    #: not a signal, and there is no IP to hijack".
    runtime: Optional[str] = None
    #: Short key for that runtime ("jvm" / "cpython" / "wasm" / "clr"), for the code that
    #: dispatches on it. It lives here so the phrase and the key cannot drift apart: both
    #: debug.stage and runtime_fault used to reverse-map the PHRASE back to a key themselves.
    runtime_key: Optional[str] = None
    #: Does the IMAGE contain machine code the host can instrument? AFL rewrites/traces machine
    #: code, so bytecode and wasm can never work: the only machine code in the process belongs
    #: to the interpreter, and instrumenting it measures coverage of CPython, not of the target.
    machine_code: bool = False
    #: Can `sandbox.run_batch` drive many inputs through one ptrace-supervised process group?
    #: Documentation only, and deliberately so: `run_batch` is handed a PATH, not a target, so it
    #: answers the same question by magic-sniffing the image. An accessor here had no callers and
    #: was removed rather than left to imply this field is what enforces the rule.
    batchable: bool = False
    #: Is a control-flow hijack (L2/L3) a claim this substrate can support at all?
    ip_control: bool = False
    #: Measured executions per second through the sandbox, for stage ordering.
    execs_per_sec: float = 0.0
    #: Why nothing here can execute it, when `backend is None`.
    no_exec: str = ""
    #: Which of `capture.MODES` (+ "env") can PHYSICALLY carry input to this substrate. The
    #: channel ranking is otherwise universal -- stdin/file/arg are offered for every target --
    #: and that is wrong for a substrate where a channel does not exist: see `channels()`.
    channels: tuple = ("stdin", "file", "arg", "env")


#: file_type -> Substrate. Keyed by `triage`'s file_type, which is the only name the rest of
#: the pipeline carries on a target.
SUBSTRATES: dict[str, Substrate] = {
    "elf": Substrate(NATIVE, machine_code=True, batchable=True, ip_control=True,
                     execs_per_sec=580.0),
    # A PE is native machine code, just for another OS: the SEH frame really is corrupted by an
    # overflow and the hijack claim holds. But it runs under wine, which AFL cannot instrument
    # and which `run_batch`'s ptrace supervision cannot follow through wineserver.
    "pe": Substrate(WINE, machine_code=True, batchable=False, ip_control=True,
                    execs_per_sec=1.0),
    # Machine code for a different OS entirely. Header analysis is real (Ghidra disassembles
    # Mach-O, every string/symbol/invocation detector applies); execution is not.
    "macho": Substrate(NONE, machine_code=True, batchable=False, ip_control=False,
                       no_exec="running a macOS/iOS binary needs a macOS host or an emulator "
                               "this Linux build does not provide"),
    "jar": Substrate(JVM, runtime="the JVM", runtime_key="jvm", execs_per_sec=36.0),
    "class": Substrate(JVM, runtime="the JVM", runtime_key="jvm", execs_per_sec=36.0),
    "pyc": Substrate(CPYTHON, runtime="CPython", runtime_key="cpython", execs_per_sec=19.0),
    # A wasm REACTOR module has exactly one channel: the bytes staged into its linear memory and
    # handed to an export as (ptr, len), which the driver feeds from stdin. It has no process, so
    # there is no argv and no environment, and WASI capabilities are granted by the host -- with
    # no preopened directory a module cannot open a file even by name. A WASI COMMAND module is
    # the opposite: it has `_start`, argv, an environment and whatever directories the host
    # preopens, so `channels()` widens for it on the evidence of that export.
    "wasm": Substrate(WASM, runtime="the WebAssembly engine", runtime_key="wasm",
                      execs_per_sec=11.0, channels=("stdin",)),
    "dotnet": Substrate(CLR, runtime="the CLR", runtime_key="clr", execs_per_sec=8.0),
    # A bare-metal image has no host process: there is no loader, no syscalls and no libc. The
    # firmware rehoster emulates the core and models the peripherals instead, which is a stage
    # of its own -- handing the image to execve() would only ever report a non-run.
    "firmware": Substrate(REHOST, machine_code=True, batchable=False, ip_control=False,
                          execs_per_sec=5.0),
    "raw": Substrate(NONE, no_exec="a raw blob has no entry point to execute; carve it or "
                                   "rehost it"),
    "other": Substrate(NONE, no_exec="this file is not an executable image"),
}

#: Used when `file_type` is empty or unknown. The DESCRIPTIVE questions ("can this substrate
#: support a hijack?", "is there machine code here?") answer conservatively for it, because
#: claiming a capability for a format we have not identified is the error that costs something.
#: The questions that BLOCK work ask `known()` first instead -- see its docstring.
_UNKNOWN = Substrate(NONE, no_exec="unrecognised image format; no execution substrate")


def of(file_type: Optional[str]) -> Substrate:
    """The substrate for a file_type, or `_UNKNOWN` if there is no row for it."""
    return SUBSTRATES.get((file_type or "").lower().strip(), _UNKNOWN)


def known(file_type: Optional[str]) -> bool:
    """Do we have a row for this file_type at all?

    An EMPTY file_type does not mean "an unrunnable image" -- it usually means triage has not
    run yet, because `ingest` creates the target row and `ingest_triage` fills it in later. The
    difference matters for the gates that BLOCK work: refusing to fuzz because we have not yet
    looked at the file would hide a capability that works. Where a non-run has a real cost
    (executing the image) the check is made on the file's own header instead, which needs no
    file_type at all -- see `sandbox._host_loadable`.
    """
    return (file_type or "").lower().strip() in SUBSTRATES


def for_target(target) -> Substrate:
    """The substrate for a target object (anything with a `.file_type`)."""
    return of(getattr(target, "file_type", None))


# ---- the questions the call sites ask ----------------------------------------------------

def managed_runtime(file_type: Optional[str]) -> Optional[str]:
    """Human name of the managed runtime owning the IP, or None for native/unrunnable."""
    return of(file_type).runtime


def managed_kind(file_type: Optional[str]) -> Optional[str]:
    """Short runtime key for the code that dispatches per managed runtime, else None."""
    return of(file_type).runtime_key


def is_managed(file_type: Optional[str]) -> bool:
    """Is a defect here an uncaught exception or a trap rather than a signal?"""
    return of(file_type).runtime is not None


def instrumentable(file_type: Optional[str]) -> bool:
    """Does this image contain machine code AFL could instrument or trace?"""
    return of(file_type).machine_code


def supports_ip_control(file_type: Optional[str]) -> bool:
    """Can L2/L3 (a control-flow hijack) be claimed on this substrate at all?"""
    return of(file_type).ip_control


def expensive(file_type: Optional[str]) -> bool:
    """Is one execution orders of magnitude dearer than a native one?

    True for every non-native backend AND for an unrunnable image -- `run_batch` refuses all of
    them, so the fuzzers fall back to one process per input and pay start-up every time.
    """
    s = of(file_type)
    return s.backend != NATIVE


def no_ip_control_reason(file_type: Optional[str]) -> Optional[str]:
    """Why L2/L3 is not a claim this substrate can support, or None if it can."""
    s = of(file_type)
    if s.ip_control:
        return None
    if s.runtime:
        return (f"{s.runtime} checks every array access and owns the instruction pointer, so "
                f"control-flow hijack is not a claim this runtime can support. L1 (a verified, "
                f"reproducible fault) is the ceiling here, and that is the runtime, not a gap "
                f"to be closed.")
    if s.backend is None:
        return f"nothing here executes this image -- {s.no_exec}."
    return ("this substrate is emulated rather than executed, so there is no host instruction "
            "pointer to take.")


#: The export that makes a wasm module a WASI COMMAND rather than a reactor/library: it has an
#: entry point, so the host gives it argv, an environment and its preopened directories.
WASI_COMMAND_EXPORT = "_start"

_ALL_CHANNELS = ("stdin", "file", "arg", "env")


def symbol_names(symbols) -> set:
    """A matchable set from a recorded symbol inventory, both qualified and short.

    Each format decorates its names differently and a matcher that ignores that sees nothing:
    the wasm parser records an import as `wasi_snapshot_preview1.fd_read [func]` and an export as
    `_start [func]`, so a plain `"_start" in symbols` is False on every module that has one.
    Strips the kind annotation and offers the last dotted component as well, since
    `System.Console` and `Console` are the same evidence.
    """
    out: set = set()
    for s in symbols or ():
        t = str(s).split(" [", 1)[0].strip()
        if t:
            out.add(t)
            out.add(t.rsplit(".", 1)[-1])
    return out


def channels(file_type: Optional[str], symbols=()) -> tuple:
    """Which delivery channels can physically reach this substrate, as a filter on the ranking.

    The ranking in `capture.modes_for` is universal by design -- it ends with every channel
    attempted, so a wrong guess costs a retry rather than a miss. That is right wherever all
    three channels EXIST, and wrong where one does not: for a wasm reactor module `arg` and
    `file` cannot carry anything at all (no process, no argv, no preopened directory), yet it
    ranked FIRST on the slowest substrate here (11 exec/s measured), so a campaign spent its
    budget delivering input nowhere before the retry reached the one channel that works.

    `symbols` is the target's recorded inventory (`ingest.triage_symbols`), used only where the
    channel set depends on the image rather than the format -- today just the WASI-command
    export. Without evidence the answer is the narrow one, because offering a channel that
    cannot carry input is what produced the empty campaign.
    """
    if not known(file_type):
        return _ALL_CHANNELS                             # not triaged yet: do not narrow anything
    s = of(file_type)
    if s.backend == WASM and WASI_COMMAND_EXPORT in symbol_names(symbols):
        return _ALL_CHANNELS
    return s.channels


# ---- `target.arch` is a CPU for a native image and a RUNTIME NAME for a managed one ------
#
# triage writes "cil" / "jvm" / "cpython" / "wasm" into `target.arch`, because those targets have
# no CPU to name. That makes `target.arch != host_arch()` TRUE for every managed target, and that
# comparison is the pipeline's test for "a foreign architecture, reachable only under an
# emulator" -- asked at 28 call sites. The conclusion usually coincides with the right answer,
# so the bug shows up as the REASON given to the operator:
#
#   * `poc_primitive` declines a .NET assembly with "L2 for cross-arch cil: no qemu gdbstub
#     register layout (host x86-64)" -- naming a missing TOOL, when the truth is that the CLR
#     owns the instruction pointer and no tool would change that (`no_ip_control_reason`);
#   * `env_fuzz` declines with "cross-arch target (cil); env fuzzing needs a native host", which
#     is the wrong reason AND the wrong conclusion -- the CLR runs as an ordinary host process
#     and reads the environment like any other;
#   * five stages set `emulated=True` and take a qemu path for something that is not emulated.
#
#: The tokens triage writes into `arch` for a managed format. Checked by NAME as well as by
#: file_type, so an arch string that outlived its target row is still not read as a CPU.
RUNTIME_ARCHS = frozenset({"cil", "clr", "jvm", "cpython", "wasm", "dotnet"})


def names_a_cpu(arch: Optional[str], file_type: Optional[str] = None) -> bool:
    """Does `target.arch` name a CPU here, or the runtime that owns the instruction pointer?"""
    a = (arch or "").lower().strip()
    if not a or a in RUNTIME_ARCHS:
        return False
    return not is_managed(file_type)


def foreign_cpu(arch: Optional[str], file_type: Optional[str] = None,
                host: Optional[str] = None) -> bool:
    """Is this target machine code for ANOTHER CPU -- i.e. does it need an emulator?

    False for every managed target, however `arch` compares to the host: there is no CPU named
    there to be foreign. Use this instead of `target.arch != host_arch()`; where the answer is
    False and the target still cannot be driven, `no_ip_control_reason` / `no_machine_code_reason`
    give the reason that is actually true.
    """
    if not names_a_cpu(arch, file_type):
        return False
    h = (host or "").lower().strip()
    return bool(h) and (arch or "").lower().strip() != h


def native_only_reason(file_type: Optional[str], what: str) -> Optional[str]:
    """Why a HOST-NATIVE-ONLY technique cannot apply to this target, or None if it can.

    An LD_PRELOAD shim, a GDB follow-fork session, a localhost socket campaign: each needs a
    host process with the host ABI. Several of these stages tested only `target.arch != host`,
    which is TRUE for a managed target by accident of `arch` holding a runtime name -- so they
    declined with the right conclusion and the wrong reason, and would have proceeded to
    execve() a .NET assembly the moment that comparison was corrected.

    `what` names the technique, so the sentence reads as the stage's own.
    """
    if not known(file_type):
        return None                                 # not triaged: the stage's own gates decide
    s = of(file_type)
    if s.backend == NATIVE:
        return None
    if s.runtime:
        return (f"{what} drives a host process through the native ABI; this target runs on "
                f"{s.runtime}, which owns the process -- nothing would be instrumented, which "
                f"is not the same as nothing found.")
    if s.backend is None:
        return f"{what} needs a running process, and {s.no_exec}."
    return (f"{what} drives a host-native process; this target runs under {s.backend}, which "
            f"it cannot reach into.")


def no_machine_code_reason(file_type: Optional[str]) -> Optional[str]:
    """Why there is no machine code to disassemble or instrument, or None if there is."""
    s = of(file_type)
    if s.machine_code:
        return None
    if s.runtime:
        store = {"the JVM": "the constant pool", "CPython": "the code object's names and "
                 "constants", "the CLR": "the metadata (#Strings / #US heaps)",
                 "the WebAssembly engine": "the name and export sections"}.get(s.runtime,
                                                                              "the metadata")
        return (f"this target runs on {s.runtime}: its body is bytecode, not machine code, so "
                f"there is nothing for a native disassembler to recover. {store.capitalize()} "
                f"gives the same inventory directly, which detect_cwe reads.")
    return f"there is no machine code here -- {s.no_exec}."


def afl_reason(file_type: Optional[str]) -> Optional[str]:
    """Why AFL++ cannot drive this file_type, or None if the format is no obstacle.

    Returning a REASON rather than silently producing an empty campaign is the whole point: the
    operator needs to know the difference between "nothing was found" and "nothing was run",
    and those two are otherwise identical on screen.
    """
    if not known(file_type):
        # Not yet triaged. Say nothing: the arch and toolchain gates below still apply, and
        # claiming "nothing to run here" on no evidence would block a working campaign.
        return None
    s = of(file_type)
    if s.machine_code and s.backend in (NATIVE, QEMU):
        return None                                      # arch/toolchain gates decide, not us
    if s.runtime:
        return (f"AFL++ instruments machine code and cannot drive a target that runs on "
                f"{s.runtime} -- the only machine code in the process belongs to the runtime, "
                f"so instrumenting it measures coverage of {s.runtime}, not of the target. Use "
                f"the black-box `fuzz` stage, which executes it directly "
                f"(~{s.execs_per_sec:.0f} exec/s measured) and reads a fault as a fault.")
    if s.backend == WINE:
        return ("AFL++ cannot instrument a Windows PE here, and the Wine path runs at about "
                "one execution a second. Use `synthesize_poc`, which derives the overflow "
                "from the recovered stack frame without executing at all.")
    if s.backend == REHOST:
        return ("a bare-metal image has no host process for AFL to instrument -- it has no "
                "loader, no syscalls and no libc. `firmware_rehost` emulates the core and "
                "models the peripherals instead.")
    return f"AFL++ has nothing to run here -- {s.no_exec}."
