"""Shared ptrace fault-capture runner: materialize the stdlib helper and drive it as a
subprocess (it must run as its own process, never forking the threaded worker). Used by the
L2 primitive stage and the root-cause stage."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..dynamic import sandbox
from ..fuzz.runner import place
from ..invocation import OUTPUT_PLACEHOLDER


def _sub_out(argv, work):
    """Replace a converter's OUTPUT placeholder with a writable scratch path, so `tool [opts] IN
    OUT` targets run under the confirmation harness too (not just the fuzzer)."""
    if OUTPUT_PLACEHOLDER not in argv:
        return argv
    return ["lykos.out" if a == OUTPUT_PLACEHOLDER else a for a in argv]

_HELPER = "ptrace_capture.py"


def materialize_helper() -> Path:
    d = Path(tempfile.mkdtemp(prefix="lykos-ptrace-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.poc") / _HELPER).read_bytes()
    except Exception:
        data = (Path(__file__).parent / _HELPER).read_bytes()
    p = d / _HELPER
    p.write_bytes(data)
    return p


def make_capture(ctx, helper: Path, exe, mode, base_argv, timeout, python):
    """Return capture(data)->dict: run `exe` on `data` (via `mode`) under the ptrace helper."""
    work = helper.parent

    def capture(data: bytes, breakpoints=None) -> dict:
        stdin_file = None
        env = None
        argv = _sub_out(list(base_argv), work)
        if mode == "stdin":
            stdin_file = str(work / "stdin.bin")
            (work / "stdin.bin").write_bytes(data)
        elif mode == "arg":
            try:
                argv = place(argv, sandbox.argv_arg(data, truncate=True))
            except sandbox.ArgvNulError as e:
                return {"ok": False, "reason": str(e)}
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = place(argv, str(work / "input.bin"))
        elif mode == "env":
            var, argv = env_var_from_argv(argv)
            if not var:
                return {"ok": False, "reason": "env mode but no NAME=@@ prefix recorded"}
            env = {var: data.decode("latin-1")}          # latin-1: lossless byte round-trip via JSON
        spec = {"exe": str(exe), "argv": argv, "stdin_file": stdin_file, "timeout": timeout}
        # A sanitizer build does NOT die on a signal by default: ASan prints its report and calls
        # _exit(1), so to the ptrace helper the detonation looks like a program that ran and
        # exited cleanly. Measured on a clang ASan build of a one-line out-of-bounds read: the
        # cyclic pattern reproduced the defect every time and the stage declined with "cyclic
        # pattern did not fault via any of stdin, file, arg" -- so no L2 primitive was ever
        # reachable on a sanitizer build, which is every target the source-code path compiles.
        # `abort_on_error=1` makes the fault a SIGABRT, which is what it is. `detect_leaks=0`
        # keeps LeakSanitizer's at-exit report from standing in for the defect we are detonating.
        env = dict(env or {})
        env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0")
        spec["env"] = env
        if breakpoints:
            spec["breakpoints"] = [int(a) for a in breakpoints]
        spec_path = work / "spec.json"
        spec_path.write_text(json.dumps(spec))
        proc = ctx.run_subprocess([python, str(helper), str(spec_path)], timeout=timeout + 30)
        out = (proc.stdout or b"").decode("latin-1", "ignore").strip()
        try:
            return json.loads(out) if out else {"ok": False, "reason": "no output"}
        except json.JSONDecodeError:
            return {"ok": False, "reason": "bad helper output: " + out[:200]}

    return capture


def make_qemu_capture(exe, arch, mode, base_argv, timeout, *, endianness=None, bits=None):
    """Return capture(data)->dict for an EMULATED target: drive qemu-user's gdbstub to capture
    the fault-time registers (pc/sp/GP) on the guest ISA. Same interface as make_capture, so
    the L2 primitive's pc-based offset recovery and marker confirmation work cross-arch. No
    ptrace helper and no bwrap (qemu is launched directly)."""
    from ..debug import qemu_gdb
    work = Path(tempfile.mkdtemp(prefix="lykos-qemucap-"))

    def capture(data: bytes, breakpoints=None) -> dict:
        argv, stdin = _sub_out(list(base_argv), work), b""
        if mode == "stdin":
            stdin = data
        elif mode == "arg":
            try:
                argv = place(argv, sandbox.argv_arg(data, truncate=True))
            except sandbox.ArgvNulError as e:
                return {"ok": False, "reason": str(e)}
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = place(argv, str(work / "input.bin"))
        return qemu_gdb.capture(exe, arch, argv=argv, stdin=stdin, timeout=timeout,
                                endianness=endianness, bits=bits, breakpoints=breakpoints)

    return capture


# Every way a target can be handed its input in the generic fallback sweep. "env" is deliberately
# NOT here: env_fuzz already discovers that channel from the getenv() names in the binary, so adding
# it would make every unrelated target pay for an extra sweep. It is still a first-class DELIVERY
# mode -- how_to_feed returns it for a crash env_fuzz recorded, and the capture/bundle paths below
# honour it -- which is what lets such a crash be replayed into a verified PoC.
MODES = ("stdin", "file", "arg")

# env_fuzz records its delivery as an argv prefix element "NAME=@@" (@@ being the input placeholder),
# so the variable's name survives on the DynResult and the replay can set the right one.
_ENV_PLACEHOLDER = "=@@"


def libfuzzer_harness(ctx, target, input_sha):
    """The stored libFuzzer harness the crash at `input_sha` was found in, or None.

    A libFuzzer crash is a crash of the HARNESS, which is a different binary from the one that
    was ingested. Replaying the input against the ingested binary is not a weaker test, it is the
    wrong one: a heap overflow reached through `TIFFReadRGBAImage` does not reproduce under a
    tool that never calls it. The run that found it recorded the harness in its isolation tag, so
    this reads the record rather than guessing.

    Lives here, beside `how_to_feed`, because it answers the same question that one does -- what
    actually consumes this input -- and two stages have to agree on the answer. They did not:
    `build_poc` staged the harness and `poc_primitive` staged the ingested binary, so the one
    real memory-safety finding in the corpus could reach L1 and never L2.
    """
    from ...db.dao import ArtifactDAO, DynResultDAO
    iso = ""
    for r in DynResultDAO(ctx.conn).list_by_target(target.id):
        if r.input_sha == input_sha and r.isolation:
            iso = r.isolation
            break
    if not iso.startswith("libfuzzer"):
        return None
    prefix = iso.split("/", 1)[1] if "/" in iso else ""
    arts = [a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
            if a.kind == "libfuzzer-harness"]
    sha = next((a.sha256 for a in arts if prefix and a.sha256.startswith(prefix)), None)
    if sha is None and arts and not prefix:
        sha = arts[-1].sha256
    return ctx.content.get_bytes(sha) if sha else None


def env_var_from_argv(argv):
    """(var_name, remaining_argv) for an env-delivered crash, or (None, argv) when there is none."""
    for i, a in enumerate(list(argv or [])):
        if isinstance(a, str) and a.endswith(_ENV_PLACEHOLDER):
            return a[:-len(_ENV_PLACEHOLDER)], [x for j, x in enumerate(argv) if j != i]
    return None, list(argv or [])


_STDIN_FUNCS = {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getchar",
                "getline", "getc", "fgetc"}
_FILE_FUNCS = {"fopen", "fopen64", "open", "open64", "freopen"}
# Interactive-stdin primitives: raw read(2), gets, the scanf family, getchar, getline. Their
# presence means the program takes its ATTACKER input from stdin, so stdin outranks a file
# channel even when the binary ALSO opens a file -- which, for this class of target, is usually
# an internal resource opened by a constant name (a program `open`s a fixed file like "flag.txt"; a service
# reads stdin yet opens a log/config). Deliberately EXCLUDES fgets/fread/getc/fgetc: a file
# parser reads its own FILE* with exactly those, so they must not pull ranking toward stdin
# (jhead is fopen+fread; the real-gate arm_config fixture is fopen+fgets). Without this split a
# binary that merely reads its flag file was classed as file-input and every stdin payload --
# the real channel -- was delivered where the program never reads it (a stdin reader that also opens a fixed file: concolic
# solved the gate to unconstrained-IP, then the input was dumped as an unread file of zeros).
_STDIN_INTERACTIVE = {"read", "gets", "scanf", "__isoc99_scanf", "getchar", "getchar_unlocked",
                      "getline"}


# ---- the SAME question on a managed runtime ----------------------------------------------
#
# A managed target has no machine code, so `disassemble` recovers no functions and writes no
# call edges -- which left the sets above matching nothing and put `arg` FIRST for every jar,
# .pyc and .NET assembly. The cost is not a wrong answer (the autopilot retries the other
# channels) but a wasted one: a .NET assembly runs at 8 exec/s, so a campaign spent ~364
# executions, about 45 seconds of its budget, fuzzing a channel the program never reads before
# trying the one it does.
#
# The names ARE available: triage reads them out of the metadata heaps / constant pool / code
# object and records them (`ingest.triage_symbols`). They are not libc symbols, so they need
# their own vocabulary, and the vocabulary has to be careful -- `ReadLine` is `Console.ReadLine`
# on stdin AND `StreamReader.ReadLine` on a file, so a read method alone decides nothing. Where
# the TYPE disambiguates, require it.
_MANAGED_CONSOLE_TYPES = {"System.Console", "Console"}
_MANAGED_CONSOLE_READS = {"ReadLine", "Read", "ReadKey", "ReadToEnd", "ReadBlock",
                          "OpenStandardInput", "get_In"}
# Unambiguous stdin markers: the name itself names the stream, whatever is called on it.
_MANAGED_STDIN_MARKERS = {
    "stdin",                      # Python: sys.stdin
    "input", "raw_input",         # Python: input() reads a line from stdin
    "System.in", "in",            # Java: System.in -- a constant-pool field ref
    "nextLine", "nextInt",        # Java: a Scanner, which is only ever built over a stream
}
# File readers. A TYPE name here is enough: `System.IO.File` / `FileStream` / `open` exist to
# touch the filesystem. Deliberately EXCLUDES the bare `System.IO` namespace and
# `MemoryStream`/`TextReader`, which a console-only program also names.
_MANAGED_FILE_NAMES = {
    "File", "FileStream", "FileInfo", "OpenRead", "OpenText", "OpenWrite",
    "ReadAllBytes", "ReadAllText", "ReadAllLines", "Directory", "DirectoryInfo",
    "FileInputStream", "FileReader", "RandomAccessFile", "Files",      # Java
    "open", "fileno",                                                  # Python
    "path_open", "fd_pread", "fd_prestat_get", "path_filestat_get",    # WASI
}
# WASI is the sharpest evidence any of these formats offers, because a wasm module can only reach
# the outside world through an IMPORT it declares: `fd_read` means it reads a descriptor, and
# without `path_open` it can never open a file at all -- so the descriptor is fd 0.
_MANAGED_STDIN_MARKERS = _MANAGED_STDIN_MARKERS | {"fd_read"}


def _managed_channels(symbols):
    """(has_stdin, has_file, interactive) from a managed target's recorded symbol names.

    `symbol_names` supplies both the qualified and the short form of every name, so a type-
    qualified marker (`System.Console`) and a bare one (`fd_read`) are matched from one set.
    """
    from .. import substrate
    names = substrate.symbol_names(symbols)
    console = bool(names & _MANAGED_CONSOLE_TYPES) and bool(names & _MANAGED_CONSOLE_READS)
    marked = bool(names & _MANAGED_STDIN_MARKERS)
    has_file = bool(names & _MANAGED_FILE_NAMES)
    has_stdin = console or marked
    # A direct console/stdin read is this runtime's interactive primitive, exactly as raw
    # read(2) and the scanf family are on a native target: it means the program takes its
    # ATTACKER input from stdin, so stdin outranks a file channel the program also touches.
    return has_stdin, has_file, has_stdin


def no_import_evidence(target) -> bool:
    """True when this target has NO import table to consult, so the absence of input-function
    names says nothing about what it reads.

    A statically linked binary resolves `read`/`fopen` inside itself: there are no dynamic
    imports by construction, and if it is also stripped there are no names at all. The ranking's
    no-evidence default (`arg`, on the reasoning that a binary importing no input function reads
    neither a file nor stdin) is sound only when the import table was actually READ -- which the
    comment in `modes_for` says in as many words.

    Measured on `zigzag`, a static-pie stripped HTB binary that reads a command menu from stdin:
    every channel came out without evidence, `arg` ranked first, the orchestrator pinned it, and
    the input never reached the program. Each execution then blocked until the 10s timeout, so
    all three engines got NINE executions between them and two of them errored out. A
    dynamically linked stripped binary is NOT this case -- its .dynsym still names its imports,
    which is why /usr/bin/readelf (stripped, dynamic) ranked correctly.
    """
    return str(getattr(target, "linking", "") or "").lower().startswith("static")


def modes_for(call_edges, given=None, symbols=(), file_type=None, *, no_imports=False):
    """The input channels to try, best first, always ending with every DELIVERABLE one attempted.

    Ranked by the input functions the binary actually imports, because "default to stdin" is
    a coin flip that loses on most real targets: a file parser reads nothing from stdin, so a
    campaign or a probe aimed there does no work at all and reports a clean zero. When a binary
    exposes BOTH channels (it opens a file and reads stdin), an interactive-stdin primitive
    breaks the tie toward stdin -- the file is then almost always an internal resource, not the
    input -- while a pure stdio file-reader (fread/fgets on a FILE*) keeps file first.

    `symbols` is the managed equivalent of `call_edges`: the names triage recovered from a
    constant pool, a metadata heap or a code object, for a target that owns no machine code and
    therefore has no call edges at all. Unioned with the native signals, never substituted for
    them. See `_managed_channels`.

    `file_type` decides which channels EXIST here, which is a different question from which is
    most likely. The ranking is universal and the fallback sweep attempts all three, which is
    the right shape wherever all three can carry input -- and wrong where one cannot: for a wasm
    reactor module `arg` and `file` reach nothing (no process, no argv, no preopened directory),
    and `arg` was nevertheless offered FIRST, on the slowest substrate measured here. Omitting
    it is not a narrowing of the search; those executions found nothing by construction.
    """
    from .. import substrate
    from ..detect.catalog import normalize
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    has_file = bool(names & _FILE_FUNCS)
    has_stdin = bool(names & _STDIN_FUNCS)
    interactive = bool(names & _STDIN_INTERACTIVE)
    # `symbols` carries a MANAGED target's recorded names, which is the only inventory such a
    # target has -- it owns no machine code, so `call_edges` is empty for it. Unioned, never
    # substituted: a native target with both sources keeps every native signal it had.
    m_stdin, m_file, m_interactive = _managed_channels(symbols)
    # A NATIVE target's recorded symbol names are the same vocabulary as its call edges -- an
    # import of `read` says exactly what a call edge to `read` says -- and they cost nothing,
    # because triage parsed the import table long before any disassembly. Reading only the
    # edges made this ranking depend on `disassemble` having produced them: measured on
    # quack_quack, whose `disassemble` returned in 0.6 s under the budget, the edge set was
    # empty, so NO channel had evidence, the no-evidence fallback (`arg`, correct for a binary
    # that genuinely reads nothing) was taken, and the concolic stage solved against argv for a
    # program whose input is `read(0, ...)`. 90,872 executions and a 300 s solver slice could
    # not reach a defect that is one stdin write away.
    #
    # Applied only when the MANAGED vocabulary recognised nothing in the set, because the same
    # spellings mean different things on a runtime: Python's `open`/`read` are a file object's
    # methods, not `open(2)` and `read(2)` on fd 0, and feeding those to the C vocabulary turned
    # a Python file reader into an interactive stdin target. The file type cannot make this
    # call on its own -- callers that know only the names pass no `file_type` at all.
    # A KNOWN native file type decides this outright; the marker heuristic is only for callers
    # that pass names and no type at all (the managed tests do). Getting this backwards
    # suppressed the C vocabulary for quack_quack -- a native ELF that imports `open` for its
    # own flag.txt, which the managed vocabulary also recognises -- so the managed reading won
    # and the channel came out `file` for a program whose input is `read(0, ...)`.
    _native = file_type is not None and not substrate.is_managed(file_type)
    if _native or not (m_stdin or m_file):
        names |= {normalize(n) for n in (symbols or ()) if isinstance(n, str) and n}
        has_file = has_file or bool(names & _FILE_FUNCS)
        has_stdin = has_stdin or bool(names & _STDIN_FUNCS)
        interactive = interactive or bool(names & _STDIN_INTERACTIVE)
    has_file = has_file or m_file
    has_stdin = has_stdin or m_stdin
    interactive = interactive or m_interactive
    ordered: list = []
    if has_file and has_stdin:
        ordered += ["stdin", "file"] if interactive else ["file", "stdin"]
    elif has_file:
        ordered.append("file")
    elif has_stdin:
        ordered.append("stdin")
    # `arg` ranks straight after whatever the evidence chose -- and FIRST when there was none,
    # which is deliberate and tested: a binary that imports no input function at all reads
    # neither a file nor stdin, so argv is what is left. That is only sound while the evidence
    # is actually consulted, which is why the symbol names above matter: without them a target
    # whose edges were merely MISSING looked identical to one that reads nothing.
    #
    # `no_imports` is the case where it CANNOT be consulted: a statically linked binary has no
    # dynamic imports at all, so "no input functions named" is silence, not a negative. Ranking
    # argv first on silence sent the whole campaign at a channel the program never reads (see
    # `no_import_evidence`). Stdin leads instead -- it is what an interactive binary reads, and
    # every channel is still attempted below.
    if no_imports and not ordered:
        ordered += ["stdin", "file"]
    ordered.append("arg")
    for m in MODES:                          # ensure every channel is attempted
        if m not in ordered:
            ordered.append(m)
    deliverable = substrate.channels(file_type, symbols)
    kept = [m for m in ordered if m in deliverable]
    # Never return nothing: a substrate with no capture-mode channel at all is fed by a stage of
    # its own (a bare-metal image through modelled MMIO), and the caller's own gate reports that.
    return kept or ordered


def how_to_feed(conn, target, input_sha, params, *, content=None):
    """(mode, argv, why) -- how this input reached the program when it crashed.

    Both the root-cause and the L2 stages used to default to stdin, so a file parser or an
    argv-driven target reported "did not fault" -- a clean-looking negative that really meant
    "we fed it the wrong way". The dynamic run that FOUND the input already recorded the mode
    and argv it used, which is authoritative whenever the crash came from this pipeline;
    anything else is a starting guess that the caller sweeps past.
    """
    from ...db.dao import DynResultDAO
    if params.get("input_mode"):
        return params["input_mode"], list(params.get("argv") or []), "given"
    for r in DynResultDAO(conn).list_by_target(target.id):
        if r.input_sha == input_sha and r.input_mode:
            # dyn_result.argv is the FLAG PREFIX, never the thing carrying the input: the
            # carrier is a scratch path that no longer exists by the time anything replays it,
            # and the caller appends its own. Recording the whole invocation made the replay
            # `jhead /tmp/<gone>/input.bin /tmp/new/input.bin`; jhead stops at the missing
            # first file and never reaches the crashing one, so a real crash was filed as
            # "did not reproduce".
            return r.input_mode, list(r.argv or []), "recorded by the run that found it"
    # Nothing recorded: rank the channels by what the binary imports rather than assuming
    # stdin. A file parser given its input on stdin looks exactly like a program with no bug.
    from ...db.dao import CallEdgeDAO
    try:
        # The import table says what the program reads even when `disassemble` has written no
        # call edges -- which is the common case, because leading with execution means the
        # dynamic stages run first. Without it the ranking had no evidence at all and the
        # fallback's first element decided the channel.
        syms = ()
        if content is not None:
            try:
                from ..ingest import triage_symbols
                syms = triage_symbols(conn, content, target)
            except Exception:                            # best-effort: fewer signals, not none
                syms = ()
        ranked = modes_for(CallEdgeDAO(conn).list_by_target(target.id), symbols=syms,
                           file_type=getattr(target, "file_type", None),
                           no_imports=no_import_evidence(target))
    except Exception:
        ranked = list(MODES)
    return (ranked or list(MODES))[0], list(params.get("argv") or []), \
        "inferred from the imported input calls"
