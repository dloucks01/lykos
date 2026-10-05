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
        spec = {"exe": str(exe), "argv": argv, "stdin_file": stdin_file, "timeout": timeout}
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


# Every way a target can be handed its input. Order matters only as a fallback sweep.
MODES = ("stdin", "file", "arg")


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


def modes_for(call_edges, given=None):
    """The input channels to try, best first, always ending with all three attempted.

    Ranked by the input functions the binary actually imports, because "default to stdin" is
    a coin flip that loses on most real targets: a file parser reads nothing from stdin, so a
    campaign or a probe aimed there does no work at all and reports a clean zero. When a binary
    exposes BOTH channels (it opens a file and reads stdin), an interactive-stdin primitive
    breaks the tie toward stdin -- the file is then almost always an internal resource, not the
    input -- while a pure stdio file-reader (fread/fgets on a FILE*) keeps file first.
    """
    from ..detect.catalog import normalize
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    has_file = bool(names & _FILE_FUNCS)
    has_stdin = bool(names & _STDIN_FUNCS)
    interactive = bool(names & _STDIN_INTERACTIVE)
    ordered: list = []
    if has_file and has_stdin:
        ordered += ["stdin", "file"] if interactive else ["file", "stdin"]
    elif has_file:
        ordered.append("file")
    elif has_stdin:
        ordered.append("stdin")
    ordered.append("arg")
    for m in MODES:                          # ensure every channel is attempted
        if m not in ordered:
            ordered.append(m)
    return ordered


def how_to_feed(conn, target, input_sha, params):
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
        ranked = modes_for(CallEdgeDAO(conn).list_by_target(target.id))
    except Exception:
        ranked = list(MODES)
    return ranked[0], list(params.get("argv") or []), "inferred from the imported input calls"
