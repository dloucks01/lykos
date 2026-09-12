"""Shared ptrace fault-capture runner: materialize the stdlib helper and drive it as a
subprocess (it must run as its own process, never forking the threaded worker). Used by the
L2 primitive stage and the root-cause stage."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..dynamic import sandbox

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
        argv = list(base_argv)
        if mode == "stdin":
            stdin_file = str(work / "stdin.bin")
            (work / "stdin.bin").write_bytes(data)
        elif mode == "arg":
            try:
                argv = argv + [sandbox.argv_arg(data, truncate=True)]
            except sandbox.ArgvNulError as e:
                return {"ok": False, "reason": str(e)}
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = argv + [str(work / "input.bin")]
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
        argv, stdin = list(base_argv), b""
        if mode == "stdin":
            stdin = data
        elif mode == "arg":
            try:
                argv = argv + [sandbox.argv_arg(data, truncate=True)]
            except sandbox.ArgvNulError as e:
                return {"ok": False, "reason": str(e)}
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = argv + [str(work / "input.bin")]
        return qemu_gdb.capture(exe, arch, argv=argv, stdin=stdin, timeout=timeout,
                                endianness=endianness, bits=bits, breakpoints=breakpoints)

    return capture


# Every way a target can be handed its input. Order matters only as a fallback sweep.
MODES = ("stdin", "file", "arg")


_STDIN_FUNCS = {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getchar",
                "getline", "getc", "fgetc"}
_FILE_FUNCS = {"fopen", "fopen64", "open", "open64", "freopen"}


def modes_for(call_edges, given=None):
    """The input channels to try, best first, always ending with all three attempted.

    Ranked by the input functions the binary actually imports, because "default to stdin" is
    a coin flip that loses on most real targets: a file parser reads nothing from stdin, so a
    campaign or a probe aimed there does no work at all and reports a clean zero.
    """
    from ..detect.catalog import normalize
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    ordered = []
    if names & _FILE_FUNCS:
        ordered.append("file")
    if names & _STDIN_FUNCS:
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
            # The recorded argv ends with the thing that CARRIES the input -- the workfile
            # path for a file target, the payload itself for an argv one -- and the caller
            # appends its own. Handing the whole thing back as a prefix made the replay
            # `jhead /tmp/<gone>/input.bin /tmp/new/input.bin`; jhead stops at the missing
            # first file and never reaches the crashing one, so a perfectly good crash was
            # filed as "did not reproduce". Only the flags in front of it belong to the setup.
            argv = list(r.argv or [])
            if r.input_mode in ("file", "arg") and argv:
                argv = argv[:-1]
            return r.input_mode, argv, "recorded by the run that found it"
    # Nothing recorded: rank the channels by what the binary imports rather than assuming
    # stdin. A file parser given its input on stdin looks exactly like a program with no bug.
    from ...db.dao import CallEdgeDAO
    try:
        ranked = modes_for(CallEdgeDAO(conn).list_by_target(target.id))
    except Exception:
        ranked = list(MODES)
    return ranked[0], list(params.get("argv") or []), "inferred from the imported input calls"
