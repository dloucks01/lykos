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
                argv = argv + [sandbox.argv_arg(data)]
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
                argv = argv + [sandbox.argv_arg(data)]
            except sandbox.ArgvNulError as e:
                return {"ok": False, "reason": str(e)}
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = argv + [str(work / "input.bin")]
        return qemu_gdb.capture(exe, arch, argv=argv, stdin=stdin, timeout=timeout,
                                endianness=endianness, bits=bits, breakpoints=breakpoints)

    return capture
