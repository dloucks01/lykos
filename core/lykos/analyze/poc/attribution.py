"""Attribution-graded proof of a weaponized effect.

lykos confirms a working exploit by RUNNING it and looking at what came out. The weak version
of that -- matching a flag banner / ``/bin/sh`` on captured stdout -- credits any target that
merely reflects the input, or a helper/harness that printed the string itself. This module
replaces that with two independent, forgery-resistant checks:

  * ATTRIBUTION -- the output must come from a ``write(2)`` made by the TARGET's own process
    subtree (see ``attribution_trace``), not the harness and not a reflected value.
  * A FORGERY-PROOF MARKER -- for a shell/code-exec effect, a challenge the target cannot
    satisfy by echoing input: arithmetic (``$((6*7))`` -> ``42``) and quote-stripping
    (``A""B`` -> ``AB``) only resolve if a shell actually ran, keyed by a per-run nonce so a
    hard-coded reply cannot pre-bake it.

The result is a graded ladder (``PROOF_LEVELS``): output attributed to the target < a win
token attributed and differential < code execution proven < a shell proven. A caller decides
which rung a given technique must reach to be credited.

The tracer is x86-64 (the native L3 confirm arch); ``supported()`` says so, and callers keep
their existing check for other guests.
"""
from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path

from ..dynamic import sandbox
from ..fuzz.runner import place

_HELPER = "attribution_trace.py"

# The rungs, weakest to strongest. `rank()` compares them.
PROOF_LEVELS = ("none", "output_attributed", "win_attributed", "code_exec_proven",
                "shell_proven")


def rank(level: str) -> int:
    try:
        return PROOF_LEVELS.index(level)
    except ValueError:
        return 0


def supported() -> bool:
    return sandbox.host_arch() == "x86-64"


def materialize_helper() -> Path:
    d = Path(tempfile.mkdtemp(prefix="lykos-attr-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.poc") / _HELPER).read_bytes()
    except Exception:
        data = (Path(__file__).parent / _HELPER).read_bytes()
    p = d / _HELPER
    p.write_bytes(data)
    return p


def make_attributed_capture(ctx, helper: Path, exe, mode, base_argv, timeout, python):
    """capture(data)->trace dict: run `exe` on `data` (via `mode`) under the attribution tracer.

    Same shape/inputs as `poc.capture.make_capture`, so it drops into the same confirm flows.
    The trace dict carries `lineage_writes`/`foreign_writes` (each {pid, fd, data, lineage})."""
    work = helper.parent

    def capture(data: bytes) -> dict:
        stdin_file, argv = None, list(base_argv)
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
        spec_path = work / "attr_spec.json"
        spec_path.write_text(json.dumps(spec))
        proc = ctx.run_subprocess([python, str(helper), str(spec_path)], timeout=timeout + 30)
        out = (proc.stdout or b"").decode("latin-1", "ignore").strip()
        try:
            return json.loads(out) if out else {"ok": False, "reason": "no output"}
        except json.JSONDecodeError:
            return {"ok": False, "reason": "bad helper output: " + out[:200]}

    return capture


def lineage_bytes(result: dict) -> bytes:
    return b"".join(w["data"].encode("latin-1", "ignore")
                    for w in (result.get("lineage_writes") or []))


def foreign_bytes(result: dict) -> bytes:
    return b"".join(w["data"].encode("latin-1", "ignore")
                    for w in (result.get("foreign_writes") or []))


class CodeMarkers:
    """A per-run challenge whose SOLVED form proves a shell/interpreter executed it, and whose
    RAW form is what an echoing target would emit instead. Send `command` to a shell primitive
    (or embed it where the exploit runs a command); grade the target's attributed output."""

    def __init__(self, nonce: str, a: int, b: int):
        self.nonce, self.a, self.b = nonce, a, b

    @property
    def command(self) -> bytes:
        # arithmetic + quote-strip, both keyed by the nonce; `id -u` is a bonus shell signal.
        return (f'echo {self.nonce}A""B_$(({self.a}*{self.b}))_$(id -u 2>/dev/null)'
                ).encode()

    @property
    def solved(self) -> bytes:
        # what a real shell prints: quotes stripped, arithmetic evaluated.
        return f"{self.nonce}AB_{self.a * self.b}_".encode()

    @property
    def raw(self) -> bytes:
        # what a target that merely echoes the command back would emit.
        return f'{self.nonce}A""B_$(({self.a}*{self.b}))'.encode()

    def proves(self, output) -> bool:
        """True iff `output` shows the challenge was EVALUATED (solved form present) and not
        merely reflected (raw form absent) -- a real shell ran it, not an echo. Use in place of
        a bare `marker in output` check to close the input-reflection false positive."""
        ob = output if isinstance(output, (bytes, bytearray)) else output.encode("latin-1", "ignore")
        return self.solved in ob and self.raw not in ob


def make_code_markers() -> CodeMarkers:
    a = 100 + secrets.randbelow(900)
    b = 100 + secrets.randbelow(900)
    return CodeMarkers(secrets.token_hex(6), a, b)


def grade(result: dict, *, win_tokens=(), markers: "CodeMarkers | None" = None,
          control: "dict | None" = None) -> dict:
    """Grade a trace to a rung of PROOF_LEVELS with the evidence that earned it.

    - output_attributed: the target subtree wrote anything.
    - win_attributed:    a win token appears in an attributed write and NOT in `control`'s
                         attributed output (the differential -- so it is the exploit, not noise).
    - code_exec_proven:  the SOLVED marker appears attributed while its RAW form does not --
                         a shell evaluated the challenge; an echo cannot.
    - shell_proven:      code exec proven AND produced by an exec'd descendant, or `uid=` seen.
    """
    ev, level = [], "none"
    lb = lineage_bytes(result)
    if lb:
        level = "output_attributed"
        ev.append(f"target subtree wrote {len(lb)} bytes")

    ctrl_lb = lineage_bytes(control) if control else b""
    for tok in win_tokens:
        t = tok if isinstance(tok, bytes) else tok.encode("latin-1", "ignore")
        if t and t in lb and t not in ctrl_lb:
            level = "win_attributed"
            ev.append(f"win token {t!r} in an attributed write, absent under control")
            break

    if markers is not None and markers.solved in lb and markers.raw not in lb:
        level = "code_exec_proven"
        ev.append(f"forgery-proof marker resolved ({markers.raw.decode('latin-1')} -> "
                  f"{markers.solved.decode('latin-1')}): a shell evaluated the challenge")
        producers = [w for w in result.get("lineage_writes") or []
                     if markers.solved.decode("latin-1", "ignore") in w.get("data", "")]
        descendant = any(w.get("pid") != (result.get("root") or _root_pid(result))
                         for w in producers) or b"uid=" in lb
        if descendant:
            level = "shell_proven"
            ev.append("marker emitted by an exec'd descendant / `id` ran: a real shell")

    return {"level": level, "rank": rank(level), "evidence": ev,
            "attributed_bytes": len(lb), "foreign_bytes": len(foreign_bytes(result))}


def _root_pid(result: dict):
    ws = result.get("lineage_writes") or []
    return min((w.get("pid", 0) for w in ws), default=0)
