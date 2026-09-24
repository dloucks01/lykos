"""angr concolic-execution integration: locate an angr-capable interpreter, run the driver
in a subprocess, and parse its JSON result. Mirrors the Ghidra pattern (locate -> run ->
parse; clear failure when absent; the driver ships as a package resource and is materialized
to disk so it works from a zipapp)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

_DRIVER = "angr_driver.py"
# angr/Z3/CLE keep only ACTIVE states capped; spilled/deferred/unconstrained stashes still grow,
# and the stage's time budget bounds runaway TIME but not runaway MEMORY within it. Cap the child's
# virtual address space so a hostile/large target cannot OOM the host mid-exploration; generous
# enough (12 GiB) that ordinary explorations are unaffected. Tunable via LYKOS_ANGR_MEM_MB.
_ANGR_MEM_MB = int(os.environ.get("LYKOS_ANGR_MEM_MB", "12288"))


def _mem_preexec():
    """A preexec_fn that caps the angr child's address space (Linux). Returns None where resource
    limits aren't available, so callers can pass it unconditionally."""
    try:
        import resource
    except Exception:
        return None

    def _apply():
        cap = _ANGR_MEM_MB * 1024 * 1024
        for _res in (resource.RLIMIT_AS, resource.RLIMIT_DATA):
            try:
                resource.setrlimit(_res, (cap, cap))
            except Exception:
                pass
    return _apply


def _imports_angr(python: Path, timeout: float = 20.0) -> bool:
    try:
        r = subprocess.run([str(python), "-c", "import angr"],
                           capture_output=True, timeout=timeout, check=False)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def locate_angr_python(config: Optional[str] = None) -> Optional[Path]:
    """Return a Python interpreter that can `import angr`, or None.

    Order: LYKOS_ANGR_PYTHON, explicit config, a bundled vendor venv, the current
    interpreter, then `python3` on PATH. Each candidate is verified by importing angr.
    """
    candidates: list[Path] = []
    for env in ("LYKOS_ANGR_PYTHON",):
        v = os.environ.get(env)
        if v:
            candidates.append(Path(v))
    if config:
        candidates.append(Path(config))
    # a vendored venv (vendor/angr-venv/bin/python) beside the package or the project root;
    # search a few parent levels so it is found from source and from an installed layout.
    here = Path(__file__).resolve()
    for up in here.parents[2:6]:
        candidates.append(up / "vendor" / "angr-venv" / "bin" / "python")
    candidates.append(Path(sys.executable))
    which = shutil.which("python3")
    if which:
        candidates.append(Path(which))

    seen = set()
    for c in candidates:
        cp = str(c)
        if cp in seen:
            continue
        seen.add(cp)
        if c.exists() and _imports_angr(c):
            return c
    return None


def _materialize_driver() -> Path:
    d = Path(tempfile.mkdtemp(prefix="lykos-angr-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.symbolic") / _DRIVER).read_bytes()
    except Exception:
        data = (Path(__file__).parent / _DRIVER).read_bytes()
    p = d / _DRIVER
    p.write_bytes(data)
    return p


def run_explore(python: Path, spec: dict, *, ctx=None, timeout: int = 300) -> dict:
    """Run the angr driver on `spec` and return the parsed result dict.

    The driver enforces its own wall-clock deadline (spec.max_seconds) and dumps partial results,
    so it should finish on its own. The subprocess timeout here is only a backstop for a driver
    stuck in native code (a z3 query, VEX lifting) that no in-process signal can interrupt -- angr
    on a large Rust binary does this. We give a short grace past the driver's deadline, then let
    the TimeoutExpired propagate: the concolic STAGE catches it and finishes cleanly with whatever
    was produced, so a stuck exploration never takes the case down."""
    work = _materialize_driver().parent
    spec_path = work / "spec.json"
    out_path = work / "out.json"
    spec_path.write_text(json.dumps(spec))
    cmd = [str(python), str(work / _DRIVER), str(spec_path), str(out_path)]
    grace = timeout + 25
    try:
        _pre = _mem_preexec()
        if ctx is not None:
            proc = ctx.run_subprocess(cmd, timeout=grace, preexec_fn=_pre)
        else:
            proc = subprocess.run(cmd, timeout=grace, capture_output=True, check=False,
                                  preexec_fn=_pre)
        if not out_path.exists():
            tail = (getattr(proc, "stderr", b"") or b"")[-600:].decode("latin-1", "ignore")
            raise RuntimeError(f"angr driver produced no output (rc="
                               f"{getattr(proc, 'returncode', '?')}): {tail}")
        return parse_result(out_path)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def parse_result(out_json: Path) -> dict:
    data = json.loads(Path(out_json).read_text())
    if "generated" not in data:
        raise ValueError("angr driver result missing 'generated'")
    if not data.get("ok"):
        raise RuntimeError("angr exploration failed: " + str(data.get("error", "unknown")))
    return data
