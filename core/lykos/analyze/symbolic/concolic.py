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
    """Run the angr driver on `spec` and return the parsed result dict."""
    work = _materialize_driver().parent
    spec_path = work / "spec.json"
    out_path = work / "out.json"
    spec_path.write_text(json.dumps(spec))
    cmd = [str(python), str(work / _DRIVER), str(spec_path), str(out_path)]
    try:
        if ctx is not None:
            proc = ctx.run_subprocess(cmd, timeout=timeout + 60)
        else:
            proc = subprocess.run(cmd, timeout=timeout + 60, capture_output=True, check=False)
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
