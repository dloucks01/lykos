"""Emulation-based rehosting integration (doc 17.5): locate a Unicorn-capable interpreter,
run the standalone rehosting driver in it, and parse the result -- keeping the Lykos core
stdlib-only. Clear, graceful failure when Unicorn is absent (like the angr/SymQEMU backends).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

_DRIVER = "unicorn_driver.py"


def _imports_unicorn(python: Path, timeout: int = 20) -> bool:
    # Actually CONSTRUCT a Uc engine, not just `import unicorn`. Unicorn loads its native library
    # (libunicorn.so) lazily, so on a laptop where that .so is missing or ABI/glibc-incompatible the
    # import can still succeed while every real use fails with "failed to load unicornlib.so". If we
    # only checked the import, `locate_unicorn_python` would hand back a broken interpreter, the
    # rehost driver would run, and its loader error would spill into the run console on EVERY
    # firmware target. Instantiating the engine here makes the failure surface in this captured probe
    # instead, so the stage reports "Unicorn unavailable" once, quietly, and never runs the driver.
    probe = "import unicorn; unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)"
    try:
        r = subprocess.run([str(python), "-c", probe],
                           capture_output=True, timeout=timeout, check=False)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def locate_unicorn_python(config: Optional[str] = None) -> Optional[Path]:
    """A Python interpreter that can `import unicorn`, or None.
    Order: LYKOS_UNICORN_PYTHON, explicit config, the vendored venv, current interpreter,
    then python3 on PATH -- each verified by importing unicorn."""
    candidates: list[Path] = []
    v = os.environ.get("LYKOS_UNICORN_PYTHON")
    if v:
        candidates.append(Path(v))
    if config:
        candidates.append(Path(config))
    here = Path(__file__).resolve()
    for up in here.parents[2:6]:
        candidates.append(up / "vendor" / "unicorn-venv" / "bin" / "python")
    candidates.append(Path(sys.executable))
    which = shutil.which("python3")
    if which:
        candidates.append(Path(which))

    seen = set()
    for c in candidates:
        if str(c) in seen:
            continue
        seen.add(str(c))
        if c.exists() and _imports_unicorn(c):
            return c
    return None


def _materialize_driver() -> Path:
    d = Path(tempfile.mkdtemp(prefix="lykos-unicorn-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.firmware") / _DRIVER).read_bytes()
    except Exception:
        data = (Path(__file__).parent / _DRIVER).read_bytes()
    p = d / _DRIVER
    p.write_bytes(data)
    return p


def run_rehost(python: Path, spec: dict, *, ctx=None, timeout: int = 180) -> dict:
    """Run the Unicorn rehosting driver on `spec`, return the parsed result dict."""
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
            raise RuntimeError(f"unicorn driver produced no output "
                               f"(rc={getattr(proc, 'returncode', '?')}): {tail}")
        data = json.loads(out_path.read_text())
        if not data.get("ok"):
            raise RuntimeError("rehost failed: " + str(data.get("error", "unknown")))
        return data
    finally:
        shutil.rmtree(work, ignore_errors=True)
