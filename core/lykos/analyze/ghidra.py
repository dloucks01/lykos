"""Phase 1 — Ghidra headless integration (locator + runner + result parser).

We do NOT require Ghidra to be pre-installed on the target: the full offline bundle ships
it (doc 11). This locator finds it via explicit config/env, a bundled copy, or PATH; if
absent the disassemble stage fails with a clear message and Phase-0 triage still works.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from glob import glob
from pathlib import Path
from typing import Optional

_HEADLESS = "analyzeHeadless"
_SCRIPT = "ExportAnalysis.java"


def locate_ghidra(config_path: Optional[str] = None) -> Optional[Path]:
    """Return the path to `analyzeHeadless`, or None if Ghidra can't be found."""
    bases: list[Path] = []
    for env in ("LYKOS_GHIDRA", "GHIDRA_INSTALL_DIR"):
        v = os.environ.get(env)
        if v:
            bases.append(Path(v))
    if config_path:
        bases.append(Path(config_path))
    # bundled with the package: <install>/vendor/ghidra
    bases.append(Path(__file__).resolve().parents[2] / "vendor" / "ghidra")
    # common install locations (+ versioned dirs)
    for pat in ("/opt/ghidra*", "/usr/share/ghidra*", "/usr/lib/ghidra*",
                str(Path.home() / "ghidra*")):
        bases += [Path(p) for p in sorted(glob(pat), reverse=True)]

    for base in bases:
        if base.name == _HEADLESS and base.exists():
            return base
        hl = base / "support" / _HEADLESS
        if hl.exists():
            return hl
    which = shutil.which(_HEADLESS)
    return Path(which) if which else None


def _materialize_scripts() -> Path:
    """Extract the Jython export script to a real temp dir (Ghidra can't read from a zipapp)."""
    d = Path(tempfile.mkdtemp(prefix="lykos-ghscript-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.ghidra_scripts") / _SCRIPT).read_bytes()
    except Exception:
        data = (Path(__file__).parent / "ghidra_scripts" / _SCRIPT).read_bytes()
    (d / _SCRIPT).write_bytes(data)
    return d


def run_headless(headless: Path, binary: Path, out_json: Path, *, ctx=None,
                 timeout: int = 1800) -> None:
    """Import + auto-analyze `binary` headlessly and run the export post-script."""
    scripts = _materialize_scripts()
    proj = Path(tempfile.mkdtemp(prefix="lykos-ghproj-"))
    cmd = [str(headless), str(proj), "lykos",
           "-import", str(binary),
           "-scriptPath", str(scripts),
           "-postScript", _SCRIPT, str(out_json),
           "-deleteProject",
           "-analysisTimeoutPerFile", str(timeout)]
    try:
        if ctx is not None:
            ctx.run_subprocess(cmd, timeout=timeout + 120)
        else:
            subprocess.run(cmd, timeout=timeout + 120, capture_output=True)
    finally:
        shutil.rmtree(scripts, ignore_errors=True)
        shutil.rmtree(proj, ignore_errors=True)


def parse_result(out_json: Path) -> dict:
    """Parse the export JSON: {'program': {...}, 'functions': [{addr,name,size,decompiled}]}."""
    data = json.loads(Path(out_json).read_text())
    if "functions" not in data:
        raise ValueError("ghidra export missing 'functions'")
    return data
