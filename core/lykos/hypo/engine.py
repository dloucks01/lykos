"""Run the hypothesis driver (hyp_driver.py, under angr's interpreter) and read its result.

The driver is a separate process for two reasons: angr lives in its own venv, and symbolic
execution can grow without bound inside one native call. Containment, strongest first:
  * a transient systemd scope with MemoryMax and no swap: the kernel kills only the driver;
  * otherwise the driver's own RSS guard (spec max_rss_mb) plus a wall-clock backstop here.
No RLIMIT_AS: z3 and angr's native code abort the process (SIGABRT, no output) when an
allocation fails, and their virtual size runs far ahead of RSS.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from .model import Hypothesis, Solution

_log = logging.getLogger(__name__)
DRIVER = Path(os.environ.get("HYP_DRIVER") or Path(__file__).with_name("hyp_driver.py"))
_SCOPE_OK: Optional[bool] = None


def angr_python() -> Optional[Path]:
    from ..analyze.symbolic.concolic import locate_angr_python
    return locate_angr_python()


def _scope_usable() -> bool:
    """Can we start a memory-capped transient scope? Probed once per process."""
    global _SCOPE_OK
    if _SCOPE_OK is None:
        exe = shutil.which("systemd-run")
        _SCOPE_OK = False
        if exe:
            try:
                r = subprocess.run([exe, "--user", "--scope", "-q", "-p", "MemoryMax=64M",
                                    "true"], capture_output=True, timeout=15, check=False)
                _SCOPE_OK = r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                _SCOPE_OK = False
    return _SCOPE_OK


def scoped(cmd: list, mem_mb: int) -> list:
    if _scope_usable():
        return [shutil.which("systemd-run"), "--user", "--scope", "-q",
                "-p", f"MemoryMax={mem_mb}M", "-p", "MemorySwapMax=0"] + list(cmd)
    return list(cmd)


def run_driver(binary, *, argv, input_mode: str, budget: float, input_size: int = 300,
               mem_mb: int = 8192, extra: Optional[dict] = None,
               workdir: Optional[Path] = None, python: Optional[Path] = None) -> dict:
    """Run one solve over `binary`. Returns the driver's out.json as a dict (with `wall`, `rc`
    and `log` added). Never raises for a driver failure: `error` carries the reason."""
    py = python or angr_python()
    if py is None:
        return {"ok": False, "hypotheses": [], "stats": {},
                "error": "no Python interpreter with angr found (vendor/angr-venv)"}
    own = workdir is None
    work = Path(workdir or tempfile.mkdtemp(prefix="lykos-hunt-"))
    work.mkdir(parents=True, exist_ok=True)
    spec = {"binary": str(binary), "argv": list(argv), "input_mode": input_mode,
            "input_size": int(input_size), "max_seconds": float(budget),
            "max_rss_mb": max(1024, int(mem_mb * 0.75))}
    spec.update(extra or {})
    sp, op, lp = work / "spec.json", work / "out.json", work / "driver.log"
    sp.write_text(json.dumps(spec))
    if op.exists():
        op.unlink()
    cmd = scoped([str(py), "-I", str(DRIVER), str(sp), str(op)], mem_mb)
    t0 = time.time()
    rc = None
    try:
        with open(lp, "w") as log:
            rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=False,
                                timeout=float(budget) + 120).returncode
    except subprocess.TimeoutExpired:
        rc = "timeout"
    except OSError as e:
        rc = f"spawn failed: {e}"
    out = {"ok": False, "hypotheses": [], "stats": {}, "error": f"no output (rc={rc})"}
    if op.exists():
        try:
            out = json.loads(op.read_text())
        except ValueError as e:
            out["error"] = f"unreadable driver output: {e}"
    out["wall"] = round(time.time() - t0, 1)
    out["rc"] = rc
    try:
        out["log_tail"] = lp.read_text(errors="replace")[-2000:]
    except OSError:
        pass
    if own:
        shutil.rmtree(work, ignore_errors=True)
    return out


def _addr2line(binary, addrs: list) -> dict:
    """file vaddr -> "file:line" (basename path kept as DWARF records it), via binutils."""
    exe = shutil.which("addr2line")
    if not exe or not addrs:
        return {}
    try:
        r = subprocess.run([exe, "-e", str(binary)] + [hex(a) for a in addrs],
                           capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return {}
    res = {}
    for a, ln in zip(addrs, r.stdout.splitlines()):
        ln = ln.split(" (discriminator")[0].strip()
        if ln and not ln.startswith("??") and not ln.endswith(":0") and not ln.endswith(":?"):
            res[a] = ln
    return res


def hypotheses_from(out: dict, binary) -> list:
    """Driver output -> [Hypothesis], with sites as FILE addresses (the driver reports loaded
    addresses; a PIE is rebased) and file:line from DWARF when the build has it."""
    img = out.get("image") or {}
    delta = int(img.get("mapped_base", 0)) - int(img.get("linked_base", 0))

    def fileaddr(v):
        if v is None:
            return None
        v = int(v, 16) if isinstance(v, str) else int(v)
        return v - delta

    hyps = []
    for h in out.get("hypotheses") or []:
        hy = Hypothesis(id=h["id"], kind=h["kind"], cwe=h.get("cwe"), site=fileaddr(h.get("site")),
                        func=h.get("func"), func_addr=fileaddr(h.get("func_addr")),
                        func_size=h.get("func_size"), reached=int(h.get("reached") or 0),
                        note=h.get("note") or "")
        for s in h.get("solutions") or []:
            import base64
            hy.solutions.append(Solution(base64.b64decode(s.get("input_b64", "")),
                                         s.get("detail", ""), s.get("t")))
        hyps.append(hy)
    locs = _addr2line(binary, sorted({h.site for h in hyps if h.site is not None}))
    for h in hyps:
        h.location = locs.get(h.site)
        h.settle()
    return hyps


def merge(old: list, new: list) -> list:
    """Fold a later solve round into earlier hypotheses (same id = same site and class)."""
    by = {h.id: h for h in old}
    for h in new:
        o = by.get(h.id)
        if o is None:
            by[h.id] = h
            continue
        o.reached = max(o.reached, h.reached)
        seen = {s.data for s in o.solutions}
        o.solutions += [s for s in h.solutions if s.data not in seen]
        o.location = o.location or h.location
    return list(by.values())


def cpu_count() -> int:
    return os.cpu_count() or 2
