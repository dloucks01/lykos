"""The find -> solve -> validate loop behind `lykos hunt` (doc 52 §3, Step 1).

  prepare     binary as-is, or source built twice (plain for angr, ASan/UBSan as the oracle)
  solve       hyp_driver proposes sites and solves each satisfiable violation to an input
  validate    every input is replayed in the sandbox; only a site-matched oracle confirms
  re-solve    while budget remains, hypotheses whose inputs all failed replay are solved again
              with those inputs excluded (the counterexample step)
  store       hunt.json + findings.md + one PoC folder per confirmed hypothesis
"""
from __future__ import annotations

import base64
import os
import shutil
import time
from pathlib import Path
from typing import Callable, Optional

from . import engine, store
from .build import prepare
from .validate import validate
from .weaponize import weaponize

MIN_ROUND = 30.0


def _display(target, hyps):
    """Source locations in the operator's own tree, not the temporary build copy."""
    if not (target.source_root and target.display_root):
        return
    root = str(target.source_root).rstrip("/") + "/"
    for h in hyps:
        if h.location and h.location.startswith(root):
            h.location = str(target.display_root / h.location[len(root):])


def _drop_known(hyps, incidental):
    """An incidental report at a line some hypothesis already CONFIRMED is not news."""
    known = {(os.path.basename((h.location or "").rsplit(":", 1)[0]), h.line)
             for h in hyps if h.status == "confirmed"}
    incidental[:] = [i for i in incidental
                     if (i["where"].rsplit(":", 1)[0], int(i["where"].rsplit(":", 1)[1]))
                     not in known]


def _validate_all(target, hyps, incidental, log):
    for h in hyps:
        for s in h.solutions:
            if s.verdict is not None:
                continue
            v, inc = validate(target, h, s.data)
            s.verdict = v
            if inc:
                kind, path, line, func = inc
                where = f"{os.path.basename(path or '?')}:{line}"
                if not any(i["where"] == where and i["kind"] == kind for i in incidental):
                    incidental.append({"kind": kind, "where": where, "func": func,
                                       "hypothesis": h.id,
                                       "input_b64": base64.b64encode(s.data).decode()})
            log(f"  {h.id:<34} {'CONFIRMED' if v.confirmed else 'no':<9} {v.method}: {v.detail}")
        h.settle()


def hunt_target(target, budget: float, *, input_size: int, mem_mb: int,
                log: Callable[[str], None]) -> dict:
    t_end = time.time() + budget
    log(f"solving {target.exe.name} ({target.mode} input, argv {target.argv}) for {int(budget)} s")
    # uninitialised-memory proposing only earns its cost (extra directing targets) when there is
    # an MSan build to confirm against; otherwise it can never reach `confirmed`.
    base_extra = {"uninit": True} if target.msan_exe else {}
    out = engine.run_driver(target.exe, argv=target.argv, input_mode=target.mode,
                            budget=max(MIN_ROUND, budget * 0.7), input_size=input_size,
                            mem_mb=mem_mb, extra=dict(base_extra))
    hyps = engine.hypotheses_from(out, target.exe)
    _display(target, hyps)
    stats = [out.get("stats", {})]
    errors = [out["error"]] if out.get("error") else []
    incidental: list = []
    _validate_all(target, hyps, incidental, log)
    left = t_end - time.time()
    retry = [h for h in hyps if h.status == "unconfirmed"]
    if retry and left >= MIN_ROUND:
        log(f"re-solving {len(retry)} hypotheses with their failed inputs excluded ({int(left)} s)")
        excl = {h.id: [base64.b64encode(s.data).decode() for s in h.solutions] for h in retry}
        out2 = engine.run_driver(target.exe, argv=target.argv, input_mode=target.mode,
                                 budget=left - 10, input_size=input_size, mem_mb=mem_mb,
                                 extra={**base_extra, "only": [h.id for h in retry], "exclude": excl})
        stats.append(out2.get("stats", {}))
        if out2.get("error"):
            errors.append(out2["error"])
        new = engine.hypotheses_from(out2, target.exe)
        _display(target, new)
        hyps = engine.merge(hyps, new)
        _validate_all(target, hyps, incidental, log)
    _drop_known(hyps, incidental)
    # Step 4: climb control-flow-hijack hypotheses to an exploit. The driver's symbolic RIP control
    # is the candidate; weaponize's own differential (clean exit with the win address vs a crash
    # with it corrupted) is a sound proof of both control AND arrival, independent of how the raw
    # crash validated -- so a confirmed L3 is itself the confirmation of the hijack.
    import base64 as _b64
    from .model import Solution as _Solution, Verdict as _Verdict
    for h in hyps:
        if h.kind != "control-flow-hijack" or not h.solutions or time.time() >= t_end:
            continue
        try:
            ex = weaponize(target, h, input_size=input_size,
                           budget=max(MIN_ROUND, min(120.0, t_end - time.time())),
                           mem_mb=mem_mb, log=log)
        except Exception as e:                          # noqa: BLE001 - weaponize never fails a hunt
            ex = {"level": "error", "note": f"weaponize raised: {e}"}
        if not ex:
            continue
        h.exploit = ex
        log(f"  {h.id:<34} exploit {ex.get('level')}: "
            f"{ex.get('evidence') or ex.get('note') or ex.get('strategy')}")
        if ex.get("level") == "L3" and ex.get("confirmed") and ex.get("payload_b64"):
            sol = _Solution(_b64.b64decode(ex["payload_b64"]), ex.get("evidence", ""), None)
            sol.verdict = _Verdict(True, "ret2win", ex.get("evidence", ""), h.line, runs=1)
            h.solutions.append(sol)
            h.settle()
    return {"binary": str(target.exe), "asan": str(target.asan_exe) if target.asan_exe else None,
            "msan": str(target.msan_exe) if target.msan_exe else None,
            "argv": target.argv, "mode": target.mode, "stats": stats,
            "error": "; ".join(errors) or None, "hypotheses": hyps, "incidental": incidental}


def hunt(path, *, argv: Optional[list] = None, mode: Optional[str] = None,
         budget: float = 600.0, out_dir=None, input_size: int = 300, mem_mb: int = 8192,
         max_targets: int = 4, log: Callable[[str], None] = print) -> dict:
    t0 = time.time()
    log(f"preparing {path}")
    prep = prepare(path, argv=argv, mode=mode)
    try:
        targets = prep.targets[:max_targets]
        if not targets:
            raise RuntimeError("nothing runnable came out of the target")
        if prep.kind != "binary":
            log(f"{prep.kind}: {len(prep.targets)} executable(s); validating with "
                f"{'sanitizer builds' if any(t.asan_exe for t in targets) else 'native crashes'}")
        results = []
        for i, t in enumerate(targets):
            share = (budget - (time.time() - t0)) / max(1, len(targets) - i)
            results.append(hunt_target(t, max(MIN_ROUND, share), input_size=input_size,
                                       mem_mb=mem_mb, log=log))
        report = {"target": str(Path(path).resolve()), "kind": prep.kind, "budget": budget,
                  "started": t0, "build_log": prep.log[-4000:], "results": results}
        if out_dir and prep.workdir:
            # builds live in a temp tree: keep them beside the PoCs so replay.sh stays runnable
            bindir = Path(out_dir) / "bin"
            bindir.mkdir(parents=True, exist_ok=True)
            for r in results:
                for key in ("binary", "asan", "msan"):
                    src = r.get(key)
                    if src and Path(src).is_relative_to(prep.workdir):
                        dst = bindir / Path(src).name
                        shutil.copy2(src, dst)
                        r[key] = str(dst)
        if out_dir:
            p = store.save(out_dir, report)
            log(f"wrote {p} and {Path(out_dir) / 'findings.md'}")
            report["saved"] = str(p)
        return report
    finally:
        if prep.workdir:
            shutil.rmtree(prep.workdir, ignore_errors=True)
