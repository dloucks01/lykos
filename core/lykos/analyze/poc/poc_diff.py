"""Verified regression / patch-verification diff.

Given a BASELINE target A (which carries proof-of-concept inputs) and a CANDIDATE target B in the
same case (typically a patched rebuild), replay each of A's PoC inputs against B in the sandbox and
report whether the fault still reproduces. If none of A's crashing inputs fault B, the bug is fixed;
if any still fault it, B is still vulnerable. This turns the workbench's static finding diff
a VERIFIED regression check -- lykos actually re-runs the exploit against the candidate build.

A's crash row supplies the delivery (stdin/arg/file) and argv the input was found under, so a target
that faults behind a flag is replayed under that flag. Deterministic; runs via run_input.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from ...jobs.registry import register_stage

POC_DIFF_STAGE = "poc_diff"


def poc_diff_stage(ctx) -> dict:
    from ...db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
    from ..fuzz.runner import run_input

    tdao = TargetDAO(ctx.conn)
    b = tdao.get(ctx.target_id) if ctx.target_id else None
    if b is None:
        raise ValueError("poc_diff requires a target_id (the candidate build)")
    params = getattr(ctx, "params", None) or {}
    a_id = params.get("baseline_target_id") or params.get("baseline")
    a = tdao.get(a_id) if a_id else None
    if a is None or a.id == b.id:
        ctx.emit("poc_diff.done", payload={"applicable": False,
                 "note": "need a distinct baseline target (with PoCs) to diff against"})
        ctx.progress(pct=100, msg="no baseline to diff")
        return {}

    a_pocs = [p for p in PocDAO(ctx.conn).list_by_target(a.id) if p.input_sha]
    if not a_pocs:
        ctx.emit("poc_diff.done", payload={"applicable": False,
                 "note": f"{a.filename} has no PoC inputs to replay against {b.filename}"})
        ctx.progress(pct=100, msg="baseline has no PoCs")
        return {}

    a_dr = {d.input_sha: d for d in DynResultDAO(ctx.conn).list_by_target(a.id) if d.input_sha}
    a_finds = {f.id: f for f in FindingDAO(ctx.conn).list_by_target(a.id)}
    workdir = Path(tempfile.mkdtemp(prefix="lykos-pocdiff-"))
    try:
        exe = workdir / "candidate.bin"
        exe.write_bytes(ctx.content.path(b.sha256).read_bytes())
        os.chmod(exe, 0o755)

        replayed: dict = {}                              # input_sha -> replay result
        results = []
        for p in a_pocs:
            if ctx.should_cancel():
                break
            if p.input_sha not in replayed:
                replayed[p.input_sha] = _replay_on(ctx, run_input, exe, b, a_dr.get(p.input_sha),
                                                   p.input_sha, workdir)
            r = replayed[p.input_sha]
            fnd = a_finds.get(p.finding_id) if p.finding_id else None
            results.append({"level": p.level, "verified": bool(p.verified),
                            "cwe": fnd.cwe if fnd else None, "title": fnd.title if fnd else None,
                            "input_sha": p.input_sha, "mode": r.get("mode"),
                            "reproduced": r.get("reproduced"), "crashed": r.get("crashed"),
                            "runs": r.get("runs"), "signal": r.get("signal"),
                            "error": r.get("error")})
            if r.get("error") is None:
                ctx.progress(msg=f"replayed {a.filename} {p.level} on {b.filename}: "
                                 f"{'still faults' if r.get('reproduced') else 'no fault'}")

        checked = [r for r in results if r.get("error") is None]
        repro = [r for r in checked if r.get("reproduced")]
        fixed = bool(checked) and not repro
        payload = {"applicable": True, "baseline": a.id, "baseline_name": a.filename,
                   "candidate": b.id, "candidate_name": b.filename,
                   "fixed": fixed, "reproduced": len(repro), "checked": len(checked),
                   "total": len(results), "results": results}
        sha = ctx.put_artifact("poc-diff", data=json.dumps(payload).encode(),
                               meta={"baseline": a.id, "candidate": b.id, "fixed": fixed})
        ctx.emit("poc_diff.done", payload=payload)
        ctx.progress(pct=100, msg=(
            f"{a.filename} → {b.filename}: fixed — none of {len(checked)} PoC input(s) reproduce"
            if fixed else
            f"{a.filename} -> {b.filename}: still vulnerable -- {len(repro)}/{len(checked)}"))
        return {"output_shas": [sha],
                "metrics": {"fixed": fixed, "reproduced": len(repro), "checked": len(checked)}}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _replay_on(ctx, run_input, exe, target, dr, input_sha, workdir, *, times: int = 3,
               timeout: float = 8.0) -> dict:
    """Replay one input against the candidate `times`; return whether it faulted. Delivery mode and
    argv come from the BASELINE's crash row (dr), so a flag-gated crash is replayed w/ the flag."""
    try:
        data = ctx.content.get_bytes(input_sha)
    except Exception:
        return {"error": "input unavailable", "reproduced": None, "mode": None}
    mode = (dr.input_mode if dr else None) or "stdin"
    argv = list(dr.argv) if (dr and dr.argv) else []
    base_argv = argv[:-1] if (mode in ("arg", "file") and argv) else argv
    crashed = 0
    sig = None
    for _ in range(times):
        try:
            _, res = run_input(exe, mode, workdir / "in.bin", timeout, target.arch, data,
                               endianness=target.endianness, bits=target.bits, base_argv=base_argv)
        except Exception:
            continue                                 # unbuildable delivery is not a crash
        if res.crashed:
            crashed += 1
            sig = res.signal_name or sig
    return {"reproduced": crashed > 0, "crashed": crashed, "runs": times, "signal": sig,
            "mode": mode, "error": None}


def register() -> None:
    register_stage(POC_DIFF_STAGE, poc_diff_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_poc_diff(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, POC_DIFF_STAGE, target_id=target.id,
                         params=params or {}, force=force)
