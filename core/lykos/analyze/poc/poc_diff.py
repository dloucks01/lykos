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
import re
import shutil
import sys
import tempfile
from pathlib import Path

# A CTF/win banner: NAME{...}. Used to recognise a no-crash exploit's success output.
_FLAG_RE = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,15}\{[^}\n]{2,64}\}")

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
        b_bytes = ctx.content.path(b.sha256).read_bytes()
        # each staged in its OWN dir so a bundled A and a bundled B don't clash on loader/libc names
        exe = ctx.content.stage_target(b, workdir / "cand", "candidate.bin")
        a_exe = ctx.content.stage_target(a, workdir / "base", "baseline.bin")

        replayed: dict = {}                              # (input_sha, kind) -> replay result
        results = []
        for p in a_pocs:
            if ctx.should_cancel():
                break
            dr = a_dr.get(p.input_sha)
            fnd = a_finds.get(p.finding_id) if p.finding_id else None
            # A crash PoC reproduces by SIGNAL; a no-crash L3 exploit exits cleanly, so it must be
            # verified by the WIN itself (breakpoint / output marker), not by a fault.
            crash_based = bool(p.signal_name) or bool(dr and dr.crashed)
            kind = "crash" if crash_based else ("win" if p.level == "L3" else "skip")
            key = (p.input_sha, kind)
            if key not in replayed:
                if kind == "crash":
                    replayed[key] = _replay_on(ctx, run_input, exe, b, dr, p.input_sha, workdir)
                elif kind == "win":
                    win_name = _win_name(ctx, FindingDAO(ctx.conn), fnd, p)
                    replayed[key] = _verify_win_on(ctx, run_input, exe, a_exe, b, b_bytes, dr,
                                                   p.input_sha, workdir, win_name)
                else:
                    replayed[key] = {"reproduced": None, "mode": None, "method": None,
                                     "error": "PoC is neither a crash nor a demonstrated win"}
            r = replayed[key]
            results.append({"level": p.level, "verified": bool(p.verified),
                            "cwe": fnd.cwe if fnd else None, "title": fnd.title if fnd else None,
                            "input_sha": p.input_sha, "mode": r.get("mode"),
                            "method": r.get("method"), "win": r.get("win"),
                            "marker": r.get("marker"),
                            "reproduced": r.get("reproduced"), "crashed": r.get("crashed"),
                            "runs": r.get("runs"), "signal": r.get("signal"),
                            "error": r.get("error")})
            if r.get("error") is None:
                how = {"crash": "still faults", "win": "win reproduces"}
                gone = {"crash": "no fault", "win": "win no longer reached"}
                verb = (how if r.get("reproduced") else gone).get(kind, "reproduces")
                ctx.progress(msg=f"replayed {a.filename} {p.level} on {b.filename}: {verb}")

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


def _win_name(ctx, fdao, fnd, poc):
    """The win function's name for an L3 exploit, so the breakpoint check can re-resolve it in B's
    own image. The chainer records it authoritatively as `target` in the PoC bundle's meta.json
    (and as the finding's site detail). Best-effort -- absent, the marker path still verifies."""
    if poc is not None and getattr(poc, "bundle_sha", None):
        try:
            import io
            import tarfile
            raw = ctx.content.path(poc.bundle_sha).read_bytes()
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                m = tar.extractfile("poc/meta.json")
                meta = json.loads(m.read().decode("utf-8", "ignore")) if m else {}
            if meta.get("target"):
                return meta["target"]
        except Exception:
            pass
    if fnd is not None:
        try:
            for s in fdao.sites(fnd.id):
                if s.get("detail"):
                    return s["detail"]
        except Exception:
            pass
    return None


def _verify_win_on(ctx, run_input, exe_b, exe_a, b, b_bytes, dr, input_sha, workdir, win_name,
                   *, timeout: float = 8.0) -> dict:
    """Verify a NO-CRASH 'win' exploit (an L3 chain) reproduces on candidate B.

    A win exploit exits cleanly -- there is no signal to match, so `_replay_on`'s crash check would
    call every such PoC 'fixed' even against an identical binary. Instead confirm the WIN itself:
      (1) breakpoint -- does A's exploit input still drive B into the win function? (causation-
          grade, reusing the ptrace capture the chainer confirmed the win with); failing that,
      (2) marker  -- does the win's distinctive output (a flag banner, or a line B does not print on
          a benign run) still appear when B is fed A's input?
    B is still vulnerable if the win reproduces, fixed if it does not.
    """
    from . import exploit
    try:
        data = ctx.content.get_bytes(input_sha)
    except Exception:
        return {"error": "input unavailable", "reproduced": None, "mode": None, "method": None}
    mode = (dr.input_mode if dr else None) or "stdin"
    argv = list(dr.argv) if (dr and dr.argv) else []
    base_argv = argv[:-1] if (mode in ("arg", "file") and argv) else argv

    # (1) breakpoint: resolve the win function in B's OWN image (a patched rebuild moves it) and
    # check A's exploit input still reaches it under the debugger.
    if win_name:
        try:
            win_addr = exploit.elf_functions(b_bytes).get(win_name)
        except Exception:
            win_addr = None
        if win_addr:
            from .capture import make_capture, materialize_helper
            helper = materialize_helper()
            try:
                capture = make_capture(ctx, helper, str(exe_b), mode, base_argv, timeout,
                                       sys.executable)
                cap = capture(data, breakpoints=[win_addr])
            except Exception as e:
                cap = {"ok": False, "reason": str(e)}
            finally:
                shutil.rmtree(helper.parent, ignore_errors=True)
            if cap.get("ok"):
                return {"reproduced": exploit.reached(cap, win_addr), "method": "breakpoint",
                        "mode": mode, "win": win_name, "runs": 1, "crashed": 0, "signal": None,
                        "error": None}
            # win symbol gone / helper failed -> fall through to the output-marker check

    # (2) output marker: the win prints something a patched B will not.
    return _marker_verify(ctx, run_input, exe_b, exe_a, b, data, mode, base_argv, workdir, win_name,
                          timeout)


def _marker_verify(ctx, run_input, exe_b, exe_a, b, data, mode, base_argv, workdir, win_name,
                   timeout: float) -> dict:
    """Learn the win's success marker from BASELINE A (exploit output minus a benign run), then
    check candidate B prints it when fed the same input."""
    def _out(exe, d):
        try:
            _, res = run_input(exe, mode, workdir / "in.bin", timeout, b.arch, d,
                               endianness=b.endianness, bits=b.bits, base_argv=base_argv)
        except Exception:
            return None
        return res.stdout or b""

    out_a = _out(exe_a, data)
    if out_a is None:
        return {"reproduced": None, "method": "marker", "mode": mode, "win": win_name,
                "error": "baseline exploit did not run"}
    marker = _win_marker(out_a, _out(exe_a, b"") or b"")
    if not marker:
        return {"reproduced": None, "method": "marker", "mode": mode, "win": win_name,
                "error": "no distinctive win output to verify (needs manual review)"}
    out_b = _out(exe_b, data)
    if out_b is None:
        return {"reproduced": None, "method": "marker", "mode": mode, "win": win_name,
                "error": "candidate did not run"}
    return {"reproduced": marker in out_b, "method": "marker", "mode": mode, "win": win_name,
            "marker": marker.decode("latin-1", "ignore")[:80], "runs": 1, "crashed": 0,
            "signal": None, "error": None}


def _win_marker(out_a: bytes, out_benign: bytes):
    """A byte string that appears when the exploit wins but not on a benign run: a flag banner if
    one is present, else the most distinctive win-only output line."""
    m = _FLAG_RE.search(out_a)
    if m:
        return m.group(0)
    benign = set(out_benign.splitlines())
    cands = [ln.strip() for ln in out_a.splitlines()
             if ln.strip() and ln not in benign and len(ln.strip()) >= 4]
    cands.sort(key=len, reverse=True)                    # the longest win-only line is most telling
    return cands[0] if cands else None


def register() -> None:
    register_stage(POC_DIFF_STAGE, poc_diff_stage, resource_class="cpu",
                   tool="ptrace", tool_version="1")


def enqueue_poc_diff(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, POC_DIFF_STAGE, target_id=target.id,
                         params=params or {}, force=force)
