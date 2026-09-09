"""Phase 4 — the `dynamic_run` stage: detonate the target in the sandbox, record the
outcome, and turn a reproduced crash into a Confirmed finding (dynamic reproduction is what
promotes findings past the static ceiling)."""
from __future__ import annotations

import base64
import os

from ...db.dao import DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from . import sandbox

DYNAMIC_STAGE = "dynamic_run"
TOOL = "sandbox"
TOOL_VERSION = "sandbox-1"
_MARGIN = 30

# fatal signal -> (cwe, severity) for the confirmed crash finding
_SIG_CWE = {
    "SIGSEGV": ("CWE-119", "critical"), "SIGBUS": ("CWE-119", "critical"),
    "SIGABRT": ("CWE-787", "high"), "SIGFPE": ("CWE-369", "high"),
    "SIGILL": ("CWE-119", "high"),
}


def crash_finding_candidate(signal_name, input_sha, isolation, detector, extra="",
                            state="confirmed", confidence=0.9, bundle_sha=None):
    """Crash finding shared by the dynamic / fuzz / poc stages.

    dedup_key is (signal, input) so building a verified PoC from the same crashing input
    merges into and promotes the finding that dynamic/fuzz already confirmed.
    """
    cwe, sev = _SIG_CWE.get(signal_name, ("CWE-119", "high"))
    short = input_sha[:12] if input_sha else "(none)"
    detail = f"{signal_name} with input {short} [{isolation}]"
    if extra:
        detail += " " + extra
    evidence = [{"channel": "dynamic", "detail": detail}]
    if bundle_sha:
        evidence.append({"channel": "poc",
                         "detail": f"verified PoC bundle {bundle_sha[:12]}"})
    return {
        "cwe": cwe, "severity": sev, "state": state, "confidence": confidence,
        "detector": detector,
        "title": f"Reproduced crash ({signal_name}) under dynamic execution",
        "site_addr": None, "function_addr": None,
        # keyed by signal alone: without a faulting address we treat same-signal crashes as
        # one finding, so a verified PoC promotes the crash that dynamic/fuzz confirmed.
        "dedup_key": f"dynamic-crash:{signal_name}",
        "evidence": evidence,
    }


def dynamic_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("dynamic_run requires a target_id")

    params = ctx.params or {}
    mode = params.get("input_mode", "none")      # stdin | arg | file | none
    argv = list(params.get("argv") or [])
    timeout = float(params.get("timeout", 10))
    input_bytes = base64.b64decode(params["input_b64"]) if params.get("input_b64") else b""
    input_sha = ctx.put_artifact("dyn-input", data=input_bytes) if input_bytes else None
    stdin = input_bytes if mode == "stdin" else b""
    if mode == "arg" and input_bytes:
        argv = argv + [input_bytes.decode("latin-1")]
    elif mode == "file" and input_bytes:         # deliver the input as a file argument
        infile = ctx.scratch() / "input.bin"
        infile.write_bytes(input_bytes)
        argv = argv + [str(infile)]

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    ctx.progress(msg="detonating in sandbox")
    res = sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=target.arch,
                      endianness=target.endianness, bits=target.bits)

    stdout_sha = ctx.put_artifact("dyn-stdout", data=res.stdout) if res.stdout else None
    stderr_sha = ctx.put_artifact("dyn-stderr", data=res.stderr) if res.stderr else None
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=argv, exit_code=res.exit_code, signal=res.signal, signal_name=res.signal_name,
        crashed=res.crashed, timed_out=res.timed_out, isolation=res.isolation,
        duration_ms=res.duration_ms, stdout_sha=stdout_sha, stderr_sha=stderr_sha,
        note=res.note)

    ctx.emit("dynamic.done", payload={"crashed": res.crashed, "signal": res.signal_name,
                                      "timed_out": res.timed_out, "isolation": res.isolation,
                                      "note": res.note})

    if res.crashed:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, res.isolation, "dynamic"))

    ctx.progress(pct=100, msg=("crash " + (res.signal_name or "")) if res.crashed
                 else ("timeout" if res.timed_out else "clean exit"))
    return {"output_shas": [x for x in (stdout_sha, stderr_sha) if x],
            "output_kind": "dyn-output"}


def register() -> None:
    register_stage(DYNAMIC_STAGE, dynamic_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_dynamic(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, DYNAMIC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
