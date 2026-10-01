"""The `cve_poc` stage: weaponize a version-matched CVE with a concrete trigger (CVE->exploit,
tier 3).

For each CVE on the target that has an authored trigger (poc.cve_triggers), this feeds the
trigger input to the target and records a VERIFIED reproduction only if the target actually
faults -- so a patched or unaffected target is never falsely flagged. A crash from a
known-CVE trigger is a demonstrated reach of that CVE in THIS binary, which the version match
alone could not prove.
"""
from __future__ import annotations

import logging
import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import cve_triggers

_log = logging.getLogger(__name__)

CVE_POC_STAGE = "cve_poc"
TOOL = "cve-poc"
TOOL_VERSION = "cve-poc-1"


def _matched_cves(fd, target) -> list:
    """(cve_id, finding) for the target's CVE findings (dedup_key is '<cve>:<lib>:<ver>')."""
    out = []
    for f in fd.list_by_target(target.id):
        if f.detector in ("cve_fingerprint", "cve_source"):
            cve = (f.dedup_key or "").split(":", 1)[0]
            if cve.upper().startswith("CVE-"):
                out.append((cve.upper(), f))
    return out


def _detonate(exe: str, trig, arch) -> "sandbox.RunResult | None":
    """Feed the trigger to the target on its channel; return the crashing RunResult or None."""
    if trig.channel in ("stdin", "stdin-slow"):
        r = sandbox.run(exe, stdin=trig.data, timeout=10, arch=arch)
        return r if r.crashed else None
    if trig.channel == "file":
        import tempfile
        d = tempfile.mkdtemp(prefix="lykos-cvepoc-")
        fp = os.path.join(d, "trigger.bin")
        with open(fp, "wb") as fh:
            fh.write(trig.data)
        try:
            r = sandbox.run(exe, argv=[fp], timeout=10, arch=arch)
            return r if r.crashed else None
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
    if trig.channel == "arg":
        r = sandbox.run(exe, argv=[trig.data], timeout=10, arch=arch)
        return r if r.crashed else None
    return None


def cve_poc_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cve_poc requires a target_id")
    fd = FindingDAO(ctx.conn)
    candidates = [(cve, f) for cve, f in _matched_cves(fd, target)
                  if cve in cve_triggers.available()]
    if not candidates:
        ctx.emit("cve_poc.done", payload={"applicable": False,
                 "note": "no matched CVE on this target has an authored trigger"})
        return {}

    exe = ctx.scratch() / "cve_target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    dd, pd = DynResultDAO(ctx.conn), PocDAO(ctx.conn)
    reproduced = []
    for cve, _finding in candidates:
        trig = cve_triggers.for_cve(cve)
        if trig is None:
            continue
        ctx.progress(msg=f"detonating {cve} trigger")
        res = _detonate(str(exe), trig, target.arch)
        if res is None:
            continue
        input_sha = ctx.put_artifact("cve-trigger-input", data=trig.data)
        iso = res.isolation or "cve-trigger"
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                  input_mode=trig.channel, signal=res.signal, signal_name=res.signal_name,
                  crashed=True, isolation=iso, note=f"{cve} trigger")
        try:
            pd.insert(target.id, target.case_id, level="L1", verified=True,
                      signal_name=res.signal_name, input_sha=input_sha)
        except Exception:
            _log.debug("recording cve_poc L1 failed", exc_info=True)
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, iso, "cve_poc",
            extra=f"({cve} trigger reproduced a fault -- {trig.note})",
            state="confirmed", confidence=0.95))
        reproduced.append(cve)

    ctx.emit("cve_poc.done", payload={"applicable": True, "tried": [c for c, _ in candidates],
             "reproduced": reproduced})
    ctx.progress(pct=100, msg=(f"reproduced {', '.join(reproduced)}" if reproduced
                               else "no CVE trigger reproduced a fault on this target"))
    return {}


def register() -> None:
    register_stage(CVE_POC_STAGE, cve_poc_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_cve_poc(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CVE_POC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
