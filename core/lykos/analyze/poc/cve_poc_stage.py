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


# A resource-exhaustion DoS (decompression bomb, XML entity expansion) is "demonstrated" by the
# target being KILLED or hanging under a tight budget -- not by a crash signal. For those CWEs a
# timeout/OOM-kill counts as a fault; a tighter memory + time budget makes the bomb trip it.
_DOS_CWES = {"CWE-409", "CWE-776", "CWE-400", "CWE-770", "CWE-789"}


def _fault(trig, r) -> bool:
    if r is None:
        return False
    if r.crashed:
        return True
    return trig.cwe in _DOS_CWES and getattr(r, "timed_out", False)


def _detonate(exe: str, trig, arch) -> "sandbox.RunResult | None":
    """Feed the trigger to the target on its channel; return the faulting RunResult or None. For a
    DoS trigger a timeout/OOM-kill under a tight budget counts as the fault."""
    dos = trig.cwe in _DOS_CWES
    timeout = 6.0 if dos else 10.0
    mem_mb = 512 if dos else 2048                  # tight cap so a bomb OOM-kills, not just grows
    if trig.channel in ("stdin", "stdin-slow"):
        r = sandbox.run(exe, stdin=trig.data, timeout=timeout, arch=arch, mem_mb=mem_mb)
        return r if _fault(trig, r) else None
    if trig.channel == "file":
        import tempfile
        d = tempfile.mkdtemp(prefix="lykos-cvepoc-")
        fp = os.path.join(d, "trigger.bin")
        with open(fp, "wb") as fh:
            fh.write(trig.data)
        try:
            r = sandbox.run(exe, argv=[fp], timeout=timeout, arch=arch, mem_mb=mem_mb)
            return r if _fault(trig, r) else None
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
    if trig.channel == "arg":
        r = sandbox.run(exe, argv=[trig.data], timeout=timeout, arch=arch, mem_mb=mem_mb)
        return r if _fault(trig, r) else None
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

    def _record(label, trig, res, confidence):
        input_sha = ctx.put_artifact("cve-trigger-input", data=trig.data)
        iso = res.isolation or "cve-trigger"
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                  input_mode=trig.channel, signal=res.signal, signal_name=res.signal_name,
                  crashed=True, isolation=iso, note=f"{label} trigger")
        try:
            pd.insert(target.id, target.case_id, level="L1", verified=True,
                      signal_name=res.signal_name, input_sha=input_sha)
        except Exception:
            _log.debug("recording cve_poc L1 failed", exc_info=True)
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, iso, "cve_poc",
            extra=f"({label} trigger reproduced a fault -- {trig.note})",
            state="confirmed", confidence=confidence))

    # 1) hand-authored, CVE-specific triggers (highest fidelity).
    specific = [cve for cve, _ in candidates]
    for cve in specific:
        trig = cve_triggers.for_cve(cve)
        if trig is None:
            continue
        ctx.progress(msg=f"detonating {cve} trigger")
        res = _detonate(str(exe), trig, target.arch)
        if res is not None:
            _record(cve, trig, res, 0.95)
            reproduced.append(cve)

    DETONATION_CAP = 60
    budget = DETONATION_CAP

    # 2) library-level format triggers (e.g. zlib decompression bomb, XML billion-laughs): apply
    #    once per distinct matched library, stopping at the first fault.
    seen_lib = set()
    for cve, finding in candidates:
        if budget <= 0:
            break
        lib = (finding.dedup_key or "").split(":")[1] if (finding.dedup_key or "").count(":") >= 2 else ""
        if not lib or lib in seen_lib:
            continue
        seen_lib.add(lib)
        for trig in cve_triggers.library_triggers(lib):
            if budget <= 0:
                break
            budget -= 1
            res = _detonate(str(exe), trig, target.arch)
            if res is not None:
                _record(f"{cve} ({lib} {trig.cwe})", trig, res, 0.85)
                reproduced.append(f"{cve}:{lib}")
                break

    # 3) generic CWE-class weaponization for any matched CVE without a bespoke trigger: try the
    #    class payloads once per distinct CWE (bounded), stopping at the first fault per class.
    seen_cwe = set()
    for cve, finding in candidates:
        if cve_triggers.for_cve(cve) is not None or budget <= 0:
            continue
        cwe = finding.cwe
        if not cwe or cwe in seen_cwe:
            continue
        seen_cwe.add(cwe)
        for trig in cve_triggers.class_triggers(cwe):
            if budget <= 0:
                break
            budget -= 1
            res = _detonate(str(exe), trig, target.arch)
            if res is not None:
                _record(f"{cve} ({cwe} class)", trig, res, 0.8)
                reproduced.append(f"{cve}:class")
                break

    ctx.emit("cve_poc.done", payload={"applicable": True, "tried": specific,
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
