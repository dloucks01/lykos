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
import time

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import cve_triggers, recipe

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


def _detonate(exe: str, trig, arch, endianness=None, bits=None) -> "sandbox.RunResult | None":
    """Feed the trigger to the target on its channel; return the faulting RunResult or None. For a
    DoS trigger a timeout/OOM-kill under a tight budget counts as the fault.

    endianness and bits MUST be forwarded to the sandbox: the ELF arch name is endianness- and
    word-blind (ppc64le and ppc64 are both "ppc64", mipsel is "mips", riscv is 32/64), so without
    them the sandbox routes a little-endian or 32/64-bit target to the WRONG qemu-user emulator,
    the target never runs, and a real reproduction is silently filed as "did not fault"."""
    dos = trig.cwe in _DOS_CWES
    timeout = 6.0 if dos else 10.0
    mem_mb = 512 if dos else 2048                  # tight cap so a bomb OOM-kills, not just grows
    kw = {"timeout": timeout, "arch": arch, "endianness": endianness, "bits": bits, "mem_mb": mem_mb}
    if trig.channel in ("stdin", "stdin-slow"):
        r = sandbox.run(exe, stdin=trig.data, **kw)
        return r if _fault(trig, r) else None
    if trig.channel == "file":
        import tempfile
        d = tempfile.mkdtemp(prefix="lykos-cvepoc-")
        fp = os.path.join(d, "trigger.bin")
        with open(fp, "wb") as fh:
            fh.write(trig.data)
        try:
            r = sandbox.run(exe, argv=[fp], **kw)
            return r if _fault(trig, r) else None
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
    if trig.channel == "arg":
        r = sandbox.run(exe, argv=[trig.data], **kw)
        return r if _fault(trig, r) else None
    return None


def _lib_of(finding) -> str:
    dk = finding.dedup_key or ""
    return dk.split(":")[1].lower() if dk.count(":") >= 2 else ""


# Bound the detonation phase: each run is up to ~10s, the stage timeout is 180s, so cap both the
# number of payloads and the wall-clock we spend firing them.
DETONATION_CAP = 60
WALLCLOCK_BUDGET = 150.0


def cve_poc_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cve_poc requires a target_id")
    fd = FindingDAO(ctx.conn)
    matched = _matched_cves(fd, target)
    # The weaponization plan covers bespoke, library-level AND generic CWE-class triggers -- so a
    # matched CVE with no bespoke trigger is still weaponized by its library and its CWE class.
    plan = cve_triggers.weaponization_plan(
        (cve, _lib_of(f), f.cwe) for cve, f in matched)
    if not plan:
        ctx.emit("cve_poc.done", payload={"applicable": False,
                 "note": ("no matched CVE on this target is weaponizable (no bespoke trigger, "
                          "no known-vulnerable library format attack, no CWE-class probe)")})
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

    deadline = time.monotonic() + WALLCLOCK_BUDGET
    fired = 0
    faulted_groups = set()          # a group ("lib:zlib"/"cwe:CWE-787") records one fault, then skips
    tried = []                      # items we detonated but did not reproduce -> become recipes
    for item in plan:
        if fired >= DETONATION_CAP or time.monotonic() >= deadline:
            break
        if item.group and item.group in faulted_groups:
            continue
        ctx.progress(msg=f"detonating {item.label}")
        fired += 1
        res = _detonate(str(exe), item.trigger, target.arch,
                        endianness=getattr(target, "endianness", None),
                        bits=getattr(target, "bits", None))
        if res is not None:
            _record(item.label, item.trigger, res, item.confidence)
            reproduced.append(item.label)
            if item.group:
                faulted_groups.add(item.group)
        else:
            tried.append(item)

    # NON-EXECUTED RECIPES: a CVE trigger that did not fault here is not proof of absence -- the
    # target may be unaffected OR could not be executed in this environment. The concrete trigger
    # input (the bytes + channel for a known CVE) is a deliverable regardless, so file it as a
    # corroborated recipe (deduped by group, capped) rather than discarding it.
    _file_cve_recipes(ctx, target, tried, faulted_groups, matched)

    bespoke_tried = [cve for cve, _f in matched if cve_triggers.for_cve(cve) is not None]
    ctx.emit("cve_poc.done", payload={"applicable": True, "bespoke_tried": bespoke_tried,
             "plan_size": len(plan), "fired": fired, "reproduced": reproduced})
    ctx.progress(pct=100, msg=(f"reproduced {', '.join(reproduced)}" if reproduced
                               else "no CVE trigger reproduced a fault on this target"))
    return {}


def _file_cve_recipes(ctx, target, tried, faulted_groups, matched) -> None:
    """One corroborated recipe per CVE trigger that was tried but did not fault here, carrying the
    concrete trigger bytes + channel. Deduped by group, capped. Honest via recipe.file_recipe."""
    cwe_lead = {}
    for _cve, _f in matched:
        if _f.cwe:
            cwe_lead.setdefault(_f.cwe, _f)
    seen, filed = set(), 0
    for item in tried:
        if filed >= 8:
            break
        grp = item.group or item.label
        if (item.group and item.group in faulted_groups) or grp in seen:
            continue
        seen.add(grp)
        trig = item.trigger
        cwe = getattr(trig, "cwe", None) or "CWE-1395"       # CWE-1395: vulnerable 3rd-party component
        lead = cwe_lead.get(cwe)
        try:
            data = bytes(trig.data) if trig.data is not None else b""
        except Exception:                                    # noqa: BLE001
            data = b""
        recipe.file_recipe(
            ctx, target, cwe=cwe, technique=f"CVE trigger ({item.label})", target_level="L1",
            severity="high", detector="cve_poc",
            dedup_key=f"recipe:cve:{item.label}:{target.id}",
            title=f"Exploitation recipe: {item.label} trigger",
            summary=(f"a concrete trigger for {item.label} is built ({len(data)} bytes over "
                     f"{trig.channel}); {getattr(trig, 'note', '') or 'feed it to reproduce the CVE'}"),
            why_not_executed=("the trigger did not fault here -- the target may be patched/unaffected "
                              "or could not be executed in this environment"),
            missing_technique=("a runnable build of the affected version to detonate the trigger "
                                "and confirm the target is the vulnerable version -- the trigger "
                                "bytes are already built"),
            lead=lead, input_bytes=data, input_mode=trig.channel)
        filed += 1


def register() -> None:
    register_stage(CVE_POC_STAGE, cve_poc_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_cve_poc(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CVE_POC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
