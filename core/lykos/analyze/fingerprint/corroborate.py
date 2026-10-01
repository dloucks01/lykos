"""CVE <-> demonstrated-crash corroboration (CVE->exploit, tier 2).

A matched CVE says a component version is KNOWN-vulnerable; a confirmed crash / PoC says this
target demonstrably faults. When both are on the same target and their CWE classes agree, that is
a real triage signal -- but NOT proof the crash IS that CVE (we lack a fault-location->component
mapping). So this links them as *corroboration*, worded "consistent with / corroborated by", and
nudges confidence; it never promotes a CVE finding to poc-backed or claims the crash is the CVE.

Runs late (after fuzzing / PoC), reads the target's findings, and annotates both sides.
"""
from __future__ import annotations

import logging

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage

_log = logging.getLogger(__name__)

CORROBORATE_STAGE = "cve_corroborate"
TOOL = "cve-corroborate"
TOOL_VERSION = "cve-corroborate-1"

# CWE classes that are all "memory corruption" for the purpose of matching a crash to a CVE.
_MEM = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
        "CWE-787", "CWE-788", "CWE-416", "CWE-415", "CWE-476", "CWE-824", "CWE-822", "CWE-190",
        "CWE-131", "CWE-191", "CWE-20", "CWE-369"}
_CVE_DETECTORS = {"cve_fingerprint", "cve_source"}
# a finding that was actually demonstrated at runtime
_DEMO_STATES = {"confirmed", "poc-backed"}


def _family(cwe: str) -> str:
    return "memory" if (cwe or "") in _MEM else (cwe or "")


def corroborate_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cve_corroborate requires a target_id")
    fd = FindingDAO(ctx.conn)
    findings = fd.list_by_target(target.id)
    cves = [f for f in findings if f.detector in _CVE_DETECTORS]
    demos = [f for f in findings if f.state in _DEMO_STATES and f.detector not in _CVE_DETECTORS]
    if not cves or not demos:
        ctx.emit("cve_corroborate.done", payload={"cves": len(cves), "demonstrated": len(demos),
                 "links": 0, "note": "nothing to corroborate on this target"})
        return {}

    links = 0
    for cve in cves:
        matching = [d for d in demos if _family(d.cwe) == _family(cve.cwe)]
        if not matching:
            continue
        links += 1
        d = matching[0]
        # annotate the CVE finding: corroborated, but not proven to BE this crash.
        fd.upsert(target.id, target.case_id, {
            "cwe": cve.cwe, "title": cve.title, "severity": cve.severity, "state": cve.state,
            "detector": cve.detector, "dedup_key": cve.dedup_key,
            "confidence": min(0.92, (cve.confidence or 0.85) + 0.05),
            "evidence": [{"channel": "corroboration", "detail":
                          f"a demonstrated {d.cwe} finding in this target ({d.title[:70]}) is "
                          f"consistent with this CVE's class -- corroborating exposure, though "
                          f"not proven to be this CVE"}]})
        # annotate the demonstrated finding: a known CVE of a matching class is present.
        fd.upsert(target.id, target.case_id, {
            "cwe": d.cwe, "title": d.title, "severity": d.severity, "state": d.state,
            "detector": d.detector, "dedup_key": d.dedup_key, "confidence": d.confidence or 0.9,
            "evidence": [{"channel": "corroboration", "detail":
                          f"a known vulnerable component in this target ({cve.title[:70]}) is of "
                          f"a matching class; this crash may be a route to it"}]})

    ctx.emit("cve_corroborate.done", payload={"cves": len(cves), "demonstrated": len(demos),
             "links": links})
    ctx.progress(pct=100, msg=f"{links} CVE/crash corroboration link(s)")
    return {}


def register() -> None:
    register_stage(CORROBORATE_STAGE, corroborate_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=60)


def enqueue_cve_corroborate(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CORROBORATE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
