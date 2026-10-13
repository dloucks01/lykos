"""Phase 3 — the `cve_scan` stage: offline third-party-component CVE fingerprinting.

Scans the target's bytes for embedded library version banners (OpenSSL/zlib/libpng/busybox/
sqlite/curl/expat/dropbear...) and matches a vendored offline CVE database. For static and
stripped firmware binaries this is often the fastest path to a real, known-exploitable bug --
and it needs no execution and no fuzzing. Findings carry the component, its version, the CVE(s),
and the version banner that revealed it.
"""
from __future__ import annotations

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from . import scan

CVE_STAGE = "cve_scan"
TOOL = "cve"
TOOL_VERSION = "cve-1"


def cve_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cve_scan requires a target_id")

    blob = ctx.content.path(target.sha256).read_bytes()
    ctx.progress(msg="fingerprinting embedded components")
    detected, matches = scan.scan_and_match(blob)

    fd = FindingDAO(ctx.conn)
    for m in matches:
        label = f"{m['library']} {m['version']} — {m['cve']}"
        if m.get("name"):
            label += f" ({m['name']})"
        cvss = f", CVSS {m['cvss']}" if m.get("cvss") else ""
        evidence = [
            {"channel": "fingerprint",
             "detail": f"detected {m['library']} {m['version']} via banner \"{m['evidence']}\""},
            {"channel": "cve", "detail": f"{m['cve']}{cvss}: {m['summary']}"},
            # Say what this IS. A version match is a statement about the build, not about this
            # run: measured on libtiff 4.0.3, 108 CVEs matched and none was reached. Filed as a
            # `candidate` because that is the tier for "this may be here" -- `cve_corroborate`
            # raises it when a demonstrated finding of the same class turns up, and `cve_poc`
            # raises it further when a trigger actually reproduces. Filing a bare match at
            # `corroborated` made the top non-demonstrated tier mean nothing.
            {"channel": "reachability",
             "detail": "version match only: this build contains the affected version. Nothing in "
                       "this run reached the defect, so this is exposure, not a demonstration."}]
        evidence += scan.exploit_evidence(m["cwe"])
        fd.upsert(target.id, target.case_id, {
            "cwe": m["cwe"], "severity": m["severity"], "detector": "cve_fingerprint",
            "title": f"Vulnerable component: {label}",
            "evidence": evidence,
            "function_addr": None, "site_addr": None,
            "dedup_key": f"{m['cve']}:{m['library']}:{m['version']}",
            "state": "candidate", "confidence": 0.8})

    ctx.emit("cve.done", payload={
        "components": [{"library": d["library"], "version": d["version"]} for d in detected],
        "cves": [{"cve": m["cve"], "library": m["library"], "version": m["version"],
                  "severity": m["severity"]} for m in matches],
        "findings": len(matches),
        "note": None if detected else "no known component version banners found "
                "(stripped of version strings, or not a covered library)"})
    ctx.progress(pct=100, msg=f"{len(detected)} component(s), {len(matches)} CVE finding(s)")
    return {}


def register() -> None:
    register_stage(CVE_STAGE, cve_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_cve_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CVE_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
