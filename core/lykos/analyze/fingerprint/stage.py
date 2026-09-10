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
        fd.upsert(target.id, target.case_id, {
            "cwe": m["cwe"], "severity": m["severity"], "detector": "cve_fingerprint",
            "title": f"Vulnerable component: {label}",
            "evidence": [
                {"channel": "fingerprint",
                 "detail": f"detected {m['library']} {m['version']} via banner "
                           f"\"{m['evidence']}\""},
                {"channel": "cve",
                 "detail": f"{m['cve']}{cvss}: {m['summary']}"}],
            "function_addr": None, "site_addr": None,
            "dedup_key": f"{m['cve']}:{m['library']}:{m['version']}",
            "state": "corroborated", "confidence": 0.85})

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
