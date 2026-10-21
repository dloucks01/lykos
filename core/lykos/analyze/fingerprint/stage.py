"""Phase 3 — the `cve_scan` stage: offline third-party-component CVE fingerprinting.

Scans the target's bytes for embedded library version banners (OpenSSL/zlib/libpng/busybox/
sqlite/curl/expat/dropbear...) and matches a vendored offline CVE database. For static and
stripped firmware binaries this is often the fastest path to a real, known-exploitable bug --
and it needs no execution and no fuzzing. Findings carry the component, its version, the CVE(s),
and the version banner that revealed it.
"""
from __future__ import annotations

import os
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from . import scan

CVE_STAGE = "cve_scan"
TOOL = "cve"
TOOL_VERSION = "cve-2"


def _needed_sonames(blob: bytes) -> list:
    """The target's DT_NEEDED shared libraries -- its component bill of materials, present even in
    a fully stripped binary (the dynamic section is load-bearing, never stripped)."""
    try:
        from ..elf import parse as _parse
        return list((_parse(blob).imports or {}).get("libraries") or [])
    except Exception:                                    # noqa: BLE001
        return []


def _dependency_blobs(ctx, target, sonames: list) -> list:
    """(soname, blob) for each DT_NEEDED library we can find -- so their version banners (which
    live in the .so, NOT in the main binary) can be scanned. Sources, in order: the companion
    files staged with the target (a directory ingest), then a `LYKOS_QEMU_SYSROOT` the operator
    supplied. Best-effort and deduped by soname."""
    out: list = []
    seen: set = set()
    want = set(sonames)

    def _take(name, blob):
        base = os.path.basename(name)
        if base in want and base not in seen and blob:
            seen.add(base)
            out.append((base, blob))

    # 1) companion deps recorded at ingest (directory ingest -> gather_bundle)
    for rel, sha in (getattr(target, "deps", None) or {}).items():
        try:
            _take(rel, ctx.content.get_bytes(sha))
        except Exception:                                # noqa: BLE001
            continue
    # 2) an operator-supplied sysroot (the same one used to RUN a dynamically-linked target)
    sr = os.environ.get("LYKOS_QEMU_SYSROOT")
    if sr and len(seen) < len(want):
        try:
            from ..dynamic.sandbox import _sysroot_lib_dirs
            for d in _sysroot_lib_dirs(sr):
                for name in sorted(os.listdir(d)):
                    if name in want and name not in seen:
                        try:
                            _take(name, (Path(d) / name).read_bytes())
                        except Exception:                # noqa: BLE001
                            continue
        except Exception:                                # noqa: BLE001
            pass
    return out


def cve_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cve_scan requires a target_id")

    blob = ctx.content.path(target.sha256).read_bytes()
    ctx.progress(msg="fingerprinting embedded components")
    detected, matches = scan.scan_and_match(blob)

    # A dynamically-linked target carries its component versions in its DEPENDENCY libraries, not
    # in the main binary -- OpenSSL/libxml2/sqlite banners live in libssl.so/libxml2.so/..., which
    # the scan above never saw. Scan each supplied dependency too (companions or a sysroot), and
    # attribute its matches to that soname. The DT_NEEDED list itself is the component BOM -- the
    # N-day surface -- even when no banner or .so is available.
    sonames = _needed_sonames(blob)
    dep_detected: list = []
    for soname, dblob in _dependency_blobs(ctx, target, sonames):
        d2, m2 = scan.scan_and_match(dblob)
        for d in d2:
            d["soname"] = soname
            dep_detected.append(d)
        for m in m2:
            m["soname"] = soname
            matches.append(m)
    detected = detected + dep_detected

    fd = FindingDAO(ctx.conn)
    for m in matches:
        in_dep = m.get("soname")
        label = f"{m['library']} {m['version']} — {m['cve']}"
        if m.get("name"):
            label += f" ({m['name']})"
        cvss = f", CVSS {m['cvss']}" if m.get("cvss") else ""
        where = (f" in the linked dependency {in_dep}" if in_dep
                 else " in the target binary")
        evidence = [
            {"channel": "fingerprint",
             "detail": f"detected {m['library']} {m['version']}{where} via banner "
                       f"\"{m['evidence']}\""},
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
            "dedup_key": f"{m['cve']}:{m['library']}:{m['version']}:{in_dep or 'main'}",
            "state": "candidate", "confidence": 0.8})

    # The DT_NEEDED bill of materials: the component surface to review for N-days, whether or not a
    # banner/.so was available for a precise version+CVE match. On a stripped binary this is often
    # the only identification channel, and it is still highly actionable (an analyst looks each up).
    scanned = {s for s, _ in _dependency_blobs(ctx, target, sonames)} if sonames else set()
    bom = [{"soname": s, "version_scanned": s in scanned} for s in sonames]
    if sonames:
        ctx.emit("cve.bom", payload={"needed": bom, "scanned": len(scanned),
                 "note": ("DT_NEEDED component surface. Libraries not version-scanned have no "
                          "supplied .so -- provide them (a directory ingest or LYKOS_QEMU_SYSROOT) "
                          "to resolve precise versions + CVEs; the sonames alone are N-day leads.")})
    ctx.emit("cve.done", payload={
        "components": [{"library": d["library"], "version": d["version"],
                        "soname": d.get("soname")} for d in detected],
        "cves": [{"cve": m["cve"], "library": m["library"], "version": m["version"],
                  "severity": m["severity"], "soname": m.get("soname")} for m in matches],
        "findings": len(matches), "needed": [b["soname"] for b in bom],
        "note": (None if detected else
                 ("no component version banners in the target or its supplied dependencies; "
                  f"{len(sonames)} DT_NEEDED libraries are the component surface to review"
                  if sonames else "no known component version banners found "
                  "(stripped of version strings, or not a covered library)"))})
    ctx.progress(pct=100, msg=f"{len(detected)} component(s), {len(matches)} CVE finding(s), "
                             f"{len(sonames)} linked libs")
    return {}


def register() -> None:
    register_stage(CVE_STAGE, cve_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_cve_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CVE_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
