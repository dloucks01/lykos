"""Stage: drive a JPEG/EXIF heap over-read to L1, directed, no fuzzing.

A JPEG-reading target that walks EXIF markers with unbounded section/offset arithmetic (the jhead
shape -- CVE-2020-26208 / CVE-2018-6612 / CVE-2020-6625) is reachable without a campaign: construct
the smallest VALID JPEG whose one malformed marker or EXIF field drives a read past the section the
parser allocated (`jpeg_overread.TRIGGERS`), then detonate it against the sanitizer build. The JPEG
is a valid container -- a raw oversized blob is rejected at the marker framing -- so a directed,
format-aware construction lands what a blind fuzzer does not.

Self-skipping and 0-FP: it runs only on a JPEG/EXIF-reading target, tries the documented triggers
in order, and files L1 only on an actual heap-buffer-overflow READ. For the GPS over-read it then
drives the NON-instrumented build with a differential disclosure oracle (`gps_disclose` /
`confirm_gps_disclosure`): a complete JPEG whose GPS latitude DECLARES one component but whose
sub-IFD is followed by two more rationals jhead's fixed three-component loop reads and PRINTS as the
coordinate's minutes/seconds. Varying only those past-the-field bytes (declared degrees fixed)
changes the printed coordinate, so the output is demonstrably a function of memory the file never
declared -- a forgery-proof CWE-125/CWE-200 disclosure (L3). L3 is filed only when that oracle
confirms; otherwise the finding stays an honest L1.
"""
from __future__ import annotations

import os
import re

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts)
from ..invocation import staged_name as _staged_name
from . import bundle, jpeg_overread
from .capture import plain_build_bytes

_LAT_RE = re.compile(rb"Latitude\s*:\s*[NS?]\s+(\d+)d\s+(\d+)m\s+(\d+)s")

STAGE = "jpeg_overread"
TOOL = "jpegread"
TOOL_VERSION = "jpegread-1"

_JPEG_TOKENS = ("Exif", "JFIF", "Jpeg", "JPEG")


def _reads_jpeg(ctx, target) -> bool:
    """Does this target parse JPEG/EXIF? True when its recovered strings carry a JPEG/EXIF marker
    token -- the same evidence the format detector uses to seed a JPEG campaign."""
    try:
        for s in StringDAO(ctx.conn).list_by_target(target.id):
            v = getattr(s, "value", None)
            if v and any(tok in v for tok in _JPEG_TOKENS):
                return True
    except Exception:                                    # noqa: BLE001 -- gate is best-effort
        pass
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        return any(tok.encode() in data for tok in _JPEG_TOKENS)
    except Exception:                                    # noqa: BLE001
        return False


def _run(exe, jpeg_path, target, timeout):
    return sandbox.run(exe, argv=[str(jpeg_path)], stdin=b"", timeout=timeout,
                       arch=target.arch, endianness=target.endianness, bits=target.bits)


def jpeg_overread_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("jpeg_overread requires a target_id")
    p = ctx.params or {}
    timeout = float(p.get("timeout", 8))

    from .. import substrate
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, sandbox.host_arch(),
                                        "JPEG over-read")
           or substrate.native_only_reason(target.file_type, "JPEG over-read"))
    if why:
        ctx.emit("jpegread.done", payload={"applicable": False, "note": why})
        return {}
    if not _reads_jpeg(ctx, target):
        ctx.emit("jpegread.done", payload={"applicable": False,
                 "note": "target does not parse JPEG/EXIF (no JPEG marker token)"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    res, trigger_name, jdata = None, None, None
    for name, make in jpeg_overread.TRIGGERS:
        data = make()
        jpath = ctx.scratch() / f"overread_{name}.jpg"
        jpath.write_bytes(data)
        ctx.progress(msg=f"detonating a constructed JPEG over-read ({name})")
        r = _run(exe, jpath, target, timeout)
        if (r.crashed and r.stderr and b"heap-buffer-overflow" in r.stderr
                and b"READ of size" in r.stderr):
            res, trigger_name, jdata = r, name, data
            break
    if res is None:
        ctx.emit("jpegread.done", payload={"applicable": True,
                 "note": "no constructed JPEG reproduced a heap over-read READ here"})
        return {}

    mode, argv_base = "file", []
    input_sha = ctx.put_artifact("jpegread-crash-input", data=jdata)
    defect_key = asan_defect_key(res.stderr)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(argv_base), signal=res.signal, signal_name=res.signal_name, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note=f"constructed JPEG EXIF over-read ({trigger_name}); no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv_base, "expected_signal": res.signal_name, "isolation": res.isolation,
            "verified": True, "level": "L1", "constructed": True, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, jdata, meta, res.stderr, mode, argv_base,
                        res.signal_name or "SIGABRT")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=res.signal_name, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, res.isolation, "jpeg_overread",
        f"(constructed JPEG: a malformed EXIF field ({trigger_name}) -> heap over-read READ behind "
        "the JPEG parser; no fuzzing)",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc, file_type=target.file_type))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(res.signal_name, fault_pc, disc))
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("jpegread.l1", payload={"level": "L1", "bundle": bundle_sha, "input_sha": input_sha,
             "trigger": trigger_name})

    # L3: the GPS over-read feeds the PRINTED coordinate (CVE-2020-6625). On the uninstrumented
    # build, drive the differential disclosure oracle -- it reaches L3 only when the printed
    # latitude demonstrably carries bytes the JPEG never declared.
    l3 = _try_gps_disclose(ctx, target, bundle_sha, timeout)
    ctx.progress(pct=100, msg=f"JPEG EXIF over-read: L1 reproduced ({trigger_name})"
                 + (" + L3 disclosure" if l3 else ""))
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def _try_gps_disclose(ctx, target, l1_bundle_sha, timeout) -> bool:
    """Drive the GPS numeric-disclosure oracle on the NON-instrumented build. The sanitizer build
    aborts on the over-read before anything is printed; the plain build reads the past-the-field
    bytes and writes them into the coordinate it prints. Files L3 (CWE-200) only on confirmation."""
    plain = plain_build_bytes(ctx, target)
    if not plain:
        ctx.emit("jpegread.l3", payload={"ok": False, "need": "plain-build",
                 "note": "no uninstrumented build available to observe the disclosed coordinate"})
        return False
    pexe = ctx.scratch() / (_staged_name(ctx, target) + ".plain")
    pexe.write_bytes(plain)
    os.chmod(pexe, 0o755)

    def read_coord(smin, ssec):
        data = jpeg_overread.gps_disclose(sentinel_min=smin, sentinel_sec=ssec)
        jp = ctx.scratch() / "gps_disc.jpg"
        jp.write_bytes(data)
        r = _run(pexe, jp, target, timeout)
        out = (getattr(r, "stdout", b"") or b"") + (getattr(r, "stderr", b"") or b"")
        m = _LAT_RE.search(out)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None

    verdict = jpeg_overread.confirm_gps_disclosure(read_coord)
    if not verdict.get("disclosed"):
        ctx.emit("jpegread.l3", payload={"ok": False, "verdict": verdict})
        return False

    probes = verdict.get("probes") or []
    detail = ("constructed JPEG GPS over-read discloses EXIF bytes past the declared coordinate "
              "into the printed latitude (ProcessGpsInfo's fixed three-component loop, CVE-2020-6625): "
              f"the latitude declares one component ({verdict.get('degrees')}d) but two probes that "
              f"differ only in the past-the-field bytes print those exact bytes as minutes/seconds "
              f"({probes}). The printed coordinate is a function of memory the file never declared. "
              "No fuzzing.")
    disc_jpeg = jpeg_overread.gps_disclose(sentinel_min=31337, sentinel_sec=22251)
    disc_sha = ctx.put_artifact("jpegread-disclose-input", data=disc_jpeg,
                                meta={"level": "L3", "disclosure": verdict})
    dedup_key = f"CWE-200:jpeg-gps-disclose:{target.id}"
    ev = [{"channel": "disclosure", "detail": detail},
          {"channel": "poc", "detail": f"verified L1 over-read bundle {l1_bundle_sha[:12]}"}]
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=disc_sha, bundle_sha=l1_bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-200", "severity": "high", "detector": "jpeg_overread",
        "title": "Information disclosure (demonstrated): GPS over-read leaks EXIF bytes to output",
        "evidence": ev, "function_addr": None, "site_addr": None,
        "dedup_key": dedup_key, "state": "poc-backed", "confidence": 0.95})
    fid = fd.id_for_dedup(target.id, dedup_key)
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("jpegread.l3", payload={"ok": True, "level": "L3", "verdict": verdict,
             "input_sha": disc_sha})
    return True


def register() -> None:
    register_stage(STAGE, jpeg_overread_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_jpeg_overread(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
