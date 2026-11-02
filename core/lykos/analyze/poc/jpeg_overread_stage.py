"""Stage: drive a JPEG/EXIF heap over-read to L1, directed, no fuzzing.

A JPEG-reading target that walks EXIF markers with unbounded section/offset arithmetic (the jhead
shape -- CVE-2020-26208 / CVE-2018-6612 / CVE-2020-6625) is reachable without a campaign: construct
the smallest VALID JPEG whose one malformed marker or EXIF field drives a read past the section the
parser allocated (`jpeg_overread.TRIGGERS`), then detonate it against the sanitizer build. The JPEG
is a valid container -- a raw oversized blob is rejected at the marker framing -- so a directed,
format-aware construction lands what a blind fuzzer does not.

Self-skipping and 0-FP: it runs only on a JPEG/EXIF-reading target, tries the documented triggers
in order, and files L1 only on an actual heap-buffer-overflow READ. The over-read bytes feed
internal comparisons / offset words here, so this is an honest L1 (a reproduced out-of-bounds
read), not a disclosure; the finding says so. The jhead instance that would reach L3 is the GPS
coordinate the over-read feeds into the printed summary -- a numeric disclosure oracle over a
complete JPEG -- which is the named next step, not claimed here.
"""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts)
from ..invocation import staged_name as _staged_name
from . import bundle, jpeg_overread

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
    ctx.progress(pct=100, msg=f"JPEG EXIF over-read: L1 reproduced ({trigger_name})")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(STAGE, jpeg_overread_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_jpeg_overread(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
