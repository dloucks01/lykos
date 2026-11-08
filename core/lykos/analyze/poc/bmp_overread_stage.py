"""Stage: drive a BMP palette over-read to L1 + L3, directed, no fuzzing.

The BMP sibling of palette_overread / png_overread: an 8-bit indexed BMP with a tiny colour table
and pixels out of range drives a decoder that indexes the table by the pixel value to read past it
(an over-read that is also a disclosure). Self-skips on a non-BMP target; files L1 only on an actual
heap-buffer-overflow READ, and L3 only when the disclosure oracle confirms.
"""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts, sanitizer_hit)
from ..invocation import staged_name as _staged_name
from . import bmp_overread, bundle
from .capture import plain_build_bytes
from .png_overread_stage import _first_pixel

STAGE = "bmp_overread"
TOOL = "bmpread"
TOOL_VERSION = "bmpread-1"

_BMP_STR_TOKENS = ("BITMAPINFOHEADER", "BITMAPFILEHEADER", ".bmp", "bmp")


def _reads_bmp(ctx, target) -> bool:
    """Does this target parse BMP? True when its strings carry a BMP header/extension token -- the
    same evidence the format detector uses to seed a BMP campaign. (The 2-byte 'BM' magic alone is
    too common to gate on; a false-positive gate merely spends one self-skipping detonation.)"""
    try:
        for s in StringDAO(ctx.conn).list_by_target(target.id):
            v = getattr(s, "value", None)
            if v and any(tok in v for tok in _BMP_STR_TOKENS):
                return True
    except Exception:                                    # noqa: BLE001 -- gate is best-effort
        pass
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        return b"BITMAPINFOHEADER" in data or b"BITMAPFILEHEADER" in data
    except Exception:                                    # noqa: BLE001
        return False


def _run(exe, bmp_path, target, timeout):
    return sandbox.run(exe, argv=[str(bmp_path)], stdin=b"", timeout=timeout,
                       arch=target.arch, endianness=target.endianness, bits=target.bits)


def bmp_overread_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("bmp_overread requires a target_id")
    p = ctx.params or {}
    timeout = float(p.get("timeout", 8))

    from .. import substrate
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, sandbox.host_arch(),
                                        "BMP palette over-read")
           or substrate.native_only_reason(target.file_type, "BMP palette over-read"))
    if why:
        ctx.emit("bmpread.done", payload={"applicable": False, "note": why})
        return {}
    if not _reads_bmp(ctx, target):
        ctx.emit("bmpread.done", payload={"applicable": False,
                 "note": "target does not parse BMP (no BMP header/extension token)"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    bmp = bmp_overread.bmp_overindexed(colors=2, index=255, width=64, height=8)
    bpath = ctx.scratch() / "overread.bmp"
    bpath.write_bytes(bmp)
    ctx.progress(msg="detonating a constructed over-indexed BMP (palette over-read)")
    res = _run(exe, bpath, target, timeout)
    if not sanitizer_hit(res, (b"heap-buffer-overflow", b"READ of size")):
        ctx.emit("bmpread.done", payload={"applicable": True, "crashed": bool(res.crashed),
                 "note": "the constructed BMP did not reproduce a heap over-read READ here"})
        return {}

    mode, argv_base = "file", []
    input_sha = ctx.put_artifact("bmpread-crash-input", data=bmp)
    eff_signal = res.signal_name or "SIGABRT"
    defect_key = asan_defect_key(res.stderr)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(argv_base), signal=res.signal, signal_name=eff_signal, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note="constructed BMP palette over-read; no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv_base, "expected_signal": eff_signal, "isolation": res.isolation,
            "verified": True, "level": "L1", "constructed": True, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, bmp, meta, res.stderr, mode, argv_base, eff_signal)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=eff_signal, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        eff_signal, input_sha, res.isolation, "bmp_overread",
        "(constructed BMP: a pixel index past the colour table -> heap over-read READ; no fuzzing)",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc, file_type=target.file_type))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(eff_signal, fault_pc, disc))
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("bmpread.l1", payload={"level": "L1", "bundle": bundle_sha, "input_sha": input_sha})

    l3 = _try_disclose(ctx, target, bundle_sha, timeout)
    ctx.progress(pct=100, msg=f"BMP palette over-read: L1 reproduced{' + L3 disclosure' if l3 else ''}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def _try_disclose(ctx, target, l1_bundle_sha, timeout) -> bool:
    plain = plain_build_bytes(ctx, target)
    if not plain:
        ctx.emit("bmpread.l3", payload={"ok": False, "need": "plain-build",
                 "note": "no uninstrumented build available to observe the disclosed bytes"})
        return False
    pexe = ctx.scratch() / (_staged_name(ctx, target) + ".plain")
    pexe.write_bytes(plain)
    os.chmod(pexe, 0o755)

    def read_pixel(bmp_bytes):
        bp = ctx.scratch() / "disc.bmp"
        bp.write_bytes(bmp_bytes)
        r = _run(pexe, bp, target, timeout)
        return _first_pixel(getattr(r, "stdout", b"") or b"")

    verdict = bmp_overread.confirm_disclosure(read_pixel)
    if not verdict.get("disclosed"):
        ctx.emit("bmpread.l3", payload={"ok": False, "verdict": verdict})
        return False

    detail = ("constructed BMP palette over-read discloses memory at an attacker-chosen offset "
              f"(palette index -> table+index*stride): the in-bounds index returns the palette entry "
              f"{verdict.get('control')} (negative control); out-of-range indices disclose distinct "
              f"non-palette triples {verdict.get('leaked')} in the decoded output. No fuzzing.")
    disc_bmp = bmp_overread.bmp_overindexed(colors=2, index=160, width=64, height=8)
    disc_sha = ctx.put_artifact("bmpread-disclose-input", data=disc_bmp,
                                meta={"level": "L3", "disclosure": verdict})
    dedup_key = f"CWE-200:bmp-palette-disclose:{target.id}"
    ev = [{"channel": "disclosure", "detail": detail},
          {"channel": "poc", "detail": f"verified L1 over-read bundle {l1_bundle_sha[:12]}"}]
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=disc_sha, bundle_sha=l1_bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-200", "severity": "high", "detector": "bmp_overread",
        "title": "Information disclosure (demonstrated): BMP palette over-read leaks memory to output",
        "evidence": ev, "function_addr": None, "site_addr": None,
        "dedup_key": dedup_key, "state": "poc-backed", "confidence": 0.95})
    fid = fd.id_for_dedup(target.id, dedup_key)
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("bmpread.l3", payload={"ok": True, "level": "L3", "verdict": verdict,
             "input_sha": disc_sha})
    return True


def register() -> None:
    register_stage(STAGE, bmp_overread_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_bmp_overread(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
