"""Stage: drive a PNG palette over-read to L1 + L3, directed, no fuzzing.

A PNG-reading target that indexes its palette by a pixel value without checking the index against
the PLTE entry count (stb_image's `stbi__expand_png_palette` and many embedded readers) is
reachable without a campaign: construct the smallest valid indexed PNG whose palette is tiny and
whose pixels are out of range (`png_overread`), detonate it once against the sanitizer build (L1, a
reproduced heap over-read), then drive the NON-instrumented build over a family of such PNGs to
confirm a forgery-proof heap disclosure (L3) -- the palette index is an attacker-chosen read
offset, and the out-of-range bytes it discloses to the decoded output vary with that offset while
an in-bounds index returns the known palette entry.

Self-skipping and 0-FP: it runs only on a PNG-reading target, files L1 only on an actual
heap-buffer-overflow READ (confirmed whether ASan aborted or exited), and files L3 only when the
disclosure oracle confirms.
"""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts, sanitizer_hit)
from ..invocation import staged_name as _staged_name
from . import bundle, png_overread
from .capture import plain_build_bytes

STAGE = "png_overread"
TOOL = "pngread"
TOOL_VERSION = "pngread-1"

#: PNG signature + chunk/library tokens a decoder carries (structure.py's PNG token set).
_PNG_TOKENS = (b"\x89PNG\r\n\x1a\n", b"IHDR", b"IDAT", b"IEND", b"PLTE", b"libpng")
_PNG_STR_TOKENS = ("IHDR", "IEND", "PLTE", "PNG", "libpng")


def _reads_png(ctx, target) -> bool:
    """Does this target parse PNG? True when its strings carry a PNG chunk/library token (the decoder
    compares chunk names against them) -- the same evidence the format detector uses to seed a PNG
    campaign."""
    try:
        for s in StringDAO(ctx.conn).list_by_target(target.id):
            v = getattr(s, "value", None)
            if v and any(tok in v for tok in _PNG_STR_TOKENS):
                return True
    except Exception:                                    # noqa: BLE001 -- gate is best-effort
        pass
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        return any(tok in data for tok in _PNG_TOKENS)
    except Exception:                                    # noqa: BLE001
        return False


def _run(exe, png_path, target, timeout):
    return sandbox.run(exe, argv=[str(png_path)], stdin=b"", timeout=timeout,
                       arch=target.arch, endianness=target.endianness, bits=target.bits)


def png_overread_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("png_overread requires a target_id")
    p = ctx.params or {}
    timeout = float(p.get("timeout", 8))

    from .. import substrate
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, sandbox.host_arch(),
                                        "PNG palette over-read")
           or substrate.native_only_reason(target.file_type, "PNG palette over-read"))
    if why:
        ctx.emit("pngread.done", payload={"applicable": False, "note": why})
        return {}
    if not _reads_png(ctx, target):
        ctx.emit("pngread.done", payload={"applicable": False,
                 "note": "target does not parse PNG (no PNG chunk/signature token)"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    # L1: construct the over-indexed indexed PNG and detonate once against the sanitizer build.
    png = png_overread.png_overindexed(colors=2, index=255, width=64, height=8)
    ppath = ctx.scratch() / "overread.png"
    ppath.write_bytes(png)
    ctx.progress(msg="detonating a constructed over-indexed PNG (palette over-read)")
    res = _run(exe, ppath, target, timeout)
    # Confirmed whether ASan aborted or exited cleanly (run() does not force abort_on_error).
    if not sanitizer_hit(res, (b"heap-buffer-overflow", b"READ of size")):
        ctx.emit("pngread.done", payload={"applicable": True, "crashed": bool(res.crashed),
                 "note": "the constructed PNG did not reproduce a heap over-read READ here"})
        return {}

    mode, argv_base = "file", []
    input_sha = ctx.put_artifact("pngread-crash-input", data=png)
    eff_signal = res.signal_name or "SIGABRT"
    defect_key = asan_defect_key(res.stderr)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(argv_base), signal=res.signal, signal_name=eff_signal, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note="constructed PNG palette over-read; no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv_base, "expected_signal": eff_signal, "isolation": res.isolation,
            "verified": True, "level": "L1", "constructed": True, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, png, meta, res.stderr, mode, argv_base, eff_signal)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=eff_signal, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        eff_signal, input_sha, res.isolation, "png_overread",
        "(constructed PNG: a pixel index past the PLTE -> heap over-read READ; no fuzzing)",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc, file_type=target.file_type))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(eff_signal, fault_pc, disc))
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("pngread.l1", payload={"level": "L1", "bundle": bundle_sha, "input_sha": input_sha})

    # L3: disclosure on the NON-instrumented build (the sanitizer build poisons the over-read).
    l3 = _try_disclose(ctx, target, bundle_sha, timeout)
    ctx.progress(pct=100, msg=f"PNG palette over-read: L1 reproduced{' + L3 disclosure' if l3 else ''}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def _first_pixel(out: bytes):
    """The first decoded RGB triple in the target's output: a P6 PPM (skip its header), else the
    first three raw bytes. None when the output is too short."""
    if out[:2] == b"P6":
        # header: P6 <w> <h> <maxval> then one whitespace byte, then raw RGB
        toks, i, seen = out[2:], 2, 0
        n = len(out)
        while i < n and seen < 3:
            while i < n and out[i] in b" \t\r\n":
                i += 1
            while i < n and out[i] not in b" \t\r\n":
                i += 1
            seen += 1
        i += 1                                           # the single whitespace after maxval
        return (out[i], out[i + 1], out[i + 2]) if i + 2 < n else None
    return (out[0], out[1], out[2]) if len(out) >= 3 else None


def _try_disclose(ctx, target, l1_bundle_sha, timeout) -> bool:
    plain = plain_build_bytes(ctx, target)
    if not plain:
        ctx.emit("pngread.l3", payload={"ok": False, "need": "plain-build",
                 "note": "no uninstrumented build available to observe the disclosed bytes"})
        return False
    pexe = ctx.scratch() / (_staged_name(ctx, target) + ".plain")
    pexe.write_bytes(plain)
    os.chmod(pexe, 0o755)

    def read_pixel(png_bytes):
        pp = ctx.scratch() / "disc.png"
        pp.write_bytes(png_bytes)
        r = _run(pexe, pp, target, timeout)
        out = (getattr(r, "stdout", b"") or b"")
        return _first_pixel(out)

    verdict = png_overread.confirm_disclosure(read_pixel)
    if not verdict.get("disclosed"):
        ctx.emit("pngread.l3", payload={"ok": False, "verdict": verdict})
        return False

    detail = ("constructed PNG palette over-read discloses heap at an attacker-chosen offset "
              f"(palette index -> palette+index*stride): the in-bounds index returns the palette "
              f"entry {verdict.get('control')} (negative control); out-of-range indices disclose "
              f"distinct non-palette heap triples {verdict.get('leaked')} in the decoded output. "
              "No fuzzing.")
    disc_png = png_overread.png_overindexed(colors=2, index=160, width=64, height=8)
    disc_sha = ctx.put_artifact("pngread-disclose-input", data=disc_png,
                                meta={"level": "L3", "disclosure": verdict})
    dedup_key = f"CWE-200:png-palette-disclose:{target.id}"
    ev = [{"channel": "disclosure", "detail": detail},
          {"channel": "poc", "detail": f"verified L1 over-read bundle {l1_bundle_sha[:12]}"}]
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=disc_sha, bundle_sha=l1_bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-200", "severity": "high", "detector": "png_overread",
        "title": "Information disclosure (demonstrated): PNG palette over-read leaks heap to output",
        "evidence": ev, "function_addr": None, "site_addr": None,
        "dedup_key": dedup_key, "state": "poc-backed", "confidence": 0.95})
    fid = fd.id_for_dedup(target.id, dedup_key)
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("pngread.l3", payload={"ok": True, "level": "L3", "verdict": verdict,
             "input_sha": disc_sha})
    return True


def register() -> None:
    register_stage(STAGE, png_overread_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_png_overread(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
