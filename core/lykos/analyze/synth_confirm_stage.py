"""Stage: DRIVER SYNTHESIS FOR PROOF -- synthesize a libFuzzer driver for a candidate's function and
prove it. Discovery (static sinks, CPG queries, int-overflow, UAF) flags candidate functions; most of
them are not reached by any in-tree harness, so the confirmation ladder never gets to them. This
stage closes that loop: for each candidate function with a synthesisable signature, it synthesizes a
`(buf,size)` driver (build_libfuzzer), builds it with ASan+UBSan, and runs the smart-fuzz rung; a
concrete input that faults under the sanitizer -- with a passing empty-input negative control -- is a
proof, and it cross-references the originating static candidate up to `confirmed`.

HONEST CONTRACT: the synthesized driver calls the function with attacker-controlled (buf,size), so a
confirmation here is a reproduced fault OF THE FUNCTION under that assumption -- the same assumption an
in-tree parser harness makes -- recorded with the caveat that reachability from a real caller is not
separately proven. It is never a bare claim: there is always a concrete reproducing input and a
negative control. Deterministic, offline, no LLM.
"""
from __future__ import annotations

import hashlib

from ..db.dao import DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report
from .fingerprint import srctaint
from .libfuzzer_stage import _materialize_source
from .source_confirm_stage import _CWE, _crossref_static, _parse_loc, _STATIC_SOURCE_DETECTORS

TOOL, TOOL_VERSION = "synth_confirm", "synth-confirm-1"
_SKIP = ("sanitizer", "ubsan", "asan", "fuzzer", "llvm", "std::", "gnu_cxx")


def _candidate_functions(ctx, target, src_root, limit: int) -> list:
    """Enclosing function names of the as-yet-unproven source candidates -- the functions worth
    synthesizing a driver for. De-duplicated, project-looking, bounded. Best-effort: a file we cannot
    read or a line with no clean enclosing signature is skipped."""
    names: list = []
    seen: set = set()
    for f in FindingDAO(ctx.conn).list_by_target(target.id):
        if (f.detector not in _STATIC_SOURCE_DETECTORS
                or (f.state or "candidate") != "candidate" or len(names) >= limit):
            continue
        fp = fline = None
        for e in (f.evidence or []):
            if e.get("channel") == "source":
                fp, fline = _parse_loc(e.get("detail"))
                if fp:
                    break
        if not fp or not fline:
            continue
        try:
            lines = (src_root / fp).read_text(errors="ignore").splitlines()
        except OSError:
            continue
        nm = srctaint.enclosing_name(lines, fline - 1)
        if (nm and nm not in seen and not nm.startswith("_")
                and not any(s in nm.lower() for s in _SKIP)):
            seen.add(nm)
            names.append(nm)
    return names


def _file_confirmed(ctx, target, fn: str, res: dict) -> int:
    rep = res.get("report") or ""
    cls = parse_asan_report(rep) or {}
    klass = res.get("class") or cls.get("class") or "memory-safety fault"
    cwe = cls.get("cwe") or _CWE.get(klass, "CWE-119")
    src_line = res.get("source") or cls.get("source")
    input_sha = ctx.put_artifact("synth-confirm-input", data=res.get("input") or b"")
    detail = (f"proven via a SYNTHESIZED driver for {fn}(): a concrete input drove {klass}"
              + (f" at {src_line}" if src_line else "")
              + f", reproduced under AddressSanitizer with a passing empty-input negative control "
              f"(input {input_sha[:12]}). The driver calls {fn}() with attacker-controlled "
              f"(buffer,size); reachability from a specific caller is not separately proven here.")
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": cwe, "title": f"{klass} (confirmed via synthesized driver for {fn})",
        "severity": "high", "detector": TOOL, "state": "confirmed", "confidence": 0.9,
        "dedup_key": f"{cwe}:synth_confirm:{fn}:{src_line or hashlib.sha1(rep[:128].encode('latin-1','ignore')).hexdigest()[:8]}",
        "site_detail": src_line, "function_addr": None, "site_addr": None,
        "evidence": [{"channel": "sanitizer", "detail": detail}]})
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, input_sha=input_sha, input_mode="file", argv=["@@"],
        crashed=True, signal_name=(cls.get("class") or klass),
        isolation=f"synth_confirm/{fn}", defect_key=f"synth_confirm:{fn}",
        note=f"synthesized-driver confirmation: {klass}" + (f" at {src_line}" if src_line else ""))
    return _crossref_static(ctx, target, src_line, cwe, input_sha, f"synth:{fn}")


def synth_confirm_stage(ctx) -> dict:
    from . import libfuzzer as LF
    from .symbolic import directed_confirm as DC
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("synth_confirm requires a target_id")
    p = ctx.params or {}
    budget = float(p.get("max_seconds") or 300)
    max_fns = int(p.get("max_functions") or 12)

    src = _materialize_source(ctx, target)
    if src is None:
        ctx.emit("synth_confirm.done", payload={"supported": False, "note": "no source tree"})
        return {"metrics": {"supported": False}}
    names = _candidate_functions(ctx, target, src, max_fns)
    if not names:
        ctx.emit("synth_confirm.done", payload={"supported": False,
                 "note": "no unproven source candidates with an enclosing function to drive"})
        return {"metrics": {"supported": False}}

    from pathlib import Path
    per = max(30, int(budget / max(1, len(names))))
    synthesized = confirmed = upgraded = 0
    ctx.progress(msg=f"synthesizing drivers for {len(names)} candidate function(s)")
    for fn in names:
        out = Path(ctx.scratch()) / f"synthdrv_{fn[:40]}.bin"
        try:
            b = LF.build_libfuzzer(src, out, harness_fn=fn, timeout=max(60, per))
        except Exception:                                    # noqa: BLE001 -- unsynthesizable fn
            continue
        if not b.get("ok") or not b.get("binary"):
            continue                                         # not a synthesizable signature / no link
        synthesized += 1
        res = DC.smartfuzz_confirm(b["binary"], lib_dirs=b.get("lib_dirs"), seeds=[b"A" * 64],
                                   input_size=int(p.get("input_size") or 4096), timeout=per)
        if res.get("confirmed"):
            confirmed += 1
            upgraded += _file_confirmed(ctx, target, fn, res)
            ctx.progress(msg=f"CONFIRMED via synthesized driver: {res.get('class')} in {fn}()")
    ctx.emit("synth_confirm.done", payload={"supported": True, "candidates": len(names),
             "synthesized": synthesized, "confirmed": confirmed, "upgraded": upgraded})
    ctx.progress(pct=100, msg=f"synth drivers: {synthesized} built, {confirmed} confirmed")
    return {"metrics": {"supported": True, "synthesized": synthesized, "confirmed": confirmed,
                        "upgraded": upgraded}}


def register() -> None:
    register_stage("synth_confirm", synth_confirm_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_synth_confirm(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "synth_confirm", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
