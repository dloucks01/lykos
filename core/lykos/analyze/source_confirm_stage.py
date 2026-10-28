"""Stage: NON-FUZZING confirmation of source-level bugs through a project's in-tree harnesses.

The primary weaponization path for a source target: build the project's in-tree libFuzzer harnesses
(the bytes->parser drivers), then run the confirmation LADDER (deterministic template -> concolic ->
directed smart-fuzz, smartest-first) to turn a candidate into a PROVEN memory-safety bug -- a concrete
ASan fault with a reproducing input, under a negative control. Discovery stays static; this confirms.

Fuzzing is NOT the discoverer here: it is only the floor rung of the ladder, under the deterministic
and solver rungs. The concolic rung needs STATIC harnesses (the parser linked into the ELF -- angr
loads auto_load_libs=False and would never see a parser left in a .so), so this builds static; a
project whose static link needs unavailable `-dev` packages declines that rung cleanly (the shared
smart-fuzz rung, B3, covers it) rather than fabricating a result.
"""
from __future__ import annotations

import hashlib

from ..db.dao import DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report
from .libfuzzer_stage import _materialize_source

TOOL, TOOL_VERSION = "source_confirm", "source-confirm-1"

#: map an ASan class to a CWE for the finding (mirrors the libfuzzer stage's conventions).
_CWE = {"stack-buffer-overflow": "CWE-121", "heap-buffer-overflow": "CWE-122",
        "global-buffer-overflow": "CWE-787", "heap-use-after-free": "CWE-416",
        "stack-use-after-return": "CWE-562", "double-free": "CWE-415",
        "dynamic-stack-buffer-overflow": "CWE-121"}


def _file_confirmed(ctx, target, r) -> None:
    """File one ladder-confirmed bug: a CONFIRMED finding + a DynResult (so the exploit ladder can see
    it) + the reproducing input as an artifact. `r` is a confirm_ladder result."""
    rep = r.get("report") or ""
    cls = parse_asan_report(rep) or {}
    klass = r.get("class") or cls.get("class") or "memory-safety fault"
    cwe = cls.get("cwe") or _CWE.get(klass, "CWE-119")
    src_line = r.get("source") or cls.get("source")
    key = src_line or hashlib.sha1(rep[:256].encode("latin-1", "ignore")).hexdigest()[:12]
    input_sha = ctx.put_artifact("source-confirm-input", data=r.get("input") or b"")
    rung, harness = r.get("rung", "?"), r.get("harness", "?")
    detail = (f"non-fuzzing ({rung}) confirmation: an input synthesised for the {harness} harness drove "
              f"{klass}" + (f" at {src_line}" if src_line else "")
              + f", reproduced under AddressSanitizer with a passing negative control "
              f"(crashing input {input_sha[:12]})")
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": cwe, "title": f"{klass} (confirmed, non-fuzzing {rung})", "severity": "high",
        "detector": TOOL, "state": "confirmed", "confidence": 0.95,
        "dedup_key": f"{cwe}:source_confirm:{key}", "function_addr": None, "site_addr": None,
        "site_detail": src_line,
        "evidence": [{"channel": "sanitizer", "detail": detail}]})
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, input_sha=input_sha, input_mode="file", argv=["@@"],
        crashed=True, signal_name=(cls.get("class") or klass),
        isolation=f"source_confirm/{harness}", defect_key=f"source_confirm:{key}",
        note=f"{rung} confirmation: {klass}" + (f" at {src_line}" if src_line else "")
             + f" [{harness}]")


def source_confirm_stage(ctx) -> dict:
    from . import libfuzzer as LF
    from .symbolic import directed_confirm as DC
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("source_confirm requires a target_id")
    p = ctx.params or {}
    budget = float(p.get("max_seconds") or p.get("seconds") or 600)
    input_size = int(p.get("input_size") or 1024)

    src = _materialize_source(ctx, target)
    if src is None:
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "no source tree for this target"})
        return {"metrics": {"supported": False}}
    if not LF.find_harnesses(src, limit=1):
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "no in-tree libFuzzer harness to drive the parser"})
        return {"metrics": {"supported": False}}

    # STATIC builds: clean (for angr to explore) + ASan (to confirm). A project whose static link
    # needs unavailable -dev packages fails here -- the concolic rung then has nothing to run, which
    # is reported, not faked.
    bslice = max(60, int(budget * 0.4))
    ctx.progress(msg="building in-tree harnesses (clean + ASan, static) for directed confirmation")
    explore = LF.cmake_build_harnesses(src, shared=False, sanitize=False, timeout=bslice,
                                       build_name="_lykos_build_explore")
    replay = LF.cmake_build_harnesses(src, shared=False, sanitize=True, timeout=bslice,
                                      build_name="_lykos_build_replay")
    if not (explore["ok"] and replay["ok"]):
        why = (explore["log"] if not explore["ok"] else replay["log"])[-400:]
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "could not build static harnesses for concolic confirmation "
                         "(a project needing unavailable static -dev libs declines this rung)",
                 "log": why})
        return {"metrics": {"supported": False, "built": False}}

    rp_by = {h["name"]: h for h in replay["harnesses"]}
    harnesses = [{"name": h["name"], "explore_binary": h["binary"],
                  "replay_binary": rp_by[h["name"]]["binary"], "lib_dirs": replay["lib_dirs"],
                  "input_size": input_size}
                 for h in explore["harnesses"] if h["name"] in rp_by]
    if not harnesses:
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "harness binaries did not pair across the clean and ASan builds"})
        return {"metrics": {"supported": False}}

    per = max(30, int((budget * 0.6) / max(1, len(harnesses))))
    proven = DC.confirm_ladder(harnesses, timeout_per=per, ctx=ctx)
    for r in proven:
        _file_confirmed(ctx, target, r)
        ctx.progress(msg=f"CONFIRMED (non-fuzzing {r.get('rung')}): {r.get('class')} "
                         f"via {r.get('harness')}")
    ctx.emit("source_confirm.done", payload={"supported": True, "harnesses": len(harnesses),
             "confirmed": len(proven), "rungs": sorted({r.get("rung") for r in proven})})
    return {"metrics": {"supported": True, "harnesses": len(harnesses), "confirmed": len(proven)}}


def register() -> None:
    register_stage("source_confirm", source_confirm_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_source_confirm(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "source_confirm", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
