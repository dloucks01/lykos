"""Stage: DRIVER SYNTHESIS FOR PROOF -- synthesize a libFuzzer driver for a candidate's function and
prove it. Discovery (static sinks, CPG queries, int-overflow, UAF) flags candidate functions; most of
them are not reached by any in-tree harness, so the confirmation ladder never gets to them. This
stage closes that loop: for each candidate function with a synthesisable signature, it synthesizes a
`(buf,size)` driver (build_libfuzzer), builds it with ASan+UBSan, and runs the smart-fuzz rung; a
concrete input that faults under the sanitizer -- with a passing empty-input negative control -- is a
proof, and it cross-references the originating static candidate up to `confirmed`.

Candidate functions come from two discoverers. (1) STATIC source detectors (file:line sinks), whose
enclosing function is driven and whose defect line steers the concolic rung. (2) UNDER-CONSTRAINED
symbolic execution (uc_symbolic): it enters UNDRIVEN functions in isolation and flags a data-derived
control-flow hijack -- functions no in-tree harness reaches and NO static detector pointed at. Routing
those UC leads through this same proof mechanism is what lets lykos confirm bugs other tools never
surface, while the confirmation bar is unchanged (a concrete faulting input + a negative control).

HONEST CONTRACT: the synthesized driver calls the function with attacker-controlled (buf,size), so a
confirmation here is a reproduced fault OF THE FUNCTION under that assumption -- the same assumption an
in-tree parser harness makes -- recorded with the caveat that reachability from a real caller is not
separately proven. It is never a bare claim: there is always a concrete reproducing input and a
negative control. Deterministic, offline, no LLM.
"""
from __future__ import annotations

import hashlib
import os as _os
import re as _re

from ..db.dao import DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report
from .fingerprint import srctaint
from .libfuzzer_stage import _materialize_source
from .source_confirm_stage import _CWE, _crossref_static, _parse_loc, _STATIC_SOURCE_DETECTORS

TOOL, TOOL_VERSION = "synth_confirm", "synth-confirm-1"
_SKIP = ("sanitizer", "ubsan", "asan", "fuzzer", "llvm", "std::", "gnu_cxx")
#: detector name under which uc_symbolic files its control-hijack discovery leads, and the shape of
#: its evidence detail ("...execution of <fn>() in isolation..."), from which the function name is
#: recovered -- a UC lead knows only the function NAME (it runs on the binary), not a source line.
_UC_TOOL = "uc_symbolic"
_UC_FN_RE = _re.compile(r"execution of ([A-Za-z_]\w*)\(\)")


def _candidate_functions(ctx, target, src_root, limit: int) -> list:
    """The as-yet-unproven source candidates worth synthesizing a driver for, as (fn, basename, line)
    -- the enclosing FUNCTION to drive AND the suspected bug SITE inside it, which steers the concolic
    rung toward the defect line (not merely the function entry). De-duplicated by function,
    project-looking, bounded. Best-effort: a file we cannot read or a line with no clean enclosing
    signature is skipped."""
    cands: list = []
    seen: set = set()
    for f in FindingDAO(ctx.conn).list_by_target(target.id):
        if (f.detector not in _STATIC_SOURCE_DETECTORS
                or (f.state or "candidate") != "candidate" or len(cands) >= limit):
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
            cands.append((nm, _os.path.basename(fp), fline))
    return cands


def _uc_candidate_functions(ctx, target, already, limit: int) -> list:
    """UC discovery leads worth synthesizing a driver for: UNDRIVEN functions where under-constrained
    symbolic execution saw data-derived control flow (a hijack candidate NO static detector pointed
    at). Each is `(fn, None, None)` -- UC runs on the binary and knows only the function NAME, so
    there is no source line to steer to; the driver loop steers to the function entry via
    `target_syms=[fn]`. The function name is recovered from the uc-symbolic evidence detail.
    De-duplicated against `already` (the static candidates) and bounded. This is the half that
    reaches functions the static-sink pipeline misses; the (buf,size)+sanitizer+negative-control
    confirmation contract is identical, so it adds no false-confirmation surface."""
    if limit <= 0:
        return []
    out: list = []
    seen = set(already)
    for f in FindingDAO(ctx.conn).list_by_target(target.id):
        if (f.detector != _UC_TOOL or (f.state or "candidate") != "candidate"
                or len(out) >= limit):
            continue
        fn = None
        for e in (f.evidence or []):
            if e.get("channel") == "uc-symbolic":
                m = _UC_FN_RE.search(e.get("detail") or "")
                if m:
                    fn = m.group(1)
                break
        if (fn and fn not in seen and not fn.startswith("_")
                and not any(s in fn.lower() for s in _SKIP)):
            seen.add(fn)
            out.append((fn, None, None))
    return out


def _fn_in_fault_stack(report: str, fn: str) -> bool:
    """True when `fn` is a frame of the sanitizer report's FAULTING stack (the first one, before any
    'allocated by'/'freed by' history) -- the fault happened in, or under, that function. A plain
    substring test would also match the allocation history or an unrelated symbol prefix."""
    head = _re.split(r"\n[^\n]*(?:allocated by|freed by|is located in)", report or "",
                     maxsplit=1)[0]
    return bool(_re.search(r"#\d+ 0x[0-9a-f]+ in " + _re.escape(fn) + r"\b", head))


def _link_uc_lead(ctx, target, fn: str, res: dict, proof_cwe: str, input_sha: str) -> bool:
    """Tie a UC control-hijack lead to the synthesized-driver proof that followed it up.

    Advances the lead to `corroborated` -- NOT `confirmed`: the proof is a memory-safety fault in the
    function under attacker-controlled (buf,size), which is how read data reaches the instruction
    pointer, but it does not itself demonstrate PC control, so claiming the CWE-94 hijack as
    confirmed would over-state it. Linked only when the function is in the FAULTING stack, so a fault
    the driver hit somewhere else never corroborates this lead. Returns whether the lead was linked."""
    if not _fn_in_fault_stack(res.get("report") or "", fn):
        return False
    lead = next((f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                 if f.detector == _UC_TOOL and f.dedup_key == f"uc:CWE-94:{target.id}:{fn}"), None)
    if lead is None:
        return False
    src_line = res.get("source") or ""
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": lead.cwe, "title": lead.title, "severity": lead.severity or "medium",
        "detector": lead.detector, "dedup_key": lead.dedup_key, "site_detail": fn,
        "state": "corroborated", "confidence": 0.6, "channel": "dynamic-confirm",
        "evidence": [{"channel": "dynamic-confirm",
                      "detail": (f"followed up by synth_confirm: a synthesized driver for {fn}() "
                                 f"reproduced a {proof_cwe} fault"
                                 + (f" at {src_line}" if src_line else "")
                                 + f" under AddressSanitizer with a passing negative control "
                                 f"(input {input_sha[:12]}; see the confirmed synth_confirm finding). "
                                 f"Instruction-pointer control itself is not demonstrated.")}]})
    return True


def _file_confirmed(ctx, target, fn: str, res: dict, *, from_uc: bool = False,
                    driver_sha: str | None = None) -> int:
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
        "evidence": [{"channel": "sanitizer", "detail": detail}]
                    + ([{"channel": "uc-symbolic",
                         "detail": f"discovered by under-constrained symbolic execution of {fn}(), "
                                   f"a function no harness or static detector reached"}]
                       if from_uc else [])})
    if from_uc:
        _link_uc_lead(ctx, target, fn, res, cwe, input_sha)
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, input_sha=input_sha, input_mode="file", argv=["@@"],
        crashed=True, signal_name=(cls.get("class") or klass),
        # The crash is a crash of the SYNTHESIZED DRIVER, not of the ingested program -- which may
        # never call `fn` at all (that is why it needed a driver). Tagged like a libFuzzer harness
        # crash so build_poc replays the input against the stored driver; tagged by function name,
        # the bundle packaged the ingested program, which exited 0 on the input ("verified: False").
        isolation=(f"libfuzzer/{driver_sha[:12]}" if driver_sha else f"synth_confirm/{fn}"),
        defect_key=f"synth_confirm:{fn}",
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
    cands = _candidate_functions(ctx, target, src, max_fns)
    # UC-discovered undriven functions (control-hijack leads no static detector flagged) get the same
    # proof treatment -- the 'find what others can't' half -- deduped against the static candidates.
    uc_cands = _uc_candidate_functions(ctx, target, {c[0] for c in cands}, max_fns - len(cands))
    uc_fns = {c[0] for c in uc_cands}
    cands += uc_cands
    if not cands:
        ctx.emit("synth_confirm.done", payload={"supported": False,
                 "note": "no unproven source/UC candidates with an enclosing function to drive"})
        return {"metrics": {"supported": False}}

    from pathlib import Path
    from . import driver_synth as DS
    from .symbolic import dwarfline
    per = max(30, int(budget / max(1, len(cands))))
    input_size = int(p.get("input_size") or 4096)
    synthesized = confirmed = upgraded = stream_synth = 0
    # STREAM-AWARE fallback (driver_synth): a protocol/format parser reads attacker bytes through a
    # project STREAM object and writes an opaque context -- a signature the plain (buf,size)
    # synthesizer rejects, so those parsers never reach a confirmation rung. Detect the project's
    # stream idiom ONCE (the scan is bounded but not free), and only then is the fallback attempted.
    idiom = DS.detect_stream_idiom(src)
    ctx.progress(msg=f"synthesizing drivers for {len(cands)} candidate function(s)"
                 + (f" (stream idiom: {idiom.name})" if idiom else ""))
    for fn, bn, line in cands:
        out = Path(ctx.scratch()) / f"synthdrv_{fn[:40]}.bin"
        lib_dirs = None
        try:
            b = LF.build_libfuzzer(src, out, harness_fn=fn, timeout=max(60, per))
        except Exception:                                    # noqa: BLE001 -- unsynthesizable fn
            b = {"ok": False}
        if not b.get("ok") or not b.get("binary"):
            # The plain synthesizer could not build a (buf,size) driver for this signature. If the
            # project has a stream idiom and this function is stream-synthesisable + exported, build
            # a stream-aware driver instead -- the half that reaches real parsers. Sound downstream:
            # the ladder's ASan replay + negative control is the only thing that confirms.
            if idiom is None:
                continue
            try:
                b = LF.build_stream_synth(src, out, fn=fn, sanitize=True, timeout=max(60, per))
            except Exception:                                # noqa: BLE001
                b = {"ok": False}
            if not b.get("ok") or not b.get("binary"):
                continue
            stream_synth += 1
            lib_dirs = b.get("lib_dirs")
        synthesized += 1
        # The EXPLORE build: the same synthesized driver with libFuzzer instrumentation only (no
        # ASan), which the concolic rung explores -- angr is confused by ASan's shadow memory.
        # Best-effort: if it does not build, concolic reuses the ASan binary (slower, still sound).
        explore = None
        ep = Path(ctx.scratch()) / f"synthdrv_{fn[:40]}.explore.bin"
        try:
            eb = LF.build_libfuzzer(src, ep, harness_fn=fn, timeout=max(60, per), sanitize=False)
            if not eb.get("ok") and idiom is not None:       # stream-synth explore (clean) variant
                eb = LF.build_stream_synth(src, ep, fn=fn, sanitize=False, timeout=max(60, per))
            if eb.get("ok"):
                explore = eb.get("binary")
                lib_dirs = lib_dirs or eb.get("lib_dirs")
        except Exception:                                    # noqa: BLE001
            explore = None
        explore = explore or b["binary"]
        # Steer the concolic rung. When DWARF resolves the suspected bug LINE, steer to THAT and NOT
        # the function entry: the entry is reached by any input, so adding it as a find target
        # short-circuits exploration there and the generated input skips the guard the defect sits
        # behind. The function name is only the fallback steer when DWARF cannot resolve the line.
        try:
            targets = dwarfline.site_addrs(explore, [(bn, line)]) if (bn and line) else []
        except Exception:                                    # noqa: BLE001
            targets = []
        harness = {"name": f"synth:{fn}", "explore_binary": explore,
                   "replay_binary": b["binary"], "fuzz_binary": b["binary"],
                   "lib_dirs": lib_dirs or b.get("lib_dirs"), "input_size": input_size,
                   "harness_fn": "LLVMFuzzerTestOneInput",
                   "target_syms": None if targets else [fn],
                   "targets": targets or None, "seeds": [b"A" * 64]}
        attempts: list = []
        proven = DC.confirm_ladder([harness], timeout_per=per, ctx=ctx, attempts_out=attempts)
        if proven:
            res = proven[0]
            confirmed += 1
            # KEEP THE DRIVER: it is half the reproducer (see libfuzzer_stage) -- the ASan build every
            # rung replayed the proving input against.
            driver_sha = None
            try:
                driver_sha = ctx.put_artifact(
                    "libfuzzer-harness", data=Path(b["binary"]).read_bytes(),
                    meta={"harness": b.get("harness"), "target": target.sha256,
                          "entry": f"{fn}()", "synthesized": True})
            except Exception:                                # noqa: BLE001 -- the finding still stands
                driver_sha = None
            upgraded += _file_confirmed(ctx, target, fn, res, from_uc=fn in uc_fns,
                                        driver_sha=driver_sha)
            ctx.progress(msg=f"CONFIRMED via synthesized driver ({res.get('rung')}): "
                             f"{res.get('class')} in {fn}()")
    ctx.emit("synth_confirm.done", payload={"supported": True, "candidates": len(cands),
             "synthesized": synthesized, "stream_synth": stream_synth,
             "stream_idiom": idiom.name if idiom else None,
             "confirmed": confirmed, "upgraded": upgraded})
    ctx.progress(pct=100, msg=f"synth drivers: {synthesized} built "
                 f"({stream_synth} stream-aware), {confirmed} confirmed")
    return {"metrics": {"supported": True, "synthesized": synthesized,
                        "stream_synth": stream_synth, "confirmed": confirmed,
                        "upgraded": upgraded}}


def register() -> None:
    register_stage("synth_confirm", synth_confirm_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_synth_confirm(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "synth_confirm", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
