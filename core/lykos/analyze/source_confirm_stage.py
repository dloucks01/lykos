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
import os
import re

from ..db.dao import DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report
from .libfuzzer_stage import _materialize_source
from .symbolic import dwarfline

TOOL, TOOL_VERSION = "source_confirm", "source-confirm-1"

#: map an ASan class to a CWE for the finding (mirrors the libfuzzer stage's conventions).
_CWE = {"stack-buffer-overflow": "CWE-121", "heap-buffer-overflow": "CWE-122",
        "global-buffer-overflow": "CWE-787", "heap-use-after-free": "CWE-416",
        "stack-use-after-return": "CWE-562", "double-free": "CWE-415",
        "dynamic-stack-buffer-overflow": "CWE-121"}

#: the STATIC source detectors whose candidates a ladder crash can confirm by co-location.
_STATIC_SOURCE_DETECTORS = ("source_sink", "int_overflow", "uaf", "cve_source", "embedded_config")
_SRC_LOC = re.compile(r"([\w./+\-]+):(\d+)")


def _parse_loc(s):
    """(path, line) from a `path:line[:col]` string, or (None, None)."""
    m = _SRC_LOC.search(s or "")
    return (m.group(1), int(m.group(2))) if m else (None, None)


def _suffix_match(a, b) -> bool:
    """True when two source paths name the same file (one is a path-component suffix of the other --
    the relative candidate path vs the absolute build path the sanitizer prints)."""
    if not a or not b:
        return False
    a, b = a.replace("\\", "/"), b.replace("\\", "/")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _steer_sites(ctx, target) -> list:
    """The (basename, line) SITES of the static source candidates, to steer the concolic rung toward
    the statically-suspected bug LINES (not the enclosing function entry -- that would stop before the
    guard the defect sits behind). Resolved per harness against its own DWARF line table. Returns a
    de-duplicated, bounded list of (basename, line)."""
    sites: list = []
    seen: set = set()
    for f in FindingDAO(ctx.conn).list_by_target(target.id):
        if f.detector not in _STATIC_SOURCE_DETECTORS or len(sites) >= 128:
            continue
        fp = fline = None
        for e in (f.evidence or []):
            if e.get("channel") == "source":
                fp, fline = _parse_loc(e.get("detail"))
                if fp:
                    break
        if not fp or not fline:
            continue
        key = (os.path.basename(fp), fline)
        if key not in seen:
            seen.add(key)
            sites.append(key)
    return sites


def _crossref_static(ctx, target, src_line, crash_cwe, input_sha, harness) -> int:
    """Upgrade a co-located STATIC source candidate to `confirmed` when this ladder crash proves it:
    the crash's file:line matches the candidate's AND the CWE agrees. Sound -- an ASan fault at the
    exact site with a matching class confirms the statically-suspected defect there; a mismatched
    class is NOT treated as a confirmation (it stays a candidate). The upgrade is recorded on a
    distinct `dynamic-confirm` verdict channel, so the static channel's own verdict is preserved and
    the discoverer keeps credit. Returns how many candidates were upgraded."""
    ap, aline = _parse_loc(src_line)
    if ap is None or not crash_cwe:
        return 0
    fd = FindingDAO(ctx.conn)
    upgraded = 0
    for f in fd.list_by_target(target.id):
        if (f.detector not in _STATIC_SOURCE_DETECTORS or f.cwe != crash_cwe
                or (f.state or "candidate") not in ("candidate", "corroborated")):
            continue
        fp = fline = None
        for e in (f.evidence or []):
            if e.get("channel") == "source":
                fp, fline = _parse_loc(e.get("detail"))
                if fp:
                    break
        if fline != aline or not _suffix_match(ap, fp):
            continue
        fd.upsert(target.id, target.case_id, {
            "cwe": f.cwe, "title": f.title, "severity": f.severity or "high",
            "detector": f.detector, "dedup_key": f.dedup_key, "site_detail": f"{fp}:{fline}",
            "state": "confirmed", "confidence": 0.95, "channel": "dynamic-confirm",
            "evidence": [{"channel": "dynamic-confirm",
                          "detail": (f"confirmed by source_confirm: an ASan {crash_cwe} fault "
                                     f"reproduced at {src_line} via the {harness} harness "
                                     f"(input {input_sha[:12]})")}]})
        upgraded += 1
    return upgraded


def _file_confirmed(ctx, target, r) -> int:
    """File one ladder-confirmed bug: a CONFIRMED finding + a DynResult (so the exploit ladder can see
    it) + the reproducing input as an artifact, and CROSS-REFERENCE it against the static source
    candidates (a co-located, class-matching candidate is upgraded to confirmed). `r` is a
    confirm_ladder result. Returns the number of static candidates upgraded by this crash."""
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
    # A static candidate at the SAME site with the SAME class is now dynamically proven -- link and
    # upgrade it, so the discovery scanners' leads are promoted by the proof rather than left behind.
    return _crossref_static(ctx, target, src_line, cwe, input_sha, harness)


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

    # Build the harnesses for the ladder's rungs. The CONCOLIC rung needs STATIC harnesses (parser in
    # the ELF): a clean build for angr + an ASan build to confirm -- these fail on a project whose
    # static link needs unavailable deps (FreeRDP's static OpenSSL cascade), and that rung then simply
    # does not run. The SMART-FUZZ rung needs an ASan SHARED build, which succeeds where static does
    # not -- so it is always attempted, and is the floor that covers the projects concolic cannot.
    bslice = max(60, int(budget * 0.25))
    ctx.progress(msg="building in-tree harnesses (static clean+ASan for concolic, shared ASan for fuzz)")
    explore = LF.cmake_build_harnesses(src, shared=False, sanitize=False, timeout=bslice,
                                       build_name="_lykos_build_explore")
    replay = LF.cmake_build_harnesses(src, shared=False, sanitize=True, timeout=bslice,
                                      build_name="_lykos_build_replay")
    fuzzb = LF.cmake_build_harnesses(src, shared=True, sanitize=True, timeout=bslice,
                                     build_name="_lykos_build_fuzz")
    if not (explore["ok"] or fuzzb["ok"]):
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "could not build harnesses for confirmation (neither static nor shared linked)",
                 "log": (fuzzb["log"] or explore["log"])[-400:]})
        return {"metrics": {"supported": False, "built": False}}

    ex_by = {h["name"]: h for h in explore["harnesses"]} if explore["ok"] else {}
    rp_by = {h["name"]: h for h in replay["harnesses"]} if replay["ok"] else {}
    fz_by = {h["name"]: h for h in fuzzb["harnesses"]} if fuzzb["ok"] else {}
    # Finding-directed steering: the LINE sites of the static source candidates, to point the concolic
    # rung at the statically-suspected bug lines (resolved per harness against its own DWARF line
    # table). Only computed when a concolic (explore) build exists -- the only rung that consumes it --
    # so a project that builds only the shared harness (FreeRDP) pays nothing. Steering only affects
    # exploration efficiency, never soundness (the ASan replay + negative control still gate confirms).
    sites = _steer_sites(ctx, target) if ex_by else []
    names = sorted(set(ex_by) | set(fz_by))
    harnesses = []
    for n in names:
        d = {"name": n, "input_size": input_size, "lib_dirs": fuzzb.get("lib_dirs") or []}
        if n in ex_by and n in rp_by:                       # concolic (static clean + ASan)
            d["explore_binary"] = ex_by[n]["binary"]
            d["replay_binary"] = rp_by[n]["binary"]
            if sites:
                addrs = dwarfline.site_addrs(ex_by[n]["binary"], sites)
                if addrs:
                    d["targets"] = [hex(a) for a in addrs]
        if n in fz_by:                                      # smart-fuzz (shared ASan)
            d["fuzz_binary"] = fz_by[n]["binary"]
        if d.get("explore_binary") or d.get("fuzz_binary"):
            harnesses.append(d)
    if not harnesses:
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "no usable harness binaries after building"})
        return {"metrics": {"supported": False}}

    per = max(30, int((budget * 0.6) / max(1, len(harnesses))))
    proven = DC.confirm_ladder(harnesses, timeout_per=per, ctx=ctx)
    upgraded = 0
    for r in proven:
        upgraded += _file_confirmed(ctx, target, r)
        ctx.progress(msg=f"CONFIRMED (non-fuzzing {r.get('rung')}): {r.get('class')} "
                         f"via {r.get('harness')}")
    ctx.emit("source_confirm.done", payload={"supported": True, "harnesses": len(harnesses),
             "confirmed": len(proven), "upgraded": upgraded,
             "rungs": sorted({r.get("rung") for r in proven})})
    return {"metrics": {"supported": True, "harnesses": len(harnesses), "confirmed": len(proven),
                        "upgraded": upgraded}}


def register() -> None:
    register_stage("source_confirm", source_confirm_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_source_confirm(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "source_confirm", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
