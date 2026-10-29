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

#: the STATIC source detectors whose candidates a ladder crash can confirm by co-location (and whose
#: functions synth_confirm drives). Includes `cpg` (CWE-120/CWE-22 queries) and `source_sink`.
_STATIC_SOURCE_DETECTORS = ("source_sink", "cpg", "int_overflow", "uaf", "cve_source",
                            "embedded_config", "assert_guard", "oob_write")
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


#: detectors whose findings are ranked by attack-surface proximity (static source + the recipe floor).
_RANKABLE_DETECTORS = _STATIC_SOURCE_DETECTORS + ("source_recipe",)


def _project_libs(lib_dirs, limit: int = 24) -> list:
    """The project's OWN shared objects under the build's lib dirs -- the parser libraries angr
    force-loads to explore a shared harness. Bounded; system libs (/usr/lib) are never here."""
    from pathlib import Path as _P
    libs: list = []
    for d in (lib_dirs or []):
        try:
            libs += [str(p) for p in sorted(_P(d).glob("*.so*")) if p.is_file()]
        except OSError:
            pass
    return libs[:limit]


def _dt_needed(elf) -> set:
    """DT_NEEDED shared-lib basenames of an ELF (readelf -d, best-effort -> empty on failure)."""
    import shutil
    import subprocess
    rd = shutil.which("readelf")
    if not rd:
        return set()
    try:
        r = subprocess.run([rd, "-d", str(elf)], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return set(re.findall(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]", r.stdout or ""))


def _relevant_libs(harness_bin, project_libs) -> list:
    """The subset of `project_libs` the harness actually needs (its DT_NEEDED, closed one level over
    project libs), so angr force-loads ONLY those. Loading every project .so is the main cost that
    makes a big target cut off before reaching the parser; the harness that drives one parser rarely
    needs them all. Falls back to all project_libs when the NEEDED list cannot be read."""
    by_base = {os.path.basename(p): p for p in (project_libs or [])}
    needed = _dt_needed(harness_bin) & set(by_base)
    if not needed:
        return list(project_libs or [])
    seen, frontier = set(needed), list(needed)
    while frontier:
        for dep in _dt_needed(by_base[frontier.pop()]) & set(by_base):
            if dep not in seen:
                seen.add(dep)
                frontier.append(dep)
    return [by_base[b] for b in sorted(seen)]


#: calls that take a (ptr, size) pair but are NOT the parser the harness drives.
_NOT_PARSER_CALLS = frozenset({
    "LLVMFuzzerTestOneInput", "memcpy", "memmove", "memcmp", "memset", "bcopy", "fwrite", "fread",
    "write", "read", "malloc", "calloc", "realloc", "free", "printf", "fprintf", "puts", "strncmp",
    "strncpy", "strncat", "if", "for", "while", "switch", "return", "sizeof"})


def _parser_entry(source_path):
    """If the harness's LLVMFuzzerTestOneInput calls exactly ONE project function with its
    (data, size) arguments IN THAT ORDER (`FN(data, size)` / `FN((cast)data, size)`), return FN:
    angr can then enter directly at FN, skipping the harness wrapper -- SOUND, because that call is
    identical to what the harness does. None when the shape is not that clean (e.g. a parser taking a
    context object, `parse(ctx, data, size, ...)`), so concolic falls back to the wrapper rather than
    enter a function whose other arguments it cannot set up (which would crash spuriously)."""
    try:
        with open(source_path, "r", errors="ignore") as f:
            text = f.read()
    except (OSError, TypeError):
        return None
    m = re.search(r"LLVMFuzzerTestOneInput\s*\(\s*[^,(]*?\b(\w+)\s*,\s*[^,)(]*?\b(\w+)\s*\)", text)
    if not m:
        return None
    data_p, size_p = m.group(1), m.group(2)
    calls = re.findall(
        rf"\b([A-Za-z_]\w*)\s*\(\s*(?:\([^()]*\)\s*)?{re.escape(data_p)}\s*,\s*{re.escape(size_p)}\s*\)",
        text)
    uniq = sorted({c for c in calls if c not in _NOT_PARSER_CALLS})
    return uniq[0] if len(uniq) == 1 else None


def _attack_surface(harness_bins, lib_dirs) -> set:
    """The set of source-file basenames compiled into the fuzz target -- the harness ELFs plus the
    shared objects they link (where a shared build keeps the parser). Bounded so a huge project cannot
    make this run away; empty when no DWARF/objdump, in which case the caller ranks nothing."""
    from pathlib import Path as _P
    objs = list(harness_bins)
    for d in (lib_dirs or []):
        try:
            objs += [str(p) for p in sorted(_P(d).glob("*.so*"))][:40]
        except OSError:
            pass
    files: set = set()
    for o in objs[:60]:
        files |= dwarfline.source_files(o)
    return files


def _rank_by_surface(ctx, target, surface) -> dict:
    """Annotate the static source findings + recipes by whether their file is on the fuzzed attack
    surface. IN-surface findings are boosted (more actionable: the fuzzer actually exercises that
    file) and annotated; OUT-of-surface ones are annotated only -- never hidden or penalised, so a
    real bug off the fuzzed path is still reported, just lower in the ranking. Returns counts."""
    fd = FindingDAO(ctx.conn)
    inc = outc = 0
    for f in fd.list_by_target(target.id):
        if f.detector not in _RANKABLE_DETECTORS:
            continue
        base = None
        for e in (f.evidence or []):
            if e.get("channel") in ("source", "recipe-source"):
                fp, _ = _parse_loc(e.get("detail"))
                if fp:
                    base = os.path.basename(fp)
                    break
        if not base:
            continue
        on = base in surface
        if on:
            inc += 1
            detail = "on the fuzzed attack surface (its file is compiled into an in-tree fuzz harness)"
            newconf = min(0.9, (f.confidence or 0.0) + 0.15)
        else:
            outc += 1
            detail = ("off the fuzzed attack surface (its file is not compiled into any in-tree fuzz "
                      "harness -- e.g. a build tool, example, or platform-specific client); lower "
                      "remote-reachability priority, not dismissed")
            newconf = f.confidence or 0.0
        fd.upsert(target.id, target.case_id, {
            "cwe": f.cwe, "title": f.title, "severity": f.severity or "medium",
            "detector": f.detector, "dedup_key": f.dedup_key, "state": f.state,
            "confidence": newconf, "channel": "attack-surface",
            "evidence": [{"channel": "attack-surface", "detail": detail}]})
    return {"in_surface": inc, "off_surface": outc}


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
    # Config-keyed build dirs (the default): the shared-ASan fuzz build is shared with libfuzzer_stage
    # (built once, not twice); the static explore/replay builds are distinct configs with their own dirs.
    explore = LF.cmake_build_harnesses(src, shared=False, sanitize=False, timeout=bslice)
    replay = LF.cmake_build_harnesses(src, shared=False, sanitize=True, timeout=bslice)
    fuzzb = LF.cmake_build_harnesses(src, shared=True, sanitize=True, timeout=bslice)
    # When the STATIC explore link fails (FreeRDP's -dev cascade) but the shared build works, build a
    # SHARED-CLEAN explore so concolic still runs: angr explores it with the project's own .so
    # force-loaded (auto_load_libs stays off, so system libs stay stubbed). This is the concolic
    # unblock that needs no `-dev` packages.
    explore_sh = None
    if not explore["ok"] and fuzzb["ok"]:
        ctx.progress(msg="static explore link failed; building shared-clean explore for concolic")
        explore_sh = LF.cmake_build_harnesses(src, shared=True, sanitize=False, timeout=bslice)
    if not (explore["ok"] or fuzzb["ok"]):
        ctx.emit("source_confirm.done", payload={"supported": False,
                 "note": "could not build harnesses for confirmation (neither static nor shared linked)",
                 "log": (fuzzb["log"] or explore["log"])[-400:]})
        return {"metrics": {"supported": False, "built": False}}

    ex_by = {h["name"]: h for h in explore["harnesses"]} if explore["ok"] else {}
    rp_by = {h["name"]: h for h in replay["harnesses"]} if replay["ok"] else {}
    fz_by = {h["name"]: h for h in fuzzb["harnesses"]} if fuzzb["ok"] else {}
    exc_by = {h["name"]: h for h in explore_sh["harnesses"]} if (explore_sh and explore_sh["ok"]) else {}
    proj_libs = _project_libs(explore_sh.get("lib_dirs")) if exc_by else []
    # Finding-directed steering: the LINE sites of the static source candidates, to point the concolic
    # rung at the statically-suspected bug lines (resolved per harness against its own DWARF line
    # table). Only computed when a concolic (explore) build exists -- the only rung that consumes it.
    # Steering only affects exploration efficiency, never soundness (replay + negative control gate it).
    sites = _steer_sites(ctx, target) if (ex_by or exc_by) else []
    names = sorted(set(ex_by) | set(exc_by) | set(fz_by))
    harnesses = []
    for n in names:
        d = {"name": n, "input_size": input_size, "lib_dirs": fuzzb.get("lib_dirs") or []}
        exp = None
        if n in ex_by and n in rp_by:                       # concolic: static clean + static ASan
            exp = ex_by[n]["binary"]
            d["replay_binary"] = rp_by[n]["binary"]
        elif n in exc_by and n in fz_by:                    # concolic: shared clean + shared ASan (.so)
            exp = exc_by[n]["binary"]
            d["replay_binary"] = fz_by[n]["binary"]
            d["load_libs"] = _relevant_libs(exp, proj_libs)  # force-load ONLY the .so this harness needs
        if exp:
            d["explore_binary"] = exp
            # PARSER-ENTRY: if the harness drives a parser with a clean (data, size) call, enter angr
            # directly there, skipping the wrapper/context setup that eats the budget (falls back to
            # LLVMFuzzerTestOneInput otherwise -- see _parser_entry).
            fn = _parser_entry((ex_by.get(n) or exc_by.get(n) or fz_by.get(n) or {}).get("source"))
            if fn:
                d["harness_fn"] = fn
            if sites:
                addrs = dwarfline.site_addrs(exp, sites)
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

    # Honest build account: which harness variants linked. A failed build is WHY a rung is skipped
    # (concolic needs explore+replay; smart-fuzz needs fuzz), so report it rather than leave the skip
    # silent. A short log tail backs a failure.
    builds = {"explore": {"ok": bool(explore["ok"]), "harnesses": len(ex_by)},
              "replay": {"ok": bool(replay["ok"]), "harnesses": len(rp_by)},
              "fuzz": {"ok": bool(fuzzb["ok"]), "harnesses": len(fz_by)},
              "explore_shared": {"ok": bool(exc_by), "harnesses": len(exc_by),
                                 "libs": len(proj_libs)}}
    for name, b in (("explore", explore), ("replay", replay), ("fuzz", fuzzb)):
        if not b["ok"]:
            builds[name]["error"] = (b.get("log") or "")[-300:]

    # Attack-surface ranking: a static finding whose file is compiled into a fuzz harness (or the libs
    # it links) is on the surface the fuzzers exercise -> boost it over build tools / platform clients.
    ctx.progress(msg="ranking source findings by attack-surface proximity")
    surf_bins = [h["binary"] for h in (fuzzb["harnesses"] if fuzzb["ok"] else [])]
    surf_bins += [h["binary"] for h in (explore["harnesses"] if explore["ok"] else [])]
    surf_bins += [h["binary"] for h in exc_by.values()]
    surface = _attack_surface(surf_bins, fuzzb.get("lib_dirs") if fuzzb["ok"] else None) if surf_bins else set()
    ranked = _rank_by_surface(ctx, target, surface) if surface else {"in_surface": 0, "off_surface": 0}

    per = max(30, int((budget * 0.6) / max(1, len(harnesses))))
    attempts: list = []
    proven = DC.confirm_ladder(harnesses, timeout_per=per, ctx=ctx, attempts_out=attempts)
    upgraded = 0
    for r in proven:
        upgraded += _file_confirmed(ctx, target, r)
        ctx.progress(msg=f"CONFIRMED (non-fuzzing {r.get('rung')}): {r.get('class')} "
                         f"via {r.get('harness')}")
    # Surface the honest no-confirm account too: each rung that RAN and did not confirm, and each one
    # skipped and why -- so '0 confirmed' explains itself (concolic skipped: static link failed;
    # smart-fuzz ran N execs, no crash; or 0 execs = the harness never ran).
    for a in attempts:
        if a["outcome"] in ("no-confirm", "error"):
            ex = f", {a['execs']} execs" if a.get("execs") is not None else ""
            ctx.progress(msg=f"{a['rung']} on {a['harness']}: {a['outcome']} "
                             f"({a.get('reason') or ''}{ex})")
    ran = sum(1 for a in attempts if a["outcome"] in ("no-confirm", "confirmed", "error"))
    ctx.emit("source_confirm.done", payload={"supported": True, "harnesses": len(harnesses),
             "confirmed": len(proven), "upgraded": upgraded,
             "rungs": sorted({r.get("rung") for r in proven}),
             "builds": builds, "rungs_ran": ran, "attempts": attempts,
             "surface_files": len(surface), "ranked": ranked})
    return {"metrics": {"supported": True, "harnesses": len(harnesses), "confirmed": len(proven),
                        "upgraded": upgraded, "rungs_ran": ran,
                        "in_surface": ranked["in_surface"], "off_surface": ranked["off_surface"]}}


def register() -> None:
    register_stage("source_confirm", source_confirm_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_source_confirm(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "source_confirm", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
