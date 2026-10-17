"""Stage: coverage-guided libFuzzer fuzzing of a source target.

Builds an LLVMFuzzerTestOneInput harness (in-tree, as OSS projects ship, or synthesized for a
named entry function) with ASan+UBSan, runs libFuzzer for a budget, and files every crash it finds
as a CONFIRMED finding classified from the sanitizer report (bug class + source file:line) -- a real
bug with reproducible evidence and no CTF oracle. This is the coverage-guided complement to the
blind-havoc `fuzz` stage, and the only path that fuzzes LIBRARY source with no `main`.
"""
from __future__ import annotations

import hashlib
import io
import re
import tarfile
import time
from pathlib import Path

from ..db.dao import ArtifactDAO, DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .debug.rootcause import parse_asan_report

TOOL, TOOL_VERSION = "libfuzzer", "libfuzzer-1"

#: How many kept units to load at the start of a run (the cache may hold more).
LF_CORPUS_UNITS = 2000


def _materialize_source(ctx, target) -> Path | None:
    """Recover the target's source into a scratch directory: the archived source-project tree, or a
    single source-code file. None when the target was not built from source."""
    arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
    d = ctx.scratch() / "src"
    d.mkdir(parents=True, exist_ok=True)
    proj = next((a for a in arts if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj:
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for m in tf.getmembers():
                    if m.isfile() and not m.name.startswith("/") and ".." not in m.name:
                        tf.extract(m, d)
            return d
        except Exception:                                # noqa: BLE001
            return None
    single = next((a for a in arts if a.kind == "source-code"
                   and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if single:
        try:
            fn = (single.meta or {}).get("filename") or "a.c"
            (d / Path(fn).name).write_bytes(ctx.content.path(single.sha256).read_bytes())
            return d
        except Exception:                                # noqa: BLE001
            return None
    return None


def _corpus_cache(ctx, target):
    """Where this target's kept corpus lives: beside the case store, keyed by the binary."""
    try:
        root = Path(ctx.content.root)
    except Exception:                                    # noqa: BLE001 -- no store, no cache
        return None
    return root / "corpus-cache" / f"libfuzzer-{(target.sha256 or 'unknown')[:16]}"


def _units_in(d) -> list:
    """The units stored directly in one directory, smallest first."""
    if d is None or not Path(d).is_dir():
        return []
    out = []
    try:
        files = [f for f in Path(d).iterdir() if f.is_file()]
        for f in sorted(files, key=lambda x: x.stat().st_size):
            try:
                out.append(f.read_bytes())
            except OSError:
                continue
    except OSError:
        return []
    return out


def _load_corpus(cache, *, pool=None) -> list:
    """Units kept from earlier runs, this harness's own first.

    Best-effort: no cache at all is a cold start.

    `pool` is the target's whole corpus cache, which holds what the OTHER harnesses kept. Every
    entry point into one library consumes the same formats, so a unit that reached new coverage
    through one door is a strong seed for the next -- and the units kept before harnesses had
    their own directories live directly in the pool, so they are still used rather than orphaned.
    """
    own = _units_in(cache)
    if pool is None:
        return own[:LF_CORPUS_UNITS]
    seen = {bytes(u) for u in own}
    extra = []
    try:
        siblings = [d for d in sorted(Path(pool).iterdir()) if d.is_dir() and d != Path(cache)]
    except OSError:
        siblings = []
    for d in [Path(pool), *siblings]:
        for u in _units_in(d):
            if bytes(u) not in seen:
                seen.add(bytes(u))
                extra.append(u)
    return (own + extra)[:LF_CORPUS_UNITS]


def _save_corpus(cache, units: list) -> int:
    """Write the distilled corpus back, named by content hash so re-runs do not duplicate it.
    Returns how many units the cache holds afterwards."""
    if cache is None or not units:
        return 0
    from hashlib import sha256 as _sha
    try:
        cache.mkdir(parents=True, exist_ok=True)
        for u in units:
            if not u:
                continue
            f = cache / _sha(u).hexdigest()[:32]
            if not f.exists():
                f.write_bytes(u)
        return sum(1 for _ in cache.iterdir())
    except OSError:
        return 0


#: `known-library harness for <name>` -> the format model whose seeds that library parses.
_HARNESS_FORMAT = {"tiff": "tiff", "expat": "xml", "zlib": "gzip", "bzip2": "bzip2"}


def _known_format(harness_desc):
    """The format a known-library harness parses, from the description the builder returned."""
    for name, fmt in _HARNESS_FORMAT.items():
        if name in (harness_desc or ""):
            return fmt
    return None


def _format_corpus(ctx, target, prefer=None) -> list:
    """Valid seeds for every format this target looks like a reader for, strongest first.

    Reuses the fuzz stage's detection seam rather than restating it: the ranked detector reads
    the target's strings AND its import table, and the strongest candidate also gets the
    crash-shaped offset/size variants and one seed per codec. Best-effort -- no detection just
    means libFuzzer starts where it used to, from nothing.
    """
    try:
        from ..db.dao import StringDAO
        from .fuzz import structure
        from .fuzz.stage import _MAX_FORMATS, _imports_for
        svals = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)]
        try:
            imps = _imports_for(ctx, target)
        except Exception:                                # noqa: BLE001 -- imports are evidence,
            imps = []                                    # not a precondition
        out: list = []
        ranked = structure.detect_formats(svals, imps)[:_MAX_FORMATS]
        if prefer:                                       # the harness's own format leads
            ranked = [prefer] + [f for f in ranked if f != prefer]
        for i, fmt in enumerate(ranked):
            if i == 0:
                out += structure.boundary_seeds(fmt) or []
            else:
                one = structure.seed_for_name(fmt)
                if one:
                    out.append(one)
        return [b for b in out if b]
    except Exception:                                    # noqa: BLE001 -- never fail the stage
        return []


#: The least fuzzing worth doing with one harness. Below this the campaign measures the process
#: start-up, so a window that cannot afford it runs fewer harnesses rather than starving them all.
MIN_FUZZ_SECONDS = 20.0

#: What an artifact that is NOT a memory fault is evidence of. libFuzzer's `oom-` artifact means
#: the library allocated past the RSS limit on a small input -- a real resource-exhaustion defect
#: (libtiff has CVEs for exactly it) and NOT memory corruption. It is filed as what it is:
#: corroborated rather than confirmed, because the evidence is the fuzzer's own accounting rather
#: than a fault, and `crashed=False` on the run so the PoC ladder does not chase a crash that
#: never happened.
_KIND_CLAIM = {
    "oom": ("CWE-400", "uncontrolled memory allocation", "medium", "corroborated"),
    "timeout": ("CWE-835", "input that does not terminate", "medium", "corroborated"),
    "leak": ("CWE-401", "memory leak", "low", "corroborated"),
}


def _file_crash(ctx, target, fd, cr, *, harness_sha, harness_desc, entry, seen) -> bool:
    """File one libFuzzer artifact as a finding, and as a RUN so the ladder can see it.

    Returns True when something new was filed. Deduplicated on the fault site across every
    harness in the stage: two entry points reaching the same defect is one defect, and the
    evidence names the entry point that reached it first.
    """
    kind = cr.get("kind") or "crash"
    cls = parse_asan_report(cr.get("report") or "") or {}
    claim = _KIND_CLAIM.get(kind)
    if cls:
        cwe = cls.get("cwe", "CWE-787")
        title = cls.get("class") or "crash under libFuzzer"
        severity = cls.get("severity", "high")
        state, faulted = "confirmed", True
    elif claim:
        cwe, title, severity, state = claim
        faulted = False
    else:
        cwe, title, severity = "CWE-787", "crash under libFuzzer", "high"
        state, faulted = "confirmed", True
    src_line = cls.get("source")
    key = src_line or hashlib.sha1(
        ((cr.get("report") or "")[:256] + kind).encode("latin-1", "ignore")).hexdigest()[:12]
    if key in seen:
        return False
    seen.add(key)
    sanitizer = cls.get("sanitizer", "AddressSanitizer")
    try:
        input_sha = ctx.put_artifact("libfuzzer-crash-input", data=cr["input"])
        detail = (f"libFuzzer + {sanitizer} reproduced {title}" if faulted
                  else f"libFuzzer recorded {title}")
        fd.upsert(target.id, target.case_id, {
            "cwe": cwe, "title": f"{title} (libFuzzer)", "severity": severity,
            "detector": "libfuzzer", "state": state, "confidence": 0.92 if faulted else 0.7,
            "dedup_key": f"{cwe}:libfuzzer:{key}", "function_addr": None, "site_addr": None,
            "site_detail": src_line,
            "evidence": [{"channel": "sanitizer",
                          "detail": detail + (f" at {src_line}" if src_line else "")
                                    + f" through {entry}"
                                    + f" (crashing input {input_sha[:12]})"}]})
        # RECORD IT AS A RUN, or the ladder cannot see it. The prove loop iterates
        # `_distinct_crashes`, which reads the dyn_result table; this stage filed only a
        # Finding, so a genuine memory-corruption crash on a real library -- a
        # heap-buffer-overflow in libtiff's own `gtStripContig` allocation, found in 20
        # executions -- produced no PoC, no primitive and no exploit. The isolation tag names
        # the harness, which is how `build_poc` knows to replay against IT and not against the
        # ingested binary (the tool may never call the vulnerable path at all).
        DynResultDAO(ctx.conn).insert(
            target.id, target.case_id, input_sha=input_sha, input_mode="file",
            argv=["@@"], crashed=faulted,
            # The sanitizer CLASS, not a made-up signal: this fault was reported by ASan,
            # not delivered by the kernel, and `build_poc` records the same string when it
            # replays -- so defaulting to "SIGSEGV" here made a correct replay look like it
            # had reproduced a different fault than the campaign found.
            signal_name=(cls.get("class") or cls.get("signal_name")
                         or ("sanitizer-error" if faulted else kind)),
            isolation=f"libfuzzer/{harness_sha[:12]}" if harness_sha else "libfuzzer",
            defect_key=f"libfuzzer:{key}",
            note=(f"{sanitizer}: {title}" if faulted else f"libFuzzer: {title}")
                 + (f" at {src_line}" if src_line else "")
                 + f" [{entry} / {harness_desc}]")
        return True
    except Exception:                                    # noqa: BLE001
        return False


#: `clang` prints the diagnostics first and `N errors generated.` last, so a tail of the log is
#: the summary line and whatever scrolled past it -- the message that says WHAT went wrong is at
#: the top. libsndfile's failure read "...rated." in the row and the real cause ("use of
#: undeclared identifier 'psf_allocate'") was only in the full log nobody prints.
_FIRST_ERROR = re.compile(r"^.*?\b(?:error|fatal error):\s*(.{0,200})", re.M)
_UNDECLARED = re.compile(r"(?:use of undeclared identifier|implicit declaration of function|"
                         r"unknown type name)\s*'([^']+)'")


def _build_why(log: str) -> str:
    """One line saying why a harness did not build, naming the cause rather than the tail.

    A door whose symbol the harness cannot even DECLARE is a planning mistake, not a toolchain
    one -- the entry point was taken from a header the harness does not include, or from one the
    project keeps to itself -- so the note says so instead of leaving an operator to guess from
    `2 errors generated.`
    """
    log = log or ""
    first = _FIRST_ERROR.search(log)
    why = (first.group(1).strip() if first else log[-240:].strip()) or "no diagnostic"
    und = _UNDECLARED.search(log)
    if und:
        why = (f"the chosen entry point is not declared where the harness can see it: "
               f"'{und.group(1)}' -- {why}")
    return "libFuzzer build failed: " + why[:240]


def _fuzz_one(ctx, target, src, spec, *, seconds, cache, corpus_root, max_len, fd, seen) -> dict:
    """Build one harness and fuzz with it. Returns a row describing what it did."""
    from . import libfuzzer as LF
    row = {"id": spec["id"], "entry": spec.get("entry"), "kind": spec["kind"],
           "built": False, "execs": 0, "crashes": 0, "seconds": seconds}
    out = ctx.scratch() / f"lf-{spec['id']}.bin"
    build = LF.build_libfuzzer(src, out, spec=spec, cache=cache)
    if not build["ok"]:
        row["why"] = _build_why(build["log"])
        return row
    row["built"], row["harness"] = True, build["harness"]
    # SEED IT with the format this target reads. `run_libfuzzer` has always taken a corpus and
    # this caller never passed one, so the in-process engine started from an empty corpus and had
    # to invent a container format byte by byte -- while the pipeline already knows the format and
    # can synthesize a valid specimen plus one per codec. libFuzzer is coverage-guided, so a
    # structurally valid starting point is worth far more to it than to a blind mutator.
    # THE HARNESS KNOWS THE FORMAT. Strings-based detection ranked this statically-linked libtiff
    # build as another format it carries vocabulary for, so the campaign got 3 seeds instead of the
    # 19 the TIFF model produces (10 of them one per codec). When a known-library harness was
    # chosen, its name IS the format, which is better evidence than any ranking.
    corpus = _format_corpus(ctx, target, prefer=_known_format(build.get("harness")))
    # A corpus kept from EARLIER runs of this target, loaded before the format seeds. This is
    # what makes in-process fuzzing compound: a run that reached 1,208 new coverage units threw
    # all of them away, so the next run paid for the same coverage again. The cache lives beside
    # the case store, so it survives the case -- each `analyze` invocation creates a new case, and
    # per-case storage would persist nothing that matters.
    cache_dir = (corpus_root / spec["id"]) if corpus_root is not None else None
    kept = _load_corpus(cache_dir, pool=corpus_root)
    corpus = kept + [c for c in corpus if c not in kept]
    ctx.progress(msg=f"libFuzzer: {spec.get('entry')} for {int(seconds)}s"
                     + (f", {len(corpus)} seeds" if corpus else ""))
    res = LF.run_libfuzzer(build["binary"], ctx.scratch() / spec["id"], seconds=int(seconds),
                           max_len=max_len, corpus=corpus or None)
    row["execs"] = int(res.get("execs") or 0)
    row["corpus_in"] = len(corpus)
    row["corpus_kept"] = _save_corpus(cache_dir, res.get("corpus") or [])
    # KEEP THE HARNESS. A libFuzzer crash is a crash of the harness binary, not of the ingested
    # executable, so the harness is half the reproducer -- without it the finding carries a
    # crashing input nobody can replay. It is also what lets `build_poc` verify the crash instead
    # of replaying the input against a target that never calls the vulnerable path.
    harness_sha = None
    try:
        harness_sha = ctx.put_artifact("libfuzzer-harness", data=Path(build["binary"]).read_bytes(),
                                       meta={"harness": build["harness"], "target": target.sha256,
                                             "entry": spec.get("entry")})
    except Exception:                                    # noqa: BLE001 -- the finding still stands
        pass
    for cr in res["crashes"]:
        if _file_crash(ctx, target, fd, cr, harness_sha=harness_sha,
                       harness_desc=build["harness"], entry=spec.get("entry") or spec["id"],
                       seen=seen):
            row["crashes"] += 1
    row["artifacts"] = sorted({c.get("kind") or "crash" for c in res["crashes"]})
    return row


def libfuzzer_stage(ctx) -> dict:
    from . import libfuzzer as LF

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("libfuzzer requires a target_id")
    p = ctx.params or {}
    # HONOUR THE BUDGET SLICE. This read only `seconds` (default 30), so the orchestrator handed
    # the stage its slice as `max_seconds` and the stage ignored it: libFuzzer ran a 30-second
    # smoke test however much clock the case had -- the exact defect `orchestrate._run_target_stage`
    # describes for the campaigns that DO read it. On a library this is the most productive engine
    # there is (measured on libtiff 4.0.3: a sanitizer finding in 36 in-process executions, against
    # 14,821 external executions that found nothing), so it is the last stage that should be capped
    # at half a minute.
    seconds = float(p.get("seconds") or p.get("max_seconds") or 30)
    # WHICH ENTRY POINTS. A library is not one function: `plan_harnesses` ranks every door into it
    # and this runs a window of that ranking, so a second call can take the next few without
    # re-fuzzing the first. Defaults to the strongest one alone, which is what this stage always
    # did.
    first = max(0, int(p.get("harness_from") or 0))
    width = max(1, int(p.get("harness_max") or 1))

    src = _materialize_source(ctx, target)
    if src is None:
        ctx.emit("libfuzzer.done", payload={"supported": False,
                 "note": "no source for this target (libFuzzer needs C/C++ source to build a harness)"})
        return {"metrics": {"supported": False}}

    if p.get("harness_fn"):
        # NAMED BY THE CALLER, which is the API's single-stage launch and the one case where the
        # ranking has nothing to add: fuzz that function and no other. The rewrite that taught
        # this stage to walk a PLAN dropped the parameter on the floor, so a caller asking for a
        # specific entry point silently got the strongest one instead.
        plan = [LF.fn_spec(src, p["harness_fn"], p.get("harness_kind"))]
        window = plan
    else:
        # PLAN IN FULL, then take the window. Planning only as far as the window reaches made
        # `more_entry_points` structurally false on the first pass -- it compares the plan's
        # length against the end of the window, and with `limit=first+width` those are equal by
        # construction. So the second pass was never scheduled: libtiff reported DOOR 1/1 with
        # six doors in the tree. Planning costs 0.2-0.4s on a real library.
        # CONFIGURE BEFORE PLANNING. The plan is read off the tree's headers, and a tree
        # nobody has configured does not have the generated ones -- libsndfile's public
        # `sndfile.h` comes from `sndfile.h.in`, so on a pristine checkout the planner could
        # see only the internal API it is now required to ignore. The build has always
        # configured; it did it AFTER the door was chosen, which is one step too late. Cheap
        # when the tree is already configured, which in the pipeline it is.
        LF.ensure_configured(src)
        plan = LF.plan_harnesses(src, limit=max(first + width, LF.MAX_HARNESSES))
        window = plan[first:first + width]
    if not window:
        # A SECOND PASS WITH NOTHING LEFT TO DO is not a decline: the stage applies to this
        # target and already ran. Reporting `supported: false` here would have overwritten the
        # first pass's record and the scorecard would call the whole engine inapplicable.
        note = (f"no entry point ranked {first} or beyond; the plan holds {len(plan)}")
        ctx.emit("libfuzzer.done", payload={"supported": True, "crashes": 0, "execs": 0,
                 "entry_points": 0, "more_entry_points": False,
                 "next_entry_point": first, "note": note})
        ctx.progress(pct=100, msg=note[:90])
        return {"metrics": {"supported": True, "entry_points": 0}}

    # ONE COMPILE, MANY HARNESSES. Each harness links the same library objects, so without a
    # shared cache the second entry point would pay for libtiff's eighty translation units again:
    # measured 13.4 s for the first harness and 0.5 s for each of the next five.
    cache = LF.BuildCache(ctx.scratch() / "objs")
    corpus_root = _corpus_cache(ctx, target)
    fd = FindingDAO(ctx.conn)
    seen: set = set()
    rows: list = []
    # The slice is divided, not multiplied: `seconds` is what the budget allowed this stage, and
    # building counts against it. A harness that cannot be given `MIN_FUZZ_SECONDS` is left
    # unrun and SAID SO, rather than being run for two seconds and reported as a campaign.
    t0 = time.monotonic()
    for i, spec in enumerate(window):
        left = seconds - (time.monotonic() - t0)
        # DIVIDED AMONG WHAT IS LEFT TO DO, not among what the window started with. A fixed
        # `seconds / len(window)` share meant the time a FAILED door spent compiling was lost
        # to nobody's benefit: libsndfile's first door died in a compile error and the five
        # behind it were each still held to a sixth of the slice, so the stage finished early
        # with time unspent. Each door now gets an equal share of the time that remains.
        share = seconds if len(window) == 1 else max(MIN_FUZZ_SECONDS,
                                                    left / (len(window) - i))
        if len(window) > 1 and left < MIN_FUZZ_SECONDS:
            rows.append({"id": spec["id"], "entry": spec.get("entry"), "kind": spec["kind"],
                         "built": False, "execs": 0, "crashes": 0, "seconds": 0,
                         "why": "no budget left in this stage's slice"})
            continue
        rows.append(_fuzz_one(ctx, target, src, spec,
                              seconds=max(MIN_FUZZ_SECONDS, min(share, left)),
                              cache=cache, corpus_root=corpus_root,
                              max_len=int(p.get("max_len", 4096)), fd=fd, seen=seen))
    nxt = first + len(window)
    more = len(plan) > nxt
    built = [r for r in rows if r["built"]]
    if not built:
        why = next((r.get("why") for r in rows if r.get("why")), "no harness could be built")
        note = ("no LLVMFuzzerTestOneInput in the source; pass params.harness_fn to synthesize a "
                "harness for an entry function" if "no LLVMFuzzer" in why else why)
        # STILL SAY WHERE THE PLAN CONTINUES. A build failure on the top-ranked door says nothing
        # about the others -- the known-library harness failing for a missing header is exactly
        # the case the gate caught -- and reporting no successor here made one bad door close the
        # whole library.
        ctx.emit("libfuzzer.done", payload={"supported": False, "note": note,
                 "harnesses": rows, "entry_points": 0,
                 "next_entry_point": nxt, "more_entry_points": more})
        ctx.progress(pct=100, msg=note[:90])
        return {"metrics": {"supported": False, "more_entry_points": more}}
    found = sum(r["crashes"] for r in built)
    execs = sum(r["execs"] for r in built)
    # Report the WORK, not only the findings: how long it ran, what it started from and what the
    # kept corpus grew to. A stage that says only "0 crashes" cannot be told apart from one that
    # did nothing, which is the distinction the run's scorecard exists to make. Per harness, now
    # that there are several: an entry point that reached nothing and one that was never built
    # are different facts, and both belong in the operator's view.
    ctx.emit("libfuzzer.done", payload={
        "supported": True, "crashes": found, "execs": execs,
        "harness": built[0].get("harness"), "seconds": round(time.monotonic() - t0, 1),
        "entry_points": len(built), "harness_from": first,
        "next_entry_point": nxt, "more_entry_points": more,
        "corpus_in": sum(r.get("corpus_in") or 0 for r in built),
        "corpus_kept": max((r.get("corpus_kept") or 0) for r in built),
        "harnesses": rows,
        "note": "; ".join(f"{r.get('entry')}: {r['execs']:,} execs, {r['crashes']} finding(s)"
                          for r in built)})
    ctx.progress(pct=100, msg=f"libFuzzer: {found} finding(s) from {len(built)} entry point(s), "
                              f"{execs:,} executions")
    return {"metrics": {"supported": True, "crashes": found, "execs": execs,
                        "entry_points": len(built),
                        "corpus_kept": max((r.get("corpus_kept") or 0) for r in built)}}


def register() -> None:
    register_stage("libfuzzer", libfuzzer_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=600)


def enqueue_libfuzzer(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "libfuzzer", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
