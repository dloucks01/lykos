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


def _load_corpus(cache) -> list:
    """Units kept from earlier runs, smallest first. Best-effort: no cache means a cold start."""
    if cache is None or not cache.is_dir():
        return []
    out = []
    try:
        files = [f for f in cache.iterdir() if f.is_file()]
        for f in sorted(files, key=lambda x: x.stat().st_size):
            try:
                out.append(f.read_bytes())
            except OSError:
                continue
    except OSError:
        return []
    return out[:LF_CORPUS_UNITS]


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
    seconds = int(p.get("seconds") or p.get("max_seconds") or 30)

    src = _materialize_source(ctx, target)
    if src is None:
        ctx.emit("libfuzzer.done", payload={"supported": False,
                 "note": "no source for this target (libFuzzer needs C/C++ source to build a harness)"})
        return {"metrics": {"supported": False}}

    ctx.progress(msg="building the libFuzzer harness (ASan+UBSan)")
    out = ctx.scratch() / "lf.bin"
    build = LF.build_libfuzzer(src, out, harness_fn=p.get("harness_fn"),
                               harness_kind=p.get("harness_kind", "cstring"))
    if not build["ok"]:
        note = ("no LLVMFuzzerTestOneInput in the source; pass params.harness_fn to synthesize a "
                "harness for an entry function" if "no LLVMFuzzer" in build["log"]
                else "libFuzzer build failed: " + build["log"][-300:])
        ctx.emit("libfuzzer.done", payload={"supported": False, "note": note})
        ctx.progress(pct=100, msg=note[:90])
        return {"metrics": {"supported": False}}

    # SEED IT with the format this target reads. `run_libfuzzer` has always taken a corpus and
    # this caller never passed one, so the in-process engine started from an empty corpus and had
    # to invent a container format byte by byte -- while the pipeline already knows the format and
    # can synthesize a valid specimen plus one per codec. libFuzzer is coverage-guided, so a
    # structurally valid starting point is worth far more to it than to a blind mutator.
    # THE HARNESS KNOWS THE FORMAT. Strings-based detection ranked this statically-linked libtiff
    # build as another format it carries vocabulary for, so the campaign got 3 seeds instead of the
    # 19 the TIFF model produces (10 of them one per codec). When a known-library harness was
    # chosen, its name IS the format, which is better evidence than any ranking.
    known_fmt = _known_format(build.get("harness"))
    corpus = _format_corpus(ctx, target, prefer=known_fmt)
    # A corpus kept from EARLIER runs of this target, loaded before the format seeds. This is
    # what makes in-process fuzzing compound: a run that reached 1,208 new coverage units threw
    # all of them away, so the next run paid for the same coverage again. The cache lives beside
    # the case store, so it survives the case -- each `analyze` invocation creates a new case, and
    # per-case storage would persist nothing that matters.
    cache = _corpus_cache(ctx, target)
    kept = _load_corpus(cache)
    corpus = kept + [c for c in corpus if c not in kept]
    ctx.progress(msg=f"fuzzing with libFuzzer ({build['harness']}) for {seconds}s"
                     + (f", {len(corpus)} format seeds" if corpus else ""))
    res = LF.run_libfuzzer(build["binary"], ctx.scratch(), seconds=seconds,
                           max_len=int(p.get("max_len", 4096)), corpus=corpus or None)
    grown = _save_corpus(cache, res.get("corpus") or [])
    # KEEP THE HARNESS. A libFuzzer crash is a crash of the harness binary, not of the ingested
    # executable, so the harness is half the reproducer -- without it the finding carries a
    # crashing input nobody can replay. It is also what lets `build_poc` verify the crash instead
    # of replaying the input against a target that never calls the vulnerable path.
    harness_sha = None
    try:
        harness_sha = ctx.put_artifact("libfuzzer-harness", data=Path(build["binary"]).read_bytes(),
                                       meta={"harness": build["harness"], "target": target.sha256})
    except Exception:                                    # noqa: BLE001 -- the finding still stands
        pass

    fd = FindingDAO(ctx.conn)
    found, seen = 0, set()
    for cr in res["crashes"]:
        cls = parse_asan_report(cr.get("report") or "") or {}
        cwe = cls.get("cwe", "CWE-787")
        src_line = cls.get("source")
        key = src_line or hashlib.sha1((cr.get("report") or "")[:256].encode("latin-1", "ignore")).hexdigest()[:12]
        if key in seen:
            continue
        seen.add(key)
        try:
            input_sha = ctx.put_artifact("libfuzzer-crash-input", data=cr["input"])
            title = cls.get("class") or "crash under libFuzzer"
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": f"{title} (libFuzzer)", "severity": cls.get("severity", "high"),
                "detector": "libfuzzer", "state": "confirmed", "confidence": 0.92,
                "dedup_key": f"{cwe}:libfuzzer:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src_line,
                "evidence": [{"channel": "sanitizer",
                              "detail": f"libFuzzer + {cls.get('sanitizer', 'AddressSanitizer')} "
                                        f"reproduced {title}" + (f" at {src_line}" if src_line else "")
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
                argv=["@@"], crashed=True,
                # The sanitizer CLASS, not a made-up signal: this fault was reported by ASan,
                # not delivered by the kernel, and `build_poc` records the same string when it
                # replays -- so defaulting to "SIGSEGV" here made a correct replay look like it
                # had reproduced a different fault than the campaign found.
                signal_name=(cls.get("class") or cls.get("signal_name") or "sanitizer-error"),
                isolation=f"libfuzzer/{harness_sha[:12]}" if harness_sha else "libfuzzer",
                defect_key=f"libfuzzer:{key}",
                note=(f"{cls.get('sanitizer', 'AddressSanitizer')}: {title}"
                      + (f" at {src_line}" if src_line else "")))
            found += 1
        except Exception:                                # noqa: BLE001
            continue
    # Report the WORK, not only the findings: how long it ran, what it started from and what the
    # kept corpus grew to. A stage that says only "0 crashes" cannot be told apart from one that
    # did nothing, which is the distinction the run's scorecard exists to make.
    ctx.emit("libfuzzer.done", payload={"supported": True, "crashes": found,
             "harness": build["harness"], "seconds": seconds,
             "corpus_in": len(corpus), "corpus_kept": grown})
    ctx.progress(pct=100, msg=f"libFuzzer: {found} crash finding(s) via {build['harness']}"
                             + (f"; corpus {len(corpus)} -> {grown}" if grown else ""))
    return {"metrics": {"supported": True, "crashes": found,
                        "corpus_in": len(corpus), "corpus_kept": grown}}


def register() -> None:
    register_stage("libfuzzer", libfuzzer_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=600)


def enqueue_libfuzzer(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "libfuzzer", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
