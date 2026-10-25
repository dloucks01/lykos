"""Three operator scans as pipeline stages, so the API and GUI can run them (they were CLI-only):

  variant_scan  (target)  hunt a known-vulnerable function of THIS build across the case's other
                          targets -- the N-day variant hunt (`lykos variant-scan`).
  weggli_scan   (target)  run the weggli vulnerability-pattern pack over the target's archived
                          source tree (`lykos weggli-scan`).
  diff_test     (case)    differential testing: fuzz 2+ targets that implement the same thing and
                          report every input they disagree on (`lykos diff-test`).

All three reuse what the case already holds: recovered functions from the disassembly, the
archived source, the staged binaries. Results are candidates -- a similar function, a matched
pattern, a disagreement -- and are labelled so; nothing here sets a PoC level.
"""
from __future__ import annotations

import io
import random
import tarfile
import time
from pathlib import Path

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage

VARIANT_STAGE = "variant_scan"
WEGGLI_STAGE = "weggli_scan"
DIFF_STAGE = "diff_test"
TOOL = "lykos-scans"
TOOL_VERSION = "scans-1"

_MAX_HITS = 5              # matches kept per scanned target
_MAX_DISAGREEMENTS = 64


# --------------------------------------------------------------------------------- variant_scan
def _find_function(funcs, name: str):
    """The reference function by its name (a `sym.` / `dbg.` prefix is ignored), else None."""
    for f in funcs:
        n = f.get("name") or ""
        if n == name or n.split(".")[-1] == name:
            return f
    return None


def variant_scan_stage(ctx) -> dict:
    from . import variant
    from .patch_diff_stage import _funcs_for_fingerprint

    tdao = TargetDAO(ctx.conn)
    ref = tdao.get(ctx.target_id) if ctx.target_id else None
    if ref is None:
        raise ValueError("variant_scan requires a target_id (the reference build)")
    p = ctx.params or {}
    fname = str(p.get("function") or "").strip()
    if not fname:
        raise ValueError("variant_scan requires params.function (the vulnerable function's name)")
    try:
        threshold = min(1.0, max(0.0, float(p.get("threshold", 0.9))))
    except (TypeError, ValueError):
        threshold = 0.9
    ref_funcs = _funcs_for_fingerprint(ctx.conn, ref.id)
    if not ref_funcs:
        out = {"applicable": False, "function": fname, "reference": ref.filename,
               "note": "the reference target has no recovered functions -- disassemble it first"}
        ctx.emit("variant_scan.done", payload=out)
        return out
    sigf = _find_function(ref_funcs, fname)
    if sigf is None:
        out = {"applicable": False, "function": fname, "reference": ref.filename,
               "note": f"no function named {fname!r} in {ref.filename} "
                       f"({len(ref_funcs)} functions recovered)"}
        ctx.emit("variant_scan.done", payload=out)
        return out
    sig = variant.function_features(sigf)

    want = p.get("target_ids")
    others = [t for t in tdao.list_by_case(ref.case_id) if t.id != ref.id
              and (not want or t.id in want)]
    results = []
    for i, t in enumerate(others):
        ctx.check_cancel()
        ctx.progress(pct=100.0 * i / max(1, len(others)), msg=f"scanning {t.filename}")
        funcs = _funcs_for_fingerprint(ctx.conn, t.id)
        if not funcs:
            # Not scanned is not clean: say so per target.
            results.append({"target_id": t.id, "filename": t.filename, "scanned": False,
                            "note": "no recovered functions (not disassembled)", "hits": []})
            continue
        hits = variant.variant_scan(sig, funcs, threshold=threshold)[:_MAX_HITS]
        results.append({"target_id": t.id, "filename": t.filename, "scanned": True,
                        "functions": len(funcs), "hits": hits})
    matched = sum(1 for r in results if r["hits"])
    out = {"applicable": True, "function": sigf.get("name") or fname, "reference": ref.filename,
           "threshold": threshold, "results": results, "matched": matched,
           "scanned": sum(1 for r in results if r["scanned"]),
           "note": ("A match is a CANDIDATE unpatched variant: the shape matches; confirm the "
                    "defect is there (recompiled-but-fixed code can still look similar).")}
    if not others:
        out["note"] = "the case has no other targets to scan -- upload the builds to hunt across"
    ctx.emit("variant_scan.done", payload={k: v for k, v in out.items() if k != "results"})
    ctx.progress(pct=100, msg=f"variant_scan: {matched} of {len(others)} target(s) match")
    return out


# ---------------------------------------------------------------------------------- weggli_scan
def _unpack_source(ctx, proj, dest: Path) -> bool:
    """Unpack the archived source tree (tar.gz) into dest -- regular files, relative paths only."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, dest, filter="data")
    except Exception:                                    # noqa: BLE001 -- reported, not raised
        return False
    return True


def weggli_scan_stage(ctx) -> dict:
    from . import weggli
    from .source_lookup import source_project_for

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("weggli_scan requires a target_id")
    p = ctx.params or {}
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        out = {"applicable": False,
               "note": "no archived source tree for this target (weggli reads C/C++ source)"}
        ctx.emit("weggli_scan.done", payload=out)
        return out
    root = ctx.scratch() / "weggli-src"
    if not _unpack_source(ctx, proj, root):
        out = {"applicable": False, "note": "could not unpack the archived source tree"}
        ctx.emit("weggli_scan.done", payload=out)
        return out
    ctx.progress(msg="running the weggli vulnerability-pattern pack")
    r = weggli.scan(root, cpp=bool(p.get("cpp")), timeout=float(p.get("query_timeout", 120)))
    if not r.get("supported"):
        out = {"applicable": False, "note": r.get("note") or "weggli unavailable"}
        ctx.emit("weggli_scan.done", level="warn", payload=out)
        return out
    fd = FindingDAO(ctx.conn)
    rows = []
    for f in r.get("findings") or []:
        files = [str(Path(x).relative_to(root)) if str(x).startswith(str(root)) else str(x)
                 for x in f.get("files") or []]
        rows.append({"name": f["name"], "cwe": f["cwe"], "severity": f["severity"],
                     "why": f["why"], "count": f["count"], "files": files[:20]})
        shown = ", ".join(files[:6]) + (f" (+{len(files) - 6} more)" if len(files) > 6 else "")
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "weggli",
            "title": f"weggli pattern '{f['name']}' matched {f['count']}x"[:200],
            "state": "candidate", "confidence": 0.35, "function_addr": None, "site_addr": None,
            "dedup_key": f"weggli:{f['name']}",
            "evidence": [{"channel": "source",
                          "detail": f"{f['why']} Matched in: {shown}. A pattern match is a "
                                    f"candidate -- confirm untrusted input reaches it."}]})
    out = {"applicable": True, "queries_run": r.get("queries_run"), "findings": rows,
           "queries_failed": len(r.get("queries_failed") or []), "note": r.get("note")}
    ctx.emit("weggli_scan.done", payload={k: v for k, v in out.items() if k != "findings"}
             | {"matched": len(rows)})
    ctx.progress(pct=100, msg=f"weggli: {len(rows)} pattern(s) matched "
                              f"({r.get('queries_run')} queries)")
    return out


# ------------------------------------------------------------------------------------ diff_test
def diff_test_stage(ctx) -> dict:
    from .fuzz import differential as D

    p = ctx.params or {}
    tdao = TargetDAO(ctx.conn)
    ids = [x for x in (p.get("target_ids") or []) if isinstance(x, str)]
    targets = [t for t in (tdao.get(x) for x in dict.fromkeys(ids))
               if t is not None and t.case_id == ctx.case_id]
    if len(targets) < 2:
        out = {"applicable": False,
               "note": "differential testing needs 2+ targets from this case (params.target_ids)"}
        ctx.emit("diff_test.done", payload=out)
        return out
    mode = p.get("mode") if p.get("mode") in ("stdin", "arg", "file") else "stdin"
    compare = p.get("compare") if p.get("compare") in ("status", "output") else "status"
    iterations = max(1, min(int(p.get("iterations") or 2000), 100_000))
    timeout = float(p.get("timeout") or 5.0)
    budget = float(p.get("max_seconds") or 300.0)
    progs = []
    for t in targets:
        d = ctx.scratch() / f"impl-{t.id[:8]}"
        exe = ctx.content.stage_target(t, d, "target.bin")
        progs.append(D.Program(t.filename or t.id[:8], str(exe), mode=mode, arch=t.arch,
                               endianness=t.endianness, bits=t.bits))
    seeds = []
    for fp in p.get("seed_files") or []:
        try:
            seeds.append(Path(fp).read_bytes()[:1 << 20])
        except OSError:
            continue
    ctx.progress(msg=f"differential testing {len(progs)} implementations ({mode}, {compare})")

    def _cancelled() -> bool:
        try:
            ctx.check_cancel()
        except Exception:                                # noqa: BLE001 -- the cancel signal
            return True
        return False
    st = D.differential_campaign(progs, seeds, rng=random.Random(int(p.get("seed") or 0)),
                                 iterations=iterations, timeout=timeout, compare=compare,
                                 max_findings=_MAX_DISAGREEMENTS,
                                 deadline=time.monotonic() + budget, should_stop=_cancelled)
    if st.stopped == "cancelled":
        ctx.check_cancel()                               # raise the job's own cancellation
    inc = {n: c for n, c in (st.inconclusive or {}).items() if c}
    live = [g.name for g in progs if inc.get(g.name, 0) < max(1, st.execs)]
    out = {"applicable": True, "programs": [g.name for g in progs], "mode": mode,
           "compare": compare, "execs": st.execs, "delta_diversity": st.delta_diversity,
           "discrepancies": st.discrepancies, "inconclusive": inc, "stopped": st.stopped,
           "compared": len(live) >= 2}
    if not out["compared"]:
        out["note"] = ("no comparison possible: fewer than two implementations produced a "
                       "conclusive result (never started or timed out)")
    elif st.discrepancies:
        out["note"] = ("Each disagreement is a candidate bug -- one implementation handles input "
                       "another does not. Confirm which behaviour violates the spec.")
    else:
        out["note"] = ("no disagreements on the inputs every implementation executed"
                       + (" (some runs were inconclusive)" if inc else ""))
    if st.stopped:
        out["note"] += f"; stopped early: {st.stopped} after {st.execs} of {iterations} inputs"
    ctx.emit("diff_test.done", level="info" if out["compared"] else "warn",
             payload={k: v for k, v in out.items() if k != "discrepancies"}
             | {"disagreements": len(st.discrepancies)})
    ctx.progress(pct=100, msg=f"diff_test: {len(st.discrepancies)} disagreement(s) over "
                              f"{st.execs} inputs")
    return out


# ------------------------------------------------------------------------------ registration
def register() -> None:
    register_stage(VARIANT_STAGE, variant_scan_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=600)
    register_stage(WEGGLI_STAGE, weggli_scan_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=900)
    register_stage(DIFF_STAGE, diff_test_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=1800)


def enqueue_variant_scan(queue, target, *, params=None, force: bool = True):
    # force: the result depends on the case's OTHER targets, which the cache key cannot see
    return queue.enqueue(target.case_id, VARIANT_STAGE, target_id=target.id,
                         params=params or {}, force=force)


def enqueue_weggli_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, WEGGLI_STAGE, target_id=target.id,
                         params=params or {}, force=force)


def enqueue_diff_test(queue, case_id: str, *, params=None, force: bool = True):
    return queue.enqueue(case_id, DIFF_STAGE, params=params or {}, force=force)
