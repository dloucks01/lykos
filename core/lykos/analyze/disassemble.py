"""Phase 1 — the `disassemble` stage: Ghidra headless -> functions + decompilation.

Heavy (resource_class="cpu"); long timeout. Persists recovered functions to the DB and
stores the full analysis JSON as an artifact. Fails clearly if Ghidra is not available.
"""
from __future__ import annotations

import os
import subprocess

from ..db.dao import CallEdgeDAO, FunctionDAO, StringDAO, TargetDAO
from ..hashing import canonical_json
from ..jobs.registry import cached_output_json, register_stage
from . import ghidra, native_re

DISASSEMBLE_STAGE = "disassemble"
TOOL = "ghidra"
# Bumped to -2 when disassembly became EXHAUSTIVE (all functions, not the first 1200) with
# geometry-inferred buffers. This is the content-addressed cache key (compute_cache_key includes
# tool_version), so the bump forces a re-analysis of any binary previously disassembled under the
# old capped logic instead of reprojecting its stale, truncated function set.
# -3: native frames carry `coords` (frame-pointer numbering), which the bounds detector needs to
# map a copy destination to the right variable -- older cached analyses lack it.
TOOL_VERSION = "ghidra-headless-3"
_TIMEOUT = 1800


def _select_backend() -> str:
    """Which RE backend to run: 'native' (rizin/radare2 + pypcode, no JVM) or 'ghidra'
    (headless + JDK). Controlled by LYKOS_DECOMPILER = native | ghidra | auto (default).

    'auto' prefers the NATIVE backend (doc 24 D-24.1: rizin/rz-ghidra + pypcode is the default
    decompiler; full Ghidra is the optional heavy profile). It falls back to Ghidra only when no
    native tool is present -- so a host that ships only Ghidra still works. Pin either with
    LYKOS_DECOMPILER."""
    pref = os.environ.get("LYKOS_DECOMPILER", "auto").lower()
    if pref in ("native", "rizin", "radare2"):
        return "native"
    if pref == "ghidra":
        return "ghidra"
    if native_re.locate_native():
        return "native"
    return "ghidra"


def _edges_from_funcs(funcs) -> list:
    edges = []
    for f in funcs:
        for c in f.get("calls", []):
            edges.append({"src_addr": f.get("addr"), "site_addr": c.get("site_addr"),
                          "dst_addr": c.get("dst_addr"), "dst_name": c.get("dst_name"),
                          "external": c.get("external")})
    return edges


def _persist_analysis(conn, target_id: str, result: dict, target_bytes: "bytes | None" = None) -> tuple:
    """Write the recovered functions / call edges / strings onto a target row. Shared by the
    stage body and the cache-hit reprojection so both project identical DB state.

    When `target_bytes` is given, a FLIRT-style library-ID pass first NAMES the security-relevant
    libc functions (system/strcpy/gets/...) in a stripped STATIC binary and propagates the names
    onto the call edges -- without it those calls stay `fcn.XXXX`, invisible to dangerous_api and
    the symbol-driven exploit paths (625 functions, 0 named, 0 findings on a static strcpy target).
    Best-effort: library-ID must never break recovery persistence."""
    funcs = result.get("functions", [])
    if target_bytes:
        try:
            from . import flirt
            n = flirt.relabel(target_bytes, funcs)       # mutates funcs + their call dst_names
            if n:
                result["flirt_named"] = n
        except Exception:                                # noqa: BLE001 -- never break persistence
            pass
    FunctionDAO(conn).replace_for_target(target_id, funcs)
    edges = _edges_from_funcs(funcs)
    CallEdgeDAO(conn).replace_for_target(target_id, edges)
    strings = result.get("strings", [])
    StringDAO(conn).replace_for_target(target_id, strings)
    return funcs, edges, strings


def reproject_disassemble(store, target_id: str, run_id: str) -> bool:
    """Rebuild a target row's function/call-edge/string rows from a disassemble run's cached
    output. A content-addressed cache hit clones the ghidra-analysis artifact but never re-runs
    the body, so a freshly uploaded copy of the same bytes (e.g. the same binary in a second
    case) has none of these rows -- and consumers (the native runtime monitor's sink resolution,
    CWE detection, the call-graph UI) would see an empty program. Returns True if it rebuilt."""
    if CallEdgeDAO(store.conn).list_by_target(target_id) or \
            FunctionDAO(store.conn).list_by_target(target_id):
        return False
    result = cached_output_json(store, run_id)
    if not isinstance(result, dict) or "functions" not in result:
        return False
    blob = None
    try:
        t = TargetDAO(store.conn).get(target_id)
        if t and t.sha256:
            blob = store.content.path(t.sha256)
    except Exception:                                    # noqa: BLE001 -- relabel is best-effort
        blob = None
    with _target_view(blob) as tb:
        _persist_analysis(store.conn, target_id, result, target_bytes=tb)
    return True


class _target_view:
    """The target's bytes for FLIRT library-ID, MAPPED rather than read: a 100MB+ engagement binary
    read whole sat in the worker's RSS for the entire persist pass. Yields None when there is no
    blob or it cannot be opened (relabel is best-effort and is then skipped, as before)."""

    def __init__(self, path):
        self._path, self._m = path, None

    def __enter__(self):
        if self._path is None:
            return None
        try:
            self._m = native_re._Mapped(self._path)
            return self._m.__enter__() or None
        except Exception:                                # noqa: BLE001 -- relabel is best-effort
            self._m = None
            return None

    def __exit__(self, *exc):
        if self._m is not None:
            self._m.__exit__(*exc)
        return False


def disassemble_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("disassemble requires a target_id referencing an ingested blob")

    # A substrate with no machine code has nothing to decompile, and saying so is the whole
    # job here. Ghidra imported the jar, produced no analysis file, and the stage surfaced
    # `FileNotFoundError(2, 'No such file or directory')` to the operator -- a raw stdlib
    # exception, in a pipeline whose other stages say things like "heap check not applicable:
    # target is statically linked". The constant pool is read by `detect_cwe` instead, which
    # needs no decompiler at all.
    ftype = (target.file_type or "").lower()
    if ftype in ("jar", "class", "dotnet"):
        managed = "a .NET" if ftype == "dotnet" else "a Java"
        store = "metadata (#Strings / #US heaps)" if ftype == "dotnet" else "constant pool"
        note = (f"{managed} target has no machine code to decompile -- its types, strings and "
                f"every method it names are already in the {store}, which `detect_cwe` "
                f"reads directly. Run detect_cwe instead; disassembly is not a step here.")
        ctx.emit("re.done", payload={"supported": False, "substrate": ftype, "functions": 0,
                                     "call_edges": 0, "strings": 0, "note": note})
        ctx.progress(pct=100, msg=f"no machine code to decompile ({'.NET' if ftype == 'dotnet' else 'Java'} target)")
        return {}

    backend = _select_backend()
    blob = ctx.content.path(target.sha256)

    if backend == "native":
        cli = native_re.locate_native()
        if cli is None:
            raise RuntimeError(
                "No native RE backend (rizin/radare2) found. Install rizin+rz-ghidra, or set "
                "LYKOS_DECOMPILER=ghidra to use Ghidra headless.")
        ctx.progress(msg="running native RE backend (%s + pypcode P-Code, no JVM)" % cli.name)
        # Recover strings + imports CHEAPLY and persist them FIRST. The full `analyze()` runs these
        # behind the expensive `aaa`, so on a large binary where the structural analysis cannot
        # finish within the budget they were lost with it and the target reported zero findings
        # (measured: a 24MB server timed `aaa` out -> 0 strings, 0 findings, read as "clean"). With
        # the strings persisted up front, the string-keyed detectors still have input and a big
        # binary never silently reads as clean.
        _qf_strings = 0
        try:
            _qf = native_re.quick_facts(blob, ctx=ctx, timeout=min(90, _TIMEOUT))
            if _qf.get("strings"):
                StringDAO(ctx.conn).replace_for_target(target.id, _qf["strings"])
                _qf_strings = len(_qf["strings"])
        except Exception:
            # Best-effort pre-pass: if the cheap strings/imports recovery fails for any reason,
            # the full analyze() below runs next and surfaces the real error (or its coverage
            # note), so swallowing here silently and falling back to 0 persisted strings is right.
            _qf_strings = 0
        try:
            result = native_re.analyze(blob, ctx=ctx, timeout=_TIMEOUT)
        except Exception as e:
            # Only a hard engine failure (not a cut-short) should propagate as an error.
            _cut = (type(e).__name__ in ("StageTimeout", "StageCancelled")
                    or isinstance(e, subprocess.TimeoutExpired))
            if not _cut:
                raise
            # Cut short -- by the stage deadline, by the autopilot's budget stop (which cancels the
            # run), or by a rizin call overrunning its own cap. Either way it is NOT a failure and
            # must NOT read as a clean 0-findings: emit a coverage note so detect's result is always
            # explained, keeping the strings/imports already persisted. The note fires whether the
            # cut came as a timeout or a cancel, because on a large binary even the cheap string
            # extraction can exceed the slice (measured: a 142MB Go binary recovered 0 strings in an
            # 89s disassemble slice) and the operator must see WHY, not infer it from a small number.
            _mb = round(blob.stat().st_size / 1048576, 1)
            _recovered = (f"{_qf_strings} strings (and imports) were recovered and the string-keyed "
                          f"detectors ran on them, but function and call-graph recovery is "
                          f"incomplete" if _qf_strings else
                          "not even the string table was fully extracted at this size")
            ctx.emit("re.done", payload={
                "functions": 0, "call_edges": 0, "strings": _qf_strings,
                "partial": True, "truncated": True,
                "note": (f"the analysis of this {_mb} MB binary did not finish within the budget; "
                         f"{_recovered} -- raise --budget (or see docs/internal/40) to analyse "
                         f"more of it")})
            ctx.progress(pct=100, msg=f"analysis cut short on a {_mb} MB binary "
                                      f"({_qf_strings} strings recovered); not a clean result")
            # A user cancel still aborts the stage (honest status); a budget/deadline cut returns
            # the partial so the run proceeds to detection on whatever was recovered.
            if type(e).__name__ == "StageCancelled" or (ctx._db_cancel()
                                                        if hasattr(ctx, "_db_cancel") else False):
                raise
            return {"output_shas": [], "output_kind": "ghidra-analysis", "truncated": True}
    else:
        headless = ghidra.locate_ghidra()
        if headless is None:
            raise RuntimeError(
                "Ghidra not found. Install it and set LYKOS_GHIDRA or GHIDRA_INSTALL_DIR, "
                "use the full offline bundle that ships Ghidra, or set LYKOS_DECOMPILER=native "
                "to use the rizin/radare2 backend.")
        ctx.progress(msg="running Ghidra headless (import + auto-analysis + decompile)")
        out = ctx.scratch() / "analysis.json"
        ghidra.run_headless(headless, blob, out, ctx=ctx, timeout=_TIMEOUT)
        ctx.check_cancel()
        result = ghidra.parse_result(out)
    # functions + call graph/xrefs (reachability + taint sinks for Phase 3) + strings. Hand the
    # bytes to the persist pass so FLIRT library-ID can name stripped-static libc sinks.
    with _target_view(blob) as _tb:
        funcs, edges, strings = _persist_analysis(ctx.conn, target.id, result, target_bytes=_tb)

    # Honest completeness bookkeeping. `analyze()` is exhaustive by default but returns a partial
    # result rather than raising when a batch times out or the function set was capped, so we
    # persist whatever was recovered and tell the operator exactly how complete it is.
    total = result.get("total_functions", len(funcs))
    partial = bool(result.get("partial"))
    failed = int(result.get("failed_batches") or 0)
    # A rizin that crashed / returned empty (old bundled rizin, a fallback to an old host r2, a
    # missing arch plugin) recovers 0 functions but USED to read as a clean "ran, 0 functions" --
    # every function-keyed detector then silently starved. analyze() now flags that as a recovery
    # FAILURE; say so in the note and the progress line rather than a silent clean small result.
    recovery_failed = bool(result.get("recovery_failed"))
    rec_note = result.get("recovery_error") or ""
    # Size-tiered recovery (native backend): which pass-1 rung produced the function list, and
    # every pass that fell short. A degradation is part of the note, never silent.
    degradations = [d for d in (result.get("degradations") or []) if d]
    if degradations and not rec_note:
        rec_note = "; ".join(degradations)
    sha = ctx.put_artifact("ghidra-analysis", data=canonical_json(result))
    ctx.emit("re.done", payload={"functions": len(funcs), "call_edges": len(edges),
                                 "strings": len(strings), "total_functions": total,
                                 "partial": partial, "failed_batches": failed,
                                 "recovery_failed": recovery_failed,
                                 "note": rec_note or None,
                                 "analysis_tier": result.get("analysis_tier"),
                                 "degradations": degradations or None,
                                 "language": result.get("program", {}).get("language")})
    if recovery_failed:
        ctx.progress(pct=100, msg="recovery FAILED — %d functions recovered (%s); not a clean "
                                  "result" % (len(funcs), rec_note or "rizin produced no program"))
        return {"output_shas": [sha], "output_kind": "ghidra-analysis"}
    suffix = ""
    if partial:
        suffix = (f" — partial: {len(funcs)}/{total} functions recovered"
                  + (f", {failed} batch(es) did not finish" if failed else ""))
    if result.get("tiered") and result.get("analysis_tier"):
        suffix += f" [large-binary analysis: {result['analysis_tier']}]"
    if degradations:
        suffix += f" — {len(degradations)} degradation(s): {degradations[0]}"
    ctx.progress(pct=100, msg="%d functions, %d call edges, %d strings%s" %
                 (len(funcs), len(edges), len(strings), suffix))
    return {"output_shas": [sha], "output_kind": "ghidra-analysis"}


def register() -> None:
    register_stage(DISASSEMBLE_STAGE, disassemble_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=_TIMEOUT,
                   on_cache_hit=reproject_disassemble)


def enqueue_disassemble(queue, target, *, force: bool = False):
    return queue.enqueue(target.case_id, DISASSEMBLE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
