"""Phase 1 — the `disassemble` stage: Ghidra headless -> functions + decompilation.

Heavy (resource_class="cpu"); long timeout. Persists recovered functions to the DB and
stores the full analysis JSON as an artifact. Fails clearly if Ghidra is not available.
"""
from __future__ import annotations

import os

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
TOOL_VERSION = "ghidra-headless-2"
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


def _persist_analysis(conn, target_id: str, result: dict) -> tuple:
    """Write the recovered functions / call edges / strings onto a target row. Shared by the
    stage body and the cache-hit reprojection so both project identical DB state."""
    funcs = result.get("functions", [])
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
    _persist_analysis(store.conn, target_id, result)
    return True


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
        result = native_re.analyze(blob, ctx=ctx, timeout=_TIMEOUT)
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
    # functions + call graph/xrefs (reachability + taint sinks for Phase 3) + strings
    funcs, edges, strings = _persist_analysis(ctx.conn, target.id, result)

    # Honest completeness bookkeeping. `analyze()` is exhaustive by default but returns a partial
    # result rather than raising when a batch times out or the function set was capped, so we
    # persist whatever was recovered and tell the operator exactly how complete it is.
    total = result.get("total_functions", len(funcs))
    partial = bool(result.get("partial"))
    failed = int(result.get("failed_batches") or 0)
    sha = ctx.put_artifact("ghidra-analysis", data=canonical_json(result))
    ctx.emit("re.done", payload={"functions": len(funcs), "call_edges": len(edges),
                                 "strings": len(strings), "total_functions": total,
                                 "partial": partial, "failed_batches": failed,
                                 "language": result.get("program", {}).get("language")})
    suffix = ""
    if partial:
        suffix = (f" — partial: {len(funcs)}/{total} functions recovered"
                  + (f", {failed} batch(es) did not finish" if failed else ""))
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
