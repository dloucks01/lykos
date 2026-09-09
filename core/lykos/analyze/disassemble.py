"""Phase 1 — the `disassemble` stage: Ghidra headless -> functions + decompilation.

Heavy (resource_class="cpu"); long timeout. Persists recovered functions to the DB and
stores the full analysis JSON as an artifact. Fails clearly if Ghidra is not available.
"""
from __future__ import annotations

from ..db.dao import CallEdgeDAO, FunctionDAO, StringDAO, TargetDAO
from ..hashing import canonical_json
from ..jobs.registry import register_stage
from . import ghidra

DISASSEMBLE_STAGE = "disassemble"
TOOL = "ghidra"
TOOL_VERSION = "ghidra-headless-1"
_TIMEOUT = 1800


def disassemble_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("disassemble requires a target_id referencing an ingested blob")

    headless = ghidra.locate_ghidra()
    if headless is None:
        raise RuntimeError(
            "Ghidra not found. Install it and set LYKOS_GHIDRA or GHIDRA_INSTALL_DIR, "
            "or use the full offline bundle that ships Ghidra.")

    blob = ctx.content.path(target.sha256)
    ctx.progress(msg="running Ghidra headless (import + auto-analysis + decompile)")
    out = ctx.scratch() / "analysis.json"
    ghidra.run_headless(headless, blob, out, ctx=ctx, timeout=_TIMEOUT)
    ctx.check_cancel()

    result = ghidra.parse_result(out)
    funcs = result.get("functions", [])
    FunctionDAO(ctx.conn).replace_for_target(target.id, funcs)

    # call graph + xrefs (reachability + taint sinks for Phase 3)
    edges = []
    for f in funcs:
        for c in f.get("calls", []):
            edges.append({"src_addr": f.get("addr"), "site_addr": c.get("site_addr"),
                          "dst_addr": c.get("dst_addr"), "dst_name": c.get("dst_name"),
                          "external": c.get("external")})
    CallEdgeDAO(ctx.conn).replace_for_target(target.id, edges)
    strings = result.get("strings", [])
    StringDAO(ctx.conn).replace_for_target(target.id, strings)

    sha = ctx.put_artifact("ghidra-analysis", data=canonical_json(result))
    ctx.emit("re.done", payload={"functions": len(funcs), "call_edges": len(edges),
                                 "strings": len(strings),
                                 "language": result.get("program", {}).get("language")})
    ctx.progress(pct=100, msg="%d functions, %d call edges, %d strings" %
                 (len(funcs), len(edges), len(strings)))
    return {"output_shas": [sha], "output_kind": "ghidra-analysis"}


def register() -> None:
    register_stage(DISASSEMBLE_STAGE, disassemble_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=_TIMEOUT)


def enqueue_disassemble(queue, target, *, force: bool = False):
    return queue.enqueue(target.case_id, DISASSEMBLE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
