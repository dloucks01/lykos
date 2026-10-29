"""Stage: under-constrained symbolic execution over a target's UNDRIVEN functions -- discovery for
code no harness reaches. For each project function with no static call path from a harness entry, run
UC (uc_symbolic); when the sound gated signal fires (data the function READ reaches the instruction
pointer), file a CANDIDATE control-hijack lead.

HONEST CONTRACT: UC analyses a function in ISOLATION with unconstrained inputs, which real callers may
constrain, so every UC lead is a `candidate` carrying the explicit caveat that it assumes the
function's inputs are attacker-reachable -- a discovery aid, never a proven bug. The confirmation
ladder (a concrete input that faults under a sanitizer with a negative control) is still the only
thing that proves one. Deterministic, offline, no LLM. Self-gates cleanly when there is no loadable
binary or no identifiable harness entry (so 'undriven' is undefined).

Known ceiling (v1): it scans functions recovered INTO the target binary; on a shared build whose
parser lives in a .so this finds few project functions. UC-on-shared-libraries (force-loading the .so,
as the concolic rung does) is a follow-up.
"""
from __future__ import annotations

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage

TOOL, TOOL_VERSION = "uc_symbolic", "uc-symbolic-1"
#: runtime / non-project name markers (a leading underscore, or a C++/sanitizer/libFuzzer token):
#: UC-scanning these wastes budget and a hijack in a dispatch helper is not a project finding.
_SKIP_MARKERS = ("sanitizer", "ubsan", "asan", "lsan", "msan", "tsan", "sancov", "fuzzer",
                 "interceptor", "cxa", "llvm", "std::", "gnu_cxx", "scudo")


def _project_name(nm: str) -> bool:
    n = nm or ""
    if not n or n.startswith("_") or n.startswith("0x"):
        return False
    nl = n.lower()
    return not any(m in nl for m in _SKIP_MARKERS)


def _undriven_scan_names(conn, target_id: str, limit: int) -> list:
    """Named PROJECT functions with no static call path from a harness entry (LLVMFuzzer*/main),
    most-code-first (block count) so the richest logic is scanned within budget. Empty when there is
    no identifiable entry (reachability undefined)."""
    fns = FunctionDAO(conn).list_by_target(target_id)
    by_addr = {f.addr: f for f in fns if f.addr}
    entries = {f.addr for f in fns if (f.name or "").startswith("LLVMFuzzer") and f.addr}
    if not entries:
        entries = {f.addr for f in fns if (f.name or "") == "main" and f.addr}
    if not entries:
        return []
    adj: dict = {}
    for e in CallEdgeDAO(conn).list_by_target(target_id):
        if e.src_addr and e.dst_addr:
            adj.setdefault(e.src_addr, set()).add(e.dst_addr)
    seen: set = set()
    stack = list(entries)
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        stack.extend(d for d in adj.get(a, ()) if d not in seen)
    undriven = [f for a, f in by_addr.items()
                if a not in seen and f.name and _project_name(f.name)]
    undriven.sort(key=lambda f: -(f.blocks or 0))
    return [f.name for f in undriven[:limit]]


def _file_uc_lead(ctx, target, fn: str, uc: dict) -> None:
    """A data-to-PC UC hit -> a CANDIDATE control-hijack lead, with the under-constrained caveat."""
    detail = (f"under-constrained symbolic execution of {fn}() in isolation: data the function READ "
              f"reaches the instruction pointer (a {uc.get('data_to_pc')}-witness control-flow "
              f"hijack candidate). CAVEAT: UC assumes this function's inputs are attacker-reachable "
              f"and unconstrained; real callers may constrain them, so this is a discovery lead, NOT "
              f"a proven bug -- confirm with a reaching input under a sanitizer.")
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-94", "title": f"Control flow reaches data-derived pointer in {fn}() "
                                  f"(under-constrained)",
        "severity": "medium", "detector": TOOL, "state": "candidate", "confidence": 0.3,
        "dedup_key": f"uc:CWE-94:{target.id}:{fn}", "site_detail": fn,
        "function_addr": None, "site_addr": None,
        "evidence": [{"channel": "uc-symbolic", "detail": detail}]})


def uc_symbolic_stage(ctx) -> dict:
    import tempfile
    from pathlib import Path
    from .uc_symbolic import uc_scan_function
    from . import concolic as _concolic

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("uc_symbolic requires a target_id")
    if _concolic.locate_angr_python() is None:
        ctx.emit("uc_symbolic.done", payload={"supported": False, "note": "angr unavailable"})
        return {"metrics": {"supported": False}}
    p = ctx.params or {}
    budget = float(p.get("max_seconds") or 240)
    max_fns = int(p.get("max_functions") or 24)

    names = _undriven_scan_names(ctx.conn, target.id, max_fns)
    if not names:
        ctx.emit("uc_symbolic.done", payload={"supported": False,
                 "note": "no undriven project functions (no recovered functions / harness entry)"})
        return {"metrics": {"supported": False}}

    # Materialise the target binary for angr; decline cleanly if its bytes are not in the store.
    try:
        raw = ctx.content.path(target.sha256).read_bytes()
    except Exception:
        ctx.emit("uc_symbolic.done", payload={"supported": False,
                 "note": "target binary bytes unavailable for symbolic loading"})
        return {"metrics": {"supported": False}}
    binp = Path(tempfile.mkdtemp(prefix="lykos-uc-", dir=str(ctx.scratch()))) / "uc_target.bin"
    binp.write_bytes(raw)

    per = max(20, int(budget / max(1, len(names))))
    scanned = hijackable = 0
    ctx.progress(msg=f"UC-scanning {len(names)} undriven project function(s)")
    for fn in names:
        uc = uc_scan_function(binp, fn, timeout=per, ctx=ctx)
        if not uc.get("reached"):
            continue
        scanned += 1
        if uc.get("hijackable"):
            _file_uc_lead(ctx, target, fn, uc)
            hijackable += 1
            ctx.progress(msg=f"UC candidate (control-flow hijack, under-constrained): {fn}()")
    ctx.emit("uc_symbolic.done", payload={"supported": True, "functions": len(names),
             "scanned": scanned, "hijackable": hijackable})
    ctx.progress(pct=100, msg=f"UC: {scanned} function(s) scanned, {hijackable} candidate(s)")
    return {"metrics": {"supported": True, "scanned": scanned, "hijackable": hijackable}}


def register() -> None:
    register_stage("uc_symbolic", uc_symbolic_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_uc_symbolic(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "uc_symbolic", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
