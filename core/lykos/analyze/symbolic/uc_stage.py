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

import re

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


#: A parameter that carries INPUT BYTES: a byte/char pointer, or an untyped pointer followed by a
#: length. Anything else a pointer parameter can be is an OBJECT the caller built.
_BYTE_PTR = re.compile(r"^(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|uint8_t|u_char|int8_t|"
                       r"u8|byte|BYTE)\s*\*", re.I)


def callback_dispatch_only(params) -> bool:
    """True when a function's declared parameters include NO input-byte buffer, so a data-derived
    PC can only have been loaded from an object its caller supplied -- a callback / vtable dispatch,
    not attacker data reaching control flow.

    UC treats everything behind a parameter as attacker data, and on md4c that filed five CWE-94
    'control-flow hijack' leads on the HTML renderer's own callbacks -- `enter_block_callback(
    MD_BLOCKTYPE type, void* detail, void* userdata)` calls `r->process_output(...)` through the
    caller's context object, by design. At machine level that is the same shape as
    `call_mem(char *p){ (*(fp*)p)(); }`, which IS a lead (bytes become a code pointer); only the
    declared types tell them apart, so this needs the source and says nothing without it."""
    if params is None:
        return False                                     # no source signature: no claim
    ps = [str(a) for a in params if str(a).strip() not in ("", "void")]
    for i, a in enumerate(ps):
        if _BYTE_PTR.match(a.strip()):
            return False
        if re.match(r"^(?:const\s+)?void\s*\*", a.strip()) and i + 1 < len(ps) and re.search(
                r"\b(size_t|ssize_t|unsigned|int|long|uint\d+_t|len|size)\b", ps[i + 1]):
            return False                                 # (void *buf, size_t n): bytes
    return True


def _source_params(src, fn):
    """`fn`'s declared parameters from the archived source tree `src`, or None without one.

    STATIC functions included: `defs_index` lists only what a harness can call, and md4c's
    renderer callbacks are all `static int enter_block_callback(...)` -- the exact functions this
    question is about -- so the lookup missed every one and the CWE-94 leads were still filed."""
    if not src:
        return None
    try:
        from pathlib import Path as _P
        from ..libfuzzer import defs_index, resolve_params, split_params, typedef_map
        hit = defs_index(src).get(fn)
        if hit:
            return list(hit[1])
        pat = re.compile(r"(?:^|\n)[^\n;{}#]*?\b" + re.escape(fn)
                         + r"[ \t]*\(((?:[^;{}()]|\([^;{}()]*\))*)\)[ \t]*(?:\r?\n[ \t]*)?\{")
        for p in sorted(_P(src).rglob("*.c"))[:4000]:
            try:
                txt = p.read_text(errors="ignore")
            except OSError:
                continue
            m = pat.search(txt)
            if m:
                return resolve_params(split_params(m.group(1)), typedef_map(src))
        return None
    except Exception:                                    # noqa: BLE001 -- no source, no claim
        return None


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

    import time as _time
    # A DEADLINE, not just a per-function share: the share has a 20 s floor, so 24 functions under
    # a 180 s slice asked for 480 s -- measured on md4c, UC ran 239 s and the black-box fuzzer after
    # it got 126 executions. Functions the clock does not reach are counted and said, not run.
    deadline = _time.monotonic() + budget
    per = max(20, int(budget / max(1, len(names))))
    scanned = hijackable = 0
    dispatch: list = []
    src = None                                           # the archived source, fetched on demand
    ctx.progress(msg=f"UC-scanning {len(names)} undriven project function(s)")
    not_reached = 0
    for i, fn in enumerate(names):
        left = deadline - _time.monotonic()
        if left < 12:
            not_reached = len(names) - i
            break
        uc = uc_scan_function(binp, fn, timeout=int(min(per, left - 10)), ctx=ctx)
        if not uc.get("reached"):
            continue
        scanned += 1
        if uc.get("hijackable") and src is None:
            from ..libfuzzer_stage import _materialize_source
            try:
                src = _materialize_source(ctx, target) or False
            except Exception:                            # noqa: BLE001 -- no source, no claim
                src = False
        if uc.get("hijackable") and callback_dispatch_only(_source_params(src, fn)):
            dispatch.append(fn)
            continue
        if uc.get("hijackable"):
            _file_uc_lead(ctx, target, fn, uc)
            hijackable += 1
            ctx.progress(msg=f"UC candidate (control-flow hijack, under-constrained): {fn}()")
    ctx.emit("uc_symbolic.done", payload={"supported": True, "functions": len(names),
             "scanned": scanned, "hijackable": hijackable,
             "not_reached_for_budget": not_reached,
             # said, not hidden: these reached PC through a caller-supplied object
             "callback_dispatch_not_filed": dispatch[:16],
             "why": ("no input-byte parameter: the called pointer comes from an object the "
                     "caller built (a callback/vtable dispatch), not from attacker data")
             if dispatch else None})
    ctx.progress(pct=100, msg=f"UC: {scanned} function(s) scanned, {hijackable} candidate(s)")
    return {"metrics": {"supported": True, "scanned": scanned, "hijackable": hijackable}}


def register() -> None:
    register_stage("uc_symbolic", uc_symbolic_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=1800)


def enqueue_uc_symbolic(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, "uc_symbolic", target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
