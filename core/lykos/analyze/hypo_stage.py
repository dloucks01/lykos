"""The `hypo_hunt` stage -- the propose -> solve -> validate loop (doc 52; `lykos hunt`) as an
autopilot stage for BINARY targets.

The hypothesis driver proposes violation sites from the binary's own code (out-of-bounds index /
length, integer-overflow-to-allocation, divide-by-zero, format string, command injection,
control-flow hijack ...), angr solves each satisfiable one to a concrete input, and every input is
replayed in the sandbox: only a SITE-ATTRIBUTED oracle confirms it (a native crash whose fault PC
is inside the hypothesis's function on 3/3 replays, or -- for a silent heap error on a binary
with no sanitizer build -- a QASan report inside that function on 3/3 replays, see
hypo/validate). Unconfirmed hypotheses are re-solved with their failed inputs excluded, and a
confirmed control-flow hijack is climbed toward an exploit.

This is the non-fuzzing-first path for binaries: directed, per-site, and it either produces an
input that a forgery-checked oracle validates at the proposed site or it files nothing. It used to
exist only as a CLI command, so no autopilot run ever used it (doc 62 item 3).

Confirmed hypotheses are filed `confirmed` (validated by execution at the site). Native-crash
confirmations are recorded as crashes so the prove loop (root cause, L2 primitive, exploit) climbs
them; QASan confirmations are recorded with isolation "qasan" (they do not crash natively, so the
native prove loop is not handed them).
"""
from __future__ import annotations

import os
import re
import time

from ..db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, TargetDAO
from ..jobs.registry import register_stage

HYPO_STAGE = "hypo_hunt"
TOOL = "hypo"
TOOL_VERSION = "hypo-1"

#: angr's cost grows with the image; above this the stage declines rather than eat the slice.
_MAX_BYTES = 32 * 1024 * 1024

_TITLES = {"heap-read": "Heap out-of-bounds read", "heap-write": "Heap out-of-bounds write",
           "stack-read": "Stack out-of-bounds read", "stack-write": "Stack out-of-bounds write",
           "div-zero": "Division by zero", "double-free": "Double free",
           "oob-read": "Out-of-bounds read", "oob-write": "Out-of-bounds write",
           "int-overflow-alloc": "Integer overflow in an allocation size",
           "div-by-zero": "Division by zero", "format-string": "Format string",
           "cmd-injection": "Command injection", "control-flow-hijack": "Control-flow hijack",
           "path-traversal": "Path traversal", "null-deref": "NULL pointer dereference",
           "uninit-read": "Use of uninitialised memory", "mem-leak": "Memory leak",
           "resource-exhaustion": "Unbounded resource consumption"}

_SIG = re.compile(r"^(SIG[A-Z]+)")


def _decline(ctx, why: str) -> dict:
    ctx.emit("hypo.done", payload={"supported": False, "note": why})
    ctx.progress(pct=100, msg=why[:90])
    return {"metrics": {"supported": False}}


def hypo_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("hypo_hunt requires a target_id")
    p = ctx.params or {}
    if (target.file_type or "").lower() != "elf":
        return _decline(ctx, "the hypothesis loop drives ELF executables")
    from ..hypo import engine
    if engine.angr_python() is None:
        return _decline(ctx, "angr is not available, so hypotheses cannot be solved")
    from .dynamic import sandbox
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)
    if sandbox._is_elf_shared_object(exe):
        return _decline(ctx, "an ELF shared object has no entry point; it is hunted through a "
                             "harness, not executed")
    if exe.stat().st_size > int(p.get("max_bytes", _MAX_BYTES)):
        return _decline(ctx, f"image is {exe.stat().st_size // (1 << 20)} MB, over the "
                             f"{int(p.get('max_bytes', _MAX_BYTES)) >> 20} MB symbolic-execution cap")

    # delivery: the operator's, else the channel the imports point at (file before stdin)
    from .poc.inject_stage import _channels
    mode = p.get("input_mode")
    if mode not in ("file", "stdin", "arg"):
        order = [m for m in _channels(CallEdgeDAO(ctx.conn).list_by_target(target.id), None)
                 if m in ("file", "stdin")]
        mode = order[0] if order else "stdin"
    argv = [str(a) for a in (p.get("argv") or [])]
    if mode == "file" and "@@" not in argv:
        argv = argv + ["@@"]

    budget = float(p.get("budget", 150))
    if ctx.deadline is not None:
        budget = min(budget, max(0.0, ctx.deadline - time.time() - 20))
    from ..hypo import loop
    if budget < loop.MIN_ROUND:
        return _decline(ctx, f"{int(budget)} s left is under the loop's {int(loop.MIN_ROUND)} s "
                             f"minimum round")

    from ..hypo.validate import Target
    t = Target(exe=exe, argv=argv, mode=mode, arch=target.arch, endianness=target.endianness,
               bits=target.bits)
    ctx.progress(msg=f"hypothesis loop: propose -> solve -> validate ({int(budget)} s, {mode})")
    lines: list = []

    def _log(msg: str) -> None:
        lines.append(msg)
        if len(lines) % 10 == 0:
            ctx.progress(msg=msg[:90])

    res = loop.hunt_target(t, budget, input_size=int(p.get("input_size", 300)),
                           mem_mb=int(p.get("mem_mb", 8192)), log=_log)
    hyps = res.get("hypotheses") or []
    filed = _file_confirmed(ctx, target, hyps, mode, argv)
    kinds: dict = {}
    for h in hyps:
        kinds[h.kind] = kinds.get(h.kind, 0) + 1
    payload = {"supported": True, "mode": mode, "budget_s": int(budget),
               "proposed": len(hyps), "solved": sum(1 for h in hyps if h.solutions),
               "confirmed": filed, "by_kind": kinds, "error": res.get("error"),
               "note": (f"{filed} hypothesis(es) solved AND validated at their site"
                        if filed else
                        "no hypothesis validated at its site -- solved inputs that did not "
                        "replay are not findings")}
    ctx.emit("hypo.done", payload=payload)
    ctx.progress(pct=100, msg=payload["note"][:90])
    return {"metrics": {"proposed": len(hyps), "confirmed": filed}}


def _file_confirmed(ctx, target, hyps, mode, argv) -> int:
    fd, dd = FindingDAO(ctx.conn), DynResultDAO(ctx.conn)
    filed = 0
    for h in hyps:
        if h.status != "confirmed":
            continue
        sol = next((s for s in h.solutions if s.verdict is not None and s.verdict.confirmed), None)
        if sol is None:
            continue
        v = sol.verdict
        sha = ctx.put_artifact("hypo-input", data=sol.data)
        where = h.func or (f"{h.site:#x}" if h.site is not None else "the site")
        title = f"{_TITLES.get(h.kind, h.kind)} in {where} (solved + validated: {v.method})"
        qasan = v.method == "qasan"
        m = _SIG.match(v.detail or "")
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=sha, input_mode=mode,
                  argv=[a for a in argv if a != "@@"],
                  signal_name="QASAN" if qasan else (m.group(1) if m else None),
                  crashed=v.method in ("native-crash", "qasan"),
                  isolation="qasan" if qasan else "hypo",
                  note=f"hypothesis {h.id}: {v.detail}"[:400], fault_pc=h.site,
                  defect_key=f"hypo:{h.kind}:{h.site}")
        ev = [{"channel": "hypothesis",
               "detail": (f"proposed {h.kind} at {h.site:#x} in {where}"
                          + (f" ({h.location})" if h.location else "")
                          + (f" -- {h.note}" if h.note else ""))},
              {"channel": "validated", "detail": f"{v.method}: {v.detail}"},
              {"channel": "hypo-input", "detail": f"input {sha[:12]} via {mode}"}]
        if h.exploit:
            ev.append({"channel": "hypo-exploit",
                       "detail": f"{h.exploit.get('level')}: "
                                 f"{h.exploit.get('evidence') or h.exploit.get('note') or ''}"[:400]})
        fd.upsert(target.id, target.case_id, {
            "cwe": h.cwe or "CWE-119", "title": title,
            "severity": "high" if h.kind in ("heap-write", "stack-write", "oob-write",
                                             "double-free", "control-flow-hijack", "cmd-injection",
                                             "format-string", "int-overflow-alloc") else "medium",
            "state": "confirmed", "confidence": 0.9, "detector": "hypo",
            "dedup_key": f"{h.cwe}:hypo:{h.kind}:{h.site}",
            "function_addr": f"{h.func_addr:#x}" if h.func_addr is not None else None,
            "site_addr": f"{h.site:#x}" if h.site is not None else None,
            "evidence": ev})
        filed += 1
    return filed


register_stage(HYPO_STAGE, hypo_stage, resource_class="cpu", tool=TOOL,
               tool_version=TOOL_VERSION, timeout=600)


def enqueue_hypo_hunt(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HYPO_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
