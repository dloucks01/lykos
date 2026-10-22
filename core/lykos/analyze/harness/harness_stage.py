"""T2 #3 (doc 46) -- the `harness` stage: rank the target's functions, drive the top few directly
under the emulator (binary libFuzzer), and file the memory faults it finds.

PROVENANCE is explicit and honest: a harness crash is demonstrated at the FUNCTION level (the
function faults when CALLED directly with the crashing input). For a library that IS the bug; for
a daemon it is a "reachable-if-driven" lead whose program-level reachability a later pass (concolic)
must still establish. The finding says exactly that and does NOT claim a program-level verified PoC.
"""
from __future__ import annotations

from ...db.dao import FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from .emulate import _HUGE_ALLOC, available
from .fuzz import fuzz_function
from .rank import rank_functions

HARNESS_STAGE = "harness"
TOOL = "lykos-harness"
TOOL_VERSION = "harness-1"

_ACCESS_CWE = {"read": ("CWE-125", "out-of-bounds read"),
               "write": ("CWE-787", "out-of-bounds write"),
               "fetch": ("CWE-119", "control-flow corruption")}
_X86_64 = {"x86-64", "x86_64", "amd64"}


def harness_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("harness requires a target_id")
    p = ctx.params or {}
    # Gating -- decline cleanly (never raise) with a reason the operator can act on.
    if (target.arch or "") not in _X86_64:
        ctx.emit("harness.done", payload={"supported": False,
                 "note": f"the harness executor is x86-64 only; this target is {target.arch}"})
        ctx.progress(pct=100, msg="harness: x86-64 only")
        return {}
    if not available():
        ctx.emit("harness.done", payload={"supported": False, "note": "unicorn is not available"})
        ctx.progress(pct=100, msg="harness: unicorn unavailable")
        return {}
    if not FunctionDAO(ctx.conn).list_by_target(target.id):
        ctx.emit("harness.done", payload={"supported": False,
                 "note": "no recovered functions -- run disassemble first"})
        ctx.progress(pct=100, msg="harness: disassemble first")
        return {}

    ranked = rank_functions(ctx.conn, target.id, top=int(p.get("rank_top", 40)))
    # Only functions with a POINTER argument can be driven by this model (we point it at the fuzzed
    # buffer). A top-ranked parser that ingests via fd/FILE instead is not directly harnessable yet.
    cands = [r for r in ranked if r.ptr_len >= 1][:int(p.get("max_functions", 6))]
    if not cands:
        ctx.emit("harness.done", payload={"supported": True, "findings": 0,
                 "note": ("no pointer-argument function among the top ranked targets -- the "
                          "promising parsers take input via fd/FILE, which this harness model does "
                          "not drive yet")})
        ctx.progress(pct=100, msg="harness: no pointer-arg target to drive")
        return {}

    data = ctx.content.path(target.sha256).read_bytes()
    execs = int(p.get("harness_execs", 8000))
    per_sec = float(p.get("harness_seconds", 20.0))
    fd = FindingDAO(ctx.conn)
    # T4 (doc 46): feed each function its OWN comparison constants as a fuzzing dictionary -- the
    # magic values / length limits / opcodes it gates on, so the campaign gets past a gate a blind
    # mutator never would. Map func addr -> IR once (the ranker gives int addrs; the DB keys by str).
    from .fuzz import dictionary_from_ir
    from .rank import _to_int
    _id_by_addr = {}
    for _f in FunctionDAO(ctx.conn).list_by_target(target.id):
        _ai = _to_int(_f.addr)
        if _ai is not None:
            _id_by_addr[_ai] = _f.id
    findings = 0
    for rf in cands:
        shape = "ptr_len" if rf.ptr_len == 2 else "ptr"
        label = rf.name or hex(rf.addr)
        _full = FunctionDAO(ctx.conn).get(_id_by_addr.get(rf.addr)) if rf.addr in _id_by_addr else None
        dict_words = dictionary_from_ir(_full.ir if _full else None)
        ctx.progress(msg=f"harness-fuzzing {label} ({shape}, {len(dict_words)} dict)")
        try:
            fr = fuzz_function(data, rf.addr, arg_shape=shape, budget_execs=execs,
                               budget_seconds=per_sec, dictionary=dict_words)
        except Exception as e:                           # noqa: BLE001 -- one function must not sink the stage
            ctx.emit("harness.progress", payload={"func": hex(rf.addr), "error": str(e)[:120]})
            continue
        ctx.emit("harness.progress", payload={
            "func": hex(rf.addr), "name": rf.name, "execs": fr.execs, "dict_words": len(dict_words),
            "coverage": len(fr.blocks), "crashes": len(fr.crashes),
            "oracle_hits": len(fr.oracle_hits)})
        for c in fr.crashes:
            r = c["result"]
            inp = c["input"]
            sha = ctx.put_artifact("harness-crash-input", data=inp)
            cwe, kind = _ACCESS_CWE.get(r.access, ("CWE-119", "memory fault"))
            fault = hex(r.fault_addr) if r.fault_addr is not None else "?"
            pc = hex(r.fault_pc) if r.fault_pc is not None else "?"
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "severity": "high",
                "title": f"Harness-demonstrated {kind} in {label} (function-level)"[:200],
                "detector": "harness", "state": "corroborated", "confidence": 0.8,
                "site_addr": pc if r.fault_pc is not None else None,
                "function_addr": hex(rf.addr),
                "dedup_key": f"harness:{rf.addr:#x}:{r.fault_pc or 0:#x}:{r.access}",
                "evidence": [{"channel": "harness", "detail": (
                    f"driving {label}({shape}) directly under the emulator, input "
                    f"{sha[:12]} ({len(inp)} B) faults: {r.access} at {fault}, pc {pc}. "
                    "PROVENANCE: demonstrated at the FUNCTION level (the function was called "
                    "directly with this input) -- a confirmed bug for a library API, and a "
                    "reachable-if-driven lead for a daemon whose entry path a concolic/reachability "
                    "pass must still connect. Not a program-level verified PoC.")}]})
            findings += 1
        # T6 sequence driving: drive the function with ORDERED message sequences in one emulator
        # state, reaching a fault that lives in a state only entered after a specific message
        # prefix -- which the single-call pass above can never reach. Additive and bounded: a short
        # extra pass that only files crashes at sites the single-call pass did NOT already find.
        if p.get("sequence", True):
            single_sites = {(c["result"].fault_pc, c["result"].access) for c in fr.crashes}
            try:
                sfr = fuzz_function(data, rf.addr, arg_shape=shape, dictionary=dict_words,
                                    sequence=True,
                                    budget_execs=int(p.get("harness_seq_execs", 3000)),
                                    budget_seconds=float(p.get("harness_seq_seconds", 8.0)))
            except Exception as e:                           # noqa: BLE001 -- never sink the stage
                sfr = None
                ctx.emit("harness.progress", payload={"func": hex(rf.addr),
                                                       "seq_error": str(e)[:120]})
            if sfr and sfr.crashes:
                ctx.emit("harness.progress", payload={"func": hex(rf.addr), "name": rf.name,
                         "seq_execs": sfr.execs, "seq_crashes": len(sfr.crashes)})
                for c in sfr.crashes:
                    r = c["result"]
                    if (r.fault_pc, r.access) in single_sites:
                        continue                             # the single-call pass already filed it
                    inp = c["input"]
                    msgs = [m for m in inp.split(b"\n") if m]
                    sha = ctx.put_artifact("harness-seq-input", data=inp)
                    cwe, kind = _ACCESS_CWE.get(r.access, ("CWE-119", "memory fault"))
                    fault = hex(r.fault_addr) if r.fault_addr is not None else "?"
                    pc = hex(r.fault_pc) if r.fault_pc is not None else "?"
                    nth = (r.seq_index + 1) if r.seq_index is not None else "?"
                    fd.upsert(target.id, target.case_id, {
                        "cwe": cwe, "severity": "high",
                        "title": f"Harness-demonstrated {kind} in {label} (stateful sequence)"[:200],
                        "detector": "harness", "state": "corroborated", "confidence": 0.8,
                        "site_addr": pc if r.fault_pc is not None else None,
                        "function_addr": hex(rf.addr),
                        "dedup_key": f"harness:{rf.addr:#x}:{r.fault_pc or 0:#x}:{r.access}",
                        "evidence": [{"channel": "harness", "detail": (
                            f"driving {label}({shape}) with an ORDERED SEQUENCE of {len(msgs)} "
                            f"message(s), input {sha[:12]} ({len(inp)} B, '\\n'-framed) faults on "
                            f"message {nth}: {r.access} at {fault}, pc {pc}. This fault is only "
                            "reachable after the earlier messages drive the parser into the "
                            "faulting state -- the single-call pass cannot reach it. PROVENANCE: "
                            "demonstrated at the FUNCTION level (the sequence was replayed directly "
                            "under the emulator); program-level reachability for a daemon must still "
                            "be connected by a concolic/reachability pass.")}]})
                    findings += 1
        # T5 resource oracle: a fuzzed input drove an attacker-controlled huge allocation (CWE-789).
        for o in fr.oracle_hits:
            r = o["result"]
            inp = o["input"]
            sha = ctx.put_artifact("harness-alloc-input", data=inp)
            size = r.huge_alloc or 0
            fd.upsert(target.id, target.case_id, {
                "cwe": "CWE-789", "severity": "medium",
                "title": f"Harness-demonstrated unbounded allocation in {label} (function-level)"[:200],
                "detector": "harness", "state": "corroborated", "confidence": 0.65,
                "function_addr": hex(rf.addr),
                "dedup_key": f"harness-alloc:{rf.addr:#x}",
                "evidence": [{"channel": "harness", "detail": (
                    f"driving {label}({shape}) directly under the emulator, a {len(inp)}-byte input "
                    f"{sha[:12]} causes an allocation request of {size:,} bytes "
                    f"(>= {_HUGE_ALLOC:,} B). A size this large driven from a small input is an "
                    "attacker-controlled (unbounded) allocation -- a memory-exhaustion / DoS lead "
                    "(CWE-789/400), not a memory-corruption fault. PROVENANCE: demonstrated at the "
                    "FUNCTION level (called directly with this input); program-level reachability "
                    "for a daemon must still be connected by a later pass.")}]})
            findings += 1
    ctx.emit("harness.done", payload={"supported": True, "functions": len(cands),
             "findings": findings})
    ctx.progress(pct=100, msg=f"harness: {findings} function-level fault(s) across "
                             f"{len(cands)} driven target(s)")
    return {"findings": findings, "functions": len(cands)}


def enqueue_harness(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HARNESS_STAGE, target_id=target.id,
                         params=params or {}, force=force)


def register() -> None:
    register_stage(HARNESS_STAGE, harness_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=240)
