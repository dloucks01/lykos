"""T2 #3 (doc 46) -- the `harness` stage: rank the target's functions, drive the top few directly
under the emulator (binary libFuzzer), and file the memory faults it finds.

PROVENANCE is explicit and honest: a harness crash is demonstrated at the FUNCTION level (the
function faults when CALLED directly with the crashing input). For a library that IS the bug; for
a daemon it is a "reachable-if-driven" lead whose program-level reachability a later pass (concolic)
must still establish. The finding says exactly that and does NOT claim a program-level verified PoC.
"""
from __future__ import annotations

from ...db.dao import DynResultDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import DANGEROUS, SOURCES, normalize
from ..dynamic import sandbox
from ..fuzz.runner import invocation
from ..poc.capture import how_to_feed
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

#: Names that are IMPORTED libc routines, not the program's own code: the decompiler recovers their
#: PLT thunk as a "function", but driving it is pointless (it just jumps through the GOT) and -- since
#: its signature is the known libc prototype -- it scores a perfect harnessable shape and crowds the
#: real parsers out of the candidate list. Exclude them from driving.
_LIBC_THUNKS = set(DANGEROUS) | set(SOURCES) | {
    "memcpy", "memmove", "memset", "mempcpy", "strlen", "strnlen", "strchr", "strrchr", "strcmp",
    "strncmp", "puts", "putchar", "putc", "printf", "fprintf", "vprintf", "snprintf", "fwrite",
    "fputs", "fflush", "setvbuf", "malloc", "calloc", "realloc", "free", "exit", "abort",
    "__stack_chk_fail", "__libc_start_main", "__cxa_finalize", "__assert_fail", "perror",
}


def _is_import_thunk(rf) -> bool:
    return normalize(rf.name) in _LIBC_THUNKS


def _drivable(rf) -> bool:
    """A function the harness can meaningfully drive: NOT an imported-libc thunk, and either a
    pointer-shaped prototype OR a real parser (touches a dangerous sink / reads input) whose param
    types the decompiler simply did not recover -- common on -O0 and stripped builds, where the old
    `ptr_len >= 1` gate silently dropped the actual vulnerable function."""
    if _is_import_thunk(rf):
        return False
    return rf.ptr_len >= 1 or bool(rf.sinks) or bool(rf.sources)


def _drive_shape(rf) -> str:
    """How to hand the fuzzed buffer to the function. ptr_len=2 (pointer+length recovered) -> set
    both; ptr_len=1 (a lone pointer, no length) -> pointer only; ptr_len=0 (nothing recovered) ->
    guess the common `f(buf, len)` and set the length too, so a `if (len < N) return;` guard does
    not early-return on an uninitialised length and mask the bug."""
    return "ptr" if rf.ptr_len == 1 else "ptr_len"


def _replay_against_program(ctx, target, p, leads) -> int:
    """THE HARNESS -> L3 BRIDGE (honest). A harness crash is demonstrated at the FUNCTION level; to
    climb the ladder it must become a PROGRAM-level fact. For each function-level crashing input, run
    the WHOLE program with that input over the operator's channel and record a real `DynResult`:

      * the program faults  -> a genuine program-level crash row (crashed=True). This is exactly what
        the autopilot prove-ladder consumes (`_distinct_crashes` -> root_cause -> build_poc ->
        poc_primitive -> build_exploit), so the lead now reaches L3 like any fuzzer-found crash, AND
        its finding is raised to `confirmed` on a new `harness-replay` channel (a channel can only
        RAISE -- the honesty invariant).
      * the program does NOT fault -> a non-crash row (crashed=False) whose input_sha then seeds
        concolic and directed_fuzz (`_gather_seeds` reads DynResult rows): the harness's hard-won,
        gate-passing input becomes the seed a steered reachability pass mutates toward a real crash.

    Nothing is fabricated: every row reflects a real execution of the program, and L3 is only ever
    reached when the program actually crashes. Returns the number of program-level crashes."""
    if not leads:
        return 0
    try:
        exe = ctx.content.stage_target(target, ctx.scratch(), "target.bin")
    except Exception as e:                                   # noqa: BLE001 -- staging is best-effort
        ctx.emit("harness.progress", payload={"replay_error": f"stage_target: {str(e)[:120]}"})
        return 0
    mode, base_argv, _why = how_to_feed(ctx.conn, target, p.get("input_sha"), p, content=ctx.content)
    exec_timeout = float(p.get("exec_timeout", 2))
    workfile = ctx.scratch() / "harness-replay.bin"
    dd, fd = DynResultDAO(ctx.conn), FindingDAO(ctx.conn)
    prog_crashes = 0
    seen = set()
    for lead in leads[: int(p.get("replay_cap", 12))]:
        if ctx.should_cancel():
            break
        sha, inp = lead["sha"], lead["input"]
        if sha in seen:
            continue
        seen.add(sha)
        try:
            argv, stdin = invocation(mode, workfile, inp, base_argv)
            r = sandbox.run(exe, argv=argv, stdin=(stdin if mode == "stdin" else b""),
                            timeout=exec_timeout, arch=target.arch,
                            endianness=target.endianness, bits=target.bits)
        except Exception as e:                               # noqa: BLE001 -- one replay must not sink it
            ctx.emit("harness.progress", payload={"replay_error": str(e)[:120], "input": sha[:12]})
            continue
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=sha,
                  input_mode=mode, argv=[], exit_code=r.exit_code, signal=r.signal,
                  signal_name=r.signal_name, crashed=r.crashed, isolation=r.isolation,
                  duration_ms=r.duration_ms,
                  note=("harness-replay: " + ("PROGRAM-LEVEL CRASH of the harness function-level "
                        "input" if r.crashed else "no program-level fault -- kept as a reachability "
                        "seed for concolic/directed_fuzz")))
        if r.crashed:
            prog_crashes += 1
            # raise the finding to confirmed: a second, PROGRAM-LEVEL channel now agrees.
            fd.upsert(target.id, target.case_id, {
                "cwe": lead["cwe"], "title": lead["title"], "severity": lead["severity"],
                "detector": "harness", "state": "confirmed",
                "confidence": max(lead.get("confidence", 0.8), 0.9),
                "site_addr": lead.get("site_addr"), "function_addr": lead.get("function_addr"),
                "dedup_key": lead["dedup_key"],
                "evidence": [{"channel": "harness-replay", "detail": (
                    f"the function-level crashing input {sha[:12]} ({len(inp)} B) ALSO faults the "
                    f"whole program when delivered over '{mode}' ({r.signal_name or 'crash'}) -- a "
                    "program-level crash. This promotes the lead from function-level to a real "
                    "program crash the exploit ladder can escalate (root_cause -> build_poc -> "
                    "poc_primitive -> build_exploit).")}]})
    return prog_crashes


def harness_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("harness requires a target_id")
    p = ctx.params or {}
    # Gating -- decline cleanly (never raise) with a reason the operator can act on.
    if (target.arch or "") not in _X86_64:
        note = f"the harness executor is x86-64 only; this target is {target.arch}"
        ctx.emit("harness.done", payload={"supported": False, "note": note})
        ctx.progress(pct=100, msg="harness: x86-64 only")
        return {"supported": False, "findings": 0, "note": note}
    if not available():
        note = "unicorn is not available"
        ctx.emit("harness.done", payload={"supported": False, "note": note})
        ctx.progress(pct=100, msg="harness: unicorn unavailable")
        return {"supported": False, "findings": 0, "note": note}
    if not FunctionDAO(ctx.conn).list_by_target(target.id):
        note = "no recovered functions -- run disassemble first"
        ctx.emit("harness.done", payload={"supported": False, "note": note})
        ctx.progress(pct=100, msg="harness: disassemble first")
        return {"supported": False, "findings": 0, "note": note}

    ranked = rank_functions(ctx.conn, target.id, top=int(p.get("rank_top", 40)))
    # Drive the program's own promising parsers -- never an imported-libc PLT thunk -- pointing the
    # fuzzed buffer at their pointer argument. A ranked function that touches a sink / reads input is
    # driven even when its param TYPES were not recovered (the old `ptr_len >= 1` gate dropped the
    # real vulnerable function on -O0 / stripped builds; see _drivable / _drive_shape).
    cands = [r for r in ranked if _drivable(r)][:int(p.get("max_functions", 6))]
    if not cands:
        note = ("no drivable parser among the top ranked targets -- the promising ones "
                "take input via fd/FILE, which this harness model does not drive yet")
        ctx.emit("harness.done", payload={"supported": True, "findings": 0, "note": note})
        ctx.progress(pct=100, msg="harness: no drivable target")
        return {"supported": True, "findings": 0, "note": note}

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
    prog_leads = []          # function-level crashes to replay against the whole program (-> L3)
    for rf in cands:
        shape = _drive_shape(rf)
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
            dedup = f"harness:{rf.addr:#x}:{r.fault_pc or 0:#x}:{r.access}"
            title = f"Harness-demonstrated {kind} in {label} (function-level)"[:200]
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "severity": "high",
                "title": title,
                "detector": "harness", "state": "corroborated", "confidence": 0.8,
                "site_addr": pc if r.fault_pc is not None else None,
                "function_addr": hex(rf.addr),
                "dedup_key": dedup,
                "evidence": [{"channel": "harness", "detail": (
                    f"driving {label}({shape}) directly under the emulator, input "
                    f"{sha[:12]} ({len(inp)} B) faults: {r.access} at {fault}, pc {pc}. "
                    "PROVENANCE: demonstrated at the FUNCTION level (the function was called "
                    "directly with this input) -- a confirmed bug for a library API, and a "
                    "reachable-if-driven lead for a daemon whose entry path a concolic/reachability "
                    "pass must still connect. Not a program-level verified PoC.")}]})
            prog_leads.append({"sha": sha, "input": inp, "cwe": cwe, "title": title,
                               "severity": "high", "confidence": 0.8,
                               "site_addr": pc if r.fault_pc is not None else None,
                               "function_addr": hex(rf.addr), "dedup_key": dedup})
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
                    dedup = f"harness:{rf.addr:#x}:{r.fault_pc or 0:#x}:{r.access}"
                    title = f"Harness-demonstrated {kind} in {label} (stateful sequence)"[:200]
                    prog_leads.append({"sha": sha, "input": inp, "cwe": cwe, "title": title,
                                       "severity": "high", "confidence": 0.8,
                                       "site_addr": pc if r.fault_pc is not None else None,
                                       "function_addr": hex(rf.addr), "dedup_key": dedup})
                    fd.upsert(target.id, target.case_id, {
                        "cwe": cwe, "severity": "high",
                        "title": title,
                        "detector": "harness", "state": "corroborated", "confidence": 0.8,
                        "site_addr": pc if r.fault_pc is not None else None,
                        "function_addr": hex(rf.addr),
                        "dedup_key": dedup,
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
    # The harness -> L3 bridge: replay the function-level crashes against the WHOLE program so a
    # real program crash becomes a DynResult the exploit ladder escalates, and the rest become
    # reachability seeds. Honest -- every row is a real execution; L3 only on a genuine crash.
    prog_crashes = 0
    if prog_leads and p.get("replay", True):
        ctx.progress(msg=f"harness: replaying {len(prog_leads)} function-level crash(es) "
                         "against the whole program")
        prog_crashes = _replay_against_program(ctx, target, p, prog_leads)
    ctx.emit("harness.done", payload={"supported": True, "functions": len(cands),
             "findings": findings, "program_crashes": prog_crashes})
    esc = (f"; {prog_crashes} reproduced at PROGRAM level (escalatable to L3)" if prog_crashes
           else (f"; {len(prog_leads)} seeded for concolic/directed_fuzz reachability"
                 if prog_leads else ""))
    ctx.progress(pct=100, msg=f"harness: {findings} function-level fault(s) across "
                             f"{len(cands)} driven target(s){esc}")
    return {"findings": findings, "functions": len(cands), "program_crashes": prog_crashes}


def enqueue_harness(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, HARNESS_STAGE, target_id=target.id,
                         params=params or {}, force=force)


def register() -> None:
    register_stage(HARNESS_STAGE, harness_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=240)
