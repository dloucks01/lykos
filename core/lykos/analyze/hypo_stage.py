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

from ..db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, TargetDAO
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

    focus, basis = ([], {})
    if p.get("focus", True):
        focus, basis = _focus_functions(ctx.conn, target, int(p.get("max_focus", _MAX_FOCUS)))
    extra = {"focus_funcs": focus} if focus else {}
    own = _program_functions(ctx, target)
    if own:
        # a STATIC binary: propose only in the program's own code, never inside the linked-in
        # libc (measured: 3,229 proposals on static jhead-3.04, nearly all in glibc, without it)
        extra["own_funcs"] = own
    seed_fmt = None
    if p.get("seed", True) and mode in ("file", "stdin"):
        seed_fmt, seed = _pick_seed(ctx, target, exe, mode, argv)
        if seed:
            import base64 as _b64
            extra["seed_b64"] = _b64.b64encode(seed).decode()
            ctx.emit("hypo.seed", payload={"format": seed_fmt, "bytes": len(seed),
                     "note": "the solver starts past this format's front gates (seed prefix pinned)"})
    ctx.emit("hypo.focus", payload={
        "functions": len(focus), "basis": basis,
        "note": (f"proposing only inside {len(focus)} function(s) other evidence names"
                 if focus else "no per-site evidence on this target yet -- proposing everywhere")})
    res = loop.hunt_target(t, budget, input_size=int(p.get("input_size", 300)),
                           mem_mb=int(p.get("mem_mb", 8192)), log=_log, extra=extra)
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


#: functions the loop is focused on at most (each one costs solver time)
_MAX_FOCUS = 12

#: per-SITE evidence detectors -> weight. Roll-ups / advisories (dangerous_api) are excluded: they
#: name an API, not a defect site. Demonstrated evidence (qasan, a crash) outranks static.
_FOCUS_WEIGHT = {"qasan": 10.0, "fuzz": 8.0, "directed_fuzz": 8.0, "coverage_fuzz": 8.0,
                 "root_cause": 8.0, "pcode_alloc_overflow": 6.0, "oob_index": 5.0,
                 "array_index": 5.0, "tainted_deref": 4.0, "stack_frame": 4.0,
                 "int_overflow_check": 2.0, "heap_fptr_call": 2.0}
_FOCUS_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126",
               "CWE-127", "CWE-129", "CWE-131", "CWE-190", "CWE-191", "CWE-369", "CWE-415",
               "CWE-416", "CWE-476", "CWE-787", "CWE-805", "CWE-822", "CWE-823", "CWE-824"}


def _program_functions(ctx, target):
    """Link-time VAs of the program's OWN functions on a statically linked target (libscope's
    library attribution: symbol files, FLIRT, names, layout + reach), or None when nothing is
    scoped (dynamic binary, no attribution)."""
    try:
        from . import elf as elfmod
        from .detect import libscope
        fns = FunctionDAO(ctx.conn).list_by_target(target.id)
        if not fns:
            return None
        blob = ctx.content.path(target.sha256).read_bytes()
        sc = libscope.library_scope(blob, fns, edges=CallEdgeDAO(ctx.conn).list_by_target(target.id))
        ex = sc.get("excluded") or {}
        if not ex:
            return None
        base = 0
        info = elfmod.parse(blob)
        if info.elf_type and "DYN" in str(info.elf_type).upper():
            from .debug import rootcause
            base = rootcause.image_base(fns, info.entry)
            if base is None:
                return None
        out = []
        for f in fns:
            if f.addr in ex:
                continue
            try:
                a = int(f.addr, 16) if isinstance(f.addr, str) else int(f.addr)
            except (TypeError, ValueError):
                continue
            out.append(a - base)
        return sorted(out) or None
    except Exception:                                    # noqa: BLE001 -- scoping is an aid
        return None


def _focus_functions(conn, target, cap: int):
    """The functions other evidence names as defect SITES, best first: ([link VA], basis).

    Read per SITE (finding_site): a roll-up finding names many functions, but its own
    function_addr is only the first. Each (finding, function) pair contributes the detector's
    weight once, x2 when that site is corroborated or better, x1.5 when grounding found the
    finding attacker-reachable, plus a small capped bonus for further sites in the same function;
    sites the bounds analysis judged guarded contribute nothing."""
    import json as _json
    import math

    def _addr(v):
        try:
            return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)
        except (TypeError, ValueError):
            return None
    findings = {f.id: f for f in FindingDAO(conn).list_by_target(target.id)
                if _FOCUS_WEIGHT.get(f.detector or "") and (f.cwe or "") in _FOCUS_CWES}
    if not findings:
        return [], {}
    reach: dict = {}
    for fid, f in findings.items():
        for e in (f.evidence or []):
            if isinstance(e, dict) and e.get("channel") == "grounding-map":
                try:
                    reach[fid] = _json.loads(e.get("detail") or "{}").get("reachable") is True
                except Exception:                        # noqa: BLE001
                    pass
                break
    per: dict = {}                                       # (fid, func) -> [site states]
    marks = ",".join("?" * len(findings))
    rows = conn.execute(f"SELECT finding_id, function_addr, state, verdict FROM finding_site "
                        f"WHERE finding_id IN ({marks})", list(findings)).fetchall()
    for r in rows:
        if (r["verdict"] or "").lower() == "guarded":
            continue
        a = _addr(r["function_addr"])
        if a is not None:
            per.setdefault((r["finding_id"], a), []).append(r["state"] or "")
    for fid, f in findings.items():                      # a finding with no site rows: its own addr
        a = _addr(f.function_addr)
        if a is not None and not any(k[0] == fid for k in per):
            per[(fid, a)] = [f.state or ""]
    score: dict = {}
    basis: dict = {}
    for (fid, a), states in per.items():
        f = findings[fid]
        w = _FOCUS_WEIGHT[f.detector]
        if any(st in ("corroborated", "confirmed", "poc-backed") for st in states + [f.state or ""]):
            w *= 2.0
        if reach.get(fid):
            w *= 1.5
        w += min(2.0, 0.5 * math.log2(len(states))) if len(states) > 1 else 0.0
        score[a] = score.get(a, 0.0) + w
        basis[f.detector] = basis.get(f.detector, 0) + 1
    ranked = sorted(score, key=lambda a: -score[a])[:max(0, cap)]
    return ranked, basis


def _pick_seed(ctx, target, exe, mode, argv):
    """(format, specimen) the target's parser gets furthest with, or (None, None). Candidates are
    the formats its strings/imports name (fuzz.structure.detect_formats, top 3); the winner is the
    specimen whose run differs from a same-length garbage input's (exit status or output) -- the
    parser accepted its front gates. jhead names tiff first (EXIF is TIFF-structured) but only
    accepts JPEG files: a fixed first pick would pin the wrong magic."""
    try:
        from ..db.dao import StringDAO
        from .dynamic import sandbox
        from .fuzz import structure
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        imps = [e.dst_name for e in CallEdgeDAO(ctx.conn).list_by_target(target.id) if e.dst_name]
        fmts = structure.detect_formats(strings, imps)[:3]
    except Exception:                                    # noqa: BLE001
        return None, None
    best = (None, None, -1)
    for fm in fmts:
        sd = structure.seed_for_name(fm)
        if not sd:
            continue
        try:
            r = sandbox.run_batch(str(exe), [sd, b"A" * len(sd)], mode=mode,
                                  base_argv=[a for a in argv if mode == "file" or a != "@@"],
                                  timeout=5.0, arch=target.arch, endianness=target.endianness,
                                  bits=target.bits)
        except Exception:                                # noqa: BLE001
            r = None
        if not r or len(r) != 2:
            continue
        good, junk = r
        score = int(good.exit_code != junk.exit_code) + int(
            (good.stdout or b"") + (good.stderr or b"") != (junk.stdout or b"") + (junk.stderr or b""))
        if not good.crashed and score > best[2]:
            best = (fm, sd, score)
    return (best[0], best[1]) if best[2] > 0 else (None, None)


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
