"""The `mem_oracle` stage: uninitialised-memory reads, and the disclosure when they leave.

A defect that NEVER CRASHES is invisible to everything else in this pipeline. Reading an
uninitialised buffer is the clearest example: the read succeeds, the process exits 0, and the
stale bytes go out with the output. The conformance case for it recorded the gap exactly --
"reading an uninitialised buffer never faults, and nothing compares output against stale frame
contents, so the disclosure is not demonstrated".

The first design for closing it was wrong, and the reason is worth keeping. The plan was a
DIFFERENTIAL oracle: fill fresh stack and heap with a pattern via `LD_PRELOAD`, run the same
input twice with different patterns, and diff the output. That cannot work on the shape this
defect usually takes, where one function's dead frame is read by the next:

    static void fill(void){ char pad[64]; memset(pad,'S',sizeof pad); }
    static void leak(void){ char b[64]; printf("%.64s\\n", b); }   /* never initialised */
    int main(void){ fill(); leak(); }

`fill()` overwrites any pre-seeded pattern microseconds before `leak()` reads it, so the output
is identical under every pattern -- and this program reads no input at all, so no black-box
variation changes anything. A differential needs a knob, and there is none.

Valgrind memcheck has the knob: shadow memory tracks definedness per byte, so it sees the read
itself, and `--track-origins` names where the undefined value came from. It also draws the
distinction that decides what may be CLAIMED:

  * `Conditional jump or move depends on uninitialised value(s)` -- an internal error. Real
    (CWE-457), but nothing left the process, so there is no effect to demonstrate.
  * `Syscall param write(buf) points to uninitialised byte(s)` -- the bytes reached a write
    syscall. That IS the effect: stack or heap residue disclosed to whoever reads the output
    (CWE-200), observed at runtime rather than inferred.

The oracle already existed in `memoracle`; what did not exist was any way to reach it without a
crash. `valgrind_triage` was called from exactly one place -- root_cause's crash-classification
block -- so a defect that does not crash could never be classified by it. Crash-centric gating
hiding a non-crash defect class. This stage is that missing path.

Honest limits: memcheck is a host-arch dynamic translator, so this is native-ELF only (the same
limit as the guard-page allocator) and 10-30x slower than a bare run, which is why it is a
bounded triage pass over a few inputs rather than anything in a fuzzing loop. It reports only
what the chosen inputs actually execute: silence means those paths were clean, not that the
program is.
"""
from __future__ import annotations

from ...db.dao import DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import substrate
from ..poc.capture import how_to_feed
from . import memoracle, sandbox

MEM_ORACLE_STAGE = "mem_oracle"
TOOL = "memcheck"
TOOL_VERSION = "memoracle-1"

#: Inputs to spend a memcheck run on. Each is 10-30x a native exec, so this is deliberately tiny.
_MAX_RUNS = 3

#: The classes only this oracle can see. A heap error is reported too -- memcheck names it
#: precisely on a binary with no source ASan -- but `heap_check`/`heap_trace` are its primary
#: owners, so those arrive here as corroboration rather than as the discovery.
_UNINIT_KINDS = frozenset({"uninit-disclosure", "uninitialised"})

_TITLES = {
    "uninit-disclosure": "Uninitialised memory disclosed to output",
    "uninitialised": "Uninitialised memory read",
}


from ..invocation import staged_name as _staged_name


def _decline(ctx, note: str) -> dict:
    ctx.emit("memoracle.done", payload={"supported": False, "note": note})
    ctx.progress(pct=100, msg=note[:90])
    return {"metrics": {"supported": False}}


def _probe_inputs(conn, target) -> list:
    """Up to `_MAX_RUNS` inputs worth a memcheck run, best first.

    A recorded crashing input is the most interesting thing available; an empty probe is the
    fallback and is not a weak one -- a program whose uninitialised read is on its default path
    discloses on the very first execution, and reads no input at all.
    """
    out: list = []
    try:
        for d in DynResultDAO(conn).list_by_target(target.id):
            if d.input_sha and d.input_sha not in out:
                out.append(d.input_sha)
    except Exception:                                    # noqa: BLE001 -- probes are advisory
        pass
    return out[:_MAX_RUNS]


#: What a disclosure of residue is WORTH. memcheck proves undefined bytes reached a write syscall
#: -- an effect, and the end of what this stage could say. But stack and heap residue full of
#: POINTERS defeats ASLR, and residue full of padding does not, and that difference decides
#: whether a reader goes looking for a write primitive to pair the leak with. The out-of-bounds
#: READ arm already draws it (`leak.disclosed_bases`, which validates a base against the target's
#: own symbol layout rather than against a second run), and nothing connected the uninitialised
#: read to it: on a plain binary with no sanitizer build to crash in, the whole class stopped at
#: a CWE-200 finding, L0, however good the bytes were **[measured on uninit_stack_read]**.
_LEAK_RUNS = 2


def _disclosed_bases(ctx, target, exe, data, mode, argv, timeout):
    """Run the UNINSTRUMENTED target (memcheck's own output is not the program's) under live ASLR
    and ask what its bytes prove. Returns `leak.disclosed_bases`' verdict, or None."""
    from ..poc import leak as _leak
    from ..poc.exploit_stage import _libc_bytes_for
    try:
        target_bytes = ctx.content.path(target.sha256).read_bytes()
    except Exception:                                    # noqa: BLE001
        return None
    libc_data = _libc_bytes_for(ctx, target) or b""
    # EACH RUN CLASSIFIED ON ITS OWN, never concatenated. ASLR is on, so two runs disclose
    # pointers from two different bases: joining them hands the classifier slots that corroborate
    # nothing, and the corroboration rule then rejects a leak that each run proves by itself
    # **[measured on the format-string fixture: 24 pointers, no base]**. The second run exists
    # because a run may disclose nothing, not to pool evidence.
    last = None
    for _ in range(_LEAK_RUNS):
        r = sandbox.run(exe, argv=list(argv or []), stdin=(data if mode == "stdin" else b""),
                        timeout=min(float(timeout), 20.0), aslr=True)
        out = (r.stdout or b"") + (r.stderr or b"")
        if not out:
            continue
        last = _leak.disclosed_bases(out, target_bytes, libc_data)
        if last.get("proved"):
            return last
    return last


def _file_uninit_l2(ctx, target, cand, disc, mode, sha) -> bool:
    """File the proved disclosure as an L2 primitive: the residue carried a pointer and the base it
    anchors was corroborated against this binary's own layout. Same rung, and the same claim, as
    the out-of-bounds read arm -- a disclosure primitive, not a hijack."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from ..poc import bundle
    got = ", ".join(n for n, k in (("image base", "pie_base"), ("libc base", "libc_base"),
                                   ("stack canary", "canary")) if disc.get(k) is not None)
    if not got:
        return False
    where = ", ".join(f"{n} {v:#x}" for n, v in
                      (("PIE base", disc.get("pie_base")), ("libc base", disc.get("libc_base")),
                       ("canary", disc.get("canary"))) if isinstance(v, int))
    # The classifier's own note is not quoted: it is written for the out-of-bounds READ arm and
    # says so, and a finding must not describe itself as a different defect.
    detail = (f"ASLR defeated by an uninitialised read: the stale {disc.get('origin') or 'stack'} "
              f"bytes memcheck saw reach a write syscall carry live pointers, and the {got} they "
              f"anchor ({where}) was corroborated against this binary's own symbol layout by the "
              f"{disc.get('rule') or 'page-offset'} rule -- not against a second run, because "
              f"residue cannot be told from residue that way. The read never faults, so no "
              f"crash-driven stage can reach this.")
    try:
        target_bytes = ctx.content.path(target.sha256).read_bytes()
    except Exception:                                    # noqa: BLE001
        return False
    data = b"" if not sha else (ctx.content.get_bytes(sha) or b"")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L2",
            "primitive": "address-disclosure (uninitialised read)",
            "pie_base": disc.get("pie_base"), "libc_base": disc.get("libc_base"),
            "tool_version": TOOL_VERSION}
    blob = bundle.build(target_bytes, data, meta, b"", mode, list(cand.get("argv") or []), None,
                        primitive={"type": "address-disclosure", "confirmed": True,
                                   "note": "uninitialised read"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=blob, meta={"level": "L2", "verified": True})
    input_sha = sha or ctx.put_artifact("uninit-disclosure-input", data=data)
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L2", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    c2 = {"cwe": "CWE-200", "title": f"ASLR defeated by an uninitialised read (discloses the {got})"
                                    " (demonstrated): L2 primitive",
          "severity": "high", "detector": TOOL, "state": "poc-backed", "confidence": 0.95,
          "authoritative": True, "title_only": True,
          "dedup_key": f"CWE-200:uninit-disclosure:aslr:{target.id}",
          "evidence": [{"channel": "effects", "detail": _json.dumps([{
              "kind": "info-disclosure", "status": "demonstrated",
              "title": "ASLR defeated by an uninitialised read", "detail": detail,
              "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                        "note": detail}}])}]}
    fd.upsert(target.id, target.case_id, c2)
    fid = fd.id_for_dedup(target.id, c2["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("memoracle.disclosure", payload={
        "proved": True, "pie_base": disc.get("pie_base"), "libc_base": disc.get("libc_base"),
        "canary": disc.get("canary"), "bundle": bundle_sha, "level": "L2"})
    ctx.progress(msg=f"L2: the uninitialised read discloses the {got}")
    return True


def mem_oracle_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("mem_oracle requires a target_id")
    p = ctx.params or {}

    sub = substrate.for_target(target)
    if sub.backend != substrate.NATIVE:
        return _decline(ctx, f"memcheck is a host-architecture dynamic translator and cannot run "
                             f"a {(target.file_type or 'non-native').upper()} target "
                             f"({sub.no_exec or 'it does not execute as a host process'})")
    host = sandbox.host_arch()
    if substrate.foreign_cpu(target.arch, target.file_type, host):
        return _decline(ctx, f"memcheck runs the target natively (target {target.arch}, host "
                             f"{host}); a cross-arch shadow-memory oracle is not available here")
    if memoracle.valgrind_bin() is None:
        return _decline(ctx, "valgrind is not installed, so uninitialised-memory reads cannot be "
                             "observed on this host -- nothing was checked, which is not the "
                             "same as nothing found")

    # Staged under the name the image dispatches on (busybox and any other multi-call
    # binary refuse every input as `target.bin`): see invocation.staged_name.
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)

    shas = [p["input_sha"]] if p.get("input_sha") else _probe_inputs(ctx.conn, target)
    timeout = float(p.get("timeout", 120))
    fd = FindingDAO(ctx.conn)
    filed, seen, tried = 0, set(), []
    leaked = False                                       # an L2 disclosure primitive, filed once

    # The empty probe goes LAST: a recorded input exercises more of the program, but a default-path
    # disclosure needs no input at all, so the list must never be empty.
    for sha in list(shas) + [None]:
        if len(tried) >= _MAX_RUNS:
            break
        data = b""
        if sha:
            try:
                data = ctx.content.get_bytes(sha)
            except Exception:                            # noqa: BLE001
                continue
        mode, argv, _why = how_to_feed(ctx.conn, target, sha, p, content=ctx.content)
        tried.append({"input_sha": sha, "mode": mode})
        ctx.progress(msg=f"memcheck under {mode} ({len(tried)}/{_MAX_RUNS})")
        verdict = memoracle.valgrind_triage(exe, data, mode=mode, base_argv=argv,
                                            timeout=timeout, ctx=ctx)
        if not verdict or verdict["kind"] in seen:
            continue
        seen.add(verdict["kind"])
        kind = verdict["kind"]
        origin = verdict.get("origin")
        where = f" ({origin} allocation)" if origin else ""
        title = _TITLES.get(kind, f"Memory error ({kind})")
        detail = f"valgrind memcheck: {verdict['detail']}"
        cand = {
            "cwe": verdict["cwe"], "title": f"{title}{where}", "severity": verdict["severity"],
            # memcheck RAN the program and watched the access, so this is reproduced, not
            # inferred. It is not poc-backed: no reproducer bundle is built here.
            "state": "confirmed", "confidence": 0.9, "detector": TOOL,
            "dedup_key": f"{verdict['cwe']}:memcheck:{kind}",
            "evidence": [{"channel": "memcheck", "detail": detail},
                         {"channel": "memcheck-input",
                          "detail": f"delivered via {mode}"
                                    + (f", input {sha[:12]}" if sha else ", no input required")}],
        }
        if kind == "uninit-disclosure":
            # The one case here with an EFFECT a report can state: the bytes left the process.
            cand["evidence"].append({
                "channel": "effects",
                "detail": __import__("json").dumps([{
                    "kind": "info-disclosure", "status": "demonstrated",
                    "title": "Uninitialised memory disclosed to output",
                    "detail": (f"memcheck observed undefined bytes from a {origin or 'stack/heap'} "
                               f"allocation reaching a write syscall"),
                }])})
        fd.upsert(target.id, target.case_id, cand)
        filed += 1
        if kind == "uninit-disclosure" and not leaked:
            # ...and WHAT the bytes were. The disclosure is the effect; the base it anchors is
            # the primitive, and only one of the two is worth pairing with a write.
            disc = _disclosed_bases(ctx, target, exe, data, mode, argv, timeout)
            if disc and disc.get("proved"):
                cand["argv"] = list(argv or [])
                leaked = _file_uninit_l2(ctx, target, cand, disc, mode, sha)
            elif disc is not None:
                ctx.emit("memoracle.disclosure", payload={
                    "proved": False, "disclosed_bytes": disc.get("disclosed_bytes"),
                    "note": "the residue that left the process anchors no base: an information "
                            "disclosure with nothing in it that defeats ASLR (which is a RESULT, "
                            "not a failure -- padding leaks are the common case)"})

    note = ("no uninitialised-memory or heap error observed on the inputs tried -- those paths "
            "were clean, which is not the same as the program being clean"
            if not filed else
            f"{filed} memory error(s) classified by shadow memory, which no crash would show")
    ctx.emit("memoracle.done", payload={
        "supported": True, "runs": len(tried), "findings": filed,
        "kinds": sorted(seen), "uninit": sorted(seen & _UNINIT_KINDS), "note": note})
    ctx.progress(pct=100, msg=note[:90])
    return {"metrics": {"runs": len(tried), "findings": filed}}


def register() -> None:
    register_stage(MEM_ORACLE_STAGE, mem_oracle_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=600)


def enqueue_mem_oracle(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, MEM_ORACLE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
