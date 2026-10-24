"""The AVAILABILITY ladder: escalate a confirmed memory-leak / resource-exhaustion finding (L1)
up to an unbounded-amplification PRIMITIVE (L2) and a realised, host-safe denial-of-service
IMPACT (L3).

The project levels by impact (see `bundle._LEVEL_MEANING`): L2 is an exploitation primitive, L3 is
the attacker's end goal happening. For the corruption family the end goal is a hijack; for an
injection it is the effect carried out. For an availability defect the end goal is the service
going down -- so:

  * L2 -- the defect is an attacker-controllable, UNBOUNDED resource grant. We measure the resource
    consumed per attacker request on the LeakSanitizer build and confirm it scales linearly with no
    ceiling (N and 2N requests consume ~1x and ~2x). That is the availability analogue of "the
    attacker controls a write": the attacker controls unbounded allocation.
  * L3 -- the impact is realised under a BOUNDED, host-safe budget. We drive the PLAIN build under a
    tight RLIMIT_AS and show the DIFFERENTIAL: a benign small request terminates normally, while the
    amplified request stream, under the same cap, terminates abnormally (allocation-failure exit,
    SIGSEGV/abort, OOM-kill, or a hang). The cap is what makes this safe to run in the gate and in a
    delivered bundle -- "out of memory" is a controlled failure inside the capped child, never the
    host.

A second track, confidentiality: when the program's OUTPUT on the benign run carries pointer-shaped
words or other leaked material, a CWE-200 disclosure finding is filed alongside -- availability and
disclosure are not exclusive, and a leak that also discloses an address is chain material. For a
pure never-freed leak (CWE-401) nothing is echoed, so this correctly does not fire.

Fully guarded: this runs inside `build_poc` after a leak has already been verified to L1, and it
must never retract that or break the campaign. Every failure path returns what was proven so far.
"""
from __future__ import annotations

import logging
import re

from ... import observe
from ...db.dao import ArtifactDAO, FindingDAO, PocDAO
from ..dynamic import sandbox
from . import bundle

_log = logging.getLogger(__name__)

TOOL_VERSION = "dos-1"

# LeakSanitizer prints a summary line we read the running total from.
_LEAK_TOTAL = re.compile(rb"LeakSanitizer:\s*(\d+)\s*byte", re.I)
# A pointer-shaped word in program output: a user-space address, the disclosure-branch oracle.
_PTR_WORD = re.compile(rb"0x[0-9a-fA-F]{8,16}")

#: The host-safe memory budget the L3 impact drive runs the target under. Small enough that a few
#: thousand un-freed allocations exhaust it in milliseconds, so the gate pays almost nothing; the
#: cap is applied to the child alone (RLIMIT_AS via sandbox.run's mem_mb), never to the host.
_CAP_MB = 32
#: Amplification sample sizes for the L2 measurement -- small and fast; the point is the RATIO.
_AMP_N = 64


def _blob(ctx, target, kind):
    """The newest artifact of `kind` built for THIS target (same binary_sha), staged to a file."""
    try:
        art = next((a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
                    if a.kind == kind
                    and (a.meta or {}).get("binary_sha") in (None, target.sha256)), None)
        if not art:
            return None
        p = ctx.scratch() / f"dos-{kind}"
        p.write_bytes(ctx.content.path(art.sha256).read_bytes())
        import os
        os.chmod(p, 0o755)
        return p
    except Exception:
        observe.absorbed(_log, "no blob")
        return None


def _unit_request(input_bytes: bytes) -> bytes:
    """One attacker 'request', newline-terminated, to repeat. For a line protocol that is the first
    non-empty line of the reproducing input (NOT a trailing terminator line like the probe's 'q').
    With no newline the whole input is one request."""
    if b"\n" not in input_bytes:
        return input_bytes
    for ln in input_bytes.split(b"\n"):
        if ln.strip():
            return ln + b"\n"
    return b"A\n"


def _stream(unit: bytes, n: int) -> bytes:
    return unit * n


def _leaked_bytes(ctx, lsbin, unit, n, mode, argv_base) -> int:
    """Run the LSan build on n requests and return the total bytes it reports leaked, or -1."""
    import os as _os

    from ..fuzz.runner import invocation
    env = dict(_os.environ)
    env["LSAN_OPTIONS"] = "symbolize=0:exitcode=23"
    prefix = sandbox.isolate_prefix(str(lsbin.parent), net=False)
    wf = ctx.scratch() / "dos-amp.bin"
    tail, stdin = invocation(mode, wf, _stream(unit, n), argv_base)
    try:
        r = sandbox.run_reaped(prefix + [str(lsbin)] + tail, input=stdin, timeout=20,
                               capture_output=True, env=env)
    except Exception:
        observe.absorbed(_log, "amp run")
        return -1
    m = _LEAK_TOTAL.search(r.stderr or b"")
    return int(m.group(1)) if m else 0


def _drive(ctx, target, exe, unit, n, mode, argv_base, cap_mb):
    """Run the PLAIN build on n requests under a cap_mb RLIMIT_AS. Returns the RunResult, or None."""
    from ..fuzz.runner import invocation
    wf = ctx.scratch() / "dos-drive.bin"
    tail, stdin = invocation(mode, wf, _stream(unit, n), argv_base)
    try:
        return sandbox.run(exe, argv=tail, stdin=stdin, timeout=15, arch=target.arch,
                           endianness=target.endianness, bits=target.bits, mem_mb=cap_mb)
    except Exception:
        observe.absorbed(_log, "drive run")
        return None


def _abnormal(res) -> bool:
    """Did this run end in an availability FAILURE -- killed, crashed, hung, or a non-zero exit
    (the program's own allocation-failure path)?"""
    if res is None:
        return False
    if getattr(res, "crashed", False) or getattr(res, "timed_out", False):
        return True
    ec = getattr(res, "exit_code", None)
    return ec is not None and ec != 0


def _normal(res) -> bool:
    return res is not None and not _abnormal(res)


def escalate(ctx, target, input_sha, mode, argv_base=()) -> dict:
    """Escalate a verified leak/exhaustion finding up the availability ladder. Returns a dict with
    the top level reached ('L2'/'L3') and the metrics, or {} if nothing above L1 was provable."""
    lsbin = _blob(ctx, target, "lsan-blob")
    plain = _blob(ctx, target, "plain-blob")
    if mode not in ("stdin", "file"):
        return {}                                        # amplification maps cleanly to a stream
    try:
        input_bytes = ctx.content.get_bytes(input_sha)
    except Exception:  # input artifact gone: nothing to escalate, the L1 stands
        return {}
    unit = _unit_request(input_bytes)
    argv_base = list(argv_base or [])

    # ---- L2: unbounded amplification primitive (measured on the LSan build) ----
    bpr = 0                                              # bytes per request
    amplified = False
    if lsbin is not None:
        a1 = _leaked_bytes(ctx, lsbin, unit, _AMP_N, mode, argv_base)
        a2 = _leaked_bytes(ctx, lsbin, unit, 2 * _AMP_N, mode, argv_base)
        # Linear and unbounded: 2N leaks ~2x N, and N already leaks a lot. A bounded cache would
        # plateau (a2 ~= a1); an attacker-controlled leak keeps climbing.
        if a1 > 0 and a2 >= int(1.6 * a1):
            amplified = True
            bpr = max(1, a1 // _AMP_N)

    # ---- L3: realised denial of service under a bounded, host-safe memory cap ----
    impact = {}
    drive_exe = plain
    if drive_exe is not None:
        # size the attack so it overruns the cap ~2x even if the per-request estimate is rough
        est = bpr or 4096
        big = min(200000, max(8000, int(_CAP_MB * 1024 * 1024 / est) * 2))
        base_res = _drive(ctx, target, drive_exe, unit, 4, mode, argv_base, _CAP_MB)
        amp_res = _drive(ctx, target, drive_exe, unit, big, mode, argv_base, _CAP_MB)
        if _normal(base_res) and _abnormal(amp_res):
            how = ("OOM-killed" if getattr(amp_res, "signal_name", None) in ("SIGKILL",)
                   else "crashed in the allocator" if getattr(amp_res, "crashed", False)
                   else "hung (made no progress)" if getattr(amp_res, "timed_out", False)
                   else f"took its allocation-failure path (exit {getattr(amp_res,'exit_code','?')})")
            impact = {"requests": big, "cap_mb": _CAP_MB, "how": how,
                      "baseline_exit": getattr(base_res, "exit_code", None)}

    # ---- disclosure branch (confidentiality): did the benign run echo leaked material? ----
    _disclosure(ctx, target, input_sha)

    # The bundle has to carry WHAT WAS MEASURED: the L3 impact was shown on the PLAIN build, fed
    # the AMPLIFIED stream, under the cap; the L2 ratio on the LSan build, fed N requests. It used
    # to ship the ingested (sanitizer) image with the single original request and no cap -- a
    # reproducer that cannot show the impact at all (ASan will not even start under a 32 MB
    # address-space cap, and one request exhausts nothing).
    if impact:
        return _file_poc(ctx, target, input_sha, mode, argv_base, "L3", bpr, impact,
                         exe_path=drive_exe, stream=_stream(unit, impact["requests"]),
                         mem_cap_mb=_CAP_MB)
    if amplified:
        return _file_poc(ctx, target, input_sha, mode, argv_base, "L2", bpr, {},
                         exe_path=lsbin, stream=_stream(unit, 2 * _AMP_N))
    return {}


def _disclosure(ctx, target, input_sha) -> None:
    """If the plain build ECHOES pointer-shaped words when fed the leak input, the leak also
    discloses memory (CWE-200) -- filed alongside. For a pure never-freed leak nothing is echoed,
    so this does not fire."""
    plain = _blob(ctx, target, "plain-blob")
    if plain is None:
        return
    try:
        from ..fuzz.runner import invocation
        data = ctx.content.get_bytes(input_sha)
        wf = ctx.scratch() / "dos-disc.bin"
        tail, stdin = invocation("stdin", wf, data, ())
        r = sandbox.run(plain, argv=tail, stdin=stdin, timeout=10, arch=target.arch,
                        endianness=target.endianness, bits=target.bits, mem_mb=256)
        out = (getattr(r, "stdout", b"") or b"")
        ptrs = _PTR_WORD.findall(out)
        if len(ptrs) >= 2:                               # >=2 pointer-shaped words = a real leak
            FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
                "cwe": "CWE-200", "severity": "medium", "detector": "dos",
                "title": "Information disclosure (leaked memory echoed to output)",
                "state": "corroborated", "confidence": 0.75,
                "dedup_key": "CWE-200:dos:disclosure", "function_addr": None, "site_addr": None,
                "evidence": [{"channel": "disclosure",
                              "detail": f"{len(ptrs)} pointer-shaped words in the target's output, "
                                        f"e.g. {ptrs[0].decode('latin-1')}"}]})
    except Exception:
        observe.absorbed(_log, "disclosure probe")


def _file_poc(ctx, target, input_sha, mode, argv_base, level, bpr, impact, *,
              exe_path=None, stream=None, mem_cap_mb=0) -> dict:
    """Mint a verified PoC at `level` for the availability finding and promote it poc-backed.

    `exe_path`/`stream`/`mem_cap_mb` are the binary, input and budget the level was MEASURED
    with; the bundle ships exactly those (falling back to the ingested image and the original
    input only when the caller has nothing more specific)."""
    if level == "L3":
        headline = (f"Denial of service: the target {impact['how']} under a {impact['cap_mb']} MB "
                    f"budget after ~{impact['requests']} attacker requests, while a benign request "
                    f"exits cleanly under the same cap")
    else:
        headline = (f"Unbounded resource amplification: ~{bpr} bytes consumed per attacker request "
                    f"with no ceiling (measured linear on the sanitizer build)")
    try:
        input_bytes = stream if stream is not None else ctx.content.get_bytes(input_sha)
    except Exception:  # input artifact gone: nothing to escalate, the L1 stands
        return {}
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": list(argv_base), "level": level, "cwe": "CWE-401",
            "availability": impact or {"bytes_per_request": bpr}, "tool_version": TOOL_VERSION,
            # the delivered PoC is run under a memory cap and is a success when it dies there
            "verdict": ({"exit": "nonzero", "note": f"run under a {mem_cap_mb} MB address-space "
                                                    f"cap, the amplified stream ends abnormally"}
                        if mem_cap_mb else
                        {"exit": "any", "stderr": "LeakSanitizer",
                         "note": "the LeakSanitizer report on stderr is the evidence; compare "
                                 "its byte total against the per-request figure in meta.json"})}
    try:
        exe_bytes = (exe_path.read_bytes() if exe_path is not None
                     else ctx.content.path(target.sha256).read_bytes())
        data = bundle.build(exe_bytes, input_bytes, meta,
                            b"", mode, list(argv_base), "resource-exhaustion",
                            mem_cap_mb=mem_cap_mb)
        bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                      meta={"verified": True, "level": level})
        poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level=level, verified=True,
                                         signal_name="resource-exhaustion", input_sha=input_sha,
                                         bundle_sha=bundle_sha)
        fd = FindingDAO(ctx.conn)
        fd.upsert(target.id, target.case_id, {
            "cwe": "CWE-401", "severity": "high" if level == "L3" else "medium",
            "detector": "dos", "title": headline, "state": "poc-backed", "confidence": 0.95,
            "dedup_key": f"CWE-401:dos:{level}", "function_addr": None, "site_addr": None,
            "evidence": [{"channel": "availability", "detail": headline},
                         {"channel": "poc", "detail": f"verified PoC bundle {bundle_sha[:12]}"}]})
        fid = fd.id_for_dedup(target.id, f"CWE-401:dos:{level}")
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
        ctx.emit("dos.done", payload={"level": level, "bytes_per_request": bpr, "impact": impact})
    except Exception:
        observe.absorbed(_log, "filing dos poc")
        return {}
    return {"level": level, "bytes_per_request": bpr, "impact": impact}


# ------------------------------------------------------------------ non-termination (CWE-835)
#: A NON-TERMINATING input (CWE-835) as a verified L1 PoC. The fuzz stage files a hang as a
#: `corroborated` finding once its differential holds twice (see `fuzz.stage._verify_hang`); this
#: is the step that turns it into a shippable reproducer, held to the same bar the shipped
#: runner.sh applies on the replaying machine:
#:   * a CONTROL input must terminate (clean exit or any status -- not a crash, not a timeout,
#:     not a target that never ran) within `_HANG_CEILING / HANG_FACTOR` seconds;
#:   * the hanging input must then still be running at max(`_HANG_FLOOR`, HANG_FACTOR x the
#:     control's measured runtime) under the same delivery, sandbox and limits.
#: Only then is an L1 filed. A control too slow to leave room for the factor under the ceiling
#: is INCONCLUSIVE, never a pass.
HANG_FACTOR = 4
_HANG_FLOOR = 4.0                 # seconds; the fuzz stage's own re-verification floor
_HANG_CEILING = 30.0              # seconds; one check never eats a run
_HANG_MODES = ("stdin", "file", "arg", "env")
#: Fallback controls when the campaign's own benign input was not recorded: inputs that most
#: programs read to EOF and leave. Each must still PROVE it terminates before it counts.
_CONTROL_FALLBACKS = (b"", b"\n")
HANG_SIGNAL = "non-termination"


def hang_limit(control_s: float, factor: float = HANG_FACTOR, floor: float = _HANG_FLOOR,
               ceiling: float = _HANG_CEILING):
    """The limit the hanging input must outlast, or None when the control is too slow for
    `factor` x its runtime to fit under `ceiling` (inconclusive, not a pass)."""
    need = max(float(floor), float(factor) * max(0.0, float(control_s)))
    return need if need <= float(ceiling) else None


def hang_record(conn, target, input_sha):
    """The CWE-835 finding the fuzz stage filed for `input_sha`: {mode, argv, control_sha,
    isolation, dedup_key}, or None when this input is not a recorded hang."""
    try:
        findings = FindingDAO(conn).list_by_target(target.id)
    except Exception:
        observe.absorbed(_log, "no hang record")
        return None
    for f in findings:
        if (f.cwe or "") != "CWE-835":
            continue
        for e in f.evidence or []:
            if isinstance(e, dict) and e.get("input_sha") == input_sha:
                return {"mode": e.get("input_mode"), "argv": list(e.get("argv") or []),
                        "control_sha": e.get("control_sha"), "isolation": e.get("isolation"),
                        "dedup_key": f.dedup_key}
    return None


def is_recorded_hang(conn, target, input_sha) -> bool:
    """A hang input, and not ALSO a crash: a crashing input keeps the crash path."""
    if hang_record(conn, target, input_sha) is None:
        return False
    try:
        from ...db.dao import DynResultDAO
        return not any(r.input_sha == input_sha and r.crashed
                       for r in DynResultDAO(conn).list_by_target(target.id))
    except Exception:
        observe.absorbed(_log, "dyn results unreadable")
        return True


def _hang_delivery(ctx, mode, argv, data):
    """(argv, stdin, env_overrides): the campaign's own delivery (`fuzz.runner.invocation`), plus
    the env channel the way build_poc replays it."""
    if mode == "env":
        from .capture import env_var_from_argv
        var, rest = env_var_from_argv(argv)
        if not var:
            return None
        return rest, b"", {var: data.decode("latin-1")}
    from ..fuzz.runner import invocation
    a, stdin = invocation(mode, ctx.scratch() / "hang-input.bin", data, argv)
    return a, stdin, None


def _hang_run(ctx, target, exe, mode, argv, data, timeout, guard):
    d = _hang_delivery(ctx, mode, argv, data)
    if d is None:
        return None
    run_argv, stdin, env = d
    try:
        return sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout, arch=target.arch,
                           endianness=target.endianness, bits=target.bits,
                           env_overrides=env, guard_page=guard)
    except Exception:
        observe.absorbed(_log, "hang replay failed to start")
        return None


def _terminated_cleanly(res) -> bool:
    return (res is not None and not res.timed_out and not res.crashed
            and not sandbox.did_not_run(res.isolation))


def verify_hang(ctx, target, exe, mode, argv, data, controls, *, guard=False):
    """Run the differential. Returns (verdict, detail): verdict is True (verified), False (the
    input terminated), or None (inconclusive -- no control terminated, the control was too slow,
    or the target never ran). `detail` carries the measurements either way."""
    detail = {"mode": mode, "factor": HANG_FACTOR, "floor_s": _HANG_FLOOR,
              "ceiling_s": _HANG_CEILING, "controls_tried": []}
    control = c_res = None
    for cand in controls:
        if cand is None or cand == data:
            continue
        r = _hang_run(ctx, target, exe, mode, argv, cand, _HANG_CEILING / HANG_FACTOR, guard)
        detail["controls_tried"].append({
            "bytes": len(cand), "terminated": _terminated_cleanly(r),
            "ms": getattr(r, "duration_ms", None),
            "isolation": getattr(r, "isolation", None)})
        if _terminated_cleanly(r):
            control, c_res = cand, r
            break
    if control is None:
        detail["why"] = ("no control input terminated under the same delivery, so a timeout on "
                         "the hanging input would not distinguish it from the target's normal "
                         "behaviour")
        detail["outcome"] = "inconclusive"
        return None, detail
    control_s = (c_res.duration_ms or 0) / 1000.0
    limit = hang_limit(control_s)
    detail.update(control=control, control_ms=c_res.duration_ms, control_exit=c_res.exit_code)
    if limit is None:
        detail["why"] = (f"the control took {control_s:.2f}s, so {HANG_FACTOR}x it does not fit "
                         f"under the {_HANG_CEILING:g}s ceiling -- the differential cannot be "
                         "measured here")
        detail["outcome"] = "inconclusive"
        return None, detail
    detail["limit_s"] = round(limit, 3)
    h = _hang_run(ctx, target, exe, mode, argv, data, limit, guard)
    if h is None or sandbox.did_not_run(h.isolation):
        detail["why"] = "the hanging input could not be run"
        detail["outcome"] = "inconclusive"
        return None, detail
    detail.update(input_ms=h.duration_ms, input_timed_out=bool(h.timed_out),
                  input_crashed=bool(h.crashed), input_exit=h.exit_code,
                  isolation=h.isolation)
    if h.timed_out and not h.crashed:
        detail["outcome"] = "does-not-terminate"
        return True, detail
    detail["outcome"] = "terminated"
    detail["why"] = ("the input crashed instead of running on" if h.crashed else
                     f"the input terminated in {h.duration_ms} ms (status {h.exit_code})")
    return False, detail


def hang_poc(ctx, target, input_sha, *, exe, params=None, target_bytes=None,
             exec_name: str = "") -> dict:
    """Verify a recorded non-terminating input and, only when the differential holds, file a
    verified L1 PoC bundle whose runner.sh applies the same check. Returns the build_poc stage
    result shape; an unverified hang files NOTHING (the corroborated finding stands, and the
    reason is emitted on `poc.done`)."""
    p = params or {}
    rec = hang_record(ctx.conn, target, input_sha) or {}
    mode = p.get("input_mode") or rec.get("mode") or "stdin"
    argv = list(p.get("argv") if p.get("argv") is not None else rec.get("argv") or [])
    guard = sandbox.GUARD_PAGE_TAG in str(rec.get("isolation") or "")
    data = ctx.content.get_bytes(input_sha)

    def _done(verified, detail, bundle_sha=None):
        ctx.emit("poc.done", payload={
            "verified": verified, "level": "L1" if verified else None, "kind": "hang",
            "signal": HANG_SIGNAL, "bundle": bundle_sha, "input_mode": mode,
            "hang": {k: v for k, v in detail.items() if k != "control"},
            **({} if verified else {"why": detail.get("why")})})
        ctx.progress(pct=100, msg=("hang PoC verified (L1): input does not terminate"
                                   if verified else
                                   "hang PoC NOT verified: " + str(detail.get("why"))))
        return ({"output_shas": [bundle_sha], "output_kind": "poc-bundle"}
                if bundle_sha else {})

    if mode not in _HANG_MODES:
        return _done(False, {"why": f"a non-termination cannot be replayed via {mode!r}"})
    controls = []
    if p.get("control_sha") or rec.get("control_sha"):
        try:
            controls.append(ctx.content.get_bytes(p.get("control_sha") or rec["control_sha"]))
        except Exception:
            observe.absorbed(_log, "recorded hang control is gone; using fallbacks")
    controls += list(_CONTROL_FALLBACKS)
    ctx.progress(msg="verifying non-termination against a terminating control")
    verdict, detail = verify_hang(ctx, target, exe, mode, argv, data, controls, guard=guard)
    if not verdict:
        return _done(False, detail)

    hang = {"factor": HANG_FACTOR, "limit_s": _HANG_FLOOR, "ceiling_s": _HANG_CEILING,
            "control_ms": detail["control_ms"], "verified_limit_s": detail["limit_s"]}
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": argv, "level": "L1", "cwe": "CWE-835", "expected_signal": HANG_SIGNAL,
            "isolation": detail.get("isolation"), "verified": True,
            "tool_version": TOOL_VERSION}
    guard_lib = ""
    if guard:
        from ..dynamic import memoracle
        guard_lib = str(memoracle.dislocator_lib() or "")
    try:
        tb = target_bytes if target_bytes is not None else \
            ctx.content.path(target.sha256).read_bytes()
        data_b = bundle.build(tb, data, meta, b"", mode, argv, HANG_SIGNAL, hang=hang,
                              control_bytes=detail["control"], guard_page=guard_lib,
                              exec_name=exec_name)
        bundle_sha = ctx.put_artifact("poc-bundle", data=data_b,
                                      meta={"verified": True, "level": "L1", "kind": "hang"})
        poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                         signal_name=HANG_SIGNAL, input_sha=input_sha,
                                         bundle_sha=bundle_sha)
        key = rec.get("dedup_key") or f"CWE-835:hang:{mode}"
        fd = FindingDAO(ctx.conn)
        fd.upsert(target.id, target.case_id, {
            "cwe": "CWE-835", "title": "Input that does not terminate (denial of service)",
            "severity": "medium", "detector": "poc", "state": "poc-backed", "confidence": 0.9,
            "dedup_key": key, "function_addr": None, "site_addr": None,
            "evidence": [{"channel": "poc",
                          "detail": (f"verified PoC bundle {bundle_sha[:12]}: input ran past "
                                     f"{detail['limit_s']:g}s ({HANG_FACTOR}x a control that "
                                     f"terminated in {detail['control_ms']} ms) and was killed"),
                          "input_sha": input_sha, "input_mode": mode, "argv": argv,
                          "bundle_sha": bundle_sha}]})
        fid = fd.id_for_dedup(target.id, key)
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
    except Exception:
        observe.absorbed(_log, "filing hang poc")
        detail["why"] = "the hang verified but the bundle could not be filed"
        return _done(False, detail)
    return _done(True, detail, bundle_sha)
