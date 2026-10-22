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
    from ..fuzz.runner import invocation
    import os as _os
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

    if impact:
        return _file_poc(ctx, target, input_sha, mode, argv_base, "L3", bpr, impact)
    if amplified:
        return _file_poc(ctx, target, input_sha, mode, argv_base, "L2", bpr, {})
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


def _file_poc(ctx, target, input_sha, mode, argv_base, level, bpr, impact) -> dict:
    """Mint a verified PoC at `level` for the availability finding and promote it poc-backed."""
    if level == "L3":
        headline = (f"Denial of service: the target {impact['how']} under a {impact['cap_mb']} MB "
                    f"budget after ~{impact['requests']} attacker requests, while a benign request "
                    f"exits cleanly under the same cap")
    else:
        headline = (f"Unbounded resource amplification: ~{bpr} bytes consumed per attacker request "
                    f"with no ceiling (measured linear on the sanitizer build)")
    try:
        input_bytes = ctx.content.get_bytes(input_sha)
    except Exception:  # input artifact gone: nothing to escalate, the L1 stands
        return {}
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": list(argv_base), "level": level, "cwe": "CWE-401",
            "availability": impact or {"bytes_per_request": bpr}, "tool_version": TOOL_VERSION,
            # the delivered PoC is run under a memory cap and is a success when it dies there
            "verdict": {"exit": "nonzero"}}
    try:
        data = bundle.build(ctx.content.path(target.sha256).read_bytes(), input_bytes, meta,
                            b"", mode, list(argv_base), "resource-exhaustion")
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
