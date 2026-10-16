"""Phase 4 — the `dynamic_run` stage: detonate the target in the sandbox, record the
outcome, and turn a reproduced crash into a Confirmed finding (dynamic reproduction is what
promotes findings past the static ceiling)."""
from __future__ import annotations

import base64
import logging
import os

from ... import observe
from ...db.dao import DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..fuzz.runner import place
from . import sandbox

_log = logging.getLogger(__name__)

DYNAMIC_STAGE = "dynamic_run"
TOOL = "sandbox"
TOOL_VERSION = "sandbox-1"
# Isolation labels sandbox.run() returns when the target NEVER EXECUTED (no qemu for the arch,
# no wine/JVM, a PE that could not be launched). A non-crash from one of these is "could not
# run", not "ran and exited cleanly" -- absence of evidence is not evidence of absence.
# "Did it run?" is answered by `sandbox.did_not_run`, beside the isolation strings it describes.
# The frozenset that used to live here listed four of the eight exact sentinels and could not
# match the `/not-runnable` suffix at all, so a .pyc with no python3, a .wasm with no node, a
# .NET with no dotnet and every managed non-run were reported as clean exits. It is GONE rather
# than aliased: a name that silently changes from a container to a callable breaks `in` at the
# call site, which is exactly what it did to a test.

# fatal signal -> (cwe, severity) for the confirmed crash finding
_SIG_CWE = {
    "SIGSEGV": ("CWE-119", "critical"), "SIGBUS": ("CWE-119", "critical"),
    "SIGABRT": ("CWE-787", "high"), "SIGFPE": ("CWE-369", "high"),
    "SIGILL": ("CWE-119", "high"),
    # A Windows PE faults with a NAMED exception, and the name says more than the signal it
    # corresponds to -- `STACK_BUFFER_OVERRUN` is the /GS cookie check firing, which is the
    # clearest evidence of a stack overflow this platform can get from any substrate. All nine
    # of them used to miss this table and take the generic ("CWE-119", "high") fallback, so a
    # PE divide-by-zero was filed as memory corruption while the SAME defect on a native target
    # went to CWE-369: the substrate, not the bug, decided the weakness class.
    "EXCEPTION_ACCESS_VIOLATION": ("CWE-119", "critical"),       # c0000005, the PE SIGSEGV
    "EXCEPTION_STACK_BUFFER_OVERRUN": ("CWE-121", "critical"),   # c0000409, /GS cookie tripped
    "EXCEPTION_HEAP_CORRUPTION": ("CWE-122", "critical"),        # c0000374, heap guard tripped
    "EXCEPTION_STACK_OVERFLOW": ("CWE-674", "high"),             # c00000fd, recursion
    "EXCEPTION_INT_DIVIDE_BY_ZERO": ("CWE-369", "high"),         # c0000094, as SIGFPE
    "EXCEPTION_ILLEGAL_INSTRUCTION": ("CWE-119", "high"),        # c000001d, as SIGILL
    # A runtime CHECK deliberately terminating the process: corruption was DETECTED, not
    # silently exploited. That is a reachable assertion, not a hijack.
    "EXCEPTION_FAIL_FAST_EXCEPTION": ("CWE-617", "high"),        # c0000602, __fastfail
    "EXCEPTION_NONCONTINUABLE_EXCEPTION": ("CWE-617", "medium"),  # c0000025
    "EXCEPTION_BREAKPOINT": ("CWE-617", "medium"),               # 80000003, an int3
}


# Signals whose faulting PC is NOT a stable defect discriminator, so the crash is bucketed by
# signal alone. A SIGABRT is raised by a runtime CHECK (glibc malloc/free consistency, a stack
# canary, _FORTIFY_SOURCE, an assert, ASan/UBSan) -- the PC sits in the check/abort machinery
# (often libc, outside the image, so it reads back as a randomized image-relative offset under
# ASLR), never at the defect. Keying an abort by that PC split ONE double-free into 47 findings.
# The defect is instead identified by root_cause (its class / source line), which relabels the
# single crash finding authoritatively.
_SIGNAL_ONLY_BUCKET = frozenset({"SIGABRT"})


def asan_defect_key(stderr) -> str | None:
    """A stable per-defect discriminator for a SANITIZER SIGABRT: the ASan/UBSan class + source
    basename (e.g. "heap-use-after-free@parser.c:88"). Returns None for a plain glibc abort with no
    sanitizer report -- which keeps the signal-only bucket, so a double free's dozens of identical
    aborts still merge. Only meaningful for SIGABRT. Derived from the crash's own stderr so every
    stage that files/looks-up the finding agrees on the key."""
    if not stderr:
        return None
    try:
        from ..debug.rootcause import parse_asan_report
        text = (stderr.decode("utf-8", "replace")
                if isinstance(stderr, (bytes, bytearray)) else str(stderr))
        rep = parse_asan_report(text)
    except Exception:
        observe.absorbed(_log, "answering None")
        return None
    if not rep:
        return None
    import os as _os
    cls = (rep.get("class") or "").strip()
    src = (rep.get("source") or "").strip()
    src = _os.path.basename(src) if src else ""
    disc = "@".join(p for p in (cls, src) if p)
    return (disc.replace(" ", "_")[:120] or None)


def crash_dedup_key(signal_name, fault_pc=None, discriminator=None, *, hijack=False) -> str:
    """The bucket a crash belongs to. Every stage that files one must agree, or a verified PoC
    opens a second finding beside the crash it just proved."""
    if signal_name in _SIGNAL_ONLY_BUCKET:
        # A plain glibc abort (double free) has no discriminator -> signal-only, merging its
        # repeats. A SANITIZER abort carries one (ASan class+source) -> two DIFFERENT sanitizer
        # defects that both abort get distinct buckets instead of collapsing into one.
        return (f"dynamic-crash:{signal_name}:{discriminator}" if discriminator
                else f"dynamic-crash:{signal_name}")
    if hijack:
        # The fault PC is attacker-controlled: the overwrite redirected execution OUTSIDE the
        # program's own code (a control-flow hijack), so the PC is whatever bytes the input put
        # at the saved return address -- it varies per input and is NOT a defect discriminator.
        # Collapse every such crash of this signal into ONE finding instead of one-per-garbage-PC
        # (a single stack overflow otherwise fans out into dozens of findings, most visibly on
        # aarch64/qemu where the hijacked PC differs on every fuzzer input).
        return f"dynamic-crash:{signal_name}:cfh"
    return (f"dynamic-crash:{signal_name}:{fault_pc:x}" if fault_pc
            else f"dynamic-crash:{signal_name}")


def _pc_addr(x):
    if x is None:
        return None
    if isinstance(x, int):
        return x
    try:
        s = str(x)
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (TypeError, ValueError):
        return None


def recovered_code_span(conn, target_id):
    """[lo, hi) spanning the target's recovered functions, or None when none were recovered."""
    from ...db.dao import FunctionDAO
    lo = hi = None
    try:
        fns = FunctionDAO(conn).list_by_target(target_id)
    except Exception:
        observe.absorbed(_log, "answering None")
        return None
    for f in fns:
        a = _pc_addr(getattr(f, "addr", None))
        if a is None:
            continue
        end = a + (getattr(f, "size", None) or 1)
        lo = a if lo is None else min(lo, a)
        hi = end if hi is None else max(hi, end)
    return (lo, hi) if lo is not None else None


def is_hijack_pc(fault_pc, code_span) -> bool:
    """True when the fault PC is OUTSIDE the recovered code -- an attacker-controlled hijack PC
    that must not discriminate the crash bucket. False when in-code, unset, or code is unknown
    (conservative: we only collapse when we can PROVE the PC is not the program's own)."""
    pc = _pc_addr(fault_pc)
    return bool(pc and code_span and not (code_span[0] <= pc < code_span[1]))


def crash_hijack(conn, target_id, fault_pc) -> bool:
    """Whether this crash's fault is a control-flow hijack (fault PC outside recovered code).
    Convenience for the single-crash stages; hot loops precompute recovered_code_span once."""
    return is_hijack_pc(fault_pc, recovered_code_span(conn, target_id))


def find_crash_finding(conn, target_id, signal_name, input_sha=None):
    """The id of the crash finding for this crash, precise key first then the legacy one.

    Stages look the crash finding up to attach a PoC to it. Once the key carries a faulting
    address, a lookup by signal alone stops matching -- and cases recorded before that still
    only have the signal -- so both are tried.
    """
    from ...db.dao import DynResultDAO, FindingDAO
    fd = FindingDAO(conn)
    dd = DynResultDAO(conn)
    pc = dd.fault_pc_for(target_id, input_sha) if input_sha else None
    disc = dd.defect_key_for(target_id, input_sha) if input_sha else None
    hijack = is_hijack_pc(pc, recovered_code_span(conn, target_id))
    return (fd.id_for_dedup(target_id, crash_dedup_key(signal_name, pc, disc, hijack=hijack))
            if (pc or disc or hijack) else None) \
        or fd.id_for_dedup(target_id, crash_dedup_key(signal_name))


def crash_key_parts(conn, target_id, input_sha):
    """`(fault_pc, defect_key, hijack)` -- the three things `crash_dedup_key` needs, read from
    the CRASH itself rather than from whichever stage happens to be filing.

    Exists because four stages each assembled two of the three. Every one looked up
    `fault_pc_for` and called `crash_hijack`, and not one looked up `defect_key_for`, so each
    finding they filed for a SANITIZER abort landed in the signal-only bucket
    `dynamic-crash:SIGABRT`. That bucket matches none of the per-defect buckets the fuzz stage
    files, so rather than PROMOTING the crash finding it opened a new one -- and then every
    sanitizer-aborting defect on the target merged into that one.

    Measured on a program with four demonstrated defects (heap over-read at :46, stack over-read
    at :22, stack overflow at :21, uninitialised disclosure at :30): the fuzz stage filed three
    correctly separated findings and the primitive stage filed a fourth holding ALL FOUR defects'
    evidence -- 20 entries, titled after whichever verdict ran last, carrying a CWE from a
    different defect than its title. `crash_dedup_key`'s own docstring says every stage that
    files one must agree; this is how they agree.

    The discriminator is what separates two sanitizer defects that both abort. For a plain signal
    it is None and the key is unchanged.
    """
    from ...db.dao import DynResultDAO
    dd = DynResultDAO(conn)
    pc = dd.fault_pc_for(target_id, input_sha) if input_sha else None
    disc = dd.defect_key_for(target_id, input_sha) if input_sha else None
    return pc, disc, is_hijack_pc(pc, recovered_code_span(conn, target_id))


def crash_finding_candidate(signal_name, input_sha, isolation, detector, extra="",
                            state="confirmed", confidence=0.9, bundle_sha=None,
                            fault_pc=None, discriminator=None, *, hijack=False,
                            file_type=None):
    """Crash finding shared by the dynamic / fuzz / poc stages.

    Keyed by WHERE it faulted when that is known, so two defects that both raise SIGSEGV stay
    two findings. Keyed by signal alone otherwise -- which is what every crash used to get, and
    it collapsed 8,516 crashes in one jhead campaign into a single "unique" finding. `hijack`
    (fault PC outside the program's own code) keys by signal alone too: the PC is attacker-
    controlled, so it is not a discriminator and every such crash is one control-flow-hijack defect.

    A later stage that reproduces the same input must land on the same key to promote rather
    than duplicate, so the faulting address is taken from the crash itself, not from whichever
    stage happened to observe it.
    """
    from ..runtime_fault import managed_fault
    # file_type disambiguates a name the JVM and the CLR share (IOException, ArithmeticException)
    # so the title attributes the fault to the runtime that actually observed it.
    managed = managed_fault(signal_name, file_type)
    cwe, sev = _SIG_CWE.get(signal_name) or (managed[:2] if managed else None) \
        or ("CWE-119", "high")
    short = input_sha[:12] if input_sha else "(none)"
    detail = f"{signal_name} with input {short} [{isolation}]"
    if hijack:
        detail += " with an attacker-controlled instruction pointer (out-of-code fault)"
    elif fault_pc:
        detail += f" faulting at +0x{fault_pc:x}"
    if extra:
        detail += " " + extra
    evidence = [{"channel": "dynamic", "detail": detail}]
    if bundle_sha:
        evidence.append({"channel": "poc",
                         "detail": f"verified PoC bundle {bundle_sha[:12]}"})
    if hijack:
        title = f"Control-flow hijack ({signal_name}): attacker-controlled instruction pointer"
    elif managed and signal_name not in _SIG_CWE:
        title = f"Reproduced fault ({signal_name}) under {managed[2]}"
    else:
        title = f"Reproduced crash ({signal_name}) under dynamic execution"
    return {
        "cwe": cwe, "severity": sev, "state": state, "confidence": confidence,
        "detector": detector, "title": title,
        # A hijack's fault PC is attacker-controlled, so it is not a meaningful site.
        "site_addr": (None if hijack else (hex(fault_pc) if fault_pc else None)),
        "function_addr": None,
        "dedup_key": crash_dedup_key(signal_name, fault_pc, discriminator, hijack=hijack),
        "evidence": evidence,
    }


def dynamic_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("dynamic_run requires a target_id")

    params = ctx.params or {}
    mode = params.get("input_mode", "none")      # stdin | arg | file | none
    argv = list(params.get("argv") or [])
    # what gets RECORDED is this prefix, never the carrier appended below: a scratch path
    # means nothing to whatever replays the crash later
    prefix = list(argv)
    timeout = float(params.get("timeout", 10))
    input_bytes = base64.b64decode(params["input_b64"]) if params.get("input_b64") else b""
    input_sha = ctx.put_artifact("dyn-input", data=input_bytes) if input_bytes else None
    stdin = input_bytes if mode == "stdin" else b""
    if mode == "arg" and input_bytes:
        try:
            argv = place(argv, sandbox.argv_arg(input_bytes))
        except sandbox.ArgvNulError as e:
            ctx.emit("dynamic.done", payload={"crashed": False, "note": str(e)})
            ctx.progress(pct=100, msg="payload undeliverable via argv")
            return {"metrics": {"undeliverable": True}}
    elif mode == "file" and input_bytes:         # deliver the input as a file argument
        infile = ctx.scratch() / "input.bin"
        infile.write_bytes(input_bytes)
        argv = place(argv, str(infile))
    env_overrides = None
    if mode == "env" and input_bytes:
        # The ENVIRONMENT channel: the input is a variable's value and its name rides along as a
        # "NAME=@@" argv prefix (how env_fuzz records it). Without this a replay of an env crash
        # delivered nothing, so the review pass would call a real, reproducible crash flaky.
        from ..poc.capture import env_var_from_argv
        var, argv = env_var_from_argv(argv)
        if var:
            env_overrides = {var: input_bytes.decode("latin-1")}

    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    # mask the case store (other targets' extracted secrets) inside the sandbox; the target is
    # copied out to scratch above, so it never needs to reach the store.
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    ctx.progress(msg="detonating in sandbox")
    res = sandbox.run(exe, argv=argv, stdin=stdin, timeout=timeout, arch=target.arch,
                      endianness=target.endianness, bits=target.bits,
                      env_overrides=env_overrides)

    stdout_sha = ctx.put_artifact("dyn-stdout", data=res.stdout) if res.stdout else None
    stderr_sha = ctx.put_artifact("dyn-stderr", data=res.stderr) if res.stderr else None
    # A sanitizer SIGABRT carries a defect discriminator (ASan class+source) so two DISTINCT
    # sanitizer defects that both abort don't collapse to one signal-only bucket. Stored on the
    # crash row so every later stage derives the same key.
    defect_key = asan_defect_key(res.stderr) if res.signal_name == "SIGABRT" else None
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=prefix, exit_code=res.exit_code, signal=res.signal, signal_name=res.signal_name,
        crashed=res.crashed, timed_out=res.timed_out, isolation=res.isolation,
        duration_ms=res.duration_ms, stdout_sha=stdout_sha, stderr_sha=stderr_sha,
        note=res.note, fault_pc=res.fault_pc, defect_key=defect_key)

    ran = not sandbox.did_not_run(res.isolation)
    ctx.emit("dynamic.done", payload={"crashed": res.crashed, "signal": res.signal_name,
                                      "timed_out": res.timed_out, "isolation": res.isolation,
                                      "ran": ran, "note": res.note})

    if res.crashed:
        _hj = is_hijack_pc(res.fault_pc, recovered_code_span(ctx.conn, target.id))
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
            res.signal_name, input_sha, res.isolation, "dynamic",
            fault_pc=res.fault_pc, discriminator=defect_key, hijack=_hj,
            file_type=target.file_type))

    if not ran:
        # never executed: do not label this "clean exit" -- it is "could not run", and the note
        # says why (no qemu for the arch, no wine/JVM, PE launch failed).
        msg = "did not run" + (": " + res.note if res.note else "")
    elif res.crashed:
        msg = "crash " + (res.signal_name or "")
    elif res.timed_out:
        msg = "timeout"
    else:
        msg = "clean exit"
    ctx.progress(pct=100, msg=msg)
    return {"output_shas": [x for x in (stdout_sha, stderr_sha) if x],
            "output_kind": "dyn-output"}


def register() -> None:
    register_stage(DYNAMIC_STAGE, dynamic_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300,
                   # P5.4: the keys dynamic_run understands; a typo now fails the run loud instead
                   # of silently running with the default (input_b64 vs input, argv vs args, ...).
                   param_schema={"input_mode", "argv", "input_b64", "env"})


def enqueue_dynamic(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, DYNAMIC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
