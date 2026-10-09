"""The `env_fuzz` stage: fuzz a program's ENVIRONMENT-VARIABLE input.

Detects a binary that reads `getenv("NAME")`, mines the env-var names it reads from its strings,
and drives envfuzz.fuzz_env -- setting a mutated value into those variables and running the target
with no other input. A confirmed, attributed crash is recorded as a DynResult (input_mode 'env')
plus a crash finding, so root_cause / build_poc pick it up exactly like a stdin/file/arg crash.

This is the channel for the Shellshock class and for setuid/config parsers that trust the
environment: input the program never reads from a file, an argument, or stdin.

A CROSS-ARCH target is out of reach (we set env and exec locally; an emulator would have to carry
the environment), but a MANAGED one is not, and this stage used to refuse both with the same
sentence. `target.arch` holds the RUNTIME's name for a jar, a .pyc or a .NET assembly ("jvm",
"cpython", "cil"), so the cross-arch test was true for every one of them and the decline read
"cross-arch target (cil); env fuzzing needs a native host" -- the wrong reason and the wrong
conclusion. The CLR, the JVM and CPython all run as ordinary host processes and read the
environment exactly as a native program reads getenv(); what is needed is a runner that knows how
to START them, because such a target cannot be exec'd and faults with an exception, not a signal.
"""
from __future__ import annotations

import logging
import os

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import substrate
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import envfuzz

_log = logging.getLogger(__name__)

ENV_FUZZ_STAGE = "env_fuzz"
TOOL = "envfuzz"
TOOL_VERSION = "envfuzz-1"


def _managed_runner(exe, argv, timeout, sub):
    """(run-callable, ran-flag) for a target that cannot simply be exec'd, else (None, flag).

    `envfuzz` discovers a crash by exec'ing the binary and reading the exit signal, which is the
    whole of the native story and none of a managed one: a .pyc is not executable, and a defect
    on the CLR/JVM/CPython is an uncaught exception with exit code 1, not a signal. `sandbox.run`
    knows both halves -- how to START each substrate and how to read its fault -- so hand it over
    rather than teaching the fuzzer five runtimes.
    """
    ran = {"ok": False, "why": "no execution was attempted"}
    if sub.backend == substrate.NATIVE or sub.backend is None:
        return None, ran

    def run(overrides):
        res = sandbox.run(exe, argv=argv, timeout=timeout, arch=None,
                          env_overrides=overrides)
        if sandbox.did_not_run(res.isolation):
            ran["why"] = res.note or res.isolation
            return False, None, None
        ran["ok"] = True
        return bool(res.crashed), res.signal, res.signal_name

    return run, ran


def env_fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("env_fuzz requires a target_id")
    p = ctx.params or {}

    host = sandbox.host_arch()
    if substrate.foreign_cpu(target.arch, target.file_type, host):
        ctx.emit("env_fuzz.done", payload={"applicable": False,
                 "note": f"cross-arch target ({target.arch} on a {host} host); the environment "
                         f"is set at exec time locally, so an emulator would have to carry it"})
        return {}
    sub = substrate.for_target(target)
    if substrate.known(target.file_type) and sub.backend is None:
        ctx.emit("env_fuzz.done", payload={"applicable": False,
                 "note": f"nothing here executes this image, so no environment reaches it -- "
                         f"{sub.no_exec}"})
        return {}

    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    # A managed target owns no machine code and therefore no call edges: its environment reads
    # are named in the metadata triage recorded (Environment.GetEnvironmentVariable, System.getenv,
    # os.environ, the WASI environ_get import).
    syms = ()
    if substrate.is_managed(target.file_type):
        from ..ingest import triage_symbols
        syms = triage_symbols(ctx.conn, ctx.content, target)
    if not envfuzz.uses_getenv(edges, syms) and "env_names" not in p:
        ctx.emit("env_fuzz.done", payload={"applicable": False,
                 "note": "nothing here reads the environment (no getenv import, and no "
                         "environment member in the recorded metadata)"})
        return {}

    strings = [s.value for s in StringDAO(ctx.conn).list_by_target(target.id) if s.value]
    names = list(p.get("env_names") or envfuzz.env_var_candidates(strings))
    if not names:
        ctx.emit("env_fuzz.done", payload={"applicable": True, "crashed": False,
                 "note": "getenv used but no env-name strings recovered to fuzz"})
        return {}

    exe = ctx.scratch() / "env_target.bin"
    # stage_target, not a bare write: a .NET assembly needs its `.dll` name and its
    # runtimeconfig staged BESIDE it or every execution is a non-run, and a bundled native
    # target needs its relocated loader.
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    argv = [str(a) for a in (p.get("argv") or [])]
    timeout = float(p.get("exec_timeout", 5))
    runner, ran = _managed_runner(exe, argv, timeout, sub)
    max_execs = int(p.get("max_execs", 1500))
    if runner is not None and sub.execs_per_sec:
        # One execution on these substrates is measured in tens or hundreds of milliseconds, not
        # the sub-millisecond of a native run (wine: ~1/s). 1500 execs would outlive the stage's
        # own timeout and be killed mid-campaign, which reports as a clean no-crash.
        budget = max(16, int(sub.execs_per_sec * 120))
        if budget < max_execs:
            ctx.emit("env_fuzz.budget", payload={
                "max_execs": budget, "substrate": sub.backend,
                "note": f"{sub.execs_per_sec:.0f} exec/s measured on {sub.runtime or sub.backend}"
                        f": {budget} executions is what fits in this stage's budget"})
            max_execs = budget
    ctx.progress(msg=f"fuzzing {len(names)} environment variable(s): {', '.join(names[:6])}")
    res = envfuzz.fuzz_env(str(exe), names, argv=argv, max_execs=max_execs,
                           seed=int(p.get("seed", 1337)), timeout=timeout, run=runner)

    if not res.crashed:
        # "it never started" is not "it never crashed". Without this a runtime that refused the
        # image every single time reported a clean campaign over the environment channel.
        note = res.note
        if runner is not None and not ran["ok"]:
            note = (f"the {sub.runtime or sub.backend} never executed this target, so the "
                    f"environment channel was not actually tested: {ran['why']}")
        ctx.emit("env_fuzz.done", payload={"applicable": True, "crashed": False,
                 "execs": res.execs, "vars": names, "note": note,
                 "ran": (ran["ok"] if runner is not None else True)})
        ctx.progress(pct=100, msg=f"{res.execs} exec(s), no crash ({note})"[:90])
        return {}

    input_sha = ctx.put_artifact("fuzz-crash-input", data=res.payload)
    iso = f"env-{res.var}"
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode="env",
        argv=[f"{res.var}=@@"] + argv, signal=res.signal, signal_name=res.signal_name,
        crashed=True, isolation=iso, note=f"env var {res.var}")
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, iso, "env_fuzz",
        extra=f"(reproduced by setting the environment variable {res.var})"))
    ctx.emit("env_fuzz.done", payload={"applicable": True, "crashed": True,
             "signal": res.signal_name, "var": res.var, "input_sha": input_sha, "execs": res.execs})
    ctx.progress(pct=100, msg=f"env crash: {res.signal_name} via ${res.var}")
    return {}


def register() -> None:
    register_stage(ENV_FUZZ_STAGE, env_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_env_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, ENV_FUZZ_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
