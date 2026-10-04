"""The `env_fuzz` stage: fuzz a program's ENVIRONMENT-VARIABLE input.

Detects a binary that reads `getenv("NAME")`, mines the env-var names it reads from its strings,
and drives envfuzz.fuzz_env -- setting a mutated value into those variables and running the target
with no other input. A confirmed, attributed crash is recorded as a DynResult (input_mode 'env')
plus a crash finding, so root_cause / build_poc pick it up exactly like a stdin/file/arg crash.

This is the channel for the Shellshock class and for setuid/config parsers that trust the
environment: input the program never reads from a file, an argument, or stdin. Host-native targets
only (we set env and exec locally); a cross-arch target would need an emulator carrying the env.
"""
from __future__ import annotations

import logging
import os

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import envfuzz

_log = logging.getLogger(__name__)

ENV_FUZZ_STAGE = "env_fuzz"
TOOL = "envfuzz"
TOOL_VERSION = "envfuzz-1"


def env_fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("env_fuzz requires a target_id")
    p = ctx.params or {}

    host = sandbox.host_arch()
    if target.arch and host and target.arch != host:
        ctx.emit("env_fuzz.done", payload={"applicable": False,
                 "note": f"cross-arch target ({target.arch}); env fuzzing needs a native host"})
        return {}

    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    if not envfuzz.uses_getenv(edges) and "env_names" not in p:
        ctx.emit("env_fuzz.done", payload={"applicable": False,
                 "note": "no getenv import; the program reads no environment variables"})
        return {}

    strings = [s.value for s in StringDAO(ctx.conn).list_by_target(target.id) if s.value]
    names = list(p.get("env_names") or envfuzz.env_var_candidates(strings))
    if not names:
        ctx.emit("env_fuzz.done", payload={"applicable": True, "crashed": False,
                 "note": "getenv used but no env-name strings recovered to fuzz"})
        return {}

    exe = ctx.scratch() / "env_target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    argv = [str(a) for a in (p.get("argv") or [])]
    ctx.progress(msg=f"fuzzing {len(names)} environment variable(s): {', '.join(names[:6])}")
    res = envfuzz.fuzz_env(str(exe), names, argv=argv, max_execs=int(p.get("max_execs", 1500)),
                           seed=int(p.get("seed", 1337)))

    if not res.crashed:
        ctx.emit("env_fuzz.done", payload={"applicable": True, "crashed": False,
                 "execs": res.execs, "vars": names, "note": res.note})
        ctx.progress(pct=100, msg=f"{res.execs} exec(s), no crash ({res.note})")
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
