"""doc 58: which input channel carries attacker-controlled bytes into a sink -- shared by the
injection stage and the deterministic PoC constructors so a constructor is not stdin-only.

A constructor that only ever delivers on stdin silently fails on the (common) target that reads
its tainted input from a command-line argument, a file it is handed, or an environment variable --
exactly the "binaries pulled off another system, run differently than we assume" case. The ranking
here is the injection stage's: the imported symbols say which channels the program actually reads,
strongest signal first, then the rest as fallbacks so a real channel is never skipped. A constructor
tries them in order and keeps the FIRST that its oracle confirms (with a negative control), so a
wrong channel simply fails to confirm -- it never fabricates a finding.
"""
from __future__ import annotations

from ..detect.catalog import normalize

#: imported libc symbols that name each channel the program reads from.
_FILE_SYMS = {"fopen", "fopen64", "open", "open64", "freopen"}
_STDIN_SYMS = {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getline", "fscanf",
               "getchar"}
_ENV_SYMS = {"getenv", "secure_getenv"}

#: all channels a constructor knows how to deliver on.
MODES = ("stdin", "arg", "file", "env")


def rank_channels(call_edges, given=None):
    """Input channels to try, highest-signal first. `given` (the operator's known input_mode) wins
    outright. `env` is offered ONLY when the binary imports getenv -- otherwise mining env-var names
    and spawning a run per name is wasted effort on a program that never reads the environment."""
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    order = []
    if names & _FILE_SYMS:
        order.append("file")
    if names & _STDIN_SYMS:
        order.append("stdin")
    if names & _ENV_SYMS:
        order.append("env")
    order.append("arg")
    for m in ("stdin", "arg", "file"):          # env is NOT a blanket fallback (see docstring)
        if m not in order:
            order.append(m)
    return order


def delivery_specs(ctx, target, *, given=None, max_env=4):
    """Ordered (mode, env_name) specs a constructor should try. `env` expands to one spec per
    candidate variable name mined from the target's strings (dropped entirely when none is found,
    so a getenv-using target with an unrecoverable name does not spawn blind runs)."""
    from ...db.dao import CallEdgeDAO
    try:
        edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    except Exception:                            # noqa: BLE001
        edges = []
    specs = []
    for mode in rank_channels(edges, given):
        if mode == "env":
            for name in _env_names(ctx, target, edges, max_env):
                specs.append(("env", name))
        else:
            specs.append((mode, None))
    return specs


def _env_names(ctx, target, edges, limit):
    """Candidate getenv variable names, mined from the target's recovered strings (no fallback to a
    generic name list: a constructor needs the RIGHT name, not a plausible one)."""
    try:
        from ...db.dao import StringDAO
        from ..fuzz import envfuzz
        if not envfuzz.uses_getenv(edges):
            return []
        strings = [s.value for s in StringDAO(ctx.conn).list_by_target(target.id)]
        return envfuzz.env_var_candidates(strings, limit=limit, fallback=False)
    except Exception:                            # noqa: BLE001
        return []


# ---- how the confirmed channel is delivered, for the PoC's reproduce text + builder ----------

def deliver_line(mode, binname, env_name=None, *, artifact="poc.bin") -> str:
    """The one-line command that delivers the saved payload artifact on `mode` -- what the tester
    actually runs. Kept identical across constructors so the reproduce text reads the same way."""
    if mode == "arg":
        return f'{binname} "$(cat {artifact})"'
    if mode == "file":
        return f"{binname} {artifact}"
    if mode == "env":
        return f'{env_name or "VAR"}="$(cat {artifact})" {binname}'
    return f"{binname} < {artifact}"             # stdin


def channel_phrase(mode, env_name=None) -> str:
    """Human phrase naming where the tainted bytes enter, for soundness/summary lines."""
    return {
        "stdin": "standard input",
        "arg": "a command-line argument",
        "file": "a file argument",
        "env": f"the environment variable {env_name}" if env_name else "an environment variable",
    }.get(mode, "standard input")
