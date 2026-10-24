"""Environment-variable fuzzing: the input channel for a program that reads `getenv("NAME")`.

Every file/argv/stdin channel feeds input the program reads explicitly; an env-var bug (the
Shellshock class, many setuid parsers) is reached by setting an ENVIRONMENT VARIABLE and running
the program with no other input. This discovers the env names the binary reads (UPPER_SNAKE strings
in a binary that imports getenv), fuzzes a value into them, and attributes a crash to the single
variable that reproduces it. rlimits-only, run-once-and-exit (not a server). Pure stdlib.
"""
from __future__ import annotations

import logging
import os
import random
import re
import subprocess
import time

from ..detect.catalog import normalize
from ..dynamic import sandbox
from .mutator import Mutator

_log = logging.getLogger(__name__)

_GETENV = {"getenv", "secure_getenv", "getenv_r"}
# An env-var name: the classic UPPER_SNAKE (LD_PRELOAD, MY_CONFIG), OR a lower/mixed-case token that
# carries an underscore (app_config_path, http_proxy) -- the all-caps-only pattern missed every
# program that names its variables in lower case, and on a stripped/large binary where the string
# table is truncated it recovered nothing at all (the "getenv used but no names" dead end).
_ENV_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+$|^[A-Z][A-Z0-9]{2,40}$")
# tokens that are not environment variables -- compiler/format/constant noise that would
# otherwise be shotgunned as candidate env names.
_NOT_ENV = {"GCC", "GNU", "GLIBC", "ELF", "NULL", "TRUE", "FALSE", "NAN", "ERROR", "WARNING",
            "DEBUG", "INFO", "FATAL", "NOTICE", "STDIN", "STDOUT", "STDERR", "EOF", "ASCII",
            "UTF", "JSON", "XML", "HTTP", "HTTPS", "TCP", "UDP", "GET", "POST", "OK"}
# When a binary demonstrably READS the environment (getenv import) but no names could be recovered
# from its strings -- a stripped/large binary whose .rodata name strings were not in the truncated
# string table -- fuzz the names most worth trying on any program: loader-injection vectors and the
# conventional configuration knobs. Fuzzing these is cheap (bounded by max_execs) and far better
# than declining the lane. A precise recovery (slicing each getenv call's .rodata arg) is the
# follow-up; this guarantees the lane never silently gives up.
_COMMON_ENV = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "HOME", "TMPDIR", "TMP",
               "SHELL", "IFS", "LANG", "LC_ALL", "NLSPATH", "HTTP_PROXY", "HTTPS_PROXY",
               "NO_PROXY", "CONFIG", "CONFIG_PATH", "CONFIG_FILE", "LOG", "LOGFILE", "LOG_LEVEL",
               "DEBUG", "VERBOSE", "PLUGIN_PATH", "DATA_DIR", "PASSWORD", "TOKEN", "SECRET"]


# The same channel on a MANAGED runtime. A jar, a .pyc and a .NET assembly own no machine code,
# so `call_edges` is empty for them and this answered False for every one -- while each reads the
# environment through a named member that triage already recorded. WASI is the sharpest case: a
# wasm module can only reach the environment through an `environ_get` import it declares.
_MANAGED_GETENV = {
    "GetEnvironmentVariable", "GetEnvironmentVariables", "ExpandEnvironmentVariables",  # .NET
    "getenv",                                                                           # Java/py
    "environ", "environb",                                                              # Python
    "environ_get", "environ_sizes_get",                                                 # WASI
}


def uses_getenv(call_edges, symbols=()) -> bool:
    """Does this target read the environment? From its imports, or from a managed inventory."""
    if any(normalize(e.dst_name) in _GETENV for e in call_edges if e.dst_name):
        return True
    from .. import substrate
    return bool(substrate.symbol_names(symbols) & _MANAGED_GETENV)


def env_var_candidates(strings, limit: int = 24, *, fallback: bool = True) -> list:
    """Tokens that look like environment-variable names, from the binary's strings. When `fallback`
    and the scan finds NONE, return the common-name list so a getenv-using target is still fuzzed
    rather than declined (the stripped/large-binary case)."""
    out, seen = [], set()
    for s in strings:
        t = (s or "").strip()
        if _ENV_NAME.match(t) and t.upper() not in _NOT_ENV and t not in seen:
            seen.add(t)
            out.append(t)
    # Prefer names with an underscore (the strongest env convention: MY_CONFIG, LD_PRELOAD) but keep
    # the plain ones too (HOME, CONFIG). Underscored first, then by appearance.
    out.sort(key=lambda t: (0 if "_" in t else 1))
    if not out and fallback:
        return list(_COMMON_ENV)[:limit]
    return out[:limit]


class EnvFuzzResult:
    def __init__(self, crashed, payload=None, var=None, signal_name=None, signal_num=None,
                 execs=0, note=None):
        self.crashed, self.payload, self.var = crashed, payload, var
        self.signal_name, self.signal, self.execs, self.note = signal_name, signal_num, execs, note


def _run_with_env(exe: str, argv: list, env_overrides: dict, timeout: float = 5.0):
    """Run `exe` once with the given env vars set (plus a minimal PATH), return its exit status
    (negative = killed by that signal), or None on spawn failure. rlimits-only.

    This is a bare subprocess, so unlike `sandbox.run` it does not reject an un-runnable image on
    its own. A shared object has no entry point and faults in the loader every time; returning
    None (spawn-failure, not a crash) keeps that loader fault from being read as a defect. The
    caller (env_fuzz_stage) already declines a shared object up front -- this is the backstop for
    any other caller."""
    return _run_with_env_detail(exe, argv, env_overrides, timeout)["rc"]


def _run_with_env_detail(exe: str, argv: list, env_overrides: dict, timeout: float = 5.0) -> dict:
    """`_run_with_env`, keeping what the attempt log needs: {rc, timed_out, spawn_failed, stderr,
    ms}. `rc` is None on a spawn failure OR a timeout -- the two are told apart here, and only
    here, which is the difference between "never started" and "started and hung"."""
    out = {"rc": None, "timed_out": False, "spawn_failed": False, "stderr": b"", "ms": 0}
    if sandbox._is_elf_shared_object(exe):
        out["spawn_failed"] = True
        return out
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ}
    env.update(env_overrides)
    t0 = time.time()
    try:
        proc = subprocess.Popen([exe] + [str(a) for a in argv], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
                                # baseline-aware: RLIMIT_NPROC counts EVERY process this user
                                # runs, so a flat 64 failed every fork on a busy desktop
                                preexec_fn=sandbox._rlimits(1024, int(timeout) + 2, set_as=True,
                                                            nproc=sandbox._nproc_cap(False)))
    except Exception:                                    # noqa: BLE001
        out["spawn_failed"] = True
        return out
    try:
        _o, err = proc.communicate(timeout=timeout)
        out["stderr"] = (err or b"")[:4096]
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=2)                  # bounded: a forked child must not wedge us
        except subprocess.TimeoutExpired:
            pass
        out["timed_out"] = True
        out["ms"] = int((time.time() - t0) * 1000)
        return out
    out["rc"] = proc.returncode
    out["ms"] = int((time.time() - t0) * 1000)
    return out


def _crashes(exe, argv, overrides, timeout, on_attempt=None, data=b"", phase="mutate"):
    d = _run_with_env_detail(exe, argv, overrides, timeout)
    if on_attempt is not None:
        on_attempt(data, d, phase, overrides)
    rc = d["rc"]
    if rc is None:
        return False, None, None
    crashed, sig, sig_name, _ = sandbox.classify_rc(rc)
    return crashed, (sig if crashed else None), (sig_name if crashed else None)


def fuzz_env(exe: str, env_names, *, argv=(), seeds=(), max_execs: int = 1500, seed: int = 1337,
             timeout: float = 5.0, run=None, should_stop=None,
             on_attempt=None) -> EnvFuzzResult:
    """Fuzz a value into the candidate env vars until one crashes `exe`, then ATTRIBUTE the crash to
    the single variable that reproduces it. Shotgun (all names set to the same payload) finds the
    bug fast; the per-variable re-run names the culprit and confirms it, killing one-off flakes.

    `run(overrides) -> (crashed, signal, signal_name)` replaces the native execute-and-read-the-
    signal path. A managed target cannot be exec'd and does not fault with a signal -- its defect
    is an uncaught exception -- so the only way this channel reaches a jar, a .pyc or a .NET
    assembly is for the caller to supply the runner that knows how to start it.

    `should_stop() -> bool` is polled before every execution, and it is not optional in practice.
    This loop bounded itself only by `max_execs`, and `max_execs` is sized from a MEASURED
    exec/s rate -- which does not hold on an interactive target, where every run blocks for the
    full `timeout` instead of milliseconds. On the HTB binary `power_greed` (real-corpus gate,
    2026-10-16) the stage ran so far past its deadline that the heartbeat stopped renewing and
    the reaper reclaimed the row: the run was recorded as `error: lease expired`, and the gate's
    contract is that an error is never an acceptable outcome while a decline is. A stage that
    loops has to watch its own clock -- the same poll `fuzz/stage.py` already does.
    """
    if not env_names:
        return EnvFuzzResult(False, note="no candidate env vars")
    # `on_attempt(data, detail, phase, overrides)` sees every execution (the attempt log). A
    # managed runner only answers crashed-or-not, so its detail is reduced to that.
    if run is not None:
        def fire(ov, _d=b"", _ph="mutate"):
            r = run(ov)
            if on_attempt is not None:
                on_attempt(_d, {"rc": None if r[0] else 0, "crashed": bool(r[0]),
                                "signal_name": r[2], "managed": True}, _ph, ov)
            return r
    else:
        def fire(ov, _d=b"", _ph="mutate"):
            return _crashes(exe, argv, ov, timeout, on_attempt, _d, _ph)
    rng = random.Random(seed)
    mut = Mutator(rng)
    corpus = [s for s in seeds if s] or [b"A" * 8, b"A" * 128, b"%n%n%n%n", b"../../etc/passwd",
                                         b"A" * 512, b";id", b"$(id)"]
    argv = list(argv)
    n = 0
    payloads = corpus_view = list(corpus)
    stop = should_stop if should_stop is not None else (lambda: False)
    while n < max_execs:
        if stop():
            return EnvFuzzResult(False, execs=n, note=f"stopped after {n} execution(s): out of "
                                                      f"budget or cancelled")
        for data in payloads:
            if stop():
                return EnvFuzzResult(False, execs=n,
                                     note=f"stopped after {n} execution(s): out of budget or "
                                          f"cancelled")
            n += 1
            val = data.replace(b"\x00", b"")             # execve env truncates at NUL
            crashed, _, _ = fire({name: val.decode("latin-1") for name in env_names}, val,
                                 "seed" if payloads is corpus_view else "mutate")
            if crashed:
                # attribute: which single variable reproduces it?
                for name in env_names:
                    c2, sig, signame = fire({name: val.decode("latin-1")}, val, "reproduce")
                    if c2:
                        return EnvFuzzResult(True, payload=val, var=name, signal_name=signame,
                                             signal_num=sig, execs=n, note=f"env {name}")
                # crashed under the shotgun but no single var reproduced -> flaky/combination
                return EnvFuzzResult(False, execs=n, note="shotgun crash not reproduced per-var")
        payloads = [mut.mutate(rng.choice(corpus), corpus) for _ in range(32)]
    return EnvFuzzResult(False, execs=n, note="no-crash")
