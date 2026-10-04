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

from ..detect.catalog import normalize
from ..dynamic import sandbox
from .mutator import Mutator

_log = logging.getLogger(__name__)

_GETENV = {"getenv", "secure_getenv", "getenv_r"}
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,40}$")
# UPPER-case tokens that are not environment variables -- compiler/format/constant noise that would
# otherwise be shotgunned as candidate env names.
_NOT_ENV = {"GCC", "GNU", "GLIBC", "ELF", "NULL", "TRUE", "FALSE", "NAN", "ERROR", "WARNING",
            "DEBUG", "INFO", "FATAL", "NOTICE", "STDIN", "STDOUT", "STDERR", "EOF", "ASCII",
            "UTF", "JSON", "XML", "HTTP", "HTTPS", "TCP", "UDP", "GET", "POST", "OK"}


def uses_getenv(call_edges) -> bool:
    return any(normalize(e.dst_name) in _GETENV for e in call_edges if e.dst_name)


def env_var_candidates(strings, limit: int = 24) -> list:
    """UPPER_SNAKE tokens that look like environment-variable names, from the binary's strings."""
    out, seen = [], set()
    for s in strings:
        t = (s or "").strip()
        if _ENV_NAME.match(t) and t not in _NOT_ENV and t not in seen:
            seen.add(t)
            out.append(t)
    # Prefer names with an underscore (the strongest env convention: MY_CONFIG, LD_PRELOAD) but keep
    # the plain ones too (HOME, CONFIG). Underscored first, then by appearance.
    out.sort(key=lambda t: (0 if "_" in t else 1))
    return out[:limit]


class EnvFuzzResult:
    def __init__(self, crashed, payload=None, var=None, signal_name=None, signal_num=None,
                 execs=0, note=None):
        self.crashed, self.payload, self.var = crashed, payload, var
        self.signal_name, self.signal, self.execs, self.note = signal_name, signal_num, execs, note


def _run_with_env(exe: str, argv: list, env_overrides: dict, timeout: float = 5.0):
    """Run `exe` once with the given env vars set (plus a minimal PATH), return its exit status
    (negative = killed by that signal), or None on spawn failure. rlimits-only."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ}
    env.update(env_overrides)
    try:
        proc = subprocess.Popen([exe] + [str(a) for a in argv], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                                preexec_fn=sandbox._rlimits(1024, int(timeout) + 2, set_as=True,
                                                            nproc=64))
    except Exception:                                    # noqa: BLE001
        return None
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return None
    return proc.returncode


def _crashes(exe, argv, overrides, timeout):
    rc = _run_with_env(exe, argv, overrides, timeout)
    if rc is None:
        return False, None, None
    crashed, sig, sig_name, _ = sandbox.classify_rc(rc)
    return crashed, (sig if crashed else None), (sig_name if crashed else None)


def fuzz_env(exe: str, env_names, *, argv=(), seeds=(), max_execs: int = 1500, seed: int = 1337,
             timeout: float = 5.0) -> EnvFuzzResult:
    """Fuzz a value into the candidate env vars until one crashes `exe`, then ATTRIBUTE the crash to
    the single variable that reproduces it. Shotgun (all names set to the same payload) finds the
    bug fast; the per-variable re-run names the culprit and confirms it, killing one-off flakes."""
    if not env_names:
        return EnvFuzzResult(False, note="no candidate env vars")
    rng = random.Random(seed)
    mut = Mutator(rng)
    corpus = [s for s in seeds if s] or [b"A" * 8, b"A" * 128, b"%n%n%n%n", b"../../etc/passwd",
                                         b"A" * 512, b";id", b"$(id)"]
    argv = list(argv)
    n = 0
    payloads = list(corpus)
    while n < max_execs:
        for data in payloads:
            n += 1
            val = data.replace(b"\x00", b"")             # execve env truncates at NUL
            crashed, _, _ = _crashes(exe, argv, {name: val.decode("latin-1") for name in env_names},
                                     timeout)
            if crashed:
                # attribute: which single variable reproduces it?
                for name in env_names:
                    c2, sig, signame = _crashes(exe, argv, {name: val.decode("latin-1")}, timeout)
                    if c2:
                        return EnvFuzzResult(True, payload=val, var=name, signal_name=signame,
                                             signal_num=sig, execs=n, note=f"env {name}")
                # crashed under the shotgun but no single var reproduced -> flaky/combination
                return EnvFuzzResult(False, execs=n, note="shotgun crash not reproduced per-var")
        payloads = [mut.mutate(rng.choice(corpus), corpus) for _ in range(32)]
    return EnvFuzzResult(False, execs=n, note="no-crash")
