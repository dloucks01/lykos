"""The environment is an input channel on every substrate, and it reached only one of them.

`sandbox.run` dispatches to the managed runtime at the very top and built its child environment
much further down, inside the native path -- so `env_overrides` was silently dropped for every
jar, .class, .pyc, .NET assembly, wasm module and Windows PE. The channel is real on all of
them: each runs as an ordinary host process, and the program reads `System.getenv` /
`os.environ` / `Environment.GetEnvironmentVariable` / WASI `environ_get` exactly as a native
target reads `getenv`. So a crash delivered through the environment could not even be REPLAYED
on such a target, and a replay that cannot deliver its input reports "did not reproduce" -- a
real finding retracted by a plumbing gap.

Discovery had the same hole from the other end. `env_fuzz` refused the whole class with
"cross-arch target (cil); env fuzzing needs a native host" -- the wrong reason (the field holds a
runtime name, see test_arch_semantics.py) and the wrong conclusion. And `envfuzz` finds a crash
by exec'ing the binary and reading the exit signal, which is the whole of the native story and
none of a managed one: a .pyc is not executable, and a defect on the CLR/JVM/CPython is an
uncaught exception with exit code 1, not a signal. `sandbox.run` knows both halves, so the
runner is injected rather than the fuzzer taught five runtimes.
"""
import os
import py_compile
import shutil
import subprocess
import sys

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.dynamic.sandbox import RunResult
from lykos.analyze.fuzz import envfuzz

_ENV_READER = """import os, sys
if len(os.environ.get("LYKOS_CFG", "")) > 32:
    raise ValueError("config too long: " + os.environ["LYKOS_CFG"][:8])
print("ok")
"""


@pytest.fixture(scope="module")
def pyc(tmp_path_factory):
    """A .pyc whose defect is reachable ONLY through the environment: it reads no input at all."""
    d = tmp_path_factory.mktemp("envpyc")
    src = d / "reader.py"
    src.write_text(_ENV_READER)
    out = d / "reader.pyc"
    py_compile.compile(str(src), cfile=str(out), doraise=True)
    return out


# ---- the child environment a managed runner builds ----------------------------------------

def test_nothing_to_apply_means_inherit_exactly_as_before():
    """None, not a copy of os.environ: the managed runners passed no env at all, and rebuilding
    one unconditionally would be a behaviour change dressed up as a fix."""
    assert sandbox._env_for_runtime(None) is None
    assert sandbox._env_for_runtime({}) is None


def test_the_override_is_applied_on_top_of_the_real_environment():
    env = sandbox._env_for_runtime({"LYKOS_CFG": "x" * 40})
    assert env["LYKOS_CFG"] == "x" * 40
    assert "PATH" in env, "the program still needs an environment to run in"


def test_the_override_wins_over_an_existing_value():
    key = next(iter(os.environ))
    env = sandbox._env_for_runtime({key: "lykos-probe"})
    assert env[key] == "lykos-probe"


def test_the_variables_that_decide_whether_the_runtime_starts_are_pinned():
    """The CLR insists on a writable HOME and will not run without one. A mutated HOME delivered
    through this channel would make every execution a non-run -- the failure mode that looks
    exactly like a clean pass, which is what this whole area exists to prevent."""
    env = sandbox._env_for_runtime({"HOME": "/nonexistent"}, pinned={"HOME": "/real"})
    assert env["HOME"] == "/real"


def test_the_runtimes_own_flags_are_still_overridable_by_the_channel():
    """Only the start-up variables are pinned. A program that genuinely reads DOTNET_SOMETHING
    is a legitimate target, and the channel must be able to reach it."""
    env = sandbox._env_for_runtime({"DOTNET_NOLOGO": "0"}, extra={"DOTNET_NOLOGO": "1"})
    assert env["DOTNET_NOLOGO"] == "0"


# ---- every substrate is handed the channel ------------------------------------------------

@pytest.mark.parametrize("sniff,runner", [
    ("_is_dotnet", "_run_dotnet"), ("_is_pe", "_run_windows"), ("_is_jvm", "_run_java"),
    ("_is_pyc", "_run_python"), ("_is_wasm", "_run_wasm"),
])
def test_run_forwards_the_environment_channel_to_every_substrate(monkeypatch, tmp_path, sniff,
                                                                 runner):
    """The gap was a missing argument at five dispatch sites, so the test is at those sites. A
    sixth substrate added without it would drop the channel silently all over again."""
    f = tmp_path / "image.bin"
    f.write_bytes(b"not sniffed, the sniffer is stubbed")
    seen = {}
    monkeypatch.setattr(sandbox, sniff, lambda _p: True)
    monkeypatch.setattr(sandbox, runner,
                        lambda exe, **kw: seen.update(kw) or RunResult(isolation="stub"))
    sandbox.run(f, env_overrides={"LYKOS_CFG": "y" * 40})
    assert seen.get("env_overrides") == {"LYKOS_CFG": "y" * 40}


def test_a_cpython_target_is_actually_crashed_through_the_environment(pyc):
    """End to end on the cheapest managed substrate: the program reads NO input -- not stdin,
    not argv, not a file -- so the environment is the only channel that can reach its defect."""
    clean = sandbox.run(pyc, timeout=30)
    assert not sandbox.did_not_run(clean.isolation), clean.note
    assert not clean.crashed

    crashed = sandbox.run(pyc, timeout=30, env_overrides={"LYKOS_CFG": "z" * 40})
    assert crashed.crashed, f"{crashed.isolation}: {crashed.note}"
    assert crashed.signal_name == "ValueError"


# ---- discovery: who reads the environment -------------------------------------------------

class _E:
    def __init__(self, name):
        self.dst_name = name


@pytest.mark.parametrize("symbols", [
    ["System.Environment.GetEnvironmentVariable"],       # .NET
    ["java.lang.System.getenv"],                         # Java
    ["os.environ"],                                      # Python
    ["wasi_snapshot_preview1.environ_get [func]"],        # WASI
])
def test_a_managed_target_that_reads_the_environment_is_recognised(symbols):
    """`call_edges` is empty for a target with no machine code, so this answered False for every
    managed target -- while each names its environment reads in the metadata triage recorded."""
    assert envfuzz.uses_getenv([], symbols)


def test_a_managed_target_that_does_not_read_the_environment_is_still_skipped():
    """The self-gate is what keeps this stage free for targets it does not apply to."""
    assert not envfuzz.uses_getenv([], ["System.Console.ReadLine", "System.String.Format"])
    assert not envfuzz.uses_getenv([], [])


def test_the_native_signal_is_unchanged():
    assert envfuzz.uses_getenv([_E("getenv")])
    assert envfuzz.uses_getenv([_E("secure_getenv")])
    assert not envfuzz.uses_getenv([_E("printf")])


# ---- discovery: the injected runner -------------------------------------------------------

def test_the_fuzzer_uses_the_injected_runner_instead_of_exec(tmp_path):
    """A .pyc cannot be exec'd, so without this the campaign measured nothing at all."""
    calls = []

    def run(overrides):
        calls.append(dict(overrides))
        return (len(calls) >= 1 and "A" * 40 in overrides.values()), 11, "SIGSEGV"

    res = envfuzz.fuzz_env("/does/not/exist", ["LYKOS_CFG"], seeds=[b"A" * 40], max_execs=4,
                           run=run)
    assert calls, "the injected runner was never called"
    assert res.crashed and res.var == "LYKOS_CFG"
    assert res.signal_name == "SIGSEGV"


def test_the_runner_attributes_the_crash_to_one_variable():
    """Unchanged behaviour, re-checked through the injected path: the shotgun finds it and the
    per-variable re-run names it."""
    def run(overrides):
        return ("B" in overrides), 6, "SIGABRT"

    res = envfuzz.fuzz_env("/x", ["A", "B", "C"], seeds=[b"q"], max_execs=4, run=run)
    assert res.crashed and res.var == "B"


def test_a_runtime_that_never_started_is_not_reported_as_no_crash(tmp_path):
    """"It never ran" and "it ran and was clean" are the two outcomes this platform must never
    confuse. The runner reports which one happened, and the stage says so."""
    from lykos.analyze import substrate
    from lykos.analyze.fuzz.env_stage import _managed_runner
    sub = substrate.of("dotnet")

    runner, ran = _managed_runner(tmp_path / "x.bin", [], 1.0, sub)
    assert runner is not None
    import lykos.analyze.fuzz.env_stage as es
    real = es.sandbox.run
    try:
        es.sandbox.run = lambda *a, **k: RunResult(isolation="dotnet-missing",
                                                   note="no `dotnet` found")
        assert runner({"A": "1"}) == (False, None, None)
    finally:
        es.sandbox.run = real
    assert not ran["ok"] and "dotnet" in ran["why"]


def test_a_native_target_keeps_the_original_exec_path(tmp_path):
    """No runner is injected for a native ELF: that path reads a real signal from a real
    process, which is strictly better evidence than any runtime's exception text."""
    from lykos.analyze import substrate
    from lykos.analyze.fuzz.env_stage import _managed_runner
    runner, _ran = _managed_runner(tmp_path / "x", [], 1.0, substrate.of("elf"))
    assert runner is None


# ---- the native channel still works, end to end -------------------------------------------

_C_ENV = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void){ char b[32]; const char *v = getenv("LYKOS_CFG");
  if (v) strcpy(b, v);            /* overflow: the environment is the input */
  printf("%s\\n", b[0] ? b : "none"); return 0; }
"""


def test_a_native_getenv_overflow_is_still_found(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    src = tmp_path / "e.c"
    src.write_text(_C_ENV)
    exe = tmp_path / "e"
    r = subprocess.run([cc, "-O0", "-w", "-fno-stack-protector", "-no-pie", "-o", str(exe),
                        str(src)], capture_output=True)
    if r.returncode != 0:
        pytest.skip(f"compiler refused the fixture: {r.stderr.decode()[:200]}")
    res = envfuzz.fuzz_env(str(exe), ["LYKOS_CFG"], seeds=[b"A" * 512], max_execs=8)
    assert res.crashed and res.var == "LYKOS_CFG", res.note
    assert res.signal_name in ("SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT")


def test_the_module_under_test_is_importable_from_a_fresh_interpreter():
    """A circular import between substrate and the fuzz package would only show up on a cold
    import, which the suite's own import order can hide."""
    r = subprocess.run([sys.executable, "-c",
                        "import lykos.analyze.fuzz.env_stage, lykos.analyze.fuzz.envfuzz"],
                       capture_output=True, cwd=str(
                           __import__("pathlib").Path(__file__).resolve().parents[1] / "core"))
    assert r.returncode == 0, r.stderr.decode()[-800:]
