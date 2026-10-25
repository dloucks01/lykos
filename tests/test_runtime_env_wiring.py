"""Runtime-environment WIRING: a confirmed environment (analyze.runtime_env) reaches every live run
path -- sandbox.run / run_batch / isolate_prefix, env fuzzing -- is discovered once per case and
adopted by every later staged copy, and is recorded in PoC bundles. A target with no record is
untouched.
"""
import io
import json
import os
import subprocess
import tarfile
from types import SimpleNamespace

import pytest
from lykos.analyze import runtime_env as R
from lykos.analyze.dynamic import sandbox
from lykos.analyze.fuzz import envfuzz
from lykos.analyze.poc import bundle
from lykos.casestore import ContentStore
from test_runtime_env import ENV_ONLY, GATE_ALL, PLAIN, _build

need_bwrap = pytest.mark.skipif(not sandbox._bwrap_usable(), reason="bubblewrap unusable here")
need_overlay = pytest.mark.skipif(not R.overlay_usable(), reason="bwrap cannot tmp-overlay here")

PRINT_TOKEN = r'''
#include <stdio.h>
#include <stdlib.h>
int main(void){
  const char *t = getenv("LYKOSRT_TOKEN");
  if(!t || !*t){ fprintf(stderr, "LYKOSRT_TOKEN must be set\n"); return 7; }
  printf("TOKEN=%s\n", t); return 0; }
'''


@pytest.fixture(autouse=True)
def _clean_registry():
    yield
    with R._REG_LOCK:
        R._REG.clear()
        R._BY_SHA.clear()
        R._LOADED.clear()
        R._ENSURE_LOCKS.clear()


def _ctx(store: ContentStore, scratch):
    events = []
    scratch.mkdir(parents=True, exist_ok=True)
    ctx = SimpleNamespace(content=store, scratch=lambda: scratch, events=events,
                          emit=lambda kind, payload=None: events.append((kind, payload)))
    return ctx


def _target(store: ContentStore, exe):
    sha = store.put_bytes(exe.read_bytes())[0]
    return SimpleNamespace(sha256=sha, deps={}, arch=sandbox.host_arch(), endianness="little",
                           bits=64, filename="target.bin")


# --- the sandbox applies a registered environment ----------------------------------------------

@need_bwrap
@need_overlay
def test_sandbox_run_applies_a_registered_environment(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    assert sandbox.run(exe, timeout=5).exit_code == 2           # gated
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    R.register(renv, exe)
    r = sandbox.run(exe, timeout=5)
    assert r.exit_code == 0 and b"REACHED" in r.stdout, r.stderr
    R.unregister(exe)
    assert sandbox.run(exe, timeout=5).exit_code == 2           # nothing registered: untouched
    assert not os.path.exists("/etc/lykosrt_t1")                # the host was never written


@need_bwrap
@need_overlay
def test_run_batch_applies_a_registered_environment(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    before = sandbox.run_batch(exe, [b""], timeout=3)
    if before is None:
        pytest.skip("batch runner unavailable here")
    assert before[0].exit_code == 2
    R.register(renv, exe)
    after = sandbox.run_batch(exe, [b"", b"x"], timeout=3)
    assert [x.exit_code for x in after] == [0, 0]
    assert b"REACHED" in after[0].stdout


@need_bwrap
@need_overlay
def test_isolate_prefix_applies_files_dirs_and_variables(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied, renv.note
    exedir = str(exe.parent)
    bare = sandbox.isolate_prefix(exedir, net=False)
    assert "--setenv" not in bare
    R.register(renv, exe)
    pre = sandbox.isolate_prefix(exedir, net=False)
    assert pre.index("--setenv") < pre.index("--")             # applied inside the sandbox
    r = subprocess.run(pre + [str(exe)], capture_output=True, timeout=10)
    assert r.returncode == 0 and b"REACHED" in r.stdout, r.stderr


@need_bwrap
def test_an_env_channel_input_wins_over_the_supplied_variable(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "t", PRINT_TOKEN)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    assert renv.applied and "LYKOSRT_TOKEN" in renv.env, renv.note
    R.register(renv, exe)
    assert b"TOKEN=" + renv.env["LYKOSRT_TOKEN"].encode() in sandbox.run(exe, timeout=5).stdout
    r = sandbox.run(exe, timeout=5, env_overrides={"LYKOSRT_TOKEN": "FUZZED"})
    assert b"TOKEN=FUZZED" in r.stdout
    pre = sandbox.isolate_prefix(str(exe.parent), net=False, env_skip=("LYKOSRT_TOKEN",))
    assert "LYKOSRT_TOKEN" not in pre
    # env fuzzing's `env -i` keeps the supplied variable as the base and the fuzzed one on top
    d = envfuzz._run_with_env_detail(str(exe), [], {"OTHER": "1"}, timeout=5)
    assert d["rc"] == 0
    d = envfuzz._run_with_env_detail(str(exe), [], {"LYKOSRT_TOKEN": ""}, timeout=5)
    assert d["rc"] == 7                                         # the fuzzed (empty) value won


# --- discovered once per case, adopted by every staged copy -------------------------------------

def test_record_round_trips_with_file_contents(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "g", GATE_ALL)
    renv = R.prepare(exe, scratch=tmp_path / "s", timeout=4.0)
    if not renv.applied:
        pytest.skip(renv.note)
    rec = json.loads(json.dumps(R.to_record(renv, argv=["-x"])))
    back = R.from_record(rec, tmp_path / "re")
    assert back.applied and back.env == renv.env and back.dirs == renv.dirs
    assert [d for _, d in back.files] == [d for _, d in renv.files]
    for (s0, _), (s1, _) in zip(renv.files, back.files):
        assert open(s0, "rb").read() == open(s1, "rb").read()
        assert s1.startswith(str(tmp_path / "re"))              # restaged, not the old scratch
    rec["files"][0]["b64"] = None
    broken = R.from_record(rec, tmp_path / "re2")
    assert not broken.applied and "incomplete" in broken.note   # never binds a missing source


@need_bwrap
def test_ensure_probes_once_and_every_staged_copy_adopts_it(gcc, tmp_path, monkeypatch):
    exe = _build(gcc, tmp_path, "env", ENV_ONLY)
    store = ContentStore(tmp_path / "case")
    tgt = _target(store, exe)
    ctx = _ctx(store, tmp_path / "scratch1")
    renv = R.ensure(ctx, tgt, [], exec_timeout=1.0)
    assert renv is not None and renv.applied
    assert [k for k, _ in ctx.events] == ["runtime_env"]
    assert ctx.events[0][1]["applied"] and not ctx.events[0][1].get("reused")
    assert R.record_path(store.root, tgt.sha256).is_file()
    assert R.for_sha(tgt.sha256) is not None

    # another stage, after the first one's scratch is gone: no probe, the record is reused
    import shutil
    shutil.rmtree(tmp_path / "scratch1")
    with R._REG_LOCK:
        R._REG.clear()
        R._LOADED.clear()
    monkeypatch.setattr(R, "prepare", lambda *a, **k: pytest.fail("re-probed"))
    staged = store.stage_target(tgt, tmp_path / "later", "target.bin")
    assert R.for_exe(staged) is not None                        # adopted at staging
    r = sandbox.run(staged, timeout=5)
    assert r.exit_code == 0 and b"REACHED" in r.stdout, r.stderr
    ctx2 = _ctx(store, tmp_path / "scratch2")
    assert R.ensure(ctx2, tgt, ["--other"], exec_timeout=1.0).applied
    assert ctx2.events[0][1]["reused"] is True


def test_plain_target_gets_no_record_and_staging_is_untouched(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "p", PLAIN)
    store = ContentStore(tmp_path / "case")
    tgt = _target(store, exe)
    ctx = _ctx(store, tmp_path / "scratch")
    assert R.ensure(ctx, tgt, [], exec_timeout=1.0) is None
    assert ctx.events and ctx.events[0][1]["applied"] is False  # reported either way
    staged = store.stage_target(tgt, tmp_path / "later", "target.bin")
    assert R.for_exe(staged) is None and R.for_sha(tgt.sha256) is None
    # a not-applied record under the same argv is not re-probed
    calls = []
    real = R.prepare
    R.prepare = lambda *a, **k: calls.append(1) or real(*a, **k)
    try:
        R.ensure(_ctx(store, tmp_path / "s2"), tgt, [], exec_timeout=1.0)
    finally:
        R.prepare = real
    assert calls == []


def test_ensure_skips_a_non_elf_target(tmp_path):
    store = ContentStore(tmp_path / "case")
    sha = store.put_bytes(b"#!/bin/sh\necho hi\n")[0]
    tgt = SimpleNamespace(sha256=sha, deps={}, arch=None, endianness=None, bits=None)
    ctx = _ctx(store, tmp_path / "scratch")
    assert R.ensure(ctx, tgt, []) is None
    assert ctx.events == [] and not R.record_path(store.root, sha).exists()


# --- PoC bundles say what the target needed, and runner.sh supplies what it safely can ------------

@need_bwrap
def test_bundle_records_and_replays_the_environment(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "env", ENV_ONLY)
    store = ContentStore(tmp_path / "case")
    tgt = _target(store, exe)
    assert R.ensure(_ctx(store, tmp_path / "scratch"), tgt, [], exec_timeout=1.0).applied
    blob = bundle.build(exe.read_bytes(), b"", {"target_sha256": tgt.sha256, "level": "L1"},
                        b"", "stdin", [], "SIGSEGV")
    out = tmp_path / "b"
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        tar.extractall(out, filter="data")
    poc = out / "poc"
    meta = json.loads((poc / "meta.json").read_text())
    assert meta["runtime_env"]["applied"] and "LYKOSRT_TOKEN" in meta["runtime_env"]["env"]
    assert "LYKOSRT_TOKEN" in (poc / "RUNTIME_ENV.txt").read_text()
    runner = (poc / "runner.sh").read_text()
    assert "export LYKOSRT_TOKEN=" in runner
    assert runner.index("export LYKOSRT_TOKEN") > runner.index('cd "$(dirname "$0")"')
    assert "RUNTIME_ENV.txt" in (poc / "README.txt").read_text()
    # the reproducer now gets past the startup gate (our own trivial program, run directly)
    r = subprocess.run(["sh", str(poc / "runner.sh")], capture_output=True, timeout=20)
    assert b"REACHED" in r.stdout, r.stdout + r.stderr


def test_bundle_without_an_environment_is_unchanged(gcc, tmp_path):
    exe = _build(gcc, tmp_path, "p", PLAIN)
    blob = bundle.build(exe.read_bytes(), b"", {"target_sha256": "0" * 64}, b"", "stdin", [],
                        "SIGSEGV")
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        names = tar.getnames()
        meta = json.loads(tar.extractfile("poc/meta.json").read())
        runner = tar.extractfile("poc/runner.sh").read()
    assert "poc/RUNTIME_ENV.txt" not in names and "runtime_env" not in meta
    assert b"export" not in runner
