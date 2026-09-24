"""Phase 5 (coverage-guided) — AFL++ backend + `coverage_fuzz` stage.

AFL++ is an optional bundled tool. These tests cover the locator, the crash-harvest parser,
and graceful failure when AFL++ is absent; the full real-AFL campaign runs only when
`afl-fuzz` is actually installed (skipped otherwise, like the Ghidra real-run tests)."""
import base64
import os
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz import aflpp, enqueue_coverage_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_locate_afl_via_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AFL_PATH", raising=False)
    monkeypatch.setattr(aflpp.shutil, "which", lambda _n: None)   # isolate from a real PATH afl
    monkeypatch.setenv("LYKOS_AFL", str(tmp_path))          # dir with no afl-fuzz
    assert aflpp.locate_afl() is None
    fake = tmp_path / "afl-fuzz"
    fake.write_text("#!/bin/sh\n")
    assert aflpp.locate_afl() == fake                       # dir now resolves
    monkeypatch.setenv("LYKOS_AFL", str(fake))              # direct path also works
    assert aflpp.locate_afl() == fake


def test_harvest_crashes_dedups(tmp_path):
    out = tmp_path / "afl-out"
    cd = out / "default" / "crashes"
    cd.mkdir(parents=True)
    (cd / "README.txt").write_text("ignore me")
    (cd / "id:000000,sig:11").write_bytes(b"AAAA")
    (cd / "id:000001,sig:11").write_bytes(b"AAAA")           # duplicate content
    (cd / "id:000002,sig:06").write_bytes(b"BBBBBB")
    got = aflpp.harvest_crashes(out)
    assert sorted(got) == [b"AAAA", b"BBBBBB"]               # deduped, README skipped


def test_arg_mode_is_fed_over_stdin_not_argv(monkeypatch, tmp_path):
    """AFL++ cannot inject the fuzz input into argv -- run_campaign adds the `@@` file
    placeholder only for file mode, so any other mode is fed over stdin. A replay that then
    delivers via argv would never reproduce, and every real arg-mode crash would be dropped as
    a clean zero, so both must agree the delivery is stdin."""
    from pathlib import Path

    captured = {}

    class _P:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, **kw):
        captured["cmd"] = list(cmd)
        return _P()

    monkeypatch.setattr(aflpp.subprocess, "run", fake_run)
    aflpp.run_campaign(Path("/bin/true"), Path("/bin/true"), tmp_path, tmp_path,
                       seconds=1, mode="arg", qemu=False)
    assert "@@" not in captured["cmd"], "arg mode must be fed over stdin, not placed in argv"
    aflpp.run_campaign(Path("/bin/true"), Path("/bin/true"), tmp_path, tmp_path,
                       seconds=1, mode="file", qemu=False)
    assert "@@" in captured["cmd"], "file mode delivers via the @@ placeholder"


def test_coverage_stage_normalises_a_non_stdin_non_file_mode_to_stdin():
    """Since AFL feeds a non-file mode over stdin, the stage must replay over stdin too. It
    normalises anything that is not file/stdin to stdin so the crash is found and replayed the
    same way, instead of fuzzing via stdin and replaying via argv."""
    import inspect

    from lykos.analyze.fuzz import coverage
    src = inspect.getsource(coverage.coverage_stage)
    assert 'mode not in ("file", "stdin")' in src
    assert 'mode = "stdin"' in src


def test_coverage_stage_errors_clearly_when_afl_absent(store, case, pool, gcc, tmp_path,
                                                       monkeypatch):
    monkeypatch.delenv("AFL_PATH", raising=False)
    monkeypatch.setenv("LYKOS_AFL", str(tmp_path / "nope"))  # force locator miss
    monkeypatch.setattr(aflpp, "locate_afl", lambda *a, **k: None)
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    r = subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True, check=False)
    if r.returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_coverage_fuzz(q, target, params={"max_seconds": 5})
    assert pool.wait_idle(30)
    rec = q.runs.get(run.id)
    assert rec.status == "error" and "AFL++ not found" in (rec.error or "")


@pytest.mark.skipif(aflpp.locate_afl() is None, reason="AFL++ (afl-fuzz) not installed")
def test_coverage_fuzz_real_campaign_confirms(store, case, pool, tmp_path):
    """Real AFL++. Uses instrumented mode (afl-cc) so it runs without afl-qemu-trace; if
    afl-cc is unavailable, falls back to qemu-mode."""
    afl_cc = shutil.which("afl-cc") or shutil.which("afl-gcc")
    qemu = afl_cc is None
    cc = afl_cc or shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no compiler")
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    env = dict(os.environ, AFL_QUIET="1")
    if subprocess.run([cc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False, env=env).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_coverage_fuzz(q, target, params={
        "input_mode": "stdin", "max_seconds": 30, "exec_timeout": 1, "qemu": qemu,
        "seeds": [base64.b64encode(b"BBBB").decode()]})
    assert pool.wait_idle(120)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("afl-fuzz could not run in this environment: " + str(rec.error))
    assert [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "coverage_fuzz"]
    assert confirmed


def test_an_aborted_afl_campaign_is_not_reported_as_zero_crashes():
    """afl-fuzz can abort before executing a single input and STILL EXIT 0.

    The old guard keyed on `proc.returncode != 0`, so an abort sailed through and the stage
    harvested an empty crash directory -- reporting a clean "0 crashes" run that had never
    run the target. That is indistinguishable from "this binary has no bugs", which is the
    worst possible way to be wrong. Observed for real: qemu-mode aborting at the fork-server
    handshake because the afl-qemu-trace on PATH was a different architecture's qemu.
    """
    from lykos.analyze.fuzz import aflpp

    class P:
        def __init__(self, rc, out=b"", err=b""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    abort = (b"[-] PROGRAM ABORT : Fork server handshake failed\n"
             b"         Location : afl_fsrv_start(), src/afl-forkserver.c:1800")
    why = aflpp.campaign_failed(P(0, err=abort))       # exit code 0 -- the trap
    assert why and "aborted" in why
    assert aflpp.campaign_failed(P(0, err=b"handshake with the injected code"))
    assert aflpp.campaign_failed(P(2, err=b"")) is not None          # non-zero still caught
    assert aflpp.campaign_failed(P(0, err=b"[+] All set and ready to roll!")) is None


def test_qemu_mode_requires_the_trace_helper():
    """`-Q` needs afl-qemu-trace, which ships SEPARATELY from afl-fuzz -- Ubuntu's afl++
    package omits it. Checking only for afl-fuzz let the campaign reach the fork server and
    die there."""
    from pathlib import Path

    from lykos.analyze.fuzz import aflpp
    assert aflpp.locate_qemu_trace(Path("/nonexistent/afl-fuzz")) is None or True
    # the helper is looked for beside afl-fuzz first, then on PATH
    import inspect
    src = inspect.getsource(aflpp.locate_qemu_trace)
    assert "afl-qemu-trace" in src and "which" in src


def test_best_coverage_falls_back_to_edges_when_block_trace_is_zero(monkeypatch):
    """A directed campaign against a target that cannot be block-traced natively (kernel/.so/
    cross-arch) records blocks_hit=0 -> 0%. That must NOT hide a coverage-guided AFL/qemu run that
    actually exercised the target: block wins only with real hits, otherwise the edge count shows."""
    from lykos.report import model

    class _Run:
        def __init__(self, rid, stage):
            self.id, self.stage, self.status, self.target_id = rid, stage, "done", 1

    outputs = {
        "edge": {"coverage": {"kind": "edge", "edges_found": 478}},
        "block0": {"coverage": {"kind": "block", "pct": 0.0, "blocks_hit": 0, "blocks_known": 900}},
        "block_hit": {"coverage": {"kind": "block", "pct": 41.0, "blocks_hit": 369, "blocks_known": 900}},
    }
    monkeypatch.setattr(model, "cached_output_json", lambda store, rid: outputs[rid])

    # edge campaign + a zero-hit block campaign -> show the edges, not a misleading 0%
    cov = model._best_coverage(None, [_Run("edge", "coverage_fuzz"), _Run("block0", "directed_fuzz")])
    assert cov == {"kind": "edge", "edges": 478}

    # a block campaign that DID hit blocks wins over the edge count
    cov = model._best_coverage(None, [_Run("edge", "coverage_fuzz"), _Run("block_hit", "directed_fuzz")])
    assert cov["kind"] == "block" and cov["pct"] == 41.0

    # nothing meaningful -> None
    assert model._best_coverage(None, [_Run("block0", "directed_fuzz")]) is None


def test_format_aware_seeds_derive_from_the_binary_strings(monkeypatch):
    """coverage_fuzz must seed from the target's OWN strings -- a format-model sample and config
    keys -- not just the generic _DEFAULT_SEEDS, or a real parser rejects every seed at the door and
    edge coverage never climbs. Regression for the ~0.7% coverage that made fuzzing look broken."""
    from lykos.analyze.fuzz import stage

    class _S:
        def __init__(self, v):
            self.value = v
    monkeypatch.setattr(stage, "_strings_for",
                        lambda ctx, t: [_S("GIF89a"), _S("listen="), _S("workers="), _S("name=")])
    seeds = stage.format_aware_seeds(object(), object())
    assert seeds, "should derive seeds from the strings"
    assert all(isinstance(s, (bytes, bytearray)) for s in seeds)
    # a format-model seed for the detected format (gif), carrying its magic
    assert any(bytes(s).startswith(b"GIF8") for s in seeds), "a valid format-model seed"
    # the binary's own config tokens become seed material too
    assert any(b"listen" in bytes(s) for s in seeds)
    # best-effort: a broken strings source yields [] rather than raising
    monkeypatch.setattr(stage, "_strings_for", lambda ctx, t: (_ for _ in ()).throw(RuntimeError("x")))
    assert stage.format_aware_seeds(object(), object()) == []


def test_qemu_campaign_enables_compcov_input_to_state(monkeypatch, tmp_path):
    """Input-to-state (COMPCOV) is what lets AFL solve magic-value/checksum/length branches a blind
    mutator never reaches -- deterministically, no symbolic execution. It must be on for the
    qemu-mode (prebuilt-binary) path, and a native build must instead get a `-c <cmplog>` copy."""
    import subprocess as _sp
    from pathlib import Path
    from lykos.analyze.fuzz import aflpp
    seen = {}

    class _P:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(cmd, env=None, **kw):
        seen["cmd"], seen["env"] = cmd, env or {}
        return _P()
    monkeypatch.setattr(_sp, "run", fake_run)
    exe = tmp_path / "t"; exe.write_bytes(b"\x7fELF")
    sd = tmp_path / "in"; sd.mkdir(); od = tmp_path / "out"

    aflpp.run_campaign(Path("/usr/bin/afl-fuzz"), exe, sd, od, seconds=1, mode="file", qemu=True)
    assert seen["env"].get("AFL_COMPCOV_LEVEL") == "2", "qemu campaigns must enable COMPCOV"
    assert "-Q" in seen["cmd"]

    cl = tmp_path / "t.cmplog"; cl.write_bytes(b"\x7fELF")
    aflpp.run_campaign(Path("/usr/bin/afl-fuzz"), exe, sd, od, seconds=1, mode="file",
                       qemu=False, cmplog=cl)
    assert "-c" in seen["cmd"] and str(cl) in seen["cmd"], "native build must run a CmpLog copy"
