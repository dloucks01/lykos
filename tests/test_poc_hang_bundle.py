"""Non-terminating input (CWE-835) -> verified L1 PoC bundle, plus the wave-2 poc/ fixes:
qemu-capture scratch cleanup, si_addr gating on si_code, the x86-only memory-operand parse, the
endianness disasm_one now receives, and DoS bundles that carry what was measured."""
import ast
import io
import json
import os
import subprocess
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from lykos.analyze.poc import bundle, dos


def _extract(data: bytes, dest: Path) -> Path:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        t.extractall(dest, filter="data")
    return dest / "poc"


# A target that never terminates on an input starting with "L" and exits 0 otherwise. A shell
# script stands in for the binary: the runner only needs ./target.bin to be executable.
_SH_TARGET = (b"#!/bin/sh\nread x\ncase \"$x\" in L*) while :; do sleep 1; done;; esac\n"
              b"exit 0\n")


def _hang_bundle(inp=b"LOOP\n", control=b"ok\n", limit_s=1.0, ceiling_s=8.0, target=_SH_TARGET):
    hang = {"factor": 4, "limit_s": limit_s, "ceiling_s": ceiling_s, "control_ms": 5,
            "verified_limit_s": limit_s}
    return bundle.build(target, inp, {"target_sha256": "x", "arch": "x86-64", "level": "L1"},
                        b"", "stdin", [], "non-termination", hang=hang, control_bytes=control)


def _run_runner(poc: Path, timeout=60):
    return subprocess.run(["sh", str(poc / "runner.sh")], capture_output=True, text=True,
                          timeout=timeout)


def _leftovers(poc: Path) -> list:
    """Processes still running out of this bundle's directory (a leaked target)."""
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            if os.readlink(f"/proc/{pid}/cwd") == str(poc):
                out.append(pid)
        except OSError:
            pass
    return out


def test_hang_bundle_reproduces_and_leaves_nothing_running(tmp_path):
    poc = _extract(_hang_bundle(), tmp_path)
    names = {p.name for p in poc.iterdir()}
    assert {"control.bin", "hang_check.py", "hang.json", "runner.sh", "input.bin"} <= names
    t0 = time.monotonic()
    r = _run_runner(poc)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REPRODUCED" in r.stdout and "control.bin terminated" in r.stdout
    assert time.monotonic() - t0 >= 1.0               # it really waited out the limit
    time.sleep(0.2)
    assert not _leftovers(poc), "the hanging target was not killed with its process group"
    meta = json.loads((poc / "meta.json").read_text())
    assert meta["verdict"]["exit"] == "zero" and meta["hang"]["factor"] == 4
    readme = (poc / "README.txt").read_text()
    assert "REPRODUCED" in readme and "control.bin" in readme


def test_hang_bundle_says_not_reproduced_when_the_input_terminates(tmp_path):
    poc = _extract(_hang_bundle(inp=b"fine\n"), tmp_path)
    r = _run_runner(poc)
    assert r.returncode == 1 and "NOT REPRODUCED" in r.stdout


def test_hang_bundle_is_inconclusive_when_the_control_also_hangs(tmp_path):
    poc = _extract(_hang_bundle(control=b"LOOP\n", ceiling_s=4.0), tmp_path)
    r = _run_runner(poc)
    assert r.returncode == 2 and "INCONCLUSIVE" in r.stdout
    time.sleep(0.2)
    assert not _leftovers(poc)


def test_hang_bundle_refuses_without_a_control():
    with pytest.raises(ValueError):
        bundle.build(b"x", b"LOOP", {}, b"", "stdin", [], "non-termination",
                     hang={"factor": 4, "limit_s": 1, "ceiling_s": 8})


def test_hang_bundle_control_command_differs_only_in_the_carrier():
    data = bundle.build(b"x", b"LOOP", {}, b"", "file", ["-c", "@@"], "non-termination",
                        hang={"factor": 4, "limit_s": 4, "ceiling_s": 30},
                        control_bytes=b"ok")
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        spec = json.loads(t.extractfile("poc/hang.json").read())
    assert spec["input"].endswith("\n./target.bin -c ./input.bin")
    assert spec["control"] == spec["input"].replace("./input.bin", "./control.bin")
    assert "./input.bin" not in spec["control"]


def test_caller_verdict_is_not_overwritten_by_the_native_default():
    data = bundle.build(b"x", b"A", {"verdict": {"exit": "nonzero"}}, b"", "stdin", [],
                        "resource-exhaustion", mem_cap_mb=32)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        meta = json.loads(t.extractfile("poc/meta.json").read())
        runner = t.extractfile("poc/runner.sh").read().decode()
    assert meta["verdict"]["exit"] == "nonzero" and meta["mem_cap_mb"] == 32
    assert "ulimit -v 32768" in runner


def test_hang_limit():
    assert dos.hang_limit(0.01) == 4.0                  # the floor
    assert dos.hang_limit(2.0) == 8.0                   # 4x the control
    assert dos.hang_limit(7.6) is None                  # 30.4s > ceiling: inconclusive


def _rr(ms, *, timed_out=False, crashed=False, iso="bwrap", ec=0):
    return SimpleNamespace(duration_ms=ms, timed_out=timed_out, crashed=crashed,
                           isolation=iso, exit_code=ec)


def _fake_ctx(tmp_path):
    return SimpleNamespace(scratch=lambda: tmp_path)


def test_verify_hang_differential(monkeypatch, tmp_path):
    seen = []

    def fake(ctx, target, exe, mode, argv, data, timeout, guard):
        seen.append((data, timeout))
        if data == b"HANG":
            return _rr(int(timeout * 1000), timed_out=True, ec=None)
        return _rr(100)

    monkeypatch.setattr(dos, "_hang_run", fake)
    ok, d = dos.verify_hang(_fake_ctx(tmp_path), None, "exe", "stdin", [], b"HANG", [b"ok"])
    assert ok is True and d["outcome"] == "does-not-terminate" and d["limit_s"] == 4.0
    assert seen[0] == (b"ok", 30.0 / 4) and seen[1] == (b"HANG", 4.0)


def test_verify_hang_input_that_terminates_is_not_a_hang(monkeypatch, tmp_path):
    monkeypatch.setattr(dos, "_hang_run", lambda *a: _rr(50))
    ok, d = dos.verify_hang(_fake_ctx(tmp_path), None, "exe", "stdin", [], b"HANG", [b"ok"])
    assert ok is False and d["outcome"] == "terminated"


def test_verify_hang_no_terminating_control_is_inconclusive(monkeypatch, tmp_path):
    monkeypatch.setattr(dos, "_hang_run",
                        lambda *a: _rr(7500, timed_out=True, ec=None))
    ok, d = dos.verify_hang(_fake_ctx(tmp_path), None, "exe", "stdin", [], b"HANG",
                            [b"a", b"", b"\n"])
    assert ok is None and len(d["controls_tried"]) == 3 and "control" in d["why"]


def test_verify_hang_slow_control_is_inconclusive(monkeypatch, tmp_path):
    monkeypatch.setattr(dos, "_hang_run",
                        lambda ctx, t, e, m, a, data, *r: _rr(7600) if data != b"HANG"
                        else _rr(1, timed_out=True))
    ok, d = dos.verify_hang(_fake_ctx(tmp_path), None, "exe", "stdin", [], b"HANG", [b"ok"])
    assert ok is None and "ceiling" in d["why"]


def test_verify_hang_never_ran_is_inconclusive(monkeypatch, tmp_path):
    monkeypatch.setattr(dos, "_hang_run",
                        lambda ctx, t, e, m, a, data, *r: _rr(10) if data != b"HANG"
                        else _rr(4000, timed_out=True, iso="unsupported-arch"))
    ok, d = dos.verify_hang(_fake_ctx(tmp_path), None, "exe", "stdin", [], b"HANG", [b"ok"])
    assert ok is None


# ------------------------------------------------------------------ end to end through build_poc
_HANG_C = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
           "if(n>0&&b[0]=='L')for(;;)sleep(1);return 0;}\n")


@pytest.fixture
def hang_bin(gcc, tmp_path):
    c = tmp_path / "h.c"
    c.write_text(_HANG_C)
    b = tmp_path / "h"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode:
        pytest.skip("build failed")
    return b


@pytest.fixture
def pool(store):
    from lykos.analyze import register
    from lykos.jobs import JobConfig, WorkerPool
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _file_hang_finding(store, target, sha, mode="stdin"):
    from lykos.db.dao import FindingDAO
    FindingDAO(store.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-835", "title": "Input that does not terminate (denial of service)",
        "severity": "medium", "detector": "fuzz", "state": "corroborated", "confidence": 0.75,
        "dedup_key": f"CWE-835:hang:{mode}", "function_addr": None, "site_addr": None,
        "evidence": [{"channel": "dynamic", "detail": "hang", "input_sha": sha,
                      "input_mode": mode, "argv": [], "isolation": "bwrap"}]})


def test_build_poc_files_a_verified_hang_as_l1(store, case, pool, hang_bin, tmp_path):
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import FindingDAO, PocDAO
    from lykos.jobs import JobQueue
    target = ingest(store, case.id, hang_bin)
    sha = store.put_artifact(case.id, "fuzz-hang-input", data=b"LOOP\n").sha256
    _file_hang_finding(store, target, sha)
    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": sha})   # recognised, not told
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert len(pocs) == 1 and pocs[0].verified and pocs[0].level == "L1"
    assert pocs[0].signal_name == "non-termination"
    f = next(f for f in FindingDAO(store.conn).list_by_target(target.id) if f.cwe == "CWE-835")
    assert f.state == "poc-backed" and pocs[0].finding_id == f.id
    poc = _extract(store.content.get_bytes(pocs[0].bundle_sha), tmp_path / "out")
    r = _run_runner(poc)
    assert r.returncode == 0 and "REPRODUCED" in r.stdout, r.stdout + r.stderr


def test_build_poc_does_not_promote_a_hang_that_terminates(store, case, pool, hang_bin):
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import FindingDAO, PocDAO
    from lykos.jobs import JobQueue
    target = ingest(store, case.id, hang_bin)
    sha = store.put_artifact(case.id, "fuzz-hang-input", data=b"fine\n").sha256
    _file_hang_finding(store, target, sha)
    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": sha, "kind": "hang"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    assert not PocDAO(store.conn).list_by_target(target.id)
    f = next(f for f in FindingDAO(store.conn).list_by_target(target.id) if f.cwe == "CWE-835")
    assert f.state == "corroborated"
    ev = store.events.payloads_of_type("poc.done", case_id=case.id)
    assert ev and ev[-1]["verified"] is False
    assert ev[-1]["hang"]["outcome"] == "terminated"


# ------------------------------------------------------------------ the smaller fixes
def test_make_qemu_capture_removes_its_scratch(monkeypatch):
    from lykos.analyze.debug import qemu_gdb
    from lykos.analyze.poc import capture as cap
    made, seen = [], []
    real = cap.tempfile.mkdtemp

    def mk(*a, **k):
        d = real(*a, **k)
        made.append(d)
        return d

    def fake_capture(exe, arch, *, argv, stdin, **kw):
        seen.append([Path(a).exists() for a in argv if a.endswith("input.bin")])
        return {"ok": True}

    monkeypatch.setattr(cap.tempfile, "mkdtemp", mk)
    monkeypatch.setattr(qemu_gdb, "capture", fake_capture)
    cap.make_qemu_capture("t", "mips", "stdin", [], 1)(b"A")
    assert made == []                                   # stdin needs no scratch at all
    c = cap.make_qemu_capture("t", "mips", "file", [], 1)
    c(b"A")
    c(b"B")
    assert len(made) == 2 and seen[-1] == [True]        # the file existed during the call
    assert not any(Path(d).exists() for d in made)      # ... and is gone after it


def test_siginfo_addr_ignores_a_user_sent_signal():
    from lykos.analyze.poc import ptrace_capture as pc

    def raw(code, addr):
        b = bytearray(128)
        b[0:4] = (11).to_bytes(4, "little")
        b[8:12] = code.to_bytes(4, "little", signed=True)
        b[16:24] = addr.to_bytes(8, "little")
        return bytes(b)

    assert pc._si_addr_from(raw(1, 0xdeadbeef)) == 0xdeadbeef      # SEGV_MAPERR
    assert pc._si_addr_from(raw(0, 1234)) is None                   # SI_USER (kill)
    assert pc._si_addr_from(raw(-6, 1234)) is None                  # SI_TKILL (raise)
    assert pc._si_addr_from(b"\0" * 8) is None


def test_mem_access_parse_is_x86_only():
    from lykos.analyze.poc import primitive as P
    assert P.parse_mem_access("mov QWORD PTR [rdx],rax")["base"] == "rdx"
    assert P.parse_mem_access("mov QWORD PTR [rdx],rax", "x86")["base"] == "rdx"
    assert P.parse_mem_access("ldr r0, [r9]", "arm") is None
    assert P.parse_mem_access("str w1, [x0]", "aarch64") is None
    assert P.parse_mem_access("mov QWORD PTR [rdx],rax", None) is None
    cap = {"regs": {"r9": 0x41414141}}
    assert P.analyze_memory_primitive(cap, 256, "ldr r0, [r9]", arch="arm") is None


def test_primitive_stage_hands_disasm_one_the_byte_order():
    src = Path(__file__).resolve().parents[1] / "core/lykos/analyze/poc/primitive_stage.py"
    calls = [n for n in ast.walk(ast.parse(src.read_text()))
             if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "disasm_one"]
    assert calls and all(len(c.args) >= 3 for c in calls), "disasm_one called without endianness"


def test_address_verdict_passes_endianness(monkeypatch):
    from lykos.analyze.debug import rootcause
    from lykos.analyze.poc import primitive_stage as ps
    got = {}

    def spy(pcb, arch, endianness=None, thumb=False):
        got.update(arch=arch, endianness=endianness)
        return "ret"

    monkeypatch.setattr(rootcause, "disasm_one", spy)
    monkeypatch.setattr(rootcause, "classify", lambda *a, **k: {"class": "control-flow-hijack"})
    ctx = SimpleNamespace(emit=lambda *a, **k: None)
    cap = {"ok": True, "signal_name": "SIGSEGV", "fault_addr": 0x10, "pc_bytes": "c3"}
    ps._address_verdict(ctx, lambda m: (lambda d: cap), ["stdin"], b"A", "mips",
                        endianness="little")
    assert got == {"arch": "mips", "endianness": "little"}


def test_dos_l3_bundle_ships_the_measured_build_stream_and_cap(store, case, tmp_path,
                                                              monkeypatch, sample_elf):
    """The L3 impact is measured on the PLAIN build, fed the AMPLIFIED stream, under a cap. The
    bundle used to ship the ingested image, the single original request and no cap -- a
    reproducer that cannot show the impact."""
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import PocDAO
    target = ingest(store, case.id, sample_elf)
    sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"GET\nq\n").sha256
    plain = tmp_path / "plain"
    plain.write_bytes(b"\x7fELF-plain-build")
    monkeypatch.setattr(dos, "_blob", lambda ctx, t, kind: plain if kind == "plain-blob" else None)
    monkeypatch.setattr(dos, "_disclosure", lambda *a: None)
    monkeypatch.setattr(dos, "_drive", lambda ctx, t, exe, unit, n, *a: (
        _rr(5, ec=0) if n == 4 else _rr(5, ec=1)))
    ctx = SimpleNamespace(
        conn=store.conn, content=store.content, scratch=lambda: tmp_path,
        emit=lambda *a, **k: None,
        put_artifact=lambda kind, data=None, meta=None: store.put_artifact(
            case.id, kind, data=data).sha256)
    out = dos.escalate(ctx, target, sha, "stdin")
    assert out["level"] == "L3"
    poc = PocDAO(store.conn).list_by_target(target.id)[0]
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(poc.bundle_sha))) as t:
        tb = t.extractfile("poc/target.bin").read()
        inp = t.extractfile("poc/input.bin").read()
        runner = t.extractfile("poc/runner.sh").read().decode()
        meta = json.loads(t.extractfile("poc/meta.json").read())
    assert tb == plain.read_bytes()
    assert inp == b"GET\n" * out["impact"]["requests"]
    assert "ulimit -v 32768" in runner
    assert meta["verdict"]["exit"] == "nonzero"


def test_ptrace_capture_reports_a_timeout_as_a_timeout(tmp_path):
    import platform
    import shutil
    import sys
    if platform.machine().lower() not in ("x86_64", "amd64", "aarch64", "arm64"):
        pytest.skip("ptrace helper supports x86-64 and aarch64 only")
    sleep = shutil.which("sleep")
    helper = Path(__file__).resolve().parents[1] / "core/lykos/analyze/poc/ptrace_capture.py"
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"exe": sleep, "argv": ["30"], "stdin_file": None,
                                "timeout": 1}))
    r = subprocess.run([sys.executable, str(helper), str(spec)], capture_output=True,
                       text=True, timeout=30)
    res = json.loads(r.stdout)
    assert res["ok"] is False and res.get("timed_out") is True
    assert "timed out" in res["reason"]


def test_synth_finalize_records_the_flag_prefix_not_the_placed_argv(store, case, tmp_path,
                                                                   sample_elf):
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc import synthesize_stage as ss
    from lykos.db.dao import DynResultDAO, PocDAO
    target = ingest(store, case.id, sample_elf)
    ctx = SimpleNamespace(
        conn=store.conn, content=store.content, scratch=lambda: tmp_path, run_id=None,
        emit=lambda *a, **k: None, progress=lambda **k: None,
        put_artifact=lambda kind, data=None, meta=None: store.put_artifact(
            case.id, kind, data=data).sha256)
    run_argv, _ = ss._deliver("file", b"PAYLOAD", ["-c", "@@", "-v"], ctx)
    assert run_argv == ["-c", str(tmp_path / "input.bin"), "-v"]
    res = SimpleNamespace(signal=11, signal_name="SIGSEGV", isolation="bwrap", duration_ms=1,
                          fault_pc=None, stderr=b"", crashed=True)
    ss._finalize(ctx, target, b"\x7fELF", b"PAYLOAD", "file", ["-c", "@@", "-v"], res,
                 {"buffer": "buf", "size": 64, "offset": 72}, 72, 0, 1)
    dr = DynResultDAO(store.conn).list_by_target(target.id)[0]
    assert dr.argv == ["-c", "@@", "-v"]
    poc = PocDAO(store.conn).list_by_target(target.id)[0]
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(poc.bundle_sha))) as t:
        runner = t.extractfile("poc/runner.sh").read().decode()
    assert "./target.bin -c ./input.bin -v" in runner and str(tmp_path) not in runner


_ECHO_ARG = b"#!/bin/sh\nprintf '%s' \"$1\" > ./got.bin\n"
_ECHO_ENV = b"#!/bin/sh\nprintf '%s' \"$LYKOS_V\" > ./got.bin\n"


@pytest.mark.parametrize("mode,argv,target", [("arg", [], _ECHO_ARG),
                                              ("env", ["LYKOS_V=@@"], _ECHO_ENV)])
@pytest.mark.parametrize("inp,want", [(b"AB\n\n", b"AB\n\n"),        # trailing newlines kept
                                      (b"AB\0CD", b"AB"),               # cut at NUL, like execve
                                      (b"plain", b"plain")])
def test_arg_and_env_bundles_deliver_exactly_what_the_kernel_did(tmp_path, mode, argv, target,
                                                                 inp, want):
    data = bundle.build(target, inp, {}, b"", mode, argv, "SIGSEGV")
    poc = _extract(data, tmp_path)
    subprocess.run(["sh", str(poc / "runner.sh")], capture_output=True, timeout=30)
    assert (poc / "got.bin").read_bytes() == want
    meta = json.loads((poc / "meta.json").read_text())
    assert ("input_truncated_at_nul" in meta) == (b"\0" in inp)
