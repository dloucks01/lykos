"""poc_diff must never call a candidate FIXED because the replay could not deliver the input:
file-mode carriers beside the exe, the recorded flag prefix intact, sanitizer exits counted,
and non-fault PoCs (hang / availability / undeliverable channels) left uncounted."""
import subprocess
from types import SimpleNamespace

import pytest
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import poc_diff
from lykos.db.dao import DynResultDAO, PocDAO

_FILE_CRASH = ("#include <stdio.h>\nint main(int c,char**v){FILE*f=fopen(v[c-1],\"rb\");"
               "if(!f)return 2;if(fgetc(f)=='A'){volatile int*p=0;*p=1;}return 0;}\n")


@pytest.fixture
def two_builds(gcc, tmp_path):
    out = []
    for i in range(2):
        c = tmp_path / f"f{i}.c"
        c.write_text(_FILE_CRASH + f"/* build {i} */\nint build_{i};\n")
        b = tmp_path / f"f{i}"
        if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode:
            pytest.skip("build failed")
        out.append(b)
    return out


def _ctx(store, case, b, a, events):
    return SimpleNamespace(
        conn=store.conn, content=store.content, target_id=b.id,
        params={"baseline_target_id": a.id}, should_cancel=lambda: False,
        emit=lambda t, payload=None, **k: events.append((t, payload)),
        progress=lambda **k: None,
        put_artifact=lambda kind, data=None, meta=None: store.put_artifact(
            case.id, kind, data=data).sha256)


def _poc(store, a, sha, signal, *, mode="file", argv=(), crashed=True, isolation="bwrap"):
    DynResultDAO(store.conn).insert(a.id, a.case_id, input_sha=sha, input_mode=mode,
                                    argv=list(argv), signal_name=signal, crashed=crashed,
                                    isolation=isolation)
    PocDAO(store.conn).insert(a.id, a.case_id, level="L1", verified=True, signal_name=signal,
                              input_sha=sha)


def test_file_mode_poc_still_reproduces_on_an_identical_candidate(store, case, two_builds):
    a = ingest(store, case.id, two_builds[0])
    b = ingest(store, case.id, two_builds[1])
    sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"AAAA").sha256
    _poc(store, a, sha, "SIGSEGV")
    ev = []
    poc_diff.poc_diff_stage(_ctx(store, case, b, a, ev))
    done = [p for t, p in ev if t == "poc_diff.done"][-1]
    assert done["fixed"] is False and done["reproduced"] == 1, done


def test_recorded_flag_prefix_is_replayed_whole(monkeypatch, tmp_path):
    seen = {}

    def fake_run_input(exe, mode, wf, timeout, arch, data, **kw):
        seen["argv"], seen["wf"] = kw["base_argv"], wf
        return [], SimpleNamespace(crashed=True, signal_name="SIGSEGV", isolation="bwrap")

    dr = SimpleNamespace(input_mode="file", argv=["-c", "@@", "-v"], isolation="bwrap")
    ctx = SimpleNamespace(content=SimpleNamespace(get_bytes=lambda s: b"A"))
    t = SimpleNamespace(arch="x86-64", endianness=None, bits=64)
    exe = tmp_path / "cand" / "candidate.bin"
    r = poc_diff._replay_on(ctx, fake_run_input, exe, t, dr, "sha", tmp_path, times=1)
    assert seen["argv"] == ["-c", "@@", "-v"] and r["reproduced"] is True
    assert seen["wf"].parent == exe.parent                 # the carrier sits beside the exe


def test_sanitizer_exit_counts_as_a_reproduction(tmp_path):
    rep = (b"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc "
           b"0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602000000011 thread T0\n")

    def fake_run_input(*a, **kw):
        return [], SimpleNamespace(crashed=False, signal_name=None, isolation="bwrap",
                                   stderr=rep, exit_code=1)

    dr = SimpleNamespace(input_mode="stdin", argv=[], isolation="bwrap")
    ctx = SimpleNamespace(content=SimpleNamespace(get_bytes=lambda s: b"A"))
    t = SimpleNamespace(arch="x86-64", endianness=None, bits=64)
    r = poc_diff._replay_on(ctx, fake_run_input, tmp_path / "x", t, dr, "sha", tmp_path, times=1)
    assert r["reproduced"] is True


@pytest.mark.parametrize("mode,iso", [("env", "bwrap"), ("socket", "net-tcp"),
                                      ("stdin", "bwrap+netns/prompted")])
def test_undeliverable_channel_is_not_counted(tmp_path, mode, iso):
    def boom(*a, **kw):
        raise AssertionError("must not replay through run_input")

    dr = SimpleNamespace(input_mode=mode, argv=[], isolation=iso)
    ctx = SimpleNamespace(content=SimpleNamespace(get_bytes=lambda s: b"A"))
    t = SimpleNamespace(arch="x86-64", endianness=None, bits=64)
    r = poc_diff._replay_on(ctx, boom, tmp_path / "x", t, dr, "sha", tmp_path)
    assert r["reproduced"] is None and r["error"]


def test_a_candidate_that_never_ran_is_not_fixed(tmp_path):
    def nr(*a, **kw):
        return [], SimpleNamespace(crashed=False, signal_name=None, isolation="unsupported-arch",
                                   stderr=b"")

    dr = SimpleNamespace(input_mode="stdin", argv=[], isolation="bwrap")
    ctx = SimpleNamespace(content=SimpleNamespace(get_bytes=lambda s: b"A"))
    t = SimpleNamespace(arch="x86-64", endianness=None, bits=64)
    r = poc_diff._replay_on(ctx, nr, tmp_path / "x", t, dr, "sha", tmp_path)
    assert r["reproduced"] is None and r["error"]


def test_poc_kinds():
    k = poc_diff._poc_kind
    P = SimpleNamespace
    assert k(P(signal_name="non-termination", level="L1"), None) == "hang"
    assert k(P(signal_name="memory-leak", level="L1"), None) == "availability"
    assert k(P(signal_name="resource-exhaustion", level="L3"), None) == "availability"
    assert k(P(signal_name="SIGSEGV", level="L1"), None) == "crash"
    assert k(P(signal_name=None, level="L3"), None) == "win"


def test_availability_poc_does_not_make_the_candidate_fixed(store, case, two_builds):
    a = ingest(store, case.id, two_builds[0])
    b = ingest(store, case.id, two_builds[1])
    sha = store.put_artifact(case.id, "x", data=b"leak\n").sha256
    PocDAO(store.conn).insert(a.id, a.case_id, level="L3", verified=True,
                              signal_name="resource-exhaustion", input_sha=sha)
    ev = []
    poc_diff.poc_diff_stage(_ctx(store, case, b, a, ev))
    done = [p for t, p in ev if t == "poc_diff.done"][-1]
    assert done["fixed"] is False and done["checked"] == 0
