"""Audit regressions: dynamic oracles run confined, heaptrace guard sizing, disclosure re-run
delivery, weggli failure honesty, upx confinement."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from lykos.analyze import unpack, weggli
from lykos.analyze.dynamic import heaptrace, memoracle, sandbox, uninit_stage


# ---------------------------------------------------------------- heaptrace guard sizing
def test_static_guard_watch_never_reaches_back_into_the_array():
    # int[] (stride 4) at an address that is 4- but not 8-aligned: an 8-byte watch would be
    # masked down to cover the element BEFORE the guard
    assert heaptrace.watch_len(0x601004) == 4
    assert heaptrace.watch_len(0x601008) == 8
    assert heaptrace.watch_len(0x601008, 4) == 4      # the [-1] guard of a stride-4 array
    assert heaptrace.watch_len(0x601003) == 1
    for a in range(0x1000, 0x1010):
        n = heaptrace.watch_len(a)
        assert a % n == 0 and n in heaptrace._DR7_LEN


# ---------------------------------------------------------------- uninit disclosure re-run
class _Ctx:
    def __init__(self, d):
        self._d = Path(d)

    def scratch(self):
        return self._d


def test_disclosure_rerun_delivers_the_input_the_way_memcheck_did(tmp_path):
    ctx = _Ctx(tmp_path)
    got = uninit_stage._delivery_argv(ctx, b"PAYLOAD", "file", ["-x", "@@"])
    assert got[0] == "-x" and got[1] != "@@"
    assert Path(got[1]).read_bytes() == b"PAYLOAD"
    got = uninit_stage._delivery_argv(ctx, b"PAYLOAD", "file", ["-x"])
    assert Path(got[-1]).read_bytes() == b"PAYLOAD"
    assert uninit_stage._delivery_argv(ctx, b"AB\0CD", "arg", ["-v"]) == ["AB", "-v"]
    assert uninit_stage._delivery_argv(ctx, b"x", "stdin", ["-v"]) == ["-v"]


# ---------------------------------------------------------------- memoracle confinement
_HOME_PROBE = os.path.expanduser("~/.lykos_dynamic_audit_probe")
_WRITER = ('#include <stdio.h>\nint main(void){FILE*f=fopen("%s","w");'
           'if(f){fputs("x",f);fclose(f);}return 0;}\n')


def _build_writer(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    src = tmp_path / "w.c"
    src.write_text(_WRITER % _HOME_PROBE)
    exe = tmp_path / "w"
    if subprocess.run([cc, "-O0", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("compile failed")
    return exe


def test_valgrind_triage_runs_the_target_confined(tmp_path):
    if memoracle.valgrind_bin() is None or not sandbox._bwrap_usable():
        pytest.skip("needs valgrind and a usable bwrap")
    exe = _build_writer(tmp_path)
    if os.path.exists(_HOME_PROBE):
        os.unlink(_HOME_PROBE)
    try:
        memoracle.valgrind_triage(exe, b"", mode="stdin", timeout=120)
        assert not os.path.exists(_HOME_PROBE)
    finally:
        if os.path.exists(_HOME_PROBE):
            os.unlink(_HOME_PROBE)


def test_confined_prefix_carries_the_preload_through_bwrap(tmp_path):
    if not sandbox._bwrap_usable():
        pytest.skip("bwrap unusable")
    exe = tmp_path / "t"
    exe.write_bytes(b"")
    cmd = memoracle._confined([str(exe)], exe, rw=[tmp_path], setenv={"LD_PRELOAD": "/x.so"})
    assert cmd[0] == "bwrap" and cmd[-1] == str(exe)
    i = cmd.index("--setenv")
    assert cmd[i + 1:i + 3] == ["LD_PRELOAD", "/x.so"]
    assert i < cmd.index("--")


# ---------------------------------------------------------------- weggli
@pytest.fixture
def wtree(tmp_path):
    if weggli.weggli_bin() is None:
        pytest.skip("weggli not installed")
    (tmp_path / "a.c").write_text("void f(char*s){char b[8]; strcpy(b,s);}\n")
    return tmp_path


def test_weggli_rejected_query_is_a_failure_not_a_clean_pass(wtree):
    r = weggli.run_query("{ strcpy( ; }", wtree)
    assert r["ok"] is False and "exited" in r["error"]
    r = weggli.run_query("{ memcpy(_,_,_); }", wtree)
    assert r["ok"] is True and r["count"] == 0


def test_weggli_scan_names_failed_queries(wtree):
    bad = [{"name": "broken", "cwe": "CWE-0", "severity": "low", "query": "{ x( ; }",
            "why": "", "cpp_only": False}]
    sc = weggli.scan(wtree, queries=bad)
    assert sc["queries_failed"] and sc["note"]


def test_weggli_hits_are_scoped_to_the_scanned_tree(wtree, tmp_path_factory, monkeypatch):
    elsewhere = tmp_path_factory.mktemp("cwd")
    (elsewhere / "README.md").write_text("x")
    monkeypatch.chdir(elsewhere)
    assert weggli._matched_files("README.md a.c", wtree) == [str((wtree / "a.c").resolve())]


# ---------------------------------------------------------------- upx
def test_upx_unpack_still_round_trips_when_confined(tmp_path):
    if not unpack.upx_available():
        pytest.skip("no upx")
    src = tmp_path / "ls.bin"
    shutil.copy("/bin/ls", src)
    packed = tmp_path / "ls.upx"
    if subprocess.run(["upx", "-q", "-o", str(packed), str(src)],
                      capture_output=True).returncode or not packed.exists():
        pytest.skip("upx could not pack /bin/ls")
    out, note = unpack.upx_unpack(packed.read_bytes())
    assert out == src.read_bytes(), note


# ---------------------------------------------------------------- review replay argv
def test_replay_keeps_a_recorded_flag_prefix_and_strips_only_a_real_carrier():
    from lykos.analyze import review
    # dynamic_run / fuzz record the PREFIX: nothing to strip
    assert review._flag_prefix(["parse"], "file", b"X") == ["parse"]
    assert review._flag_prefix(["-d", "@@"], "file", b"X") == ["-d", "@@"]
    assert review._flag_prefix(["-v"], "arg", b"PAY") == ["-v"]
    # synthesize / msan record the whole invocation: the carrier goes
    assert review._flag_prefix(["parse", "/tmp/lykos-gone-xyz/input.bin"], "file", b"X") == ["parse"]
    assert review._flag_prefix(["-v", "PAY"], "arg", b"PAY\0tail") == ["-v"]
    assert review._flag_prefix(["x"], "stdin", b"") == ["x"]
