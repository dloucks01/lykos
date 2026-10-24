"""doctor's probes must prove an engine RUNS, never just that its file exists.

The air-gap bundle shipped several present-but-broken engines (a symqemu whose SymCC runtime could
not load, relink-corrupted qemu, ...) and `doctor` printed every one "[ok]" because its probes were
existence-only. These tests build fake broken tools in a temp dir and check each probe reports them
MISSING -- and still reports a working one present.
"""
from __future__ import annotations

import os
import platform
import shutil
import stat

import pytest
from lykos import toolchain as tc


def _script(path, body):
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def test_v_rejects_a_loader_failure_even_though_it_printed_a_line(tmp_path):
    """ld.so prints its complaint and exits 127: that first stderr line is not a version banner."""
    bad = _script(tmp_path / "tool", "echo 'tool: error while loading shared libraries: "
                  "libfoo.so: cannot open shared object file' >&2; exit 127")
    assert tc._v(bad, "--version") is None


def test_v_rejects_a_tool_that_dies_on_a_signal(tmp_path):
    bad = _script(tmp_path / "tool", "kill -SEGV $$")
    assert tc._v(bad, "--version") is None


def test_v_keeps_a_banner_from_a_clean_nonzero_exit(tmp_path):
    """`afl-fuzz -h` prints its usage and exits 1 -- it ran; that is not a failure."""
    ok = _script(tmp_path / "tool", "echo 'afl-fuzz++4.33c usage'; exit 1")
    assert tc._v(ok, "-h") == "afl-fuzz++4.33c usage"


@pytest.fixture
def fake_symqemu(tmp_path, monkeypatch):
    if platform.machine().lower() not in ("x86_64", "amd64"):
        pytest.skip("locate_symqemu defaults to the x86-64 emulator name")
    if not shutil.which("true"):
        pytest.skip("needs coreutils true")
    d = tmp_path / "symqemu"
    d.mkdir()
    monkeypatch.setenv("LYKOS_SYMQEMU", str(d))

    def make(body):
        return _script(d / "symqemu-x86_64", body)
    return make


def test_symqemu_whose_runtime_cannot_load_is_missing(fake_symqemu):
    fake_symqemu("echo 'symqemu-x86_64: error while loading shared libraries: "
                 "libSymCCRtShared.so: cannot open shared object file' >&2; exit 127")
    assert tc._probe_symqemu() is None


def test_symqemu_that_prints_a_banner_but_cannot_run_a_guest_is_missing(fake_symqemu):
    fake_symqemu('if [ "$1" = --version ]; then echo "qemu-x86_64 version 9.1.1"; exit 0; fi\n'
                 "exit 139")
    assert tc._probe_symqemu() is None


def test_symqemu_needs_the_runtime_dir_on_the_loader_path(fake_symqemu):
    """The probe must give symqemu the SAME env run_once does (its dir on LD_LIBRARY_PATH);
    otherwise a working vendored copy would be reported missing."""
    d = fake_symqemu('case ":$LD_LIBRARY_PATH:" in *":$(dirname "$0"):"*) ;; '
                     "*) echo 'error while loading shared libraries' >&2; exit 127;; esac\n"
                     'if [ "$1" = --version ]; then echo "qemu-x86_64 version 9.1.1"; fi\n'
                     '[ -n "$SYMCC_OUTPUT_DIR" ] || exit 3\nexit 0')
    got = tc._probe_symqemu()
    assert got and "qemu-x86_64 version 9.1.1" in got and str(d) in got


def test_a_corrupt_preload_object_is_not_a_working_dislocator(tmp_path, monkeypatch):
    """ld.so ignores an unloadable LD_PRELOAD with a warning and exit 0 -- so every 'guarded' run
    would silently be unguarded."""
    if not shutil.which("true"):
        pytest.skip("needs coreutils true")
    bad = tmp_path / "libdislocator.so"
    bad.write_bytes(b"not an elf")
    assert tc._preloads(bad) is False
    monkeypatch.setenv("LYKOS_DISLOCATOR", str(bad))
    assert tc._probe_dislocator() is None


def test_a_broken_afl_fuzz_is_missing(tmp_path, monkeypatch):
    _script(tmp_path / "afl-fuzz", "echo 'afl-fuzz: error while loading shared libraries' >&2; "
            "exit 127")
    monkeypatch.setenv("LYKOS_AFL", str(tmp_path))
    assert tc._probe_afl() is None


def test_a_broken_weggli_is_missing(tmp_path, monkeypatch):
    w = _script(tmp_path / "weggli", "kill -SEGV $$")
    monkeypatch.setenv("LYKOS_WEGGLI", str(w))
    assert tc._probe_weggli() is None
    _script(tmp_path / "weggli", "echo 'weggli 0.2.4'")
    assert tc._probe_weggli().startswith("weggli 0.2.4")


def test_a_qemu_on_path_that_segfaults_is_not_counted(tmp_path, monkeypatch):
    _script(tmp_path / "qemu-aarch64", "kill -SEGV $$")
    _script(tmp_path / "qemu-arm", "echo 'qemu-arm version 9.1.1'")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + "/usr/bin:/bin")
    got = (tc._probe_qemu() or "").split(": ", 1)[-1].split()
    assert "arm" in got                       # the fake dir is first on PATH: it shadows the host
    assert "aarch64" not in got
