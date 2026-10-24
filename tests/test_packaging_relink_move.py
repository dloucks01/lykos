"""relink-bundle.sh must survive the operator MOVING the extracted bundle.

The first relink fronts a binary that patchelf corrupts (gcc's 42MB cc1) with a loader-wrapper over
the pristine `cc1.real`. After a move, the old relink walked `cc1.real` as an ordinary executable,
failed to patch it again and wrapped it a SECOND time (`cc1.real.real`), while `cc1` still named the
old root's loader -> gcc could not compile offline. This builds a miniature bundle (the host's own
loader + libc, two tiny dynamic programs, and a patchelf shim that corrupts anything named cc1) and
drives relink -> move -> relink for real.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "relink-bundle.sh"
PATCHELF = ROOT / "packaging" / "bin" / "patchelf-static-x86_64"
LOADER = Path("/lib64/ld-linux-x86-64.so.2")

pytestmark = pytest.mark.skipif(
    platform.machine() != "x86_64" or not PATCHELF.exists() or not LOADER.exists(),
    reason="needs an x86-64 host, its glibc loader and the vendored static patchelf")


def _libc() -> Path:
    for c in ("/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6",
              "/lib64/libc.so.6"):
        if Path(c).exists():
            return Path(c).resolve()
    pytest.skip("no host libc.so.6")


def _bundle(base: Path, gcc) -> Path:
    vendor = base / "lykos" / "vendor"
    tc = vendor / "toolchain"
    lib = tc / "usr" / "lib" / "x86_64-linux-gnu"
    lib.mkdir(parents=True)
    shutil.copy2(LOADER.resolve(), lib / "ld-linux-x86-64.so.2")
    shutil.copy2(_libc(), lib / "libc.so.6")
    (tc / ".relink").mkdir()
    shim = tc / ".relink" / "patchelf"
    # the 0.19.1 large-ELF corruption, reproduced deterministically for anything named cc1*
    shim.write_text("#!/bin/sh\n"
                    f'"{PATCHELF}" "$@"; rc=$?\n'
                    'for last; do :; done\n'
                    'case "$*" in *--set-interpreter*) case "$last" in *cc1*) : > "$last";; esac;; esac\n'
                    "exit $rc\n")
    shim.chmod(0o755)
    for rel, word in (("usr/bin/tool", "tool-ok"), ("usr/libexec/gcc/cc1", "cc1-ok")):
        out = tc / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        src = base / (out.name + ".c")
        src.write_text('#include <stdio.h>\nint main(void){puts("%s");return 0;}\n' % word)
        if subprocess.run([gcc, str(src), "-o", str(out)], capture_output=True).returncode:
            pytest.skip("cannot build the fixture")
    return vendor


def _relink(vendor: Path, cwd=None, arg=None):
    env = {k: v for k, v in os.environ.items() if k not in ("LD_LIBRARY_PATH", "LD_PRELOAD")}
    r = subprocess.run(["sh", str(SCRIPT), arg or str(vendor)], cwd=cwd, env=env,
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def _run(p: Path) -> str:
    r = subprocess.run([str(p)], capture_output=True, text=True, timeout=20, env={})
    assert r.returncode == 0, f"{p} failed: {r.stderr}"
    return r.stdout.strip()


def _rpath(p: Path) -> str:
    return subprocess.run([str(PATCHELF), "--print-rpath", str(p)], capture_output=True,
                          text=True).stdout.strip()


def test_relink_then_move_then_relink_keeps_wrappered_tools_working(tmp_path, gcc):
    p1 = tmp_path / "p1"
    vendor = _bundle(p1, gcc)
    tc = vendor / "toolchain"
    cc1 = tc / "usr/libexec/gcc/cc1"
    _relink(vendor)
    assert cc1.with_name("cc1.real").exists() and "lykos loader-wrapper" in cc1.read_text()
    assert _run(cc1) == "cc1-ok" and _run(tc / "usr/bin/tool") == "tool-ok"

    # the operator moves the extracted folder; the old root is gone
    p2 = tmp_path / "p2"
    shutil.move(str(p1), str(p2))
    vendor2 = p2 / "lykos" / "vendor"
    tc2 = vendor2 / "toolchain"
    cc1b = tc2 / "usr/libexec/gcc/cc1"
    _relink(vendor2)
    assert not cc1b.with_name("cc1.real.real").exists(), "cc1 was wrapped a second time"
    body = cc1b.read_text()
    assert str(p1) not in body and str(p2) in body, "wrapper still names the old root"
    assert _run(cc1b) == "cc1-ok", "cc1 broken after a move (gcc can't compile offline)"
    assert _run(tc2 / "usr/bin/tool") == "tool-ok"
    assert str(p1) not in _rpath(tc2 / "usr/bin/tool"), "stale pre-move rpath entries stacked"

    # and a third run on the same root is a silent no-op
    assert _relink(vendor2) == ""


def test_relink_is_a_noop_when_vendor_is_passed_relative(tmp_path, gcc):
    vendor = _bundle(tmp_path / "r", gcc)
    _relink(vendor, cwd=vendor.parent, arg="vendor")
    assert _relink(vendor, cwd=vendor.parent, arg="vendor") == "", \
        "a relative vendor path never matched the stamp -> relinked on every launch"


def test_relink_heals_a_bundle_an_older_relink_double_wrapped(tmp_path, gcc):
    p1 = tmp_path / "h1"
    vendor = _bundle(p1, gcc)
    _relink(vendor)
    p2 = tmp_path / "h2"
    shutil.move(str(p1), str(p2))
    cc1 = p2 / "lykos/vendor/toolchain/usr/libexec/gcc/cc1"
    # reproduce the old script's damage: cc1.real wrapped again around cc1.real.real
    real = cc1.with_name("cc1.real")
    real.rename(cc1.with_name("cc1.real.real"))
    real.write_text("#!/bin/sh\n# lykos loader-wrapper: old\nexec /nonexistent \"$@\"\n")
    real.chmod(0o755)
    _relink(p2 / "lykos" / "vendor")
    assert not cc1.with_name("cc1.real.real").exists()
    assert _run(cc1) == "cc1-ok"
