""""Nothing was run" must never look like "nothing was found" -- on the NATIVE path too.

Every other substrate reported a non-run explicitly: `jvm-missing`, `python-missing`,
`node-missing`, `dotnet-missing`, `unsupported-arch`, `unsupported-windows`,
`wine-launch-failed`, and the `/not-runnable` suffix the managed paths carry. The native path
had no such signal at all, and it is the fall-through for every file_type without a backend of
its own -- a Mach-O (which triage marks `analyzable`), a raw blob, a bare-metal image, a
truncated ELF.

What happened instead is worth stating because it is not obvious: glibc's `execvp()` falls back
to `/bin/sh` when `execve` returns ENOEXEC, so an unrunnable image came back with `rc=127`,
stderr `"<path>: 1: <magic>: not found"`, and `crashed=False, note=None`. A whole campaign could
complete against a macOS binary and report it clean.
"""
import os
import struct
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox

# A 64-bit Mach-O header (MH_MAGIC_64, x86_64, MH_EXECUTE). Enough for triage to call it macho
# and for the kernel to refuse it, which is all this file is about.
_MACHO = struct.pack("<IiiIIIII", 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0) + b"\x00" * 256


def _executable(tmp_path, name, blob):
    p = tmp_path / name
    p.write_bytes(blob)
    os.chmod(p, 0o755)                   # the exec BIT is set: this is not a permissions test
    return p


@pytest.mark.parametrize("name,blob", [
    ("stub.macho", _MACHO),
    ("garbage.bin", b"\x7f\x7f\x7fNOTANELF" + b"\x00" * 256),
    ("truncated.elf", b"\x7fELF"),        # the magic alone, no program headers
    ("empty.bin", b""),
])
def test_an_image_the_host_cannot_execute_is_reported_as_a_non_run(tmp_path, name, blob):
    r = sandbox.run(_executable(tmp_path, name, blob), stdin=b"A" * 64, timeout=10.0)
    assert not r.crashed
    assert "not-runnable" in r.isolation, f"{name} reported {r.isolation!r} -- a clean run"
    assert r.note, "a non-run must say WHY, or the operator cannot tell it from a clean run"


def test_the_header_check_names_what_it_would_accept(tmp_path):
    why = sandbox._host_loadable(_executable(tmp_path, "x.macho", _MACHO))
    assert why and "ELF" in why


def test_an_elf_and_a_shebang_script_are_both_loadable(tmp_path):
    assert sandbox._host_loadable(_executable(tmp_path, "s.sh", b"#!/bin/sh\necho hi\n")) is None
    assert sandbox._host_loadable(_executable(tmp_path, "e.bin", b"\x7fELF" + b"\x00" * 64)) is None


def test_an_empty_image_says_so_specifically(tmp_path):
    why = sandbox._host_loadable(_executable(tmp_path, "z.bin", b""))
    assert why and "empty" in why


def test_the_post_hoc_check_needs_both_the_code_and_a_marker():
    """`rc == 127` alone is not enough: a program is entitled to exit 127. Requiring a loader
    marker as well keeps a legitimate exit from being reported as a non-run."""
    assert sandbox._exec_failed(127, b"/t/x: 1: \x7f\x7f: not found\n")
    assert sandbox._exec_failed(126, b"cannot execute binary file\n")
    assert not sandbox._exec_failed(127, b"usage: tool [-v] FILE\n")
    assert not sandbox._exec_failed(0, b": not found\n")
    assert not sandbox._exec_failed(1, b"exec format error\n")


def test_dynamic_loader_failure_is_a_nonrun_whatever_the_exit_code():
    """The air-gap case: a binary built for a NEWER glibc than the (older) target. A glibc
    VERSION mismatch exits 1 (not 127) and prints `version `GLIBC_2.34' not found (required by
    ...)`; a MISSING library exits 127 with `error while loading shared libraries`. Both mean the
    image never ran and must be caught regardless of exit code -- otherwise the target reads as a
    clean campaign when in fact nothing executed."""
    assert sandbox._exec_failed(
        1, b"/bad: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /bad)\n")
    assert sandbox._exec_failed(
        127, b"/t/x: error while loading shared libraries: libfoo.so.1: cannot open shared object file\n")
    # a program that merely mentions 'not found' in its own output (and exits cleanly) is NOT a non-run
    assert not sandbox._exec_failed(0, b"config key 'timeout' not found, using default\n")


# ---- the regression that matters: a real target must still run and still crash -------------

@pytest.fixture(scope="module")
def native(tmp_path_factory):
    import shutil
    if not shutil.which("gcc"):
        pytest.skip("no gcc")
    d = tmp_path_factory.mktemp("native")
    src = d / "t.c"
    src.write_text("#include <stdio.h>\n#include <string.h>\n"
                   "int main(void){char b[16],l[512];"
                   "if(!fgets(l,sizeof l,stdin))return 0;strcpy(b,l);"
                   "printf(\"%s\",b);return 0;}\n")
    exe = d / "t"
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-no-pie", "-o", str(exe), str(src)],
                   check=True, capture_output=True)
    return exe


def test_a_real_native_target_still_runs_cleanly(native):
    r = sandbox.run(native, stdin=b"hi\n", timeout=10.0)
    assert "not-runnable" not in r.isolation
    assert not r.crashed


def test_a_real_native_target_still_crashes(native):
    r = sandbox.run(native, stdin=b"A" * 400 + b"\n", timeout=10.0)
    assert r.crashed and r.signal_name == "SIGSEGV"
    assert "not-runnable" not in r.isolation


def test_the_batch_runner_still_drives_a_native_target(native):
    """The batch path is the one that makes native fuzzing ~580 exec/s; the header check must
    not have cost it."""
    out = sandbox.run_batch(native, [b"hi\n", b"A" * 400 + b"\n"], host=sandbox.host_arch())
    if out is None:
        pytest.skip("batch runner unavailable here (no bwrap/python3)")
    assert len(out) == 2
    assert any(getattr(r, "crashed", False) for r in out)
