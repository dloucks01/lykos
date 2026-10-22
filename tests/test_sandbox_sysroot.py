"""R2 (doc 47): native shared-library dep resolution via LYKOS_QEMU_SYSROOT.

A dynamically-linked daemon run off its own system exits at the loader ("error while loading shared
libraries: ...") and reads as not-runnable -- so its --help mining, its baseline run and its fuzzing
all silently find nothing (measured on the real asterisk: missing libasteriskpj.so.2). `sandbox.run`
now, for a NATIVE target, prepends an operator-supplied sysroot's lib dirs to LD_LIBRARY_PATH and
binds the sysroot into the sandbox -- mirroring the afl campaign path -- so the program reaches
main(). Additive + opt-in: it fires only when LYKOS_QEMU_SYSROOT is set.
"""
import subprocess

import pytest

from lykos.analyze.dynamic import sandbox


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("native dep-resolution test is x86-64 native only")


def test_native_sysroot_resolves_a_missing_dependency(gcc, tmp_path, x86_64_only, monkeypatch):
    # A custom shared library the target links against, and a program that calls into it.
    (tmp_path / "foo.c").write_text("int lykos_foo(void){return 7;}\n")
    lib = tmp_path / "liblykosfoo.so"
    subprocess.run([gcc, "-shared", "-fPIC", str(tmp_path / "foo.c"), "-o", str(lib)],
                   check=True, capture_output=True)
    (tmp_path / "main.c").write_text(
        "#include <stdio.h>\n"
        "extern int lykos_foo(void);\n"
        "int main(void){ printf(\"LYKOS_FOO=%d\\n\", lykos_foo()); return 0; }\n")
    exe = tmp_path / "prog"
    # Link against the lib but DO NOT embed an rpath -- so at runtime it needs LD_LIBRARY_PATH.
    subprocess.run([gcc, str(tmp_path / "main.c"), "-L", str(tmp_path), "-llykosfoo",
                    "-o", str(exe)], check=True, capture_output=True)

    # Move the dependency into a SYSROOT lib dir, away from the program and off any default path.
    sysroot = tmp_path / "rootfs"
    (sysroot / "lib").mkdir(parents=True)
    lib.rename(sysroot / "lib" / "liblykosfoo.so")

    def _ran_ok(r):
        return b"LYKOS_FOO=7" in ((r.stdout or b"") + (r.stderr or b""))

    # Without the sysroot: the loader cannot find the dependency -> the program never reaches main().
    monkeypatch.delenv("LYKOS_QEMU_SYSROOT", raising=False)
    r0 = sandbox.run(exe, timeout=15)
    assert not _ran_ok(r0), f"expected a loader failure without the sysroot, got {r0.isolation}"

    # With the sysroot: LD_LIBRARY_PATH is set from it and it is bound into the sandbox -> runs.
    monkeypatch.setenv("LYKOS_QEMU_SYSROOT", str(sysroot))
    r1 = sandbox.run(exe, timeout=15)
    assert _ran_ok(r1), f"expected the program to run with the sysroot; iso={r1.isolation} " \
                        f"out={((r1.stdout or b'') + (r1.stderr or b''))[:200]!r}"
