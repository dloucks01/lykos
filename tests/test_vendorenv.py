"""Run-in-place toolchain activation: the mechanism that lets the air-gap bundle work with
nothing installed. `vendorenv.activate` puts a vendored toolchain's executable directory on
the process PATH, so every locator that resolves through `shutil.which` finds the bundled
engine. It must be a clean no-op when there is no vendored toolchain, and -- the safety
property that matters most -- it must NEVER touch a library-search path, so the laptop's own
binaries are never relinked against bundle libraries.
"""
from __future__ import annotations

import os
import shutil

import pytest
from lykos import vendorenv


@pytest.fixture
def clean_env(monkeypatch):
    """A fresh activation each time: no leftover activate flag, no vendor pointers."""
    for var in ("_LYKOS_VENDOR_ACTIVE", "LYKOS_VENDOR", "LYKOS_TOOLCHAIN", "LYKOS_PYSITE",
                "LYKOS_GHIDRA", "GHIDRA_INSTALL_DIR", "JAVA_HOME",
                "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
                "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH_64"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")


def _make_toolchain(root, wrappers=False):
    """A minimal extracted prefix: a bin dir with a fake tool and a multiarch lib dir.
    With wrappers=True, also a .wrappers/ dir as setup.sh would generate."""
    (root / "toolchain" / "usr" / "bin").mkdir(parents=True)
    tool = root / "toolchain" / "usr" / "bin" / "faketool"
    tool.write_text("#!/bin/sh\necho hi\n")
    tool.chmod(0o755)
    (root / "toolchain" / "usr" / "lib" / "x86_64-linux-gnu").mkdir(parents=True)
    if wrappers:
        wdir = root / "toolchain" / ".wrappers"
        wdir.mkdir()
        w = wdir / "faketool"
        w.write_text("#!/bin/sh\nexec /does/not/matter\n")
        w.chmod(0o755)
    return root / "toolchain"


def test_activation_is_a_noop_without_a_vendored_toolchain(clean_env, monkeypatch, tmp_path):
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))  # exists, but has no toolchain/
    summary = vendorenv.activate()
    assert summary["toolchain"] is None
    assert summary["bin"] == []
    assert os.environ["PATH"] == "/usr/bin:/bin"  # untouched


def test_activation_never_sets_a_library_search_path(clean_env, monkeypatch, tmp_path):
    """The safety property: the bundle's libraries must never join a process-wide search path,
    or the laptop's own binaries would prefer them. Activation touches PATH and nothing that
    controls dynamic linking."""
    _make_toolchain(tmp_path, wrappers=True)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    for var in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH_64"):
        assert var not in os.environ, f"activation set {var} -- it must not"


def test_activation_puts_the_vendored_bin_on_the_path(clean_env, monkeypatch, tmp_path):
    tc = _make_toolchain(tmp_path)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    summary = vendorenv.activate()

    assert summary["toolchain"] == str(tc)
    bindir = str(tc / "usr" / "bin")
    # PATH now leads with the vendored bin, and the host entries survive behind it
    assert os.environ["PATH"].split(os.pathsep)[0] == bindir
    assert "/usr/bin" in os.environ["PATH"].split(os.pathsep)
    # shutil.which -- the thing every locator uses -- now finds the bundled tool
    assert shutil.which("faketool") == str(tc / "usr" / "bin" / "faketool")


def test_the_scoped_wrapper_dir_is_preferred_on_the_path(clean_env, monkeypatch, tmp_path):
    """When setup.sh has generated .wrappers/, that dir goes first so a tool resolves to its
    scoped wrapper (bundle libs private to that process), not the raw binary."""
    tc = _make_toolchain(tmp_path, wrappers=True)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    assert os.environ["PATH"].split(os.pathsep)[0] == str(tc / ".wrappers")
    assert shutil.which("faketool") == str(tc / ".wrappers" / "faketool")


def test_activation_is_idempotent(clean_env, monkeypatch, tmp_path):
    _make_toolchain(tmp_path)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    path_after_first = os.environ["PATH"]
    assert vendorenv.activate() == {"already": True}
    assert os.environ["PATH"] == path_after_first  # no double-prepend


def test_ltoolchain_env_var_overrides_vendor(clean_env, monkeypatch, tmp_path):
    tc = _make_toolchain(tmp_path)
    monkeypatch.setenv("LYKOS_TOOLCHAIN", str(tc))
    summary = vendorenv.activate()
    assert summary["toolchain"] == str(tc)


def test_bundled_ghidra_points_the_locator_env_when_unset(clean_env, monkeypatch, tmp_path):
    _make_toolchain(tmp_path)
    (tmp_path / "ghidra" / "support").mkdir(parents=True)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    assert os.environ["LYKOS_GHIDRA"] == str(tmp_path / "ghidra")


def test_ghidra_extracted_inside_the_toolchain_prefix_is_found(clean_env, monkeypatch, tmp_path):
    """The apt/container path extracts Ghidra's deb into toolchain/usr/share/ghidra, where
    analyzeHeadless lives under support/ -- not on PATH and not where locate_ghidra looks.
    Activation must still point LYKOS_GHIDRA at it."""
    _make_toolchain(tmp_path)
    groot = tmp_path / "toolchain" / "usr" / "share" / "ghidra_11.0"
    (groot / "support").mkdir(parents=True)
    (groot / "support" / "analyzeHeadless").write_text("#!/bin/sh\n")
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    assert os.environ["LYKOS_GHIDRA"] == str(groot)


def test_a_vendored_jdk_is_put_on_java_home_and_path(clean_env, monkeypatch, tmp_path):
    """The JDK lives under usr/lib/jvm/<vm>/bin, off PATH -- so activation must export JAVA_HOME
    (for Ghidra) and add that bin to PATH (so `java`/`javac` resolve and JARs can run)."""
    tc = _make_toolchain(tmp_path)
    jbin = tc / "usr" / "lib" / "jvm" / "java-25-openjdk-amd64" / "bin"
    jbin.mkdir(parents=True)
    (jbin / "java").write_text("#!/bin/sh\n")
    (jbin / "java").chmod(0o755)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    assert os.environ["JAVA_HOME"] == str(jbin.parent)
    assert str(jbin) in os.environ["PATH"].split(os.pathsep)
    assert shutil.which("java") == str(jbin / "java")
    # and it did NOT set a library search path to do it
    assert "LD_LIBRARY_PATH" not in os.environ


def test_activation_points_the_compilers_at_the_vendored_sysroot(clean_env, monkeypatch, tmp_path):
    """A relocated gcc looks for headers/startfiles at absolute /usr paths (empty on a minimal
    target). Activation must point C_INCLUDE_PATH / LIBRARY_PATH at the vendored sysroot so the
    bundled compilers actually compile and link -- without touching how anything else builds."""
    tc = _make_toolchain(tmp_path)
    (tc / "usr" / "include").mkdir(parents=True)
    (tc / "usr" / "include" / "x86_64-linux-gnu").mkdir()
    for var in ("C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    vendorenv.activate()
    inc = os.environ["C_INCLUDE_PATH"].split(os.pathsep)
    lib = os.environ["LIBRARY_PATH"].split(os.pathsep)
    assert str(tc / "usr" / "include") in inc
    assert str(tc / "usr" / "include" / "x86_64-linux-gnu") in inc
    assert str(tc / "usr" / "lib" / "x86_64-linux-gnu") in lib
    assert os.environ["CPLUS_INCLUDE_PATH"] == os.environ["C_INCLUDE_PATH"]


def test_an_explicit_compiler_env_is_not_overridden(clean_env, monkeypatch, tmp_path):
    _make_toolchain(tmp_path)
    (tmp_path / "toolchain" / "usr" / "include").mkdir(parents=True)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    monkeypatch.setenv("C_INCLUDE_PATH", "/my/own/includes")
    vendorenv.activate()
    assert os.environ["C_INCLUDE_PATH"] == "/my/own/includes"


def test_an_explicit_ghidra_choice_is_not_overridden(clean_env, monkeypatch, tmp_path):
    _make_toolchain(tmp_path)
    (tmp_path / "ghidra" / "support").mkdir(parents=True)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    monkeypatch.setenv("LYKOS_GHIDRA", "/opt/my-own-ghidra")
    vendorenv.activate()
    assert os.environ["LYKOS_GHIDRA"] == "/opt/my-own-ghidra"


def test_vendored_pysite_goes_on_sys_path_and_pythonpath(clean_env, monkeypatch, tmp_path):
    """The bundle vendors pypcode under vendor/pysite (a pip --target tree). Activation must put
    it on sys.path so `import <pkg>` resolves in-place, and on PYTHONPATH for child processes."""
    import sys
    (tmp_path / "pysite" / "vendored_pkg").mkdir(parents=True)
    (tmp_path / "pysite" / "vendored_pkg" / "__init__.py").write_text("VALUE = 42\n")
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(sys, "path", list(sys.path))  # isolate the mutation
    summary = vendorenv.activate()

    assert summary["pysite"] == str(tmp_path / "pysite")
    assert str(tmp_path / "pysite") == sys.path[0]
    assert str(tmp_path / "pysite") in os.environ["PYTHONPATH"].split(os.pathsep)
    import importlib
    mod = importlib.import_module("vendored_pkg")
    try:
        assert mod.VALUE == 42          # the vendored package is importable in-place
    finally:
        sys.modules.pop("vendored_pkg", None)


def test_doctor_activates_the_vendored_toolchain(clean_env, monkeypatch, tmp_path, capsys):
    """End to end through the CLI: `lykos doctor` must run activation before it surveys, so a
    vendored tool is reported present. The status line names where the toolchain came from."""
    tc = _make_toolchain(tmp_path)
    monkeypatch.setenv("LYKOS_VENDOR", str(tmp_path))
    from lykos import cli
    cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "run-in-place" in out and str(tc) in out
