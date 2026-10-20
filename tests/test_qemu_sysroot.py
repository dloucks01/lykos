"""A cross-arch target must RUN, not merely be recognised as foreign.

qemu-user needs QEMU_LD_PREFIX to find the GUEST's dynamic loader and libraries; without it a
dynamically-linked foreign ELF (firmware, or any cross-compiled binary) exits at the loader before
main() -- the real air-gap symptom where a cross-arch binary "did not execute" and every input
read as a silent no-op. `qemu_ld_prefix` resolves a guest sysroot from, in order: an operator
override (an uploaded firmware rootfs), the binary's own directory (a carved rootfs / bundled
libs), then the host cross-arch sysroot /usr/<triple>.
"""
import os

from lykos.analyze.dynamic import sandbox


def _make_sysroot(root, triple, loader="ld-linux-fake.so.1"):
    d = root / triple / "lib"
    d.mkdir(parents=True)
    (d / loader).write_bytes(b"\x7fELF")           # presence is all the resolver checks
    return root / triple


def test_operator_override_wins(tmp_path, monkeypatch):
    rootfs = _make_sysroot(tmp_path, "firmware-rootfs")
    monkeypatch.setenv("LYKOS_QEMU_SYSROOT", str(rootfs))
    # Even with an exedir loader and a host triple available, the explicit override is returned.
    assert sandbox.qemu_ld_prefix("aarch64", exedir=str(tmp_path)) == str(rootfs)


def test_override_ignored_when_not_a_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("LYKOS_QEMU_SYSROOT", str(tmp_path / "does-not-exist"))
    # Falls through to the host sysroot (or None) rather than returning a bogus path.
    got = sandbox.qemu_ld_prefix("aarch64")
    assert got != str(tmp_path / "does-not-exist")


def test_exedir_with_loader_beside_binary(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_QEMU_SYSROOT", raising=False)
    # A carved rootfs / relocated bundle: the guest loader sits under the binary's own dir.
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "ld-uClibc.so.0").write_bytes(b"\x7fELF")
    got = sandbox.qemu_ld_prefix("arm", exedir=str(tmp_path))
    assert got == str(tmp_path.resolve())


def test_exedir_without_loader_is_not_a_sysroot(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_QEMU_SYSROOT", raising=False)
    (tmp_path / "notes.txt").write_text("no loader here")
    # exedir is not a sysroot, so the resolver must not return it (host fallback or None).
    assert sandbox.qemu_ld_prefix("m68k", exedir=str(tmp_path)) != str(tmp_path.resolve())


def test_unknown_arch_without_any_sysroot_is_none(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_QEMU_SYSROOT", raising=False)
    assert sandbox.qemu_ld_prefix("no-such-arch", exedir=str(tmp_path)) is None


def test_host_cross_sysroot_when_present():
    # Advisory: on a box with the aarch64 cross toolchain, the host sysroot is resolved. Skip
    # cleanly where it is not installed so the suite stays green on a minimal host.
    if not os.path.isdir("/usr/aarch64-linux-gnu/lib"):
        import pytest
        pytest.skip("no host aarch64 cross-sysroot installed")
    got = sandbox.qemu_ld_prefix("aarch64")
    assert got == "/usr/aarch64-linux-gnu"
