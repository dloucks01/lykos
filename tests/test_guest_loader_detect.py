"""Guest-loader detection for QEMU_LD_PREFIX (symbol-lookup -> handshake fix).

When a target is ingested WITH its own libraries, afl-qemu must run it against THOSE libs, or a
binary built on a newer glibc dies with `symbol lookup error: undefined symbol` and afl reports
"Fork server handshake failed" even though the libs were supplied. qemu_ld_prefix routes
QEMU_LD_PREFIX at the target's dir only if _dir_has_guest_loader finds the loader -- which must
look at the TOP level and the multiarch layout, not just lib64/."""
from __future__ import annotations

from lykos.analyze.dynamic import sandbox


def test_loader_at_top_level_is_detected(tmp_path):
    (tmp_path / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF")
    assert sandbox._dir_has_guest_loader(tmp_path) is True


def test_loader_in_lib64_is_detected(tmp_path):
    (tmp_path / "lib64").mkdir()
    (tmp_path / "lib64" / "ld-2.31.so").write_bytes(b"\x7fELF")
    assert sandbox._dir_has_guest_loader(tmp_path) is True


def test_loader_in_multiarch_dir_is_detected(tmp_path):
    d = tmp_path / "lib" / "x86_64-linux-gnu"
    d.mkdir(parents=True)
    (d / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF")
    assert sandbox._dir_has_guest_loader(tmp_path) is True


def test_dir_without_a_loader_is_not_a_sysroot(tmp_path):
    (tmp_path / "libc.so.6").write_bytes(b"\x7fELF")   # a lib, but no LOADER
    (tmp_path / "data.bin").write_bytes(b"x")
    assert sandbox._dir_has_guest_loader(tmp_path) is False


def test_qemu_ld_prefix_uses_a_directory_with_its_own_loader(tmp_path):
    # a native directory-ingested target: its own loader beside it -> QEMU_LD_PREFIX = that dir
    (tmp_path / "lib64").mkdir()
    (tmp_path / "lib64" / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF")
    got = sandbox.qemu_ld_prefix("x86-64", exedir=str(tmp_path))
    assert got == str(tmp_path.resolve())
