"""Firmware filesystem extraction runs external extractors on UNTRUSTED images -- bound what they
write and keep every write inside the throwaway directory (analyze/firmware/carve.py)."""
import gzip
import os
import shutil
import subprocess

import pytest
from lykos.analyze.firmware import carve


def _newc(entries) -> bytes:
    """entries: [(name, mode, body)] -> a newc cpio archive (with trailer)."""
    out = bytearray()

    def pad(n):
        return b"\0" * ((4 - n % 4) % 4)
    for i, (name, mode, body) in enumerate(entries + [("TRAILER!!!", 0, b"")]):
        nb = name.encode() + b"\0"
        hdr = b"070701" + b"".join(f"{v:08x}".encode() for v in (
            i + 1, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(nb), 0))
        out += hdr + nb
        out += pad(len(out))
        out += body
        out += pad(len(out))
    return bytes(out)


def test_newc_parser_never_yields_an_absolute_or_dotdot_path():
    arc = _newc([("../../etc/evil", 0o100644, b"x"), ("/abs/path", 0o100644, b"y")])
    files = carve._cpio_newc_files(arc)
    assert files
    for f in files:
        assert not f["path"].startswith("/") and ".." not in f["path"].split("/")


def test_system_cpio_fallback_cannot_write_through_a_symlink(tmp_path, monkeypatch):
    if not shutil.which("cpio"):
        pytest.skip("no cpio")
    outside = tmp_path / "outside"
    outside.mkdir()
    arc = _newc([("evil", 0o120777, str(outside).encode()),
                 ("evil/pwned", 0o100644, b"\x7fELF owned")])
    monkeypatch.setattr(carve, "_cpio_newc_files", lambda *_a, **_k: [])
    carve._unpack_cpio(arc)
    assert not (outside / "pwned").exists()
    assert list(outside.iterdir()) == []


def _mksquash(tmp_path, populate) -> bytes:
    if not (shutil.which("mksquashfs") and shutil.which("unsquashfs")):
        pytest.skip("squashfs tools absent")
    root = tmp_path / "root"
    root.mkdir()
    populate(root)
    img = tmp_path / "fs.sqsh"
    r = subprocess.run(["mksquashfs", str(root), str(img), "-quiet", "-noappend"],
                       capture_output=True, timeout=120)
    if r.returncode != 0:
        pytest.skip("mksquashfs failed")
    return img.read_bytes()


def test_squashfs_dedup_bomb_is_bounded_before_it_hits_disk(tmp_path, monkeypatch):
    blob = os.urandom(256 << 10)

    def populate(root):
        (root / "data").mkdir()
        for i in range(40):                       # 40 x 256 KiB, deduplicated to ~256 KiB
            (root / "data" / f"f{i:02d}").write_bytes(blob)
        (root / "bin").mkdir()
        (root / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\0" * 60 + blob[:1024])
        os.symlink("/etc/passwd", root / "bin" / "pw")
    fs = _mksquash(tmp_path, populate)
    monkeypatch.setattr(carve, "_MAX_FS_EXTRACT", 4 * (256 << 10) + 4096)
    files = carve._unpack_squashfs(fs)
    paths = {f["path"] for f in files}
    # binaries are taken first, the selection stops at the byte cap, symlinks are never read
    assert "bin/busybox" in paths
    assert "bin/pw" not in paths
    assert len(files) <= 5
    assert sum(len(f["bytes"]) for f in files) <= carve._MAX_FS_EXTRACT


def test_squashfs_normal_tree_is_fully_extracted(tmp_path):
    def populate(root):
        (root / "bin").mkdir()
        (root / "etc").mkdir()
        (root / "bin" / "app").write_bytes(b"\x7fELF" + b"\1" * 100)
        (root / "etc" / "shadow").write_text("root:$1$abc$def:0:0\n")
    fs = _mksquash(tmp_path, populate)
    files = carve._unpack_squashfs(fs)
    assert {f["path"] for f in files} == {"bin/app", "etc/shadow"}
    assert {f["kind"] for f in files if f["path"] == "bin/app"} == {"elf"}


def test_many_gzip_members_share_one_decompression_budget(monkeypatch):
    member = gzip.compress(b"\0" * (1 << 20))     # 1 MiB of zeros per member, not an ELF
    img = b"".join(b"PAD!" + member for _ in range(30))
    calls = []
    real = carve._decompress

    def counting(typ, blob):
        out = real(typ, blob)
        calls.append(len(out or b""))
        return out
    monkeypatch.setattr(carve, "_decompress", counting)
    monkeypatch.setattr(carve, "_MAX_DECOMPRESS_TOTAL", 5 << 20)
    carve.extract_components(img)
    assert sum(calls) <= (5 << 20) + (64 << 20)    # stops once the shared budget is spent
    assert len(calls) < 30
