"""Carving components out of a firmware image.

A firmware blob is a concatenation of things with no table of contents, so every component is
found by its magic and sized by parsing it. Both halves fail quietly: a missed ELF is a
component that never gets analysed, and a wrongly-sized one is a truncated binary that gets
analysed and produces nonsense -- which looks like a finding-free component rather than a
carving bug.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import struct

import pytest
from lykos.analyze.firmware import carve


def _elf64(payload_len=0x40, endian="<"):
    """A minimal but structurally valid ELF64 whose extent is computable."""
    ehsize, phentsize, phnum = 64, 56, 1
    phoff = ehsize
    body_off = phoff + phentsize * phnum
    ident = b"\x7fELF" + bytes([2, 1 if endian == "<" else 2, 1]) + b"\x00" * 9
    eh = ident + struct.pack(
        endian + "HHIQQQIHHHHHH",
        2, 0x3E, 1, 0x400000, phoff, 0, 0, ehsize, phentsize, phnum, 64, 0, 0)
    ph = struct.pack(endian + "IIQQQQQQ", 1, 5, body_off, 0x400000, 0x400000,
                     payload_len, payload_len, 0x1000)
    return eh + ph + b"\x90" * payload_len


# ---- sizing an embedded ELF --------------------------------------------------------------

def test_an_embedded_elf_is_sized_by_its_own_headers():
    elf = _elf64(0x100)
    blob = b"\xaa" * 512 + elf + b"\xbb" * 512
    size = carve._elf_extent(blob, 512)
    assert size == len(elf), f"extent {size} vs real {len(elf)}"


def test_a_big_endian_elf_is_sized_too():
    """Firmware for MIPS and PowerPC targets is big-endian, and reading its headers
    little-endian yields an absurd size -- which either truncates the component or swallows
    the rest of the image."""
    elf = _elf64(0x80, endian=">")
    assert carve._elf_extent(elf, 0) == len(elf)


def test_a_truncated_elf_reports_no_extent_rather_than_a_wrong_one():
    """Better to carve nothing than to hand the analyser a binary that stops mid-section."""
    elf = _elf64(0x400)
    assert carve._elf_extent(elf[:80], 0) is None


def test_a_header_claiming_more_than_the_image_holds_is_refused():
    """A section table past the end of the image would carve a component that runs off the
    buffer. e_shnum has to be non-zero for the section table to be consulted at all."""
    elf = bytearray(_elf64(0x40))
    struct.pack_into("<Q", elf, 16 + 24, 1 << 40)      # e_shoff far past the end
    struct.pack_into("<H", elf, 16 + 44, 4)            # e_shnum: make it be read
    assert carve._elf_extent(bytes(elf), 0) is None


def test_something_that_is_not_an_elf_has_no_extent():
    assert carve._elf_extent(b"MZ" + b"\x00" * 200, 0) is None
    assert carve._elf_extent(b"", 0) is None
    assert carve._elf_extent(b"\x7fELF", 0) is None            # too short to parse


# ---- signature scanning ------------------------------------------------------------------

def test_every_shipped_signature_is_usable():
    assert carve.SIGNATURES
    for magic, typ, desc in carve.SIGNATURES:
        assert isinstance(magic, bytes) and len(magic) >= 2, (typ, magic)
        assert typ and desc, magic


def test_a_two_byte_magic_is_only_tolerable_because_it_is_never_carved():
    """JFFS2's node magic really is two bytes (0x1985), which hits roughly once per 64 KB of
    random data. That is survivable ONLY because such a type is reported as a signature and
    never extracted as a component -- the carver builds sub-targets from ELF and compressed
    streams alone. If a short magic is ever added to the extraction set, the noise stops being
    cosmetic and starts registering garbage sub-targets."""
    two_byte = {t for m, t, _d in carve.SIGNATURES if len(m) < 3}
    carved = {"elf", "gzip", "xz", "bzip2"}
    assert two_byte, "no two-byte magic left -- tighten this test rather than delete it"
    assert not (two_byte & carved), \
        f"a two-byte magic is carved into components: {two_byte & carved}"
    # three bytes (gzip, bzip2) is one hit per 16 MB of random data, which is a different
    # order of problem and is why those are safe to carve
    assert all(len(m) >= 3 for m, t, _d in carve.SIGNATURES if t in carved)


def test_an_embedded_elf_is_found_at_its_offset():
    blob = b"\x00" * 300 + _elf64(0x40)
    hits = carve.scan_signatures(blob)
    elfs = [h for h in hits if h["type"] == "elf"]
    assert elfs and elfs[0]["offset"] == 300
    assert elfs[0].get("size"), "an ELF hit carries no size, so it cannot be carved"


def test_hits_come_back_in_offset_order():
    """The carver walks them in order to avoid overlapping extractions."""
    blob = _elf64(0x40) + b"\x00" * 64 + gzip.compress(b"x" * 64) + b"\x00" * 64 + b"hsqs"
    hits = carve.scan_signatures(blob)
    assert hits == sorted(hits, key=lambda h: h["offset"])


def test_dense_repeats_of_one_type_are_collapsed():
    """A JFFS2 image contains a node magic every few bytes; without collapsing, one filesystem
    produces thousands of hits and buries every real component."""
    spam = b"\x85\x19" * 2000
    hits = carve.scan_signatures(spam)
    assert len(hits) < 2000, f"{len(hits)} hits from one dense filesystem"


def test_the_hit_count_is_capped():
    """A pathological image must not make the scan unbounded."""
    assert carve._MAX_HITS > 0
    blob = b"".join(b"\x7fELF" + b"\x00" * 8 for _ in range(carve._MAX_HITS + 500))
    assert len(carve.scan_signatures(blob)) <= carve._MAX_HITS


def test_an_empty_image_yields_nothing():
    assert carve.scan_signatures(b"") == []


# ---- decompression -----------------------------------------------------------------------

@pytest.mark.parametrize("typ,comp", [
    ("gzip", lambda b: gzip.compress(b)),
    ("xz", lambda b: lzma.compress(b)),
    ("bzip2", lambda b: bz2.compress(b)),
])
def test_each_compressed_stream_decompresses(typ, comp):
    payload = b"payload-" * 32
    assert carve._decompress(typ, comp(payload)) == payload


@pytest.mark.parametrize("typ", ["gzip", "xz", "bzip2"])
def test_a_corrupt_stream_is_none_rather_than_an_exception(typ):
    """Firmware is full of things that begin like a compressed stream and are not. One of them
    must not take the carve down."""
    assert carve._decompress(typ, b"\x1f\x8b\x08" + b"\xff" * 64) is None
    # empty in, nothing out -- `extract_components` guards with `if dec and ...`, so a falsy
    # result is what it relies on, whether that is None or b""
    assert not carve._decompress(typ, b"")


def test_an_unknown_type_decompresses_to_nothing():
    assert carve._decompress("squashfs", b"hsqs" + b"\x00" * 64) is None


def test_a_decompression_bomb_is_bounded():
    """A few kilobytes that expand to gigabytes would otherwise be held in memory whole."""
    bomb = gzip.compress(b"\x00" * (80 << 20))
    out = carve._decompress("gzip", bomb)
    assert out is None or len(out) <= (64 << 20) + 4096


# ---- component extraction ----------------------------------------------------------------

def test_an_embedded_elf_is_extracted_whole():
    elf = _elf64(0x100)
    blob = b"\xcc" * 256 + elf + b"\xdd" * 256
    comps = carve.extract_components(blob)
    assert comps, "an embedded ELF was not extracted"
    got = [c for c in comps if c["bytes"].startswith(b"\x7fELF")]
    assert got and got[0]["bytes"] == elf, "the carved ELF is not byte-identical"


def test_a_compressed_elf_payload_is_extracted():
    """Firmware routinely gzips its kernel and userland binaries; a carver that stops at the
    compressed stream registers an opaque blob nothing can analyse."""
    elf = _elf64(0x80)
    blob = b"\x00" * 64 + gzip.compress(elf) + b"\x00" * 64
    comps = carve.extract_components(blob)
    assert any(c["bytes"].startswith(b"\x7fELF") for c in comps), \
        "the ELF inside the gzip stream was not recovered"


def test_the_component_count_is_capped():
    elf = _elf64(0x20)
    blob = b"".join(elf for _ in range(200))
    comps = carve.extract_components(blob, max_components=8)
    assert len(comps) <= 8


def test_every_component_carries_what_registration_needs():
    blob = b"\x00" * 128 + _elf64(0x40)
    for c in carve.extract_components(blob):
        assert isinstance(c.get("offset"), int)
        assert c.get("kind") and c.get("filename") and c.get("bytes")


def test_an_image_with_nothing_in_it_extracts_nothing():
    assert carve.extract_components(b"\x00" * 8192) == []
    assert carve.extract_components(b"") == []


# ---- embedded filesystem unpack ----------------------------------------------------------
# Real firmware keeps its binaries inside a COMPRESSED root filesystem, so they are invisible to
# the raw ELF/gzip scan above. extract_filesystems() shells out to the system extractor to reach
# them; these tests cover the superblock sizing, the graceful degradation when no extractor is
# installed, and a real cpio round-trip when `cpio` is on PATH.

def _squashfs_superblock(bytes_used: int, endian="<") -> bytes:
    """A v4.0 SquashFS superblock prefix with the magic and bytes_used (+40) we read."""
    magic = b"hsqs" if endian == "<" else b"sqsh"
    sb = bytearray(96)
    sb[0:4] = magic
    struct.pack_into(endian + "Q", sb, 40, bytes_used)
    return bytes(sb)


def test_squashfs_size_is_read_from_the_superblock():
    sb = _squashfs_superblock(96) + b"\x00" * 64         # bytes_used covers the whole region
    assert carve._squashfs_size(sb, 0) == 96


def test_squashfs_size_handles_big_endian_sqsh():
    sb = _squashfs_superblock(100, endian=">") + b"\x00" * 64
    assert carve._squashfs_size(sb, 0) == 100


def test_squashfs_size_refuses_a_bytes_used_past_the_image():
    sb = _squashfs_superblock(1 << 40) + b"\x00" * 64
    assert carve._squashfs_size(sb, 0) is None           # claims more than the buffer holds


def test_squashfs_size_rejects_non_squashfs():
    assert carve._squashfs_size(b"not a superblock" + b"\x00" * 80, 0) is None


def test_extract_filesystems_is_empty_without_a_filesystem():
    assert carve.extract_filesystems(b"\x00" * 8192) == []
    assert carve.extract_filesystems(b"") == []


def test_extract_filesystems_degrades_when_no_extractor_is_installed(monkeypatch):
    """No unsquashfs on PATH must mean an empty result, never a crash -- the optional tool is a
    capability, not a dependency."""
    monkeypatch.setattr(carve.shutil, "which", lambda _name: None)
    img = _squashfs_superblock(96) + b"\x00" * 64
    assert carve.extract_filesystems(img) == []


def _newc_cpio(entries: list[tuple[str, bytes]]) -> bytes:
    """A newc-format cpio archive of (name, data) pairs, built by hand so the test needs no tool
    to CREATE the archive -- only `cpio` to extract it."""
    def field(v):
        return b"%08x" % v

    def entry(name: str, data: bytes) -> bytes:
        name_b = name.encode() + b"\x00"
        hdr = (b"070701" + field(0) + field(0o100644) + field(0) + field(0) + field(1)
               + field(0) + field(len(data)) + field(0) + field(0) + field(0) + field(0)
               + field(len(name_b)) + field(0))
        buf = bytearray(hdr + name_b)
        while len(buf) % 4:
            buf += b"\x00"
        buf += data
        while len(buf) % 4:
            buf += b"\x00"
        return bytes(buf)

    out = b"".join(entry(n, d) for n, d in entries)
    trailer = (b"070701" + field(0) * 7 + field(1) + field(0) * 3 + field(len(b"TRAILER!!!\x00"))
               + field(0) + b"TRAILER!!!\x00")
    out += trailer
    buf = bytearray(out)
    while len(buf) % 512:
        buf += b"\x00"
    return bytes(buf)


@pytest.mark.skipif(not __import__("shutil").which("cpio"), reason="cpio not installed")
def test_a_cpio_rootfs_is_unpacked_and_its_elf_is_an_elf_component():
    """The end the fix exists for: a filesystem container whose binaries are only reachable by
    actually unpacking it. The ELF file must come back tagged kind='elf' so the stage registers
    it as a sub-target; a config file comes back as kind='file' for secret scanning."""
    elf = _elf64(0x40)
    archive = _newc_cpio([("bin/app", elf), ("etc/app.conf", b"api_key=AKIAIOSFODNN7EXAMPLE1\n")])
    files = carve.extract_filesystems(archive)
    by_path = {f["path"]: f for f in files}
    assert "bin/app" in by_path and by_path["bin/app"]["kind"] == "elf"
    assert by_path["bin/app"]["bytes"] == elf, "the unpacked ELF is not byte-identical"
    assert "etc/app.conf" in by_path and by_path["etc/app.conf"]["kind"] == "file"
