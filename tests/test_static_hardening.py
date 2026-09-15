"""Regressions for the static-analysis/ingest hardening audit:

  1. crafted-header ELF entropy DoS is capped (elf.py)
  2. a bare-metal / carvable firmware blob is triaged as firmware, not "not a binary"
     (triage.py)
  3. an invalid ELF ident is rejected instead of parsed with a guessed layout (elf.py)
  4. a truncated PE optional header does not NameError-then-look-clean (pe.py)
"""
from __future__ import annotations

import gzip
import struct
import time

from lykos.analyze import elf as elfmod
from lykos.analyze import pe as pemod
from lykos.analyze.triage import build_triage, validate
from lykos.hashing import hash_all_file

# ---- helpers ----------------------------------------------------------------------------

def _elf64_with_sections(n_sections, *, sh_size, file_pad, shnum=None,
                         sh_type=elfmod.SHT_PROGBITS):
    """A minimal 64-bit little-endian x86-64 ELF whose section header table declares
    `n_sections` PROGBITS sections all pointing at offset 0 with `sh_size` bytes."""
    e_shoff = 64
    sh_ent = 64
    shnum = n_sections if shnum is None else shnum
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9          # e_ident (64-bit, little)
    hdr += struct.pack("<HHIQQQIHHHHHH",
                       2, 0x3E, 1, 0, 0, e_shoff, 0, 64,
                       0, 0,          # phentsize, phnum
                       sh_ent, shnum, 0)                       # shentsize, shnum, shstrndx
    sh_table = b""
    for _ in range(n_sections):
        sh_table += struct.pack("<IIQQQQIIQQ",
                                0, sh_type, 0, 0, 0, sh_size, 0, 0, 0, 0)
    body = hdr + sh_table
    return body + b"\xab" * file_pad


def _triage_bytes(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    rec = build_triage(p, hash_all_file(p), name)
    assert validate(rec) == [], rec.get("parse_errors")
    return rec


# ---- finding 1: entropy DoS cap ---------------------------------------------------------

def test_elf_entropy_scan_is_capped_by_section_count():
    # 400 PROGBITS sections each claiming 2 MiB, in a small file: without the cap this is a
    # per-section byte loop run 400x. Assert at most 96 sections get a computed entropy.
    data = _elf64_with_sections(400, sh_size=2 << 20, file_pad=8192)
    t0 = time.monotonic()
    info = elfmod.parse(data)
    assert time.monotonic() - t0 < 5.0
    assert len(info.sections) == 400
    scored = [s for s in info.sections if s["entropy"] is not None]
    assert len(scored) <= 96


def test_elf_shnum_bounded_to_file_size():
    # e_shnum lies (65535) but the file holds only a handful of section headers.
    data = _elf64_with_sections(4, sh_size=16, file_pad=64, shnum=65535)
    info = elfmod.parse(data)
    # only the records the file can actually hold are parsed, and the lie is recorded
    assert len(info.sections) <= 5
    assert any("e_shnum" in e for e in info.errors)


def test_elf_entropy_dos_bytes_bounded(tmp_path):
    # end-to-end through triage (runs on every ingest): must return quickly.
    data = _elf64_with_sections(300, sh_size=2 << 20, file_pad=4 << 20)
    t0 = time.monotonic()
    rec = _triage_bytes(tmp_path, "bomb.elf", data)
    assert time.monotonic() - t0 < 10.0
    assert rec["file_type"] == "elf"


# ---- finding 3: invalid ELF ident -------------------------------------------------------

def test_elf_invalid_ei_class_is_rejected_not_guessed():
    data = bytearray(b"\x7fELF" + bytes([7, 1, 1]) + b"\x00" * 100)   # EI_CLASS=7 (invalid)
    info = elfmod.parse(bytes(data))
    assert info.arch is None                     # no arch guessed from a bad layout
    assert info.bits is None
    assert any("invalid ELF ident" in e for e in info.errors)


def test_elf_invalid_ei_data_is_rejected_not_guessed():
    data = bytearray(b"\x7fELF" + bytes([2, 9, 1]) + b"\x00" * 100)   # EI_DATA=9 (invalid)
    info = elfmod.parse(bytes(data))
    assert info.arch is None
    assert info.endianness is None
    assert any("invalid ELF ident" in e for e in info.errors)


# ---- finding 2: firmware fallback in triage --------------------------------------------

def _cortex_m_image(size=0x1000):
    base = 0x08000000
    words = [0x20005000, base + 0x101] + [base + 0x140 + i * 4 + 1 for i in range(12)]
    vt = b"".join(struct.pack("<I", w) for w in words)
    return vt + b"\x00" * (size - len(vt))


def test_headerless_firmware_is_triaged_as_firmware(tmp_path):
    rec = _triage_bytes(tmp_path, "fw.bin", _cortex_m_image())
    assert rec["file_type"] == "firmware"
    assert rec["analyzable"] is True
    assert rec["arch"] == "arm"
    assert "not a binary" not in (rec["detected"] or "").lower()
    assert "firmware" in (rec["detected"] or "").lower()


def test_embedded_component_blob_is_triaged_as_firmware(tmp_path):
    # a blob with no container magic at offset 0 but a gzip stream embedded at a nonzero offset
    blob = b"NOTMAGIC" + gzip.compress(b"payload" * 64) + b"\x00" * 16
    rec = _triage_bytes(tmp_path, "dump.bin", blob)
    assert rec["file_type"] == "firmware"
    assert rec["analyzable"] is True
    assert "firmware" in (rec["detected"] or "").lower()


def test_plain_text_is_still_not_a_binary(tmp_path):
    rec = _triage_bytes(tmp_path, "notes.txt", b"hello world\nthis is just text\n" * 8)
    assert rec["file_type"] in ("raw", "other")
    assert rec["analyzable"] is False
    assert "not a binary" in (rec["detected"] or "").lower()


# ---- finding 4: truncated PE optional header -------------------------------------------

def test_pe_truncated_optional_header_no_crash():
    # a valid MZ + PE signature + COFF header, but the file ends before the optional header.
    e_lfanew = 0x40
    dos = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", e_lfanew)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 3, 0, 0, 0, 0xE0, 0x22)
    data = dos + coff                                    # nothing after the COFF header
    info = pemod.parse(data)                             # must not raise
    assert info.imports.get("libraries", []) == []
    assert info.linking in (None, "static")
    # the fix: dir_off is None (not unbound), so imports returns cleanly rather than raising a
    # NameError that then gets recorded as if it were a real parse failure
    assert not any("NameError" in e for e in info.errors)
