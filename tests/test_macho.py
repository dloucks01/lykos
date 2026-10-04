"""Mach-O header parsing (macOS / iOS). A synthetic thin binary pins the header/flag/load-command
decode deterministically; real dylibs on the host (when present) prove it on true compiler output;
and the triage route proves a Mach-O now parses to an analyzable record instead of "detected only"."""
import struct
from pathlib import Path

import pytest
from lykos.analyze import macho

# load-command / flag constants mirrored from the parser so the test states its own expectations
_LC_SEGMENT_64, _LC_LOAD_DYLIB, _LC_MAIN = 0x19, 0xC, (0x28 | 0x80000000)
_MH_PIE, _MH_DYLDLINK = 0x200000, 0x4


def _synth_thin_macho():
    """A minimal 64-bit little-endian x86_64 MH_EXECUTE with one __TEXT segment, a linked dylib and
    LC_MAIN, PIE + dyldlink flags set. Built byte-exact so the decode is checkable without a mac."""
    def lc_segment_text():
        body = struct.pack("<16s", b"__TEXT")
        body += struct.pack("<QQQQ", 0x100000000, 0x1000, 0, 0x1000)   # vmaddr,vmsize,fileoff,filesize
        body += struct.pack("<iiII", 0x5, 0x5, 0, 0)                   # maxprot,initprot(r-x),nsects,flags
        return struct.pack("<II", _LC_SEGMENT_64, 8 + len(body)) + body

    def lc_load_dylib(name):
        raw = name.encode() + b"\x00"
        raw += b"\x00" * (-(len(raw) + 24) % 8)                        # pad whole command to 8
        head = struct.pack("<IIIIII", _LC_LOAD_DYLIB, 24 + len(raw), 24, 0, 0x10000, 0x10000)
        return head + raw

    def lc_main():
        return struct.pack("<IIQQ", _LC_MAIN, 24, 0x3a40, 0)           # entryoff, stacksize

    cmds = lc_segment_text() + lc_load_dylib("/usr/lib/libSystem.B.dylib") + lc_main()
    ncmds, szcmds = 3, len(cmds)
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, ncmds, szcmds,
                      _MH_PIE | _MH_DYLDLINK, 0)
    return hdr + cmds


def test_synthetic_thin_macho_decode():
    i = macho.parse(_synth_thin_macho())
    assert not i.errors
    assert i.arch == "x86-64" and i.bits == 64 and i.endianness == "little"
    assert i.macho_type == "executable" and not i.fat
    assert i.linking == "dynamic" and "libSystem.B.dylib" in i.imports["libraries"]
    assert i.entry == 0x3a40                              # LC_MAIN entryoff
    assert i.mitigations["pie"] == "on" and i.mitigations["nx"] == "on"
    txt = [s for s in i.sections if s["name"] == "__TEXT"]
    assert txt and txt[0]["exec"] is True


def test_rejects_non_macho():
    assert macho.parse(b"\x7fELF" + b"\x00" * 60).errors        # an ELF is not a Mach-O
    assert macho.parse(b"xx").errors                            # too short


def test_filetype_routes_fat64_universal_to_macho():
    # fat/universal Mach-O with 64-bit offsets (FAT_MAGIC_64 / FAT_CIGAM_64) must route to the
    # Mach-O parser, not fall through to "other" (macho.parse already handles these slices).
    from lykos.analyze import filetype
    assert filetype.detect(b"\xca\xfe\xba\xbf" + b"\x00" * 60) == "macho"   # fat64 big-endian
    assert filetype.detect(b"\xbf\xba\xfe\xca" + b"\x00" * 60) == "macho"   # fat64 little-endian
    # the Java class CAFEBABE (identical to fat32 magic) must still resolve to CLASS, not Mach-O
    assert filetype.detect(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 56) == "class"


def test_bits_and_arch_mapping():
    # arm64 sets the 64-bit ABI bit even though we pass bits from the magic
    aname, abits = macho._arch_name(0x0100000C, 64)
    assert aname == "aarch64" and abits == 64
    assert macho._arch_name(12, 32) == ("arm", 32)
    assert macho._arch_name(7, 32) == ("x86", 32)
    assert macho._arch_name(0x01000007, 64) == ("x86-64", 64)


_REAL = next((p for p in [
    "/usr/share/powershell-empire/empire/server/data/misc/templateLauncher64.dylib",
] if Path(p).exists()), None)


@pytest.mark.skipif(not _REAL, reason="no real Mach-O dylib on host")
def test_real_dylib_parses_cleanly():
    i = macho.parse(Path(_REAL).read_bytes())
    assert not i.errors
    assert i.arch in ("x86-64", "aarch64", "arm", "x86")
    assert i.macho_type in ("dylib", "executable", "bundle")
    assert i.imports["libraries"]                         # a real dylib links at least libSystem
    # the launcher is built with stack protection -> the canary symbols are visible
    assert i.mitigations["canary"] == "on"


def test_triage_routes_macho_to_analyzable(tmp_path):
    from lykos.analyze import triage
    p = tmp_path / "x.macho"
    p.write_bytes(_synth_thin_macho())
    rec = triage.build_triage(p, {"sha256": "0" * 64, "size": p.stat().st_size}, "x.macho")
    assert rec["file_type"] == "macho"
    assert rec["analyzable"] is True
    assert rec["arch"] == "x86-64"
    assert rec["mitigations"]["pie"] == "on"
    assert "Mach-O analysed" in (rec.get("advisory") or "")
