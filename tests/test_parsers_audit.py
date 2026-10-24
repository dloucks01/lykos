"""Audit regressions: format parsers on hostile input, jar inflate budget, confined source builds."""
import io
import os
import shutil
import struct
import subprocess
import time
import zipfile

import pytest
from lykos.analyze import dotnet, jvm, macho, source_project, wasm


# ---------------------------------------------------------------- dotnet
def _pe_header_only(n_dirs=16):
    d = bytearray(0x200)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3C, 0x80)
    d[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", d, 0x84, 0x8664, 0, 0, 0, 0, 240, 0x22)
    opt = 0x84 + 20
    struct.pack_into("<H", d, opt, 0x20B)
    struct.pack_into("<I", d, opt + 108, n_dirs)
    return bytes(d), opt


def test_dotnet_parse_on_a_pe_truncated_inside_the_directories_does_not_raise():
    d, opt = _pe_header_only()
    info = dotnet.parse(d[:opt + 112 + 14 * 8 + 4])
    assert not info.is_dotnet
    assert any("truncated" in e for e in info.errors)


def test_dotnet_rva_in_a_sections_zero_fill_tail_maps_to_nothing():
    secs = [(0x1000, 0x2000, 0x400, 0x200)]          # vsize 0x2000, only 0x200 raw bytes
    assert dotnet._rva_to_off(0x1100, secs) == 0x500
    assert dotnet._rva_to_off(0x1300, secs) is None


# ---------------------------------------------------------------- macho
def _nlist64(strx, ntype, value):
    return struct.pack("<IBBHQ", strx, ntype, 0, 0, value)


def _thin_with_symtab():
    """x86_64 MH_EXECUTE with an LC_SYMTAB: one import ___memcpy_chk, one import _strcpy,
    one export _main. Offsets are relative to the image start."""
    strtab = b"\0___memcpy_chk\0_strcpy\0_main\0"
    syms = (_nlist64(1, 0x01, 0) + _nlist64(15, 0x01, 0) + _nlist64(23, 0x0F, 0x100003f00))
    hdr_sz, lc_sz = 32, 24
    symoff = hdr_sz + lc_sz
    stroff = symoff + len(syms)
    lc = struct.pack("<IIIIII", 0x2, lc_sz, symoff, 3, stroff, len(strtab))
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, lc_sz, 0, 0)
    return hdr + lc + syms + strtab


def test_macho_strips_exactly_one_c_underscore():
    info = macho.parse(_thin_with_symtab())
    assert "__memcpy_chk" in info.imported_symbols
    assert "strcpy" in info.imported_symbols
    assert "main" in info.exported_symbols


def test_macho_fat_slice_symbols_are_read_relative_to_the_slice():
    thin = _thin_with_symtab()
    slice_off = 0x1000
    fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iiIII", 0x01000007, 3, slice_off,
                                                          len(thin), 12)
    fat = fat + b"\0" * (slice_off - len(fat)) + thin
    info = macho.parse(fat)
    assert info.fat
    assert "strcpy" in info.imported_symbols
    assert "main" in info.exported_symbols


# ---------------------------------------------------------------- wasm
def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def test_wasm_overlong_export_name_does_not_desync_the_section():
    long_name = b"A" * 5000
    entries = (_uleb(len(long_name)) + long_name + b"\x00" + _uleb(0)
               + _uleb(4) + b"main" + b"\x00" + _uleb(1))
    body = _uleb(2) + entries
    mod = b"\x00asm" + struct.pack("<I", 1) + b"\x07" + _uleb(len(body)) + body
    info = wasm.parse(mod)
    assert info.exports_count == 2
    assert info.exported_symbols[1].startswith("main ")


# ---------------------------------------------------------------- jvm
def test_jar_total_inflate_is_budgeted(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(20):
            z.writestr(f"p/C{i}.class", b"\xca\xfe\xba\xbe" + b"\0" * (1 << 20))
    monkeypatch.setattr(jvm, "_MAX_TOTAL_BYTES", 3 << 20)
    info = jvm.parse(buf.getvalue())
    assert any("inflated past" in e for e in info.errors)


# ---------------------------------------------------------------- source builds
def test_build_command_timeout_kills_the_whole_process_group(tmp_path):
    marker = tmp_path / "survivor"
    script = f"(sleep 3; touch {marker}) & sleep 30"
    t = time.time()
    rc, out = source_project._run_group(["sh", "-c", script], cwd=tmp_path,
                                        env=dict(os.environ), timeout=1)
    assert rc != 0 and "timed out" in out
    assert time.time() - t < 15
    time.sleep(3.5)
    assert not marker.exists()                       # the backgrounded grandchild died too


def test_backgrounded_child_does_not_hold_a_finished_build_open(tmp_path):
    t = time.time()
    rc, out = source_project._run_group(["sh", "-c", "sleep 30 & echo done"], cwd=tmp_path,
                                        env=dict(os.environ), timeout=20)
    # `sh` exits at once; the sleeper holding the pipe is reaped after a short grace instead of
    # the call blocking for the full 20s budget
    assert rc == 0 and "done" in out
    assert time.time() - t < 8


def test_hostile_makefile_cannot_write_outside_its_tree(tmp_path):
    if not (shutil.which("make") and shutil.which("gcc") and shutil.which("bwrap")):
        pytest.skip("needs make, gcc and bwrap")
    from lykos.analyze.dynamic import sandbox
    if not sandbox._bwrap_usable():
        pytest.skip("bwrap unusable here")
    home_target = os.path.expanduser("~/.lykos_audit_pwned_probe")
    if os.path.exists(home_target):
        os.unlink(home_target)
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.c").write_text("int main(void){return 0;}\n")
    (proj / "Makefile").write_text(
        f"all:\n\t-echo pwned > {home_target}\n\t$(CC) $(CFLAGS) a.c -o prog $(LDFLAGS)\n")
    try:
        r = source_project.build_source_project(proj, timeout=120)
        assert r["ok"], r["log"]
        assert not os.path.exists(home_target)
    finally:
        if os.path.exists(home_target):
            os.unlink(home_target)
