"""Win64 composed ROP: the PE executable-segment source that unblocks the semantic ROP solver.

`rop_solver.solve_reg_chain` and `gadget_emu` are format-agnostic and already map the Win64 ABI arg
registers (rcx/rdx/r8/r9), but they derive their gadget search segments from `rop._loads`, which
parses ELF PT_LOADs only -- so on a PE they get nothing and return gadget VAs at file offsets that
match no loaded address. `exploit_stage._pe_exec_segments` supplies the PE's executable sections
with ABSOLUTE vaddrs; these tests pin that this is the one enabling piece.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from lykos.analyze.poc import exploit_stage, rop_solver


def test_segments_let_the_solver_compose_a_chain_at_absolute_vaddrs():
    """With explicit segments the solver finds `pop rcx; ret` and emits an ABSOLUTE gadget VA inside
    the segment; with no segments (the ELF-only fallback) a non-ELF blob yields nothing."""
    if not rop_solver.gadget_emu.available():
        pytest.skip("gadget emulation engine unavailable")
    vaddr = 0x140001000
    pos = 32
    data = b"\x90" * pos + b"\x59\xc3" + b"\x90" * 64     # pop rcx ; ret  at a known offset
    segs = [(0, len(data), vaddr)]
    sol = rop_solver.solve_reg_chain(data, "x86-64", sets={"rcx": 0xDEADBEEF},
                                     final_va=0x140002000, offset=16, segments=segs)
    assert sol is not None, "a clean `pop rcx; ret` must compose when the segment is given"
    gva = sol["chain"][0][0]
    assert vaddr <= gva < vaddr + len(data), "the gadget VA must be absolute (segment-relative)"
    assert gva == vaddr + pos
    assert sol["final"] == 0x140002000               # the final ret transfers to the sink
    # Without segments: rop._loads finds no ELF PT_LOAD in this blob, so the engine scans the whole
    # file at vaddr 0 and returns the gadget at its FILE OFFSET (32) -- an address that matches no
    # loaded PE section. That wrong-VA chain is exactly what passing _pe_exec_segments prevents.
    nos = rop_solver.solve_reg_chain(data, "x86-64", sets={"rcx": 1}, final_va=0x140002000,
                                     offset=16, segments=None)
    assert nos is not None and nos["chain"][0][0] == pos      # file offset, NOT the loaded vaddr
    assert nos["chain"][0][0] != gva                          # different from the absolute-VA chain


def _build_pe(tmp_path):
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        pytest.skip("no mingw cross compiler")
    src = tmp_path / "t.c"
    src.write_text('int main(int c,char**v){char b[32];__builtin_strcpy(b,v[1]);return b[0];}\n')
    out = tmp_path / "t.exe"
    if subprocess.run([cc, "-O0", "-w", str(src), "-o", str(out)],
                      capture_output=True, timeout=180).returncode != 0:
        pytest.skip("mingw cannot link here")
    return out.read_bytes()


def test_pe_exec_segments_are_absolute_and_executable(tmp_path):
    data = _build_pe(tmp_path)
    segs = exploit_stage._pe_exec_segments(data)
    assert segs, "a PE with a .text section must yield at least one executable segment"
    from lykos.analyze.pe import parse as pe_parse
    info = pe_parse(data)
    for off, size, vaddr in segs:
        assert size > 0 and off + size <= len(data)
        assert vaddr >= info.image_base             # absolute (image_base + RVA), not a file offset
    # a non-PE yields None rather than raising
    assert exploit_stage._pe_exec_segments(b"not a pe") is None
    assert exploit_stage._pe_exec_segments(b"\x7fELF" + b"\x00" * 128) is None


def test_the_solver_composes_a_win64_rcx_chain_on_a_real_pe(tmp_path):
    """End-to-end on a real mingw PE: with _pe_exec_segments the solver can set rcx from a gadget in
    the image (the register-setting half of the Win64 command-exec chain). Skips honestly if the
    particular image has no clean rcx setter -- the point proven is the segment source, not that
    every binary is exploitable."""
    if not rop_solver.gadget_emu.available():
        pytest.skip("gadget emulation engine unavailable")
    data = _build_pe(tmp_path)
    segs = exploit_stage._pe_exec_segments(data)
    assert segs
    sol = rop_solver.solve_reg_chain(data, "x86-64", sets={"rcx": 0x1000},
                                     final_va=segs[0][2], offset=64, segments=segs)
    if sol is None:
        pytest.skip("this image has no clean `pop rcx`-style setter (segment source still proven)")
    gva = sol["chain"][0][0]
    assert any(v <= gva < v + s for (o, s, v) in segs), "gadget VA lies in an executable segment"
