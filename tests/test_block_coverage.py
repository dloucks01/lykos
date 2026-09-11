"""Does the campaign know where the program went, or only what it printed?

The coverage proxy was the SHAPE of the program's output. That notices a parser printing
something new; it does not notice a parser taking a branch it has never taken. On jhead it saw
a few thousand distinct "behaviours" where the binary has 1,887 basic blocks -- a signal
loosely correlated with coverage rather than a measure of it.

The decompiler already walked the binary, so its block list is instrumentation we have paid
for. Breakpoints are one-shot and the campaign only ever arms blocks it has not reached, so
the cost decays as coverage saturates -- and "did this input reach anywhere new?" is exactly
the question a fuzzer needs answered.
"""
import struct

import pytest
from lykos.analyze.fuzz import batch_runner


def _elf(pie: bool, load_vaddr: int) -> bytes:
    """A 64-bit ELF header with one PT_LOAD at `load_vaddr`."""
    e = bytearray(4096)
    e[0:4] = b"\x7fELF"
    e[4] = 2                                            # ELFCLASS64
    phoff = 0x40
    struct.pack_into("<Q", e, 0x20, phoff)
    struct.pack_into("<HH", e, 0x36, 56, 1)             # phentsize, phnum
    struct.pack_into("<I", e, phoff, 1)                 # PT_LOAD
    struct.pack_into("<Q", e, phoff + 0x10, load_vaddr)
    return bytes(e)


def test_a_fixed_image_reports_its_load_address(tmp_path):
    """A non-PIE binary is placed exactly where it asks, so a file vaddr IS a runtime one."""
    p = tmp_path / "nopie"
    p.write_bytes(_elf(False, 0x400000))
    assert batch_runner._elf_min_vaddr(str(p)) == 0x400000


def test_a_position_independent_image_reports_zero(tmp_path):
    """PIE asks for 0 and the loader picks the address, so every block needs the runtime base
    added. Getting this backwards arms breakpoints at addresses that are not code."""
    p = tmp_path / "pie"
    p.write_bytes(_elf(True, 0))
    assert batch_runner._elf_min_vaddr(str(p)) == 0


def test_a_non_elf_is_not_guessed_at(tmp_path):
    p = tmp_path / "nope"
    p.write_bytes(b"MZ" + b"\x00" * 200)
    assert batch_runner._elf_min_vaddr(str(p)) == 0


def test_a_missing_file_does_not_raise():
    assert batch_runner._elf_min_vaddr("/nonexistent/at/all") == 0


# ---------------------------------------------------------------- end to end
def test_coverage_is_recorded_only_when_blocks_are_asked_for(tmp_path, gcc):
    """The plumbing: no block list means no tracing cost and no coverage; a block list means
    the runner traces the child and reports what it reached.

    Deliberately NOT asserting which blocks: a real block list comes from the decompiler, and
    a synthetic one (every Nth address) is not block boundaries -- arming those would prove
    something about arithmetic rather than about coverage. The discriminating property is
    measured on real targets instead: jhead reaches 378 of 1,887 recovered blocks, ncompress
    83-148 of 433 depending on the input channel.
    """
    import subprocess

    from lykos.analyze.dynamic import sandbox
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\nint main(void){ char b[64];'
                   ' if(!fgets(b,sizeof b,stdin)) return 1; puts(b); return 0; }\n')
    exe = tmp_path / "t"
    subprocess.run([gcc, "-O0", str(src), "-o", str(exe)], check=True)

    plain = sandbox.run_batch(exe, [b"hi\n"], mode="stdin", timeout=5.0)
    if plain is None:
        pytest.skip("batched sandbox unavailable here")
    assert plain[0].note is None, "no block list asked for, so nothing to report"

    entry = batch_runner._elf_min_vaddr(str(exe))
    assert isinstance(entry, int), "the address contract must resolve for a real binary"
    traced = sandbox.run_batch(exe, [b"hi\n"], mode="stdin", timeout=5.0,
                               blocks=[0x1000, 0x1040, 0x1080])
    assert traced is not None and traced[0].exit_code == 0, "tracing must not break the run"
