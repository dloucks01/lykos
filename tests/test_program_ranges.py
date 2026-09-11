"""Which of a binary's code is the PROGRAM, and which came in with the linker?

A statically linked binary carries its libc, so the decompiler recovers every block of it:
jhead is 1,887 blocks dynamically linked and 38,418 statically. Counting the library as
coverage understates the program by twenty times -- and an input that wanders into a new printf
path scores as "novel" and takes a place in the corpus that a new parser branch should have had.

Every binary in the new architecture corpus is statically linked, because qemu-user then needs
no sysroot, so this is not an edge case there: it is all of them.
"""
import pathlib
import shutil
import subprocess
import textwrap

import pytest
from lykos.analyze.elf import program_ranges

# A `static` function is what anchors a source file in the symbol table: the linker groups
# LOCAL symbols under the STT_FILE symbol naming the object they came from, and globals are
# not grouped at all. Real C has statics -- four of jhead's eight files do -- but a file with
# none cannot be attributed, which is what the last test here pins down.
_MAIN = """
    #include <string.h>
    #include <stdio.h>
    static int width(const char *s) { return (int) strlen(s); }
    int helper(const char *s, char *out) { strcpy(out, s); return width(out); }
    int main(int argc, char **argv) {
        char buf[64];
        printf("%d\\n", helper(argc > 1 ? argv[1] : "x", buf));
        return 0;
    }
"""

_NO_STATICS = """
    #include <stdio.h>
    int main(void) { printf("hi\\n"); return 0; }
"""


def _build(tmp_path, *flags, source=None):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("no gcc to build a fixture with")
    src = tmp_path / "prog.c"
    src.write_text(textwrap.dedent(source or _MAIN))
    out = tmp_path / "prog"
    done = subprocess.run([gcc, "-O0", "-w", *flags, str(src), "-o", str(out)],
                          capture_output=True, timeout=120)
    if done.returncode != 0:
        pytest.skip(f"toolchain cannot build this fixture: {done.stderr[:120]!r}")
    return out


def _symbol(path, name):
    """Address of a function, straight from the symbol table (nm, not our own parser)."""
    if not shutil.which("nm"):
        pytest.skip("no nm")
    out = subprocess.run(["nm", str(path)], capture_output=True, text=True, timeout=60).stdout
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[2] == name and f[1] in "tTiI":
            return int(f[0], 16)
    return None


def _covered(ranges, addr):
    return any(lo <= addr < hi for lo, hi in ranges)


def test_the_program_is_separated_from_the_libc_linked_into_it(tmp_path):
    exe = _build(tmp_path, "-static")
    ranges = program_ranges(exe.read_bytes())
    assert ranges, "a static binary with symbols must be attributable"
    for own in ("main", "helper"):
        addr = _symbol(exe, own)
        assert addr and _covered(ranges, addr), f"{own} is the program's own code"
    # printf and friends came in from libc.a; whichever of them this libc exposes must be out
    library = [n for n in ("printf", "malloc", "qsort", "strtod", "fopen")
               if _symbol(exe, n) is not None]
    assert library, "expected a static libc to contribute some named functions"
    for name in library:
        assert not _covered(ranges, _symbol(exe, name)), f"{name} is not the program"


def test_a_stripped_binary_says_nothing_rather_than_something_wrong(tmp_path):
    """No symbols, no attribution. The caller must fall back to instrumenting everything --
    silently claiming the program is tiny would hide most of it from coverage."""
    exe = _build(tmp_path, "-static", "-s")
    assert program_ranges(exe.read_bytes()) == []


def test_ranges_are_in_the_elf_s_own_address_space(tmp_path):
    """They are compared against decompiler addresses, which on a PIE sit at a different image
    base. Getting the space wrong dropped every function in the binary -- gif2rgb went to zero
    blocks, not to fewer."""
    exe = _build(tmp_path, "-fPIE", "-pie")
    ranges = program_ranges(exe.read_bytes())
    if not ranges:
        pytest.skip("this toolchain leaves a PIE without usable local symbols")
    addr = _symbol(exe, "main")
    assert addr and _covered(ranges, addr)
    assert max(hi for _, hi in ranges) < 0x1000000, "a PIE's own vaddrs are small"


def test_nothing_is_claimed_for_a_binary_that_is_not_elf():
    assert program_ranges(b"MZ\x90\x00" + b"\x00" * 512) == []
    assert program_ranges(b"") == []


def test_a_file_with_no_local_symbols_cannot_be_attributed(tmp_path):
    """Attribution hangs on local symbols: the linker groups them under the file they came
    from, and a global is not grouped at all. A source file with no statics therefore anchors
    nothing -- and the answer must be "I don't know" (instrument everything), never "the
    program is the empty set"."""
    exe = _build(tmp_path, "-static", source=_NO_STATICS)
    assert program_ranges(exe.read_bytes()) == []


def test_a_thumb_symbol_does_not_shift_the_range(tmp_path):
    """ARM marks a Thumb function by setting bit 0 of its symbol value, while the code sits at
    the even address. Left in, every range starts one byte late and drops whichever function
    sits exactly on the edge -- on jhead's ARM build that was Put16u and process_DQT."""
    gcc = shutil.which("arm-linux-gnueabihf-gcc")
    if not gcc:
        pytest.skip("no ARM cross toolchain")
    src = tmp_path / "prog.c"
    src.write_text(textwrap.dedent(_MAIN))
    exe = tmp_path / "prog"
    done = subprocess.run([gcc, "-O0", "-w", "-static", str(src), "-o", str(exe)],
                          capture_output=True, timeout=180)
    if done.returncode != 0:
        pytest.skip("ARM toolchain cannot link statically here")
    ranges = program_ranges(exe.read_bytes())
    assert ranges
    assert all(lo % 2 == 0 for lo, _ in ranges), "a range must start on an even address"


def test_a_powerpc64_elfv1_binary_declines_rather_than_guessing():
    """There, a function symbol's value addresses its OPD descriptor, not its code, so every
    range derived would be in the wrong address space -- it produced 311 false positives."""
    from lykos.analyze import elf
    exe = pathlib.Path("examples/vuln-targets/bin/jhead_ppc64")
    if not exe.exists():
        pytest.skip("run examples/vuln-targets/fetch_build.sh for the ppc64 build")
    data = exe.read_bytes()
    assert any(s.get("name") == ".opd" for s in elf.parse(data).sections)
    assert elf.program_ranges(data) == []
