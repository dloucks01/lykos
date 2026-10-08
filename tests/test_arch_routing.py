"""Choosing the emulator: an ELF's e_machine names a FAMILY, not a qemu binary.

`e_machine` is endianness-blind (a little-endian MIPS is still EM_MIPS) and word-size-blind
(EM_MIPS covers MIPS32 and MIPS64, EM_RISCV covers RV32 and RV64). The ELF CLASS and DATA bytes
carry the rest, so the emulator has to be chosen from all three.

The chain of special cases this replaced applied ENDIANNESS to mips/ppc64 and BITS to
riscv/sparc, and the families needing the other axis were simply missed:

  * every MIPS64 target was handed a 32-bit emulator, and since `elf._MACHINES` emits "mips" for
    both ELF classes, `bits` was the ONLY route to qemu-mips64el -- so both 64-bit MIPS emulators
    were unreachable by any code path;
  * a big-endian ARM or SH target was handed the little-endian emulator, with qemu-armeb and
    qemu-sh4eb installed.

Why it survived: the gate's cross-arch cases are aarch64, arm32 HF (LE), ppc64le, riscv64 and
s390x -- exactly the ones that need no discriminator or hit a branch that was implemented. There
was no MIPS case. These tests are pure functions over the two tables, so they need no cross
toolchain and no emulator; `mips64el_overflow` covers the end-to-end run where a toolchain exists.
"""
import struct

import pytest
from lykos.analyze import elf
from lykos.analyze.dynamic.sandbox import _QEMU, _qemu_suffix


def _suf(arch, endian=None, bits=None):
    return _qemu_suffix(arch, endian, bits)


# ---- the axis each family actually needs --------------------------------------------------

@pytest.mark.parametrize("endian,bits,want", [
    ("little", 32, "mipsel"), ("big", 32, "mips"),
    ("little", 64, "mips64el"), ("big", 64, "mips64"),
])
def test_mips_needs_both_endianness_and_word_size(endian, bits, want):
    """The family where BOTH axes matter, and the one that was wrong."""
    assert _suf("mips", endian, bits) == want


@pytest.mark.parametrize("endian,want", [("big", "armeb"), ("little", "arm")])
def test_arm_needs_endianness(endian, want):
    assert _suf("arm", endian, 32) == want


@pytest.mark.parametrize("endian,want", [("big", "sh4eb"), ("little", "sh4")])
def test_sh_needs_endianness(endian, want):
    assert _suf("sh", endian, 32) == want


@pytest.mark.parametrize("bits,want", [(32, "riscv32"), (64, "riscv64")])
def test_riscv_needs_word_size(bits, want):
    assert _suf("riscv", "little", bits) == want


@pytest.mark.parametrize("endian,want", [("little", "ppc64le"), ("big", "ppc64")])
def test_ppc64_needs_endianness(endian, want):
    assert _suf("ppc64", endian, 64) == want


@pytest.mark.parametrize("bits,want", [(32, "sparc"), (64, "sparc64")])
def test_sparc_needs_word_size(bits, want):
    assert _suf("sparc", "big", bits) == want


@pytest.mark.parametrize("arch", ["aarch64", "s390", "x86-64", "x86", "m68k", "loongarch"])
def test_a_family_with_one_variant_is_unaffected_by_either_axis(arch):
    """m68k is always big-endian, aarch64 always little; asking for the other must not invent a
    second emulator name."""
    answers = {_suf(arch, e, b) for e in ("little", "big", None) for b in (32, 64, None)}
    assert len(answers) == 1, answers
    assert answers.pop() == _QEMU[arch]


def test_no_variant_resolves_to_a_bare_family_name_where_a_variant_exists():
    """The specific regression: `mips` + 64 bits must NOT fall through to the 32-bit default."""
    assert _suf("mips", "little", 64) != _QEMU["mips"]
    assert _suf("arm", "big", 32) != _QEMU["arm"]
    assert _suf("sh", "big", 32) != _QEMU["sh"]


# ---- the two tables have to agree ---------------------------------------------------------

def test_every_arch_the_elf_parser_emits_can_be_routed():
    """A name the parser produces that the router does not know is a silent `unsupported-arch`."""
    produced = {v for v in elf._MACHINES.values() if v}
    unroutable = sorted(a for a in produced if _suf(a, "little", 64) is None)
    assert not unroutable, unroutable


def test_the_four_added_architectures_are_wired_in_both_tables():
    """Their qemu-user binaries ship on a stock host; only these two tables kept them
    unsupported end-to-end. xtensa is the ESP32, which the firmware path meets in the wild."""
    for em, name in ((0x5E, "xtensa"), (0xBD, "microblaze"), (0x0F, "hppa"), (0x9026, "alpha")):
        assert elf._MACHINES[em] == name
        assert _suf(name, "little", 32), name


# ---- end to end through the parser -------------------------------------------------------

def _elf_header(bits, endian, machine):
    ei_class, ei_data = (2 if bits == 64 else 1), (1 if endian == "little" else 2)
    e = "<" if endian == "little" else ">"
    h = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    if bits == 64:
        h += struct.pack(e + "HHIQQQIHHHHHH", 2, machine, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64,
                         0, 0)
    else:
        h += struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0x8048000, 52, 0, 0, 52, 32, 1, 40,
                         0, 0)
    return h + b"\x00" * 256


@pytest.mark.parametrize("machine,bits,endian,want", [
    (0x08, 64, "little", "mips64el"),     # EM_MIPS, ELFCLASS64 -> the 64-bit emulator
    (0x08, 64, "big", "mips64"),
    (0x08, 32, "little", "mipsel"),
    (0x08, 32, "big", "mips"),
    (0x28, 32, "big", "armeb"),           # EM_ARM, big-endian
    (0x2A, 32, "big", "sh4eb"),           # EM_SH, big-endian
])
def test_a_crafted_elf_header_routes_to_the_right_emulator(machine, bits, endian, want):
    """Through the real parser, because the bug needed BOTH halves: the parser collapses MIPS32
    and MIPS64 to one name, and the router then has to use `bits`."""
    info = elf.parse(_elf_header(bits, endian, machine))
    assert _suf(info.arch, info.endianness, info.bits) == want


def test_the_parser_really_does_collapse_mips32_and_mips64():
    """Stated as a test because it is WHY `bits` is load-bearing here: if the parser emitted
    "mips64" the router could key on the name alone."""
    a32 = elf.parse(_elf_header(32, "little", 0x08))
    a64 = elf.parse(_elf_header(64, "little", 0x08))
    assert a32.arch == a64.arch == "mips"
    assert (a32.bits, a64.bits) == (32, 64)


# ---- runtime comparison tokens ------------------------------------------------------------
#
# `fuzz.cmpdict` mines input-to-state tokens from the recovered IR, so it sees only comparisons
# whose operand is a constant IN THE CODE. A magic value that is COMPUTED -- a decoded header, a
# checksum, a token read from a config or the environment -- exists only at runtime, and that is
# the gate a blind campaign never gets past. libtokencap reports exactly those, which is why it
# was built; `memoracle.tokencap_lib` resolved it and nothing ever called it.

_GATE_SRC = """#include <stdio.h>
#include <string.h>
int main(void){ char b[64];
  if(!fgets(b,sizeof b,stdin)) return 0;
  if(!strncmp(b,"SUPERSECRET",11)) puts("gate passed"); else puts("nope");
  return 0; }
"""


def test_the_token_file_parser_handles_afl_dictionary_escaping():
    from lykos.analyze.dynamic.memoracle import parse_token_file
    toks = parse_token_file(b'"MAGIC"\n"\\x7fELF"\nkey="ab"\n"x"\n"' + b"A" * 80 + b'"\n')
    assert b"MAGIC" in toks
    assert b"\x7fELF" in toks, "a byte escape must be decoded, not kept literal"
    assert b"ab" in toks, "libtokencap also emits `name=\"tok\"` lines"
    assert not any(len(t) < 2 for t in toks), "a one-byte token is noise in a dictionary"
    assert not any(len(t) > 64 for t in toks), "a whole buffer is not a magic value"


def test_longer_tokens_come_first():
    """A mutator that inserts the whole magic value passes the gate in one step; a prefix only
    gets past the first byte of the comparison."""
    from lykos.analyze.dynamic.memoracle import parse_token_file
    toks = parse_token_file(b'"ab"\n"abcdef"\n"abcd"\n')
    assert toks == sorted(toks, key=len, reverse=True)


def test_duplicate_tokens_collapse():
    from lykos.analyze.dynamic.memoracle import parse_token_file
    assert parse_token_file(b'"MAGIC"\n"MAGIC"\n"MAGIC"\n') == [b"MAGIC"]


def test_a_computed_comparison_value_is_recovered_at_runtime(tmp_path):
    """The capability that existed and was never called, end to end."""
    import shutil as _sh
    import subprocess as _sp

    from lykos.analyze.dynamic import memoracle
    if memoracle.tokencap_lib() is None:
        pytest.skip("libtokencap not installed")
    cc = _sh.which("gcc") or _sh.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    src = tmp_path / "gate.c"
    src.write_text(_GATE_SRC)
    exe = tmp_path / "gate"
    assert _sp.run([cc, "-O0", "-w", "-o", str(exe), str(src)],
                   capture_output=True).returncode == 0
    toks = memoracle.runtime_tokens(exe, b"AAAA\n", mode="stdin",
                                    host_arch="x86-64", target_arch="x86-64")
    assert b"SUPERSECRET" in toks, toks


def test_a_cross_arch_target_gets_no_tokens_rather_than_a_broken_preload():
    """LD_PRELOAD injects into the loader of a process of the SAME architecture, so a guest under
    qemu would reject the object. Decline instead of preloading something incompatible."""
    from lykos.analyze.dynamic import memoracle
    assert memoracle.runtime_tokens("/bin/true", b"", host_arch="x86-64",
                                    target_arch="aarch64") == []


# ---- partial information ------------------------------------------------------------------
#
# The regression my own tests missed, and an existing one caught: every case above passes BOTH
# axes, but callers do not always know both. `sandbox.run(arch=...)` may be given an arch with no
# endianness or bits at all, and the first version of the table silently fell through to the
# family default -- which for MIPS is the BIG-endian 32-bit emulator, so a little-endian MIPS
# target regressed to the wrong one.

@pytest.mark.parametrize("endian,want", [("little", "mipsel"), ("big", "mips")])
def test_mips_with_unknown_word_size_still_gets_the_right_endianness(endian, want):
    assert _suf("mips", endian, None) == want


@pytest.mark.parametrize("bits,want", [(32, "mips"), (64, "mips64")])
def test_mips_with_unknown_endianness_still_honours_a_known_word_size(bits, want):
    assert _suf("mips", None, bits) == want


def test_no_information_at_all_falls_back_to_the_family_default():
    """Not a guess dressed up as knowledge: with neither axis the family default is the only
    honest answer, and it is what this always did."""
    for arch in ("mips", "arm", "sh", "riscv", "sparc", "ppc64"):
        assert _suf(arch, None, None) == _QEMU[arch]


@pytest.mark.parametrize("arch,endian,bits", [
    ("riscv", None, None), ("sparc", None, None), ("ppc64", None, None),
    ("arm", None, 32), ("sh", None, 64),
])
def test_partial_information_never_returns_None_for_a_known_family(arch, endian, bits):
    """Returning None here would be reported as `unsupported-arch` for an architecture that is
    perfectly supported."""
    assert _suf(arch, endian, bits)
