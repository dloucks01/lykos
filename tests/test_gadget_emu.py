"""Semantic (emulation-based) gadget discovery -- gadget_emu.find_reg_control_gadgets.

The pattern-matching finders recognise textbook gadget shapes by byte decode; this engine EMULATES
short instruction windows ending in a return and records each register's real effect (zeroed /
loaded from the attacker stack / cleanly copied from another GPR), so it finds register-control
gadgets the matchers miss -- notably the argument-register control (a1 <- a loader-controlled reg,
a1 <- x0 == 0) that reads as 'gadget-blocked' to the pattern finders and is the cross-arch
execve-syscall ceiling. Optional: skips where Unicorn/Capstone (or the riscv assembler) are absent.

Gadgets are ASSEMBLED with the real cross `as` so the test asserts the engine against known-correct
machine code, not hand-encoded bytes."""
import shutil
import subprocess

import pytest
from lykos.analyze.poc import gadget_emu as ge

_AS = shutil.which("riscv64-linux-gnu-as")
_OC = shutil.which("riscv64-linux-gnu-objcopy")


def test_available_is_bool():
    """available() is callable and truthy/falsey under a stdlib-only import (no hard dependency)."""
    assert isinstance(ge.available(), bool)
    assert ge.arch_supported("riscv64") and not ge.arch_supported("sparc64")


def _asm(src, tmp_path):
    o, b = tmp_path / "g.o", tmp_path / "g.bin"
    subprocess.run([_AS, "-o", str(o), "-"], input=src.encode(), check=True)
    subprocess.run([_OC, "-O", "binary", "-j", ".text", str(o), str(b)], check=True)
    return b.read_bytes()


@pytest.mark.skipif(not ge.available(), reason="needs unicorn + capstone")
@pytest.mark.skipif(not (_AS and _OC), reason="needs riscv64-linux-gnu-as/objcopy")
@pytest.mark.parametrize("src,want,expect", [
    ("ld a1,16(sp)\n ret\n", ("a1",), {"a1": "stack@16"}),            # loaded from the overflow
    ("li a1,0\n ret\n", ("a1",), {"a1": "zero"}),                     # zeroed
    ("mv a1,a3\n ret\n", ("a1",), {"a1": "reg:x13"}),                 # copied from a3 (x13)
    ("li a2,0\n ld a1,8(sp)\n ret\n", ("a1", "a2"), {"a1": "stack@8", "a2": "zero"}),
    # a realistic chainable epilogue: ra is RESTORED from the stack, yet the effect is still read
    # (the ret-hook stops before the return, so the gadget is not rejected for not ending at a fixed
    # address).
    ("ld a1,24(sp)\n ld ra,40(sp)\n addi sp,sp,48\n ret\n", ("a1",), {"a1": "stack@24"}),
])
def test_classifies_known_gadget(tmp_path, src, want, expect):
    g = ge.find_reg_control_gadgets(_asm(src, tmp_path), "riscv64", want=want)
    assert g and g[0]["effects"] == expect, f"{src!r} -> {g}"


@pytest.mark.skipif(not ge.available(), reason="needs unicorn + capstone")
@pytest.mark.skipif(not (_AS and _OC), reason="needs riscv64-linux-gnu-as/objcopy")
def test_unchanged_register_is_not_reported(tmp_path):
    """A register the gadget leaves alone (its own input survives) is NOT control -- only registers
    the gadget actually sets are returned."""
    g = ge.find_reg_control_gadgets(_asm("mv a0,a3\n ret\n", tmp_path), "riscv64", want=("a1",))
    assert g == [] or all("a1" not in x["effects"] for x in g)       # a1 untouched -> not reported


@pytest.mark.skipif(not ge.available(), reason="needs unicorn + capstone")
@pytest.mark.skipif(not (_AS and _OC), reason="needs riscv64-linux-gnu-as/objcopy")
def test_multiple_rets_in_one_blob(tmp_path):
    """Several ret-terminated gadgets back to back are each discovered (the scan walks the whole
    instruction stream, not just the final return)."""
    blob = _asm("li a1,0\n ret\n ld a2,8(sp)\n ret\n", tmp_path)
    g = ge.find_reg_control_gadgets(blob, "riscv64", want=("a1", "a2"))
    kinds = {v for x in g for v in x["effects"].values()}
    assert "zero" in kinds and any(e.startswith("stack@") for e in kinds)
