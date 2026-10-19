"""Unit tests for the cross-arch ret2libc model (poc/archmodel.py) -- the pure data + packing.

The end-to-end driver behaviour is exercised by tests/test_ret2libc_cross.py (which builds real
cross-arch fixtures and drives them under qemu); here we only pin the ABI table and the address
packer, which need no qemu and must stay exactly right for every arch that folds through the
driver."""
from __future__ import annotations

from lykos.analyze.poc import archmodel


def test_registry_covers_the_shipped_arches():
    assert set(archmodel.MODELS) == {"aarch64", "arm", "riscv64", "ppc64", "loongarch", "s390"}


def test_s390_is_big_endian_with_r2_arg():
    m = archmodel.model_for("s390")
    assert m is archmodel.model_for("s390x") and m.endian == "big" and m.arg0_reg == "r2"
    assert m.slug == "s390x-ret2libc"
    assert m.pack(0x1000f04) == b"\x00\x00\x00\x00\x01\x00\x0f\x04"      # big-endian address


def test_model_for_resolves_aliases():
    # the aliases mirror the arch gates in exploit_stage: arm64->aarch64, riscv->riscv64,
    # ppc64le/powerpc64->ppc64, loongarch64->loongarch.
    assert archmodel.model_for("aarch64").slug == "aarch64-ret2libc"
    assert archmodel.model_for("arm64") is archmodel.MODELS["aarch64"]
    assert archmodel.model_for("riscv") is archmodel.MODELS["riscv64"]
    assert archmodel.model_for("ppc64le") is archmodel.MODELS["ppc64"]
    assert archmodel.model_for("powerpc64") is archmodel.MODELS["ppc64"]
    assert archmodel.model_for("loongarch") is archmodel.MODELS["loongarch"]
    assert archmodel.model_for("loongarch64") is archmodel.MODELS["loongarch"]
    assert archmodel.model_for("loongarch").slug == "loongarch64-ret2libc"
    assert archmodel.model_for("ARM") is archmodel.MODELS["arm"]     # case-insensitive
    assert archmodel.model_for("mips") is None                       # not yet a shipped model
    assert archmodel.model_for(None) is None


def test_arg0_reg_is_the_gdbstub_key_and_label_is_prose():
    # the confirm key is what the gdbstub names the first-arg register; riscv's is x10, shown as a0.
    assert archmodel.MODELS["aarch64"].arg0_reg == "x0"
    assert archmodel.MODELS["arm"].arg0_reg == "r0"
    assert archmodel.MODELS["riscv64"].arg0_reg == "x10"
    assert archmodel.MODELS["riscv64"].arg0_label == "a0"
    assert archmodel.MODELS["ppc64"].arg0_reg == "r3"


def test_pack_width_and_endianness():
    a64 = archmodel.MODELS["aarch64"]          # 8-byte little-endian
    assert a64.pack(0x4005a0) == b"\xa0\x05\x40\x00\x00\x00\x00\x00"
    arm = archmodel.MODELS["arm"]              # 4-byte little-endian
    assert arm.pack(0x8390) == b"\x90\x83\x00\x00"
    # truncation to the target word, matching the inline `& 0xFFFF...` masks the functions used.
    assert arm.pack(0x1_0000_8390) == b"\x90\x83\x00\x00"


def test_pack_big_endian_is_ready_for_future_arches():
    # no shipped model is big-endian yet, but the packer must honour it for ppc/s390 BE later.
    be = archmodel.ArchModel("demo-be", 8, "big", "r3", "r3", "Demo", "demo-ret2libc")
    assert be.pack(0x4005a0) == b"\x00\x00\x00\x00\x00\x40\x05\xa0"
