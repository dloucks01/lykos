"""Multi-architecture firmware rehosting + Fuzzware-style MMIO access-pattern modeling.

Two layers: the pure arch-name resolution (no Unicorn needed), and a Unicorn-gated integration
run of the standalone driver that proves (a) a status-poll loop is broken so init proceeds, and
(b) non-ARM-Cortex-M arches (aarch64, mipsel) actually execute -- the QEMU-board-model problem
sidestepped.
"""
from __future__ import annotations

import json
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from lykos.analyze.firmware import unicorn_driver as drv
from lykos.analyze.firmware.rehost import locate_unicorn_python

_UNI = locate_unicorn_python()
_DRIVER = Path(drv.__file__)


def test_resolve_arch_maps_canonical_names():
    assert drv._resolve_arch({"arch": "arm", "sub": "cortex-m"}) == "cortex-m"
    assert drv._resolve_arch({"arch": "aarch64"}) == "aarch64"
    assert drv._resolve_arch({"arch": "arm64"}) == "aarch64"
    assert drv._resolve_arch({"arch": "mips", "endianness": "big"}) == "mips"
    assert drv._resolve_arch({"arch": "mips", "endianness": "little"}) == "mipsel"
    assert drv._resolve_arch({"arch": "mips", "endianness": "little", "bits": 64}) == "mips64el"
    assert drv._resolve_arch({"arch": "ppc"}) == "ppc"
    assert drv._resolve_arch({"arch": "ppc", "bits": 64}) == "ppc64"
    assert drv._resolve_arch({"arch": "riscv", "bits": 64}) == "riscv64"
    assert drv._resolve_arch({"arch": "sparc"}) is None     # unsupported


def _run(spec: dict) -> dict:
    with tempfile.TemporaryDirectory() as d:
        bp = Path(d) / "fw.bin"
        bp.write_bytes(spec.pop("_blob"))
        spec["blob"] = str(bp)
        sp = Path(d) / "spec.json"
        op = Path(d) / "out.json"
        sp.write_text(json.dumps(spec))
        subprocess.run([str(_UNI), str(_DRIVER), str(sp), str(op)], timeout=120, check=True)
        return json.loads(op.read_text())


@pytest.mark.skipif(_UNI is None, reason="Unicorn venv not available")
def test_poll_loop_is_broken_so_init_proceeds():
    """A Cortex-M reset handler that spins on an MMIO status bit must be driven PAST the poll
    (naive fuzz-every-read hangs forever). polls_satisfied > 0 and it reaches the proceed block."""
    img = bytearray(0x80)
    struct.pack_into("<I", img, 0x00, 0x20010000)              # SP
    for off in range(0x04, 0x40, 4):
        struct.pack_into("<I", img, off, 0x08000041)           # vectors -> entry 0x40
    # ldr r0,[pc,#8]; loop: ldr r1,[r0]; cmp r1,#0; beq loop; b . ; pool=0x40000000
    img[0x40:0x50] = bytes([0x02, 0x48, 0x01, 0x68, 0x00, 0x29, 0xFC, 0xD0,
                            0xFE, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40])
    out = _run({"_blob": bytes(img), "arch": "cortex-m", "mode": "run", "budget": 5000})
    assert out["ok"] and out["arch"] == "cortex-m"
    r = out["run"]
    assert r["polls_satisfied"] >= 1, "the status poll was never satisfied -- init hung"
    assert r["nblocks"] >= 3, "did not get past the poll loop"


@pytest.mark.skipif(_UNI is None, reason="Unicorn venv not available")
@pytest.mark.parametrize("arch,code", [
    ("aarch64", struct.pack("<IIII", 0xD503201F, 0xD503201F, 0xD503201F, 0x14000000)),  # nop*3;b .
    ("mipsel", struct.pack("<IIII", 0, 0, 0x1000FFFF, 0)),                              # nop;nop;b .
])
def test_non_cortex_m_arches_execute(arch, code):
    """aarch64 and mipsel blobs run under the driver with no board model -- the case QEMU
    cannot do without a machine definition."""
    out = _run({"_blob": code, "arch": arch, "mode": "run", "budget": 2000,
                "base": 0, "entry": 0})
    assert out["ok"], out.get("error")
    assert out["arch"] == arch
    assert out["run"]["nblocks"] >= 1, "no blocks executed"


@pytest.mark.skipif(_UNI is None, reason="Unicorn venv not available")
def test_interrupt_handler_is_dispatched_when_main_waits():
    """Interrupt-driven firmware whose main() just spins waiting for an IRQ must still have its
    ISR reached: when deeply stuck, the driver fires a vector-table handler as a subroutine."""
    img = bytearray(0x100)
    struct.pack_into("<I", img, 0x00, 0x20010000)              # SP
    struct.pack_into("<I", img, 0x04, 0x08000081)              # Reset -> main 0x80
    struct.pack_into("<I", img, 0x40, 0x08000091)              # IRQ vector -> ISR 0x90
    img[0x80:0x82] = bytes([0xFE, 0xE7])                       # main: b . (wait for interrupt)
    # ISR: ldr r0,[pc,#4]; movs r1,#1; str r1,[r0]; bx lr ; pool=0x1000 (unmapped -> fault)
    img[0x90:0x9C] = bytes([0x01, 0x48, 0x01, 0x21, 0x01, 0x60, 0x70, 0x47,
                            0x00, 0x10, 0x00, 0x00])
    out = _run({"_blob": bytes(img), "arch": "cortex-m", "mode": "run", "budget": 20000})
    assert out["ok"]
    r = out["run"]
    assert r["irq_fires"] >= 1, "no interrupt was ever fired -- main spin never escaped"
    assert r["nblocks"] >= 2, "the ISR code was never reached"
    assert r["fault"] and r["fault"]["kind"] == "write"        # the ISR's bad write


@pytest.mark.skipif(_UNI is None, reason="Unicorn venv not available")
def test_value_search_satisfies_a_specific_magic_gate():
    """A poll that waits for a SPECIFIC value (r1 == 0x55), where all-ones/zero do not satisfy
    it, must still be broken -- the deterministic value-set search reaches 0x55."""
    img = bytearray(0x80)
    struct.pack_into("<I", img, 0x00, 0x20010000)
    for off in range(0x04, 0x40, 4):
        struct.pack_into("<I", img, off, 0x08000041)
    # ldr r0,[pc,#8]; loop: ldr r1,[r0]; cmp r1,#0x55; bne loop; b . ; pool=0x40000000
    img[0x40:0x50] = bytes([0x02, 0x48, 0x01, 0x68, 0x55, 0x29, 0xFC, 0xD1,
                            0xFE, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40])
    out = _run({"_blob": bytes(img), "arch": "cortex-m", "mode": "run", "budget": 20000})
    assert out["ok"]
    r = out["run"]
    assert r["polls_satisfied"] >= 1, "the magic-value poll was never satisfied"
    assert r["nblocks"] >= 3, "did not get past the magic-value poll"


@pytest.mark.skipif(_UNI is None, reason="Unicorn venv not available")
def test_bad_write_is_a_fault():
    """A write to a wild unmapped address under Cortex-M is a genuine fault (memory corruption)."""
    img = bytearray(0x80)
    struct.pack_into("<I", img, 0x00, 0x20010000)
    for off in range(0x04, 0x40, 4):
        struct.pack_into("<I", img, off, 0x08000041)
    # ldr r0,[pc,#4]; movs r1,#1; str r1,[r0]; b . ; pool=0x00001000 (unmapped, not RAM/MMIO)
    img[0x40:0x4C] = bytes([0x01, 0x48, 0x01, 0x21, 0x01, 0x60, 0xFE, 0xE7,
                            0x00, 0x10, 0x00, 0x00])
    out = _run({"_blob": bytes(img), "arch": "cortex-m", "mode": "run", "budget": 2000})
    assert out["ok"]
    assert out["run"]["fault"] and out["run"]["fault"]["kind"] == "write"
