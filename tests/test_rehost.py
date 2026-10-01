"""Multi-architecture firmware rehosting + Fuzzware-style MMIO access-pattern modeling.

Two layers: the pure arch-name resolution (no Unicorn needed), and a Unicorn-gated integration
run of the standalone driver that proves (a) a status-poll loop is broken so init proceeds, and
(b) non-ARM-Cortex-M arches (aarch64, mipsel) actually execute -- the QEMU-board-model problem
sidestepped.
"""
from __future__ import annotations

import base64
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest

from lykos.analyze.firmware import angr_mmio as amod
from lykos.analyze.firmware import unicorn_driver as drv
from lykos.analyze.firmware.rehost import locate_unicorn_python, run_angr_mmio

_UNI = locate_unicorn_python()
_DRIVER = Path(drv.__file__)
try:
    from lykos.analyze.symbolic.concolic import locate_angr_python
    _ANGR = locate_angr_python()
except Exception:
    _ANGR = None


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


def test_every_driver_fault_kind_maps_to_a_cwe():
    """The rehost stage looks up _FAULT_CWE[kind] for the fault the driver reports. Every kind the
    driver can emit (_kind()'s returns plus the 'invalid' UcError trap) must be present, or a real
    firmware fault crashes the stage with a TypeError instead of being filed. Regression: a real
    FreeRTOS image reached an invalid-instruction fault once the init loop was no longer mis-read
    as stuck, and 'invalid' was missing from the map."""
    from lykos.analyze.firmware.rehost_stage import _FAULT_CWE
    for kind in ("write", "fetch", "read", "unknown", "invalid"):
        assert kind in _FAULT_CWE, f"driver fault kind {kind!r} has no CWE mapping"


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
def test_write_progress_init_loop_is_not_mistaken_for_stuck():
    """A long startup loop that ZEROES/copies RAM (a real RTOS image zeroes KBs of .bss before
    main) re-executes one block hundreds of times with no NEW coverage -- but it is making real
    progress, not stuck. The driver must NOT mistake it for a spin and fire an interrupt into it
    (into a weak `b .` Default_Handler, which then hangs), or init never reaches application code.
    Regression for a real FreeRTOS Cortex-M image that stopped at 7 blocks in its bss-zero loop."""
    # movs r0,#200; r1=0x20000000; loop: str r2,[r1]; r1+=4; r0-=1; bne loop; app: r3=[0x40000000]; b .
    CODE = bytes.fromhex("c82000212021090600220a60043110f1ff30fad140231b061b68fee7")
    img = bytearray(0x80)
    struct.pack_into("<I", img, 0x00, 0x20010000)              # SP
    struct.pack_into("<I", img, 0x04, 0x08000041)              # Reset -> code at 0x40 (thumb)
    for off in range(0x08, 0x40, 4):
        struct.pack_into("<I", img, off, 0x08000061)           # IRQ vectors -> weak handler at 0x60
    img[0x40:0x40 + len(CODE)] = CODE
    struct.pack_into("<H", img, 0x60, 0xE7FE)                  # weak Default_Handler: `b .`
    out = _run({"_blob": bytes(img), "arch": "cortex-m", "mode": "run", "budget": 8000})
    assert out["ok"]
    # the app block PAST the 200-iteration write loop must be reached; if the loop had been
    # mistaken for a spin, an interrupt would have fired into the weak handler and hung first.
    assert "0x8000054" in out["run"]["blocks"], "init write-loop was derailed before reaching app"


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
def test_hal_handler_skips_a_known_function():
    """A recognised function (e.g. a blocking delay) can be intercepted and returned-from on the
    host: without the handler the firmware hangs in the delay; with it, execution proceeds."""
    img = bytearray(0x100)
    struct.pack_into("<I", img, 0x00, 0x20010000)
    struct.pack_into("<I", img, 0x04, 0x08000081)             # Reset -> main 0x80
    # main: bl 0x90 (delay); ldr r0,[pc,#4]; str r1,[r0]; b . ; pool=0x1000 (unmapped -> fault)
    img[0x80:0x8E] = bytes([0x00, 0xF0, 0x06, 0xF8, 0x01, 0x48, 0x01, 0x60,
                            0xFE, 0xE7, 0x00, 0x00, 0x00, 0x10])
    struct.pack_into("<I", img, 0x8C, 0x00001000)
    img[0x90:0x92] = bytes([0xFE, 0xE7])                       # delay: b . (spin forever)
    blob = bytes(img)
    base = {"_blob": blob, "arch": "cortex-m", "mode": "run", "budget": 30000}
    without = _run(dict(base))
    assert without["run"]["halt"] == "budget" and without["run"]["fault"] is None  # hung in delay
    with_h = _run(dict(base, handlers={"0x08000090": "skip"}))
    assert with_h["run"]["handled_calls"] >= 1
    assert with_h["run"]["fault"] and with_h["run"]["fault"]["kind"] == "write"    # proceeded


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


@pytest.mark.skipif(_ANGR is None, reason="angr venv not available")
def test_angr_oracle_solves_an_arbitrary_mmio_gate(tmp_path):
    """The symbolic tier: a poll that waits for an ARBITRARY 32-bit MMIO value (0xCAFEBABE),
    which the deterministic value-set search cannot guess, is solved by angr -- it returns a
    seed whose MMIO byte-stream contains that value, so Unicorn can replay past the gate."""
    img = bytearray(0x80)
    struct.pack_into("<I", img, 0x00, 0x20010000)
    for off in range(0x04, 0x40, 4):
        struct.pack_into("<I", img, off, 0x08000041)
    # ldr r0,[pc,#0xC]; loop: ldr r1,[r0]; ldr r2,[pc,#0xC]; cmp r1,r2; bne loop; b .
    img[0x40:0x4C] = bytes([0x03, 0x48, 0x01, 0x68, 0x03, 0x4A, 0x91, 0x42, 0xFC, 0xD1, 0xFE, 0xE7])
    struct.pack_into("<I", img, 0x50, 0x40000000)             # MMIO address
    struct.pack_into("<I", img, 0x54, 0xCAFEBABE)             # the awaited magic
    bp = tmp_path / "fw.bin"
    bp.write_bytes(bytes(img))
    spec = {"blob": str(bp), "arch": "cortex-m", "base": 0x08000000,
            "entry": 0x08000040, "steps": 150}
    seeds = run_angr_mmio(_ANGR, spec)
    assert seeds, "angr produced no MMIO seeds"
    streams = [base64.b64decode(s) for s in seeds]
    assert any(b"\xbe\xba\xfe\xca" in s for s in streams), \
        "no seed carried the solved magic value 0xCAFEBABE"


def test_angr_oracle_arch_mapping_is_pure():
    """Arch gating in the oracle must not need angr imported."""
    assert "cortex-m" in amod._ARCH and "aarch64" in amod._ARCH
    assert "sparc" not in amod._ARCH


def test_hal_signatures_detect_weak_default_handlers():
    """Deterministic HAL signatures: a vector target that is an infinite `b .` (a weak
    Default_Handler) is mapped to skip, while a real handler is left alone -- no disassembler or
    SDK data needed."""
    import struct as _s
    from lykos.analyze.firmware import hal_signatures as hs
    img = bytearray(0x80)
    _s.pack_into("<I", img, 0x00, 0x20010000)
    _s.pack_into("<I", img, 0x04, 0x08000041)          # Reset -> 0x40 (real)
    _s.pack_into("<I", img, 0x08, 0x08000061)          # NMI  -> 0x60 (weak: b .)
    img[0x40:0x44] = bytes([0x00, 0x20, 0x70, 0x47])   # real: movs r0,#0; bx lr
    img[0x60:0x62] = bytes([0xFE, 0xE7])               # weak default handler: b .
    h = hs.scan(bytes(img), "cortex-m", 0x08000000, "little")
    assert h.get("0x8000060") == "skip"
    assert "0x8000040" not in h
