"""32-bit ARM (armhf) capability coverage + the Thumb-interworking L2 fix.

ARM's `pop {pc}` / `bx` interprets bit 0 of the loaded value as the Thumb/ARM state select and
CLEARS it from the actual PC. So a controlled return address whose low byte is odd lands in the
program counter as `value & ~1`. When that masked value happens to alias an earlier window of the
De Bruijn cyclic pattern (the neighbouring word differs only in bit 0), the naive offset search
pins the control offset one word early and the marker confirmation then fails. `primitive_stage`
now also searches `(pc | 1)` (restoring the masked bit) and lets confirmation, not the raw
heuristic, decide the reported offset -- so ARM IP-control is recovered at the true slot.

The first test reproduces the aliasing purely from the pattern (no qemu). The rest run the real
`vuln_arm` corpus binary under qemu-arm and are skipped where that binary or qemu-arm is absent.
"""
import os
import struct

import pytest
from lykos.analyze.debug import elfsyms, monitor, qemu_gdb
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import primitive

_CORPUS = os.path.join(os.path.dirname(__file__), "..", "examples", "re-corpus", "bin")
_ARM = os.path.join(_CORPUS, "vuln_arm")


def _need_arm():
    if not os.path.exists(_ARM):
        pytest.skip("needs the vuln_arm corpus binary (build with the arm musl cross toolchain)")
    if sandbox.host_arch() == "arm" or not sandbox._qemu_for("arm"):
        pytest.skip("needs a non-arm host with qemu-arm")
    if not qemu_gdb.breakpoints_supported("arm"):
        pytest.skip("no cross-arch monitor for arm")


def test_thumb_masked_pc_aliases_one_word_early():
    """Regression for the Thumb-interworking bug: the naive pc search pins the aliased (early)
    offset, but restoring the masked bit via `(pc | 1)` recovers the true return-address slot."""
    length = 300
    pat = primitive.cyclic(length)
    true_off = 132                                   # saved pc slot in vuln_arm's handle() frame
    v_true = struct.unpack_from("<I", pat, true_off)[0]
    assert v_true & 1, "test premise: the true return address has bit0 set"
    # ARM masks bit0 off the PC actually fetched
    masked_pc = v_true & ~1
    # ...and here that masked value equals the previous word -> the naive search aliases early
    aliased_off = primitive.cyclic_find(
        primitive._reg_window(masked_pc, 4, "little", 4), length, 4)
    assert aliased_off == true_off - 4               # the bug: one word too early
    # the fix: search (pc | 1) to restore the masked bit -> the true slot
    restored_off = primitive.cyclic_find(
        primitive._reg_window(masked_pc | 1, 4, "little", 4), length, 4)
    assert restored_off == true_off


@pytest.mark.skipif(not sandbox._qemu_for("arm") or sandbox.host_arch() == "arm",
                    reason="needs a non-arm host with qemu-arm")
def test_arm_capture_masks_thumb_bit():
    """The concrete mechanism, live: feeding the cyclic pattern to vuln_arm over qemu-arm, the
    captured PC is the true return address with bit 0 cleared (Thumb select)."""
    _need_arm()
    length = 220
    cap = qemu_gdb.capture(_ARM, "arm", stdin=primitive.cyclic(length), argv=[],
                           endianness="little", bits=32, timeout=20)
    assert cap.get("signal_name") == "SIGSEGV"
    pc = cap.get("pc") or 0
    assert pc & 1 == 0                                # the fetched PC never has the Thumb bit set
    # the true controlled slot is recovered once the masked bit is restored
    off = primitive.cyclic_find(primitive._reg_window(pc | 1, 4, "little", 4), length, 4)
    assert off == 132


@pytest.mark.skipif(not sandbox._qemu_for("arm") or sandbox.host_arch() == "arm",
                    reason="needs a non-arm host with qemu-arm")
def test_arm_ip_control_confirms_at_true_offset():
    """End to end: place the marker at the recovered slot and confirm the ARM PC equals it --
    a genuine, verified instruction-pointer-control primitive on 32-bit ARM."""
    _need_arm()
    length = 220
    control = primitive.control_input(132, length, 4, "little")
    cap = qemu_gdb.capture(_ARM, "arm", stdin=control, argv=[], endianness="little",
                           bits=32, timeout=20)
    assert primitive.marker_confirmed(cap, word=4, endian="little")
    assert (cap.get("pc") or 0) == primitive._ip_marker(4)


@pytest.mark.skipif(not sandbox._qemu_for("arm") or sandbox.host_arch() == "arm",
                    reason="needs a non-arm host with qemu-arm")
def test_arm_monitor_captures_system_command():
    """The cross-arch dangerous-call monitor breakpoints ARM sinks and captures the concrete
    command passed to system() -- CWE-78 dynamic evidence on 32-bit ARM."""
    _need_arm()
    info = elfsyms.read(_ARM)
    funcs = sorted(set(info["symbols"]) & set(monitor.CATALOG))
    assert "system" in funcs
    res = qemu_gdb.monitor_calls(_ARM, "arm", symbols=info["symbols"], entry=info["entry"],
                                 pie=info["pie"], sink_names=set(funcs),
                                 endianness="little", bits=32, argv=["4242"], timeout=30)
    assert res.get("ok"), res.get("note")
    # the raw gdbstub monitor returns each arg register dereferenced as a C-string; the stage's
    # _decode_xarch later maps argstrs[0] -> the `cmd` field. The command is captured either way.
    sys_args = [h.get("argstrs", []) for h in res.get("hits", []) if h.get("func") == "system"]
    assert any("echo unlocked" in (a[0] if a else "") for a in sys_args)
