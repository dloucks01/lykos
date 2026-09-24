"""The qemu-user gdbstub client: the RSP protocol handling every cross-architecture capability
sits on.

Nothing tested this layer directly -- the existing tests drive it end-to-end through a real
emulator, so they cover the architectures this host can run and nothing else, and a protocol
bug on an ISA without a local toolchain was unreachable. These drive the wire format against a
scripted stub, so every architecture's register layout, byte order and stop-reply handling is
checked on any host.
"""
from __future__ import annotations

import pytest
from lykos.analyze.debug import qemu_gdb as qg


class FakeStub:
    """A gdbstub that answers from a script. `sendall` parses the RSP packet, `recv` hands back
    the scripted reply already framed -- the same bytes a real stub would put on the wire."""

    def __init__(self, answers):
        self.answers = dict(answers)
        self.asked: list = []
        self._out = b""
        self.default = ""

    def sendall(self, data: bytes):
        if data == b"+":                       # an ack, not a request
            return
        body = data[data.index(b"$") + 1:data.index(b"#")].decode()
        self.asked.append(body)
        reply = self.answers.get(body)
        if reply is None:
            for k, v in self.answers.items():
                if k.endswith("*") and body.startswith(k[:-1]):
                    reply = v
                    break
        if reply is None:
            reply = self.default
        self._out += f"${reply}#00".encode()

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        out, self._out = self._out, b""
        return out


# ---- packet framing ----------------------------------------------------------------------

def test_a_packet_carries_the_modulo_256_checksum_the_protocol_requires():
    """A stub that cannot verify the checksum drops the packet, and the client then waits for a
    reply that is never coming -- which looks like a hung target rather than a framing bug."""
    assert qg._pkt("g") == b"$g#67"
    assert qg._pkt("qSupported") == b"$qSupported#37"
    # sums wrap at 256 rather than growing
    long = "m" + "f" * 300
    body = qg._pkt(long)
    assert body.endswith(b"#%02x" % (sum(long.encode()) & 0xFF))


def test_a_transaction_acks_the_reply_and_returns_only_the_body():
    stub = FakeStub({"g": "deadbeef"})
    assert qg._txn(stub, "g") == "deadbeef"


def test_a_stub_that_closes_mid_transaction_returns_empty_rather_than_hanging():
    class Dead(FakeStub):
        def recv(self, _n):
            return b""
    assert qg._txn(Dead({}), "g") == ""


# ---- the g-packet: the register file, per ISA --------------------------------------------

def test_registers_are_sliced_by_the_architectures_own_layout():
    """Each ISA's g-packet is a different shape. Slicing with the wrong one silently yields
    plausible-looking garbage rather than an error."""
    # arm: 13 r-regs + sp, lr, pc, cpsr, all 4 bytes
    g = "".join(f"{i:02x}000000" for i in range(17))          # little-endian 0..16
    regs = qg._parse_regs(g, "arm")
    assert regs["r0"] == 0 and regs["r1"] == 1
    assert regs["sp"] == 13 and regs["lr"] == 14 and regs["pc"] == 15


def test_a_big_endian_target_is_read_big_endian():
    """The regression this guards: a register's bytes are in TARGET order, so reading a
    big-endian target little-endian returns a byte-swapped address that points nowhere --
    and a wrong PC is not obviously wrong, it is just a different number."""
    g = "".join("00000001" for _ in range(17))                 # value 1 in big-endian, 4 bytes
    be = qg._parse_regs(g, "arm", endianness="big")
    le = qg._parse_regs(g, "arm", endianness="little")
    assert be["pc"] == 1
    assert le["pc"] == 0x01000000
    assert be["pc"] != le["pc"]


def test_a_short_g_packet_drops_the_registers_it_cannot_fill():
    """A truncated reply must not produce a register whose value is a fragment."""
    regs = qg._parse_regs("00000000" + "11111111", "arm")
    assert set(regs) == {"r0", "r1"}
    assert regs["r1"] == 0x11111111


def test_an_architecture_with_no_layout_yields_no_registers():
    assert qg._parse_regs("deadbeef" * 8, "nosucharch") == {}


@pytest.mark.parametrize("arch", sorted(qg._LAYOUTS))
def test_every_declared_layout_round_trips_a_full_register_file(arch):
    """A layout whose widths do not line up with its own g-packet would mis-slice every
    register after the mistake, and only on that ISA."""
    layout = qg._LAYOUTS[arch]
    g = "".join("%0*x" % (w * 2, i + 1) for i, (_n, w) in enumerate(layout))
    regs = qg._parse_regs(g, arch, endianness="big")
    assert len(regs) == len(layout)
    for i, (name, _w) in enumerate(layout):
        assert regs[name] == i + 1, f"{arch}: {name} mis-sliced"


# ---- what each architecture claims it can do ---------------------------------------------

def test_an_architecture_is_supported_only_if_its_registers_can_be_read():
    for arch in qg._LAYOUTS:
        assert qg.supported(arch)
    for arch in qg._STUB_ABI:
        assert qg.supported(arch)
    assert not qg.supported("nosucharch")


def test_breakpoints_need_an_argument_register_map_not_just_a_layout():
    """A breakpoint you can set but whose arguments you cannot read gives a hit with no
    evidence attached, which is worse than declining: it reports a call and says nothing
    about it."""
    for arch in qg._ARG_REGS:
        assert qg.breakpoints_supported(arch), arch
    assert not qg.breakpoints_supported("nosucharch")
    # every arch that claims breakpoint support must name registers its layout actually has
    for arch, regs in qg._ARG_REGS.items():
        layout = qg._layout_for(arch)
        if not layout:
            continue
        have = {n for n, _w in layout}
        assert set(regs) <= have, f"{arch}: arg regs {set(regs) - have} are not in its layout"


@pytest.mark.parametrize("arch", sorted(qg._ARG_REGS))
def test_every_breakpoint_architecture_can_name_its_stack_and_program_counter(arch):
    """`capture` returns `regs.get(_sp_name(arch))`, so a name the layout does not have comes
    back as None -- not as an error. On s390 that is exactly what happened: the stack pointer
    is r15, `_sp_name` fell through to the default "sp", and every capture reported no stack
    pointer at all while the value sat in `regs["r15"]` the whole time."""
    layout = qg._layout_for(arch)
    if not layout:
        pytest.skip(f"{arch} derives its layout from the live stub")
    have = {n for n, _w in layout}
    assert qg._pc_name(arch) in have, f"{arch}: no pc register"
    assert qg._sp_name(arch) in have, f"{arch}: no sp register"


# ---- stop replies ------------------------------------------------------------------------

@pytest.mark.parametrize("reply,expect", [
    ("T05thread:01;", ("trap", 5)),
    ("S0b", ("trap", 11)),
    ("W00", ("exit", None)),
    ("X09", ("term", None)),
    ("", ("none", None)),
    ("OK", ("none", None)),
    ("Tzz", ("trap", None)),          # malformed signal: a trap we cannot name, not a crash
])
def test_a_stop_reply_is_classified(reply, expect):
    assert qg._stop_sig(reply) == expect


# ---- memory reads ------------------------------------------------------------------------

def test_memory_comes_back_as_bytes():
    stub = FakeStub({"m1000,4": "41424344"})
    assert qg._read_mem(stub, 0x1000, 4) == b"ABCD"


def test_an_error_reply_reads_as_no_memory_rather_than_as_data():
    """`E01` is hex-decodable nonsense if it is not recognised as an error first."""
    assert qg._read_mem(FakeStub({"m1000,4": "E01"}), 0x1000, 4) == b""
    assert qg._read_mem(FakeStub({"m1000,4": ""}), 0x1000, 4) == b""
    assert qg._read_mem(FakeStub({"m1000,4": "zzzz"}), 0x1000, 4) == b""


def test_a_c_string_stops_at_its_terminator():
    stub = FakeStub({"m1000,40": b"hello\x00padpadpad".hex()})
    assert qg._cstr(stub, 0x1000) == "hello"


def test_a_c_string_spanning_reads_is_reassembled():
    """The read is chunked at 64 bytes, so a longer string is several transactions and the
    pieces have to be joined in order."""
    first = b"A" * 64
    second = b"B" * 10 + b"\x00" + b"C" * 53
    stub = FakeStub({"m1000,40": first.hex(), "m1040,40": second.hex()})
    assert qg._cstr(stub, 0x1000) == "A" * 64 + "B" * 10


def test_a_c_string_is_capped_rather_than_read_forever():
    """A pointer into unterminated memory must not turn into an unbounded read loop."""
    stub = FakeStub({})
    stub.default = ("41" * 64)
    assert len(qg._cstr(stub, 0x1000, cap=128)) == 128


def test_a_null_pointer_is_the_empty_string_and_costs_no_transaction():
    stub = FakeStub({})
    assert qg._cstr(stub, 0) == ""
    assert stub.asked == []


def test_unreadable_memory_ends_the_string_instead_of_looping():
    stub = FakeStub({})
    stub.default = "E01"
    assert qg._cstr(stub, 0x1000) == ""
