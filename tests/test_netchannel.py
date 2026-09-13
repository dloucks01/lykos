"""Datagram channels: multicast and UDP receivers.

A receiver that joins a multicast group and parses a video stream never reads stdin, a file or
argv -- so every existing input channel delivers nothing, and a campaign against one starves
while looking busy. Measured before this existed: 8 executions, 1 distinct behaviour,
`starved: true`, and an input_mode of "argv/none" for a program that reads a socket.
"""
from lykos.analyze.link.harness import DRIVABLE, _hostport
from lykos.analyze.link.harness_stage import _hostport_of


def test_datagram_families_are_drivable():
    assert {"udp", "multicast"} <= DRIVABLE
    # the stream families are untouched
    assert {"fifo", "unix", "tcp"} <= DRIVABLE


def test_a_channel_key_yields_the_address_to_fill_in():
    """Invocation discovery proposes generic placeholders because it cannot know a deployment.
    The harness DOES know -- it picked the address it is about to send to -- so a receiver is
    told to join the group the driver uses rather than one named "x"."""
    assert _hostport_of("239.9.9.9:5004") == ("239.9.9.9", 5004)
    assert _hostport_of("/tmp/some.fifo") == (None, None)
    assert _hostport_of(None) == (None, None)
    assert _hostport("127.0.0.1:9000") == ("127.0.0.1", 9000)


def test_a_multicast_group_is_recognised_as_an_address():
    """`-g <group>` got no value kind at all, so nothing could fill it in and the receiver
    joined a group named "x" while the harness sent to the real one."""
    from lykos.analyze import invocation
    found = invocation.discover(["usage: recv -g <group> -p <port>", "g:p:v"])
    kinds = {f["flag"]: f["kind"] for f in found["flags"]}
    assert kinds["-g"] == "host"
    assert kinds["-p"] == "port"


def test_the_transport_stream_model_keeps_the_sync_byte():
    """A TS packet whose first byte is not 0x47 is dropped before any parsing code runs, so
    blind mutation tests nothing. Measured over multicast: byte mutation found 0 crashes in 60
    executions, the model found 1."""
    import random

    from lykos.analyze.fuzz import structure
    assert "mpegts" in structure.builtin_names()
    seed = structure.seed_for_name("mpegts")
    assert seed[:1] == b"\x47"
    mut = structure.StructMutator(random.Random(11), structure.builtin("mpegts"), [])
    kept = sum(1 for _ in range(300) if mut.mutate(seed)[:1] == b"\x47")
    assert kept > 240, f"sync byte survived only {kept}/300 mutations"


def test_the_adaptation_length_is_a_field_the_mutator_can_drive():
    """It is one byte, the stream chooses it, and a receiver that trusts it copies that many
    bytes out of a 188-byte packet. That is the field the bug lives behind."""
    from lykos.analyze.fuzz import structure

    def names(spec):
        """Field names anywhere in the tree -- the adaptation field is a nested group, which
        is what makes the model faithful rather than a flat stub."""
        out = []
        for f in spec:
            out.append(f.get("name"))
            if f["type"] in ("group", "array"):
                out += names(f["spec"])
        return out

    all_names = names(structure.builtin("mpegts").spec)
    assert "af_len" in all_names, all_names
    assert "adaptation" in all_names, "the adaptation field is a group, not a loose byte"
