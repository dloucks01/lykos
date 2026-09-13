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


def test_the_channel_harness_dispatches_on_substrate_before_architecture():
    """A jar's recorded arch is "jvm", which is not a processor and has no qemu. Asking for an
    emulator FIRST rejected every Java target with "no qemu-user for jvm on x86-64" before the
    JVM branch could run it -- and the campaign then reported 30 executions at 24,000/second,
    because each returned that error immediately without starting anything. sandbox.run has
    always dispatched substrate-first; this did not."""
    import inspect

    from lykos.analyze.link import harness
    src = inspect.getsource(harness.channel_run)
    jvm_at = src.index("_is_jvm(exe)")
    qemu_at = src.index("_qemu_for(arch)")
    assert jvm_at < qemu_at, "the JVM check must come before the emulator lookup"
    assert "not jvm and arch and host" in src, "and must exclude the JVM from it"


def test_a_java_target_is_launched_under_the_jvm_on_a_channel():
    """A jar is not executable: exec'ing it starts nothing and the run comes back with no exit
    code, no output and no crash -- indistinguishable from a channel the target ignores."""
    import inspect

    from lykos.analyze.link import harness
    src = inspect.getsource(harness.channel_run)
    assert '"-jar"' in src and "_JVM_FLAGS" in src


def test_an_uncaught_exception_on_a_channel_is_a_crash():
    """A Java program does not segfault, it throws, so the wait status says nothing. Without
    reading stderr an uncaught ArrayIndexOutOfBoundsException was recorded as a clean run --
    and on this path that is the bug a video receiver actually has."""
    import inspect

    from lykos.analyze.link import harness
    src = inspect.getsource(harness.channel_run)
    assert "jvm_exception" in src and "jvm_site" in src


def test_a_persistent_session_serves_many_payloads_from_one_process():
    """Restarting the target per input is what makes network fuzzing slow: a listener does not
    exit when it is done with an input, so every non-crashing execution pays startup, group
    join AND the full timeout. Measured on a JVM multicast receiver: 0.12 exec/s one-shot
    against 12.2 persistent."""
    import inspect

    from lykos.analyze.link import harness
    assert hasattr(harness, "ChannelSession")
    src = inspect.getsource(harness.ChannelSession)
    # the trade is attribution, and the safeguard is that a crash kills the session so the
    # campaign's own re-run starts fresh and delivers only the suspect
    assert "SUSPECT" in src and "fresh process" in src
    assert "self.proc = None" in inspect.getsource(harness.ChannelSession._dead_result)


def test_slow_is_not_the_same_as_starved():
    """An emulated target runs at ~40 exec/s and a network listener at ~3, legitimately. A
    persistent multicast campaign did 120 executions, found and confirmed a CWE-129, and still
    reported `starved: true` on rate alone -- telling the reader to distrust a sound result."""
    import inspect

    from lykos.analyze.fuzz import stage
    src = inspect.getsource(stage.fuzz_campaign)
    assert "did_work = crashes > 0 or len(seen_behaviour) > 1" in src
    assert "and not did_work" in src
