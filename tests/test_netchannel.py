"""Datagram channels: multicast and UDP receivers.

A receiver that joins a multicast group and parses a video stream never reads stdin, a file or
argv -- so every existing input channel delivers nothing, and a campaign against one starves
while looking busy. Measured before this existed: 8 executions, 1 distinct behaviour,
`starved: true`, and an input_mode of "argv/none" for a program that reads a socket.
"""
import pytest
from lykos.analyze.fuzz import structure as S_MOD
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


def test_the_channel_harness_dispatches_on_substrate_before_architecture(tmp_path):
    """A jar's recorded arch is "jvm", which is not a processor and has no qemu. Asking for an
    emulator FIRST rejected every Java target with "no qemu-user for jvm on x86-64" before the
    JVM branch could run it -- and the campaign then reported 30 executions at 24,000/second,
    because each returned that error immediately without starting anything. sandbox.run has
    always dispatched substrate-first; this did not."""
    import zipfile

    from lykos.analyze.link.harness import _launch_cmd
    # a jar whose recorded arch is "jvm" on an x86-64 host: the emulator lookup must never
    # be reached, because there is no processor called "jvm". The substrate is read from the
    # target's BYTES, so this needs a real jar -- which is the point: the dispatch cannot be
    # decided from the arch column alone.
    jar = tmp_path / "recv.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    cmd, jvm, err = _launch_cmd(jar, "jvm", (), host="x86-64")
    assert err is None, err
    assert jvm is True and "-jar" in cmd
    # and a NATIVE target of an arch with no emulator is still the honest error
    native = tmp_path / "recv.bin"
    native.write_bytes(b"\x7fELF" + b"\x00" * 60)
    _cmd, _jvm, err2 = _launch_cmd(native, "nosucharch", (), host="x86-64")
    assert err2 and "nosucharch" in err2


def test_a_java_target_is_launched_under_the_jvm_on_a_channel(tmp_path):
    """A jar is not executable: exec'ing it starts nothing and the run comes back with no exit
    code, no output and no crash -- indistinguishable from a channel the target ignores."""
    import zipfile

    from lykos.analyze.link.harness import _launch_cmd
    jar = tmp_path / "x.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    cmd, jvm, err = _launch_cmd(jar, "jvm", ["-g", "239.1.1.1"], host="x86-64")
    assert jvm is True and err is None
    assert "-jar" in cmd and str(jar) in cmd
    assert cmd[-2:] == ["-g", "239.1.1.1"], "the listener's own flags still go last"


def test_the_one_shot_and_session_paths_launch_a_target_the_same_way(tmp_path):
    """`_launch_cmd`'s docstring promised the two could not drift on substrate dispatch while
    `channel_run` carried its own copy of that logic and never called it -- a guarantee that
    was simply not in force. Assert the shared launcher is the only one there is."""
    import inspect

    from lykos.analyze.link import harness
    one_shot = inspect.getsource(harness.channel_run)
    session = inspect.getsource(harness.ChannelSession)
    assert "_launch_cmd(" in one_shot and "_launch_cmd(" in session
    # neither may re-derive the substrate for itself
    for src, who in ((one_shot, "channel_run"), (session, "ChannelSession")):
        assert "_qemu_for(" not in src, f"{who} re-derives the emulator instead of sharing it"


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


_RECV_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
static void handle(const unsigned char *p, int n) {
    unsigned char out[16];
    if (n < 5 || p[0] != 0x47) return;              /* a real parser drops these */
    if ((p[3] >> 5) & 1) {
        int afl = p[4];
        memcpy(out, p + 5, afl);                     /* unchecked: the bug */
        fprintf(stderr, "af=%d\n", afl);
    }
}
int main(int argc, char **argv) {
    const char *g = NULL; int port = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-g") && i + 1 < argc) g = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
    }
    if (!g || !port) { fprintf(stderr, "usage: %s -g <group> -p <port>\n", argv[0]); return 2; }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    int on = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind(s, (struct sockaddr*)&a, sizeof a) < 0) return 1;
    struct ip_mreq m; m.imr_multiaddr.s_addr = inet_addr(g);
    m.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m);
    unsigned char buf[2048];
    for (int i = 0; i < 32; i++) { ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break; handle(buf, (int)n); }
    return 0;
}
"""


def _multicast_works():
    """Can this machine loop a multicast datagram back to itself? Containers and some CI
    networks cannot, and that is a property of the host rather than a regression -- so the
    tests below skip with THAT reason rather than failing or being silently absent."""
    import socket
    try:
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rx.bind(("", 51999))
        rx.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                      socket.inet_aton("239.9.9.31") + socket.inet_aton("0.0.0.0"))
        rx.settimeout(1.5)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        tx.sendto(b"ping", ("239.9.9.31", 51999))
        got = rx.recv(16)
        rx.close(); tx.close()
        return got == b"ping"
    except Exception:
        return False


def _build(tmp_path, cc="cc", extra=()):
    import shutil
    import subprocess
    if not shutil.which(cc):
        return None
    src = tmp_path / "recv.c"
    src.write_text(_RECV_C)
    out = tmp_path / "recv"
    r = subprocess.run([cc, "-O0", "-fno-stack-protector", "-w", *extra,
                        str(src), "-o", str(out)], capture_output=True)
    return out if r.returncode == 0 else None


def test_a_multicast_receiver_is_driven_to_its_bug(tmp_path):
    """The whole chain for a target that reads neither stdin, a file, nor argv: the harness
    joins nothing and SENDS, the listener is told which group to join, and the adaptation-field
    length the stream controls overflows a fixed buffer."""
    if not _multicast_works():
        pytest.skip("no multicast loopback on this host")
    exe = _build(tmp_path)
    if exe is None:
        pytest.skip("no C compiler")
    from lykos.analyze.link.harness import channel_run
    argv = ["-g", "239.9.9.32", "-p", "51997"]
    ok = bytes([0x47, 0x00, 0x21, 0x20, 4]) + b"\x00" * 183
    bad = bytes([0x47, 0x00, 0x21, 0x20, 0xff]) + b"\xff" * 183
    clean = channel_run(exe, "multicast", "239.9.9.32:51997", ok, timeout=10,
                        argv=argv, readiness=2.0)
    assert not clean.crashed, (clean.note, clean.stderr[:120])
    assert b"af=4" in (clean.stderr or b""), "the valid packet must reach the parser"
    crash = channel_run(exe, "multicast", "239.9.9.32:51997", bad, timeout=10,
                        argv=argv, readiness=2.0)
    assert crash.crashed and crash.signal_name == "SIGSEGV", (crash.note, crash.stderr[:120])


def test_a_persistent_session_serves_many_packets_and_still_catches_the_crash(tmp_path):
    """One process, many datagrams -- and the crash still lands, which is the property that
    makes the speed safe to take."""
    if not _multicast_works():
        pytest.skip("no multicast loopback on this host")
    exe = _build(tmp_path)
    if exe is None:
        pytest.skip("no C compiler")
    from lykos.analyze.link.harness import ChannelSession
    argv = ["-g", "239.9.9.33", "-p", "51996"]
    ok = bytes([0x47, 0x00, 0x21, 0x20, 4]) + b"\x00" * 183
    bad = bytes([0x47, 0x00, 0x21, 0x20, 0xff]) + b"\xff" * 183
    s = ChannelSession(exe, "multicast", "239.9.9.33:51996", argv=argv, readiness=2.0)
    try:
        for _ in range(6):
            assert not s.send(ok).crashed
        assert s.restarts == 1, f"the process should be reused, not restarted ({s.restarts})"
        # The crash may be seen on this send or reported as a late death on the next: a loaded
        # machine can take longer to die than the settle window, and the session reports that
        # rather than swallowing it. Either way it must not be lost.
        seen = [s.send(bad), s.send(bad)]
        assert any(r.crashed and r.signal_name == "SIGSEGV" for r in seen), \
            [(r.crashed, r.signal_name, r.note) for r in seen]
    finally:
        s.close()


def test_the_same_receiver_on_arm_under_qemu(tmp_path):
    """The multicast work was built and proved on x86-64, and "the pieces are arch-agnostic"
    was an inference until this ran. ARM and AArch64 are most of what this platform is pointed
    at, so the inference is not good enough.

    Static, because the ARM dynamic loader is not installed on an x86-64 host -- binfmt routes
    the binary to qemu-arm either way, but only a static image needs no interpreter.
    """
    import shutil
    if not _multicast_works():
        pytest.skip("no multicast loopback on this host")
    if not shutil.which("arm-linux-gnueabihf-gcc"):
        pytest.skip("no ARM cross toolchain")
    exe = _build(tmp_path, cc="arm-linux-gnueabihf-gcc", extra=("-static",))
    if exe is None:
        pytest.skip("ARM cross-compile failed")
    from lykos.analyze.link.harness import channel_run
    argv = ["-g", "239.9.9.34", "-p", "51995"]
    bad = bytes([0x47, 0x00, 0x21, 0x20, 0xff]) + b"\xff" * 183
    r = channel_run(exe, "multicast", "239.9.9.34:51995", bad, timeout=15,
                    argv=argv, arch="arm", readiness=2.5)
    assert r.cmd and "qemu-arm" in r.cmd[0], f"should run under qemu: {r.cmd[:1]}"
    assert r.crashed and r.signal_name == "SIGSEGV", (r.note, r.stderr[:140])


# --- coverage on the wire ----------------------------------------------------------------

_RTP_C = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
/* trusts the CC nibble: copies cc*4 bytes into a four-entry table */
static void handle(unsigned char *p, int n) {
    if (n < 12) return;
    if ((p[0] >> 6) != 2) return;
    int cc = p[0] & 0x0F;
    unsigned int csrc[4];
    memcpy(csrc, p + 12, cc * 4);
    fprintf(stderr, "cc=%d\n", cc);
}
int main(int argc, char **argv) {
    const char *g = NULL; int port = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-g") && i + 1 < argc) g = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
    }
    if (!g || !port) return 2;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    int on = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind(s, (struct sockaddr*)&a, sizeof a) < 0) return 1;
    unsigned char buf[2048];
    for (int i = 0; i < 256; i++) { ssize_t n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break; handle(buf, (int)n); }
    return 0;
}
"""


def _cross_rtp(tmp_path):
    """A static aarch64 receiver, or None. Coverage on a channel is only answerable for an
    EMULATED target -- qemu's block log is the instrumentation -- so this is the case the
    feature exists for, and the one it has to be proved on."""
    import shutil
    import subprocess
    cc = shutil.which("aarch64-linux-gnu-gcc")
    if not cc or not shutil.which("qemu-aarch64"):
        return None
    src = tmp_path / "rtp.c"
    src.write_text(_RTP_C)
    out = tmp_path / "rtp-a64"
    r = subprocess.run([cc, "-O0", "-static", "-fno-stack-protector", "-w",
                        str(src), "-o", str(out)], capture_output=True)
    return out if r.returncode == 0 else None


def test_a_persistent_channel_reports_coverage_per_payload_not_cumulatively(tmp_path):
    """The bug this guards is subtle and silent: one process serves many payloads, so qemu's
    block log is CUMULATIVE. Read whole, it credits every payload with everything reached
    before it -- a number that only ever grows, in which no payload is ever novel and the
    corpus never ratchets. Only the bytes the log gained since the last send are this
    payload's coverage."""
    exe = _cross_rtp(tmp_path)
    if exe is None:
        pytest.skip("no aarch64 cross toolchain + qemu-aarch64 on this host")
    from lykos.analyze.link.harness import ChannelSession
    blocks = tuple(range(0x400000, 0x420000, 4))
    port = 51873
    s = ChannelSession(exe, "udp", f"127.0.0.1:{port}",
                       argv=["-g", "127.0.0.1", "-p", str(port)], arch="aarch64",
                       readiness=3.0, settle=0.25, blocks=blocks)
    try:
        seed = S_MOD.seed_for_name("rtp")
        sends = [s.send(seed) for _ in range(4)]
        assert all(r.blocks_hit is not None for r in sends)
        counts = [len(r.blocks_hit) for r in sends]
        startup = counts[0]
        assert startup > 0, "an emulated listener has to report the blocks it ran"
        # The same payload, four times. Every send after the first reaches the parse loop and
        # NOT the process startup, so it must report far fewer blocks. Read cumulatively they
        # would all report `startup` or more.
        assert max(counts[1:]) < startup / 2, (
            f"per-send block counts {counts}: after the first send these should be the parse "
            f"loop alone, so the log is being re-read from the top and startup is credited "
            f"to every payload")
        # ...and the same code each time, so nothing is new. qemu buffers its log writes, so
        # the tail of one send can land in the next send's window; sends 3 and 4 are clear of
        # that boundary and must add nothing at all.
        seen = set(sends[0].blocks_hit) | set(sends[1].blocks_hit)
        for i, r in enumerate(sends[2:], start=3):
            assert not (set(r.blocks_hit) - seen), \
                f"send {i} reported blocks never seen before for an identical payload"
    finally:
        s.close()


def test_a_channel_without_coverage_says_so_rather_than_reporting_none_reached(tmp_path):
    """None and () are different answers: the first means "no coverage available here, judge
    this payload on its behaviour", the second means "this payload reached nothing". Collapsed
    together, every native target looks like a target that never reaches new code -- so the
    campaign would keep nothing and the corpus would never grow."""
    exe = _build(tmp_path)
    if exe is None:
        pytest.skip("no C compiler")
    from lykos.analyze.link.harness import ChannelSession
    port = 51872
    s = ChannelSession(exe, "udp", f"127.0.0.1:{port}",
                       argv=["-g", "127.0.0.1", "-p", str(port)], readiness=1.0, settle=0.1)
    try:
        assert s.send(b"\x47" + b"\x00" * 187).blocks_hit is None
    finally:
        s.close()


def test_the_campaign_offers_blocks_to_any_runner_that_takes_them():
    """Gated on `run_fn is run_input`, a network campaign could not be given coverage at all,
    however well the runner underneath it supported the idea."""
    from lykos.analyze.fuzz.stage import _takes_blocks, run_input

    def channel_like(exe, mode, workfile, timeout, arch, data, *, endianness=None,
                     bits=None, blocks=()):
        return [], None

    def old_style(exe, mode, workfile, timeout, arch, data, *, endianness=None, bits=None):
        return [], None

    assert _takes_blocks(run_input)
    assert _takes_blocks(channel_like)
    assert not _takes_blocks(old_style)
    assert not _takes_blocks(object())          # never raises on something odd
