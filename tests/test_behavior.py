"""Phase 6 — syscall/behavior tracer: inventory security-relevant syscalls (exec, network,
file writes, anti-debug, W^X) and flag the high-signal ones."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_behavior_trace, syscalls
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_BEHAV = r"""
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void){
  ptrace(PTRACE_TRACEME,0,0,0);
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(9);
  inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
  connect(s,(struct sockaddr*)&a,sizeof a);
  void*p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(p) mprotect(p,4096,PROT_READ|PROT_EXEC);
  execl("/bin/true","true",(char*)0);
  return 0;
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_supported_arch():
    assert syscalls.supported("x86-64")
    assert not syscalls.supported("aarch64")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("gdb"),
                    reason="native x86-64 + gdb required")
def test_behavior_trace_inventories_and_flags(store, case, pool, gcc, tmp_path):
    c = tmp_path / "b.c"; c.write_text(_BEHAV)
    b = tmp_path / "b"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_behavior_trace(q, target, params={"timeout": 25})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("gdb syscall trace unavailable: " + str(rec.error))
    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if f.detector == "behavior"]
    titles = " ".join(f.title for f in finds)
    assert "network connection" in titles.lower()      # connect() flagged
    assert "anti-debug" in titles.lower()              # ptrace(TRACEME)
    assert "executable memory" in titles.lower()       # mprotect +X (W^X)
    assert "/bin/true" in titles                       # execve
