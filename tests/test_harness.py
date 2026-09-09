"""Phase 8 (doc 17.4) — boundary-driven harnessing: fuzz a consumer via its IPC endpoint."""
from __future__ import annotations

import base64
import os
import subprocess

import pytest

from lykos.analyze import register
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.link import enqueue_boundary
from lykos.analyze.link.harness import channel_run
from lykos.db.dao import ComponentEdgeDAO, DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_FIFO = "/tmp/lykos_h_fifo"
_SOCK = "/tmp/lykos_h_sock"

# classic stack overflow: read the channel into a 16-byte buffer -> smashes the return
# address (crash) once the payload exceeds ~24 bytes
_FIFO_C = f"""
#include <fcntl.h>
#include <unistd.h>
int main(void){{
  int fd=open("{_FIFO}", O_RDONLY); if(fd<0) return 2;
  char small[16]; int n=read(fd,small,4096); if(n<0) return 1;
  return small[0];
}}
"""
_SOCK_C = f"""
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
int main(void){{
  int fds=socket(AF_UNIX,SOCK_STREAM,0); if(fds<0) return 2;
  struct sockaddr_un a; memset(&a,0,sizeof a); a.sun_family=AF_UNIX;
  strcpy(a.sun_path,"{_SOCK}"); unlink(a.sun_path);
  if(bind(fds,(void*)&a,sizeof a)) return 2; listen(fds,1);
  int c=accept(fds,0,0); if(c<0) return 2;
  char small[16]; int n=read(c,small,4096); if(n<0) return 1;
  return small[0];
}}
"""


def _build(gcc, tmp, name, src):
    c = tmp / (name + ".c"); c.write_text(src)
    out = tmp / name
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(out)],
                       capture_output=True)
    if r.returncode != 0:
        pytest.skip(f"cannot build {name}")
    return out


@pytest.fixture
def fifo_bin(gcc, tmp_path_factory):
    return _build(gcc, tmp_path_factory.mktemp("h"), "fifo_c", _FIFO_C)


@pytest.fixture
def sock_bin(gcc, tmp_path_factory):
    return _build(gcc, tmp_path_factory.mktemp("h"), "sock_c", _SOCK_C)


def _cleanup():
    for p in (_FIFO, _SOCK):
        try:
            os.unlink(p)
        except OSError:
            pass


def test_channel_run_fifo_crash_and_clean(fifo_bin):
    _cleanup()
    try:
        crash = channel_run(fifo_bin, "fifo", _FIFO, b"A" * 80, timeout=5)
        assert crash.crashed and crash.signal_name in ("SIGSEGV", "SIGBUS", "SIGILL")
        assert crash.isolation == "rlimits-only(channel)"
        ok = channel_run(fifo_bin, "fifo", _FIFO, b"ok", timeout=5)
        assert not ok.crashed
    finally:
        _cleanup()


def test_channel_run_unix_socket_crash(sock_bin):
    _cleanup()
    try:
        crash = channel_run(sock_bin, "unix", _SOCK, b"B" * 512, timeout=5, readiness=2.0)
        assert crash.crashed and crash.signal_name in ("SIGSEGV", "SIGBUS", "SIGILL")
    finally:
        _cleanup()


def test_channel_run_unsupported_family():
    r = channel_run("/bin/true", "mq", "/reqq", b"x", timeout=2)
    assert r.isolation == "unsupported-channel" and not r.crashed


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_boundary_fuzz_stage_finds_crash(store, case, pool, fifo_bin):
    _cleanup()
    try:
        t = ingest(store, case.id, fifo_bin)
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(20)
        run = enqueue_boundary(q, t, params={
            "family": "fifo", "key": _FIFO,
            "seeds": [base64.b64encode(b"A" * 80).decode()],
            "max_execs": 40, "max_seconds": 20, "exec_timeout": 3})
        assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"

        crashes = [d for d in DynResultDAO(store.conn).list_by_target(t.id) if d.crashed]
        assert crashes and crashes[0].input_mode == "channel"
        fs = [f for f in FindingDAO(store.conn).list_by_target(t.id)
              if f.detector == "boundary"]
        assert fs and fs[0].state in ("confirmed", "poc-backed")
        assert any("boundary harness" in e.get("detail", "") for e in fs[0].evidence)
    finally:
        _cleanup()


def test_boundary_fuzz_auto_derives_channel_from_ipc_edge(store, case, pool, fifo_bin):
    _cleanup()
    try:
        t = ingest(store, case.id, fifo_bin)
        # a producer component + an ipc edge naming this fifo channel
        other = store.targets.upsert(case.id, filename="producer",
                                     sha256="p" * 64, size=1)
        ComponentEdgeDAO(store.conn).upsert(case.id, other.id, t.id, kind="ipc",
                                            symbol=_FIFO, detail=f"fifo:{_FIFO}")
        store.conn.commit()
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(20)
        run = enqueue_boundary(q, t, params={
            "seeds": [base64.b64encode(b"A" * 80).decode()],
            "max_execs": 30, "max_seconds": 20, "exec_timeout": 3})   # no family/key given
        assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
        assert [d for d in DynResultDAO(store.conn).list_by_target(t.id) if d.crashed]
    finally:
        _cleanup()
