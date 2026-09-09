"""Phase 8 (doc 17.3) — whole-system detonation + cross-boundary blame."""
from __future__ import annotations

import base64
import os
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.link import enqueue_whole_system
from lykos.analyze.link.detonate import detonate
from lykos.db.dao import ComponentEdgeDAO, DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_FIFO = "/tmp/lykos_ws_fifo"

# producer: reads stdin, forwards it verbatim onto the FIFO
_PROD_C = f"""
#include <fcntl.h>
#include <unistd.h>
int main(void){{
  char b[4096]; int n=read(0,b,4095); if(n<0) return 1;
  int fd=open("{_FIFO}", O_WRONLY); if(fd<0) return 2;
  if(n>0) {{ ssize_t w=write(fd,b,n); (void)w; }}
  close(fd); return 0;
}}
"""
# consumer: reads the FIFO into a 16-byte buffer -> overflow (crash) on a long message
_CONS_C = f"""
#include <fcntl.h>
#include <unistd.h>
int main(void){{
  int fd=open("{_FIFO}", O_RDONLY); if(fd<0) return 2;
  char s[16]; int n=read(fd,s,4096); if(n<0) return 1;
  return s[0];
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
def sys_bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("ws")
    return {"prod": _build(gcc, d, "prod", _PROD_C),
            "cons": _build(gcc, d, "cons", _CONS_C)}


def _clean():
    try:
        os.unlink(_FIFO)
    except OSError:
        pass


def _comps(bins):
    return [
        {"exe": bins["cons"], "target_id": "t_cons", "filename": "cons", "role": "service"},
        {"exe": bins["prod"], "target_id": "t_prod", "filename": "prod", "role": "entry"},
    ]


def test_detonate_cross_boundary_crash(sys_bins):
    _clean()
    try:
        res = detonate(_comps(sys_bins), channel={"family": "fifo", "key": _FIFO},
                       entry_input=b"A" * 200, timeout=6)
        assert res.cross_boundary
        assert res.blame["entry"] == "prod" and res.blame["crashed"] == "cons"
        assert res.blame["signal"] in ("SIGSEGV", "SIGBUS", "SIGILL")
        # the consumer outcome is the crashing service; producer exited clean
        by = {o.filename: o for o in res.outcomes}
        assert by["cons"].crashed and not by["prod"].crashed
    finally:
        _clean()


def test_detonate_no_crash_on_short_input(sys_bins):
    _clean()
    try:
        res = detonate(_comps(sys_bins), channel={"family": "fifo", "key": _FIFO},
                       entry_input=b"ok", timeout=6)
        assert not res.cross_boundary and res.blame is None
    finally:
        _clean()


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_whole_system_stage_single_detonation(store, case, pool, sys_bins):
    _clean()
    try:
        prod = ingest(store, case.id, sys_bins["prod"], filename="prod")
        cons = ingest(store, case.id, sys_bins["cons"], filename="cons")
        q = JobQueue(store.conn)
        enqueue_triage(q, prod, force=True); enqueue_triage(q, cons, force=True)
        assert pool.wait_idle(20)
        run = enqueue_whole_system(q, case.id, params={
            "entry_target": prod.id, "services": [cons.id],
            "channel": {"family": "fifo", "key": _FIFO},
            "input": base64.b64encode(b"A" * 200).decode()})
        assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"

        # the crash + finding land on the CONSUMER (the crashing service), with blame
        crashes = [d for d in DynResultDAO(store.conn).list_by_target(cons.id) if d.crashed]
        assert crashes and crashes[0].input_mode == "whole-system"
        fs = [f for f in FindingDAO(store.conn).list_by_target(cons.id)
              if f.detector == "whole_system"]
        assert fs
        assert any("cross-boundary blame: input into prod" in e.get("detail", "")
                   for e in fs[0].evidence)
    finally:
        _clean()


def test_whole_system_auto_derives_from_ipc_edge(store, case, pool, sys_bins):
    _clean()
    try:
        prod = ingest(store, case.id, sys_bins["prod"], filename="prod")
        cons = ingest(store, case.id, sys_bins["cons"], filename="cons")
        ComponentEdgeDAO(store.conn).upsert(case.id, prod.id, cons.id, kind="ipc",
                                            symbol=_FIFO, detail=f"fifo:{_FIFO}")
        store.conn.commit()
        q = JobQueue(store.conn)
        enqueue_triage(q, prod, force=True); enqueue_triage(q, cons, force=True)
        assert pool.wait_idle(20)
        run = enqueue_whole_system(q, case.id, params={
            "fuzz": True, "seeds": [base64.b64encode(b"A" * 200).decode()],
            "max_execs": 12, "max_seconds": 25, "exec_timeout": 5})
        assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
        assert [d for d in DynResultDAO(store.conn).list_by_target(cons.id) if d.crashed]
    finally:
        _clean()
