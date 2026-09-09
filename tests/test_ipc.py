"""Phase 8 (doc 17.1/17.3) — IPC channel modelling: producer/consumer over a shared key."""
from __future__ import annotations

from lykos.analyze.link import ipc
from lykos.analyze.link.ipc import component_ipc, match_channels


class _Content:
    """Content-store stub: sha256 -> bytes."""
    def __init__(self, blobs):
        self._b = blobs

    def exists(self, sha):
        return sha in self._b

    def get_bytes(self, sha):
        return self._b[sha]


class _T:
    def __init__(self, tid, filename, sha):
        self.id, self.filename, self.sha256 = tid, filename, sha


def test_scan_keys_filters_system_paths():
    keys = ipc._scan_keys(b"junk\x00/reqq\x00/usr/lib/x\x00/tmp/sock\x00/lib64/ld.so\x00ab")
    assert "/reqq" in keys and "/tmp/sock" in keys
    assert "/usr/lib/x" not in keys and "/lib64/ld.so" not in keys


def test_component_ipc_profile_producer():
    rec = {"imports": {"symbols": ["read", "mq_open", "mq_send", "printf"]}}
    t = _T("a", "producer", "sha_a")
    content = _Content({"sha_a": b"\x00/reqq\x00"})
    p = component_ipc(content, t, rec)
    assert "mq" in p["families"] and "send" in p["families"]["mq"]
    assert "read" in p["sources"]           # untrusted-input source present
    assert "/reqq" in p["keys"]


def test_component_ipc_profile_consumer_with_sink():
    rec = {"imports": {"symbols": ["mq_open", "mq_receive", "system"]}}
    t = _T("b", "consumer", "sha_b")
    content = _Content({"sha_b": b"\x00/reqq\x00"})
    p = component_ipc(content, t, rec)
    assert "recv" in p["families"]["mq"]
    assert ("CWE-78", "high", "system") in p["sinks"]


def test_match_channels_pairs_and_flags():
    ta = _T("a", "producer", "sa")
    tb = _T("b", "consumer", "sb")
    ca = _Content({"sa": b"/reqq\x00", "sb": b"/reqq\x00"})
    pa = component_ipc(ca, ta, {"imports": {"symbols": ["read", "mq_open", "mq_send"]}})
    pb = component_ipc(ca, tb, {"imports": {"symbols": ["mq_open", "mq_receive", "system"]}})
    edges, findings = match_channels({"a": ta, "b": tb}, {"a": pa, "b": pb})
    assert edges == [{"src": "a", "dst": "b", "family": "mq", "key": "/reqq"}]
    assert len(findings) == 1
    f = findings[0]
    assert f["_target"] == "b" and f["cwe"] == "CWE-78" and f["detector"] == "ipc_taint"
    assert "producer" in f["title"] and "consumer" in f["title"] and "/reqq" in f["title"]
    chans = {e["channel"] for e in f["evidence"]}
    assert {"ipc", "ipc-reachability"} <= chans


def test_no_match_without_shared_key():
    ta = _T("a", "p", "sa")
    tb = _T("b", "c", "sb")
    ca = _Content({"sa": b"/reqq\x00", "sb": b"/otherq\x00"})
    pa = component_ipc(ca, ta, {"imports": {"symbols": ["read", "mq_send"]}})
    pb = component_ipc(ca, tb, {"imports": {"symbols": ["mq_receive", "system"]}})
    edges, findings = match_channels({"a": ta, "b": tb}, {"a": pa, "b": pb})
    assert edges == [] and findings == []


def test_no_match_when_both_receive():
    ta = _T("a", "c1", "sa")
    tb = _T("b", "c2", "sb")
    ca = _Content({"sa": b"/q\x00", "sb": b"/q\x00"})
    pa = component_ipc(ca, ta, {"imports": {"symbols": ["mq_receive", "system"]}})
    pb = component_ipc(ca, tb, {"imports": {"symbols": ["mq_receive", "system"]}})
    edges, findings = match_channels({"a": ta, "b": tb}, {"a": pa, "b": pb})
    assert edges == []


# ------------------------------------------------------------------ integration (real triage)
import subprocess  # noqa: E402

import pytest  # noqa: E402
from lykos.analyze import register  # noqa: E402
from lykos.analyze.ingest import enqueue_triage, ingest  # noqa: E402
from lykos.analyze.link.ipc import model_ipc_case  # noqa: E402
from lykos.db.dao import ComponentEdgeDAO, FindingDAO  # noqa: E402
from lykos.jobs import JobConfig, JobQueue, WorkerPool  # noqa: E402

_PROD = ('#include <mqueue.h>\n#include <unistd.h>\n#include <string.h>\n'
         'int main(){char b[128];int n=read(0,b,127);if(n<0)return 1;'
         'mqd_t q=mq_open("/reqq",1);mq_send(q,b,n,0);return 0;}\n')
_CONS = ('#include <mqueue.h>\n#include <stdlib.h>\n'
         'int main(){char b[128];mqd_t q=mq_open("/reqq",0);'
         'mq_receive(q,b,128,0);system(b);return 0;}\n')


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_model_ipc_case_end_to_end(store, case, gcc, tmp_path, pool):
    prod, cons = tmp_path / "prod.c", tmp_path / "cons.c"
    prod.write_text(_PROD); cons.write_text(_CONS)
    pexe, cexe = tmp_path / "prod", tmp_path / "cons"
    for src, out in ((prod, pexe), (cons, cexe)):
        r = subprocess.run(["gcc", str(src), "-o", str(out), "-lrt"], capture_output=True)
        if r.returncode != 0:
            pytest.skip("cannot build POSIX mq binaries")
    q = JobQueue(store.conn)
    for exe in (pexe, cexe):
        t = ingest(store, case.id, exe)
        enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)

    summary = model_ipc_case(store.conn, store.content, case.id, persist=True)
    assert summary["ipc_edges"] >= 1
    assert any(c.endswith("/reqq") for c in summary["channels"])
    assert summary["cross_findings"] >= 1

    ipc_edges = [e for e in ComponentEdgeDAO(store.conn).list_by_case(case.id)
                 if e.kind == "ipc"]
    assert ipc_edges and ipc_edges[0].symbol == "/reqq"
    # the candidate finding is CWE-78 (system) on the consumer
    tmap = {t.id: t.filename for t in store.targets.list_by_case(case.id)}
    consumer = next(t.id for t in store.targets.list_by_case(case.id) if t.filename == "cons")
    xf = [f for f in FindingDAO(store.conn).list_by_target(consumer)
          if f.detector == "ipc_taint"]
    assert xf and xf[0].cwe == "CWE-78"
    assert tmap[ipc_edges[0].src_target] == "prod"
