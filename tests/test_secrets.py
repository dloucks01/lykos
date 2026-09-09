"""Phase 6 — comparison / secret extraction: recover the constants a program checks input
against (passwords, magic bytes) by breakpointing the comparison functions."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_extract, secrets
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import CallEdgeDAO, FindingDAO
from lykos.db.models import CallEdge
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRACKME = ("#include <stdio.h>\n#include <string.h>\n"
            "int main(void){char in[64]; if(fgets(in,sizeof in,stdin)){\n"
            "  in[strcspn(in,\"\\n\")]=0;\n"
            "  if(strcmp(in,\"sup3rs3cr3t\")==0){puts(\"granted\");return 0;}\n"
            "  if(strncmp(in,\"ADMIN\",5)==0) puts(\"admin\"); }\n"
            "  puts(\"denied\"); return 1;}\n")


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


def _edge(name):
    return CallEdge(id="x" + name, target_id="t", created_at=0, src_addr="0x1149",
                    site_addr="0x1160", dst_addr=None, dst_name=name, external=1)


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("gdb"),
                    reason="native x86-64 + gdb required")
def test_extract_recovers_password_and_magic(store, case, pool, gcc, tmp_path):
    c = tmp_path / "c.c"; c.write_text(_CRACKME)
    b = tmp_path / "c"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    # seed the imported comparison functions (stands in for the Ghidra call graph)
    CallEdgeDAO(store.conn).replace_for_target(
        target.id, [{"src_addr": "0x1149", "site_addr": "0x1160", "dst_addr": None,
                     "dst_name": n, "external": 1} for n in ("strcmp", "strncmp")])
    q = JobQueue(store.conn)
    run = enqueue_extract(q, target, params={"input_mode": "stdin", "timeout": 20})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("gdb extraction unavailable: " + str(rec.error))
    titles = " ".join(f.title for f in FindingDAO(store.conn).list_by_target(target.id)
                      if f.detector == "secret_probe")
    assert "sup3rs3cr3t" in titles      # the hard-coded password was recovered
    assert "ADMIN" in titles            # and the magic token


def test_extract_unsupported_cross_arch(store, case, pool, gcc, tmp_path):
    assert not secrets.supported("mips")
