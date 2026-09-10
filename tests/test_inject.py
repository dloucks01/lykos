"""Phase 6 — injection PoC synthesis: command injection / format string / path traversal
confirmed by effect, without fuzzing."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_inject, injection
from lykos.db.dao import CallEdgeDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CMDI = ('#include <stdio.h>\n#include <stdlib.h>\n'
         'int main(int c,char**v){if(c<2)return 1;char cmd[256];'
         'snprintf(cmd,sizeof cmd,"echo got: %s",v[1]);return system(cmd);}\n')
_FMT = ('#include <stdio.h>\n'
        'int main(int c,char**v){if(c<2)return 1;printf(v[1]);printf("\\n");return 0;}\n')
_TRAV = ('#include <stdio.h>\nint main(int c,char**v){if(c<2)return 1;FILE*f=fopen(v[1],"r");'
         'if(!f)return 1;char b[512];size_t n=fread(b,1,sizeof b,f);fwrite(b,1,n,stdout);'
         'fclose(f);return 0;}\n')


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _edges(sinks):
    return [{"src_addr": "0x1149", "site_addr": "0x1160", "dst_addr": None,
             "dst_name": s, "external": 1} for s in sinks]


def _run(store, pool, gcc, tmp_path, src, name, sinks, cwe):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    case = store.cases.create(name)
    target = ingest(store, case.id, b)
    CallEdgeDAO(store.conn).replace_for_target(target.id, _edges(sinks))
    q = JobQueue(store.conn)
    run = enqueue_inject(q, target, params={"input_mode": "arg", "timeout": 8})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("sandbox unavailable: " + str(rec.error))
    cwes = {f.cwe for f in FindingDAO(store.conn).list_by_target(target.id)
            if f.detector == "inject_synth"}
    return cwe in cwes


def test_fmt_and_traversal_payloads_and_confirm():
    # unit: confirmation logic
    assert injection.cmdi_confirm(b"got: \nMARK123\n", "; echo MARK123", "MARK123")
    assert not injection.cmdi_confirm(b"got: ; echo MARK123\n", "x", "MARK123")
    assert injection.fmt_confirm(b"AAA.0x7ffe.0x40.0x0", b"AAA...", "AAA")
    assert not injection.fmt_confirm(b"AAA.%p.%p", b"AAA...", "AAA")
    assert injection.traversal_confirm(b"root:x:0:0:root:/root", b"", "")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_command_injection_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _CMDI, "ci", ["system"], "CWE-78")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_format_string_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _FMT, "fs", ["printf"], "CWE-134")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64")
def test_path_traversal_confirmed(store, pool, gcc, tmp_path):
    assert _run(store, pool, gcc, tmp_path, _TRAV, "tv", ["fopen"], "CWE-22")
