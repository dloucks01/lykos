"""Native path traversal (CWE-22): a file operation whose PATH is attacker-controlled. Modelled
like the existing format-string/copy sinks -- advisory on its own (every program opens files),
promoted to a corroborated CWE-22 only when the taint channel proves the path argument carries
untrusted input. Previously CWE-22 existed only on the JVM path; this brings it to native/ELF."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import DetectContext, dangerous_api
from lykos.analyze.detect.catalog import DANGEROUS, SINK_TAINT_ARGS, normalize
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest, enqueue_triage
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_path_sinks_registered():
    for fn in ("fopen", "open", "openat", "creat", "unlink", "rename"):
        assert DANGEROUS[fn][0] == "CWE-22"
        assert fn in SINK_TAINT_ARGS                       # taint knows which arg is the path
    assert SINK_TAINT_ARGS["openat"] == frozenset({1})     # openat(dirfd, PATH, ...)


def test_dangerous_api_flags_fopen():
    e = types.SimpleNamespace(dst_name="fopen", src_addr="0x1149", site_addr="0x1160")
    ctx = DetectContext(target_id="t", case_id="c", call_edges=[e], strings=[], functions=[],
                        frames={}, func_irs={}, bits=64, arch="x86-64")
    out = dangerous_api(ctx)
    assert out and out[0]["cwe"] == "CWE-22" and out[0]["state"] == "candidate"


@pytest.fixture
def gcc_or_skip():
    import shutil
    if sandbox.host_arch() != "x86-64" or not (shutil.which("gcc") or shutil.which("cc")):
        pytest.skip("native x86-64 + C compiler required")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _detect(store, case, pool, gcc, csrc, name):
    import subprocess as sp
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    (d / "s.c").write_text(csrc)
    exe = d / name
    if sp.run([gcc, "-no-pie", "-O0", str(d / "s.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    t = ingest(store, case.id, exe, filename=name)
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(90)
    return [dict(zip(("cwe", "state", "severity", "detector"), r)) for r in
            store.conn.execute("SELECT cwe,state,severity,detector FROM finding WHERE target_id=?",
                               (t.id,)).fetchall()]


def test_tainted_path_is_corroborated_cwe22(store, case, pool, gcc_or_skip):
    import shutil
    gcc = shutil.which("gcc") or shutil.which("cc")
    rows = _detect(store, case, pool, gcc,
                   "#include <stdio.h>\nint main(int c,char**v){ if(c<2)return 0;"
                   " FILE*f=fopen(v[1],\"r\"); if(f)fclose(f); return 0; }\n", "pt")
    cwe22 = [r for r in rows if r["cwe"] == "CWE-22"]
    assert cwe22 and any(r["state"] == "corroborated" for r in cwe22), rows


def test_constant_path_not_corroborated(store, case, pool, gcc_or_skip):
    import shutil
    gcc = shutil.which("gcc") or shutil.which("cc")
    rows = _detect(store, case, pool, gcc,
                   "#include <stdio.h>\nint main(void){ FILE*f=fopen(\"/etc/config\",\"r\");"
                   " if(f)fclose(f); return 0; }\n", "ptc")
    # a hard-coded path is not attacker-controlled: no corroborated CWE-22 path-traversal claim
    assert not any(r["cwe"] == "CWE-22" and r["state"] == "corroborated" for r in rows), rows
