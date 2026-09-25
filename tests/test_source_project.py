"""Multi-file / build-system source PROJECTS: lykos builds them with ASan+UBSan (via a compiler
wrapper that forces instrumentation through the project's own build) and analyses the produced
binary, so real source -- not just a single .c -- gets sanitizer-diagnosed findings with a source
file:line and no CTF oracle."""
from __future__ import annotations

import os
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.source_project import build_source_project, is_source_project
from lykos.db.dao import ArtifactDAO, TargetDAO


@pytest.fixture
def gcc_or_skip():
    if not (sandbox.host_arch() == "x86-64"):
        pytest.skip("native x86-64 only")
    import shutil
    if not (shutil.which("gcc") or shutil.which("clang")):
        pytest.skip("no C compiler")


def _make_project(d):
    (d / "dup.c").write_text("#include <stdlib.h>\n#include <string.h>\n"
                             "char* dup_line(const char*s){char*b=malloc(8); strcpy(b,s); return b;}\n")
    (d / "main.c").write_text("#include <stdio.h>\nchar* dup_line(const char*);\n"
                              "int main(int c,char**v){ char*d=dup_line(c>1?v[1]:\"x\");"
                              " printf(\"%s\",d); return 0; }\n")
    (d / "Makefile").write_text("app: main.c dup.c\n\t$(CC) $(CFLAGS) main.c dup.c -o app $(LDFLAGS)\n")


def test_is_source_project(tmp_path):
    _make_project(tmp_path)
    assert is_source_project(tmp_path)
    empty = tmp_path / "sub"; empty.mkdir()
    assert not is_source_project(empty)                   # no build file, no sources


def test_build_make_project_is_instrumented(tmp_path, gcc_or_skip):
    _make_project(tmp_path)
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "make" and r["primary"], r["log"][-400:]
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:halt_on_error=1:detect_leaks=0"
    p = subprocess.run([str(r["primary"]), "A" * 64], capture_output=True, env=env, timeout=10)
    assert p.returncode == -6                              # SIGABRT from the sanitizer
    assert b"heap-buffer-overflow" in p.stderr             # ASan classified it


def test_build_loose_multifile(tmp_path, gcc_or_skip):
    # no build file, two source files -> compiled together with sanitizers
    (tmp_path / "a.c").write_text("int helper(int x){ return x + 1; }\n")
    (tmp_path / "b.c").write_text("int helper(int); int main(){ return helper(0); }\n")
    r = build_source_project(tmp_path)
    assert r["ok"] and r["system"] == "loose" and r["primary"]


def test_ingest_source_project(store, case, gcc_or_skip):
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    _make_project(d)
    register()
    t = ingest(store, case.id, d, filename="myproj")
    assert t and t.sha256
    got = TargetDAO(store.conn).get(t.id)
    assert got is not None
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "source-project"]
    assert arts, "the source tree should be archived for the code view + provenance"
    assert arts[0].meta.get("build_system") == "make"


def test_static_detect_runs_on_instrumented_source_binary(store, case, gcc_or_skip):
    """A source file compiles to an ASan+UBSan (PIE) binary whose huge runtime used to make
    _program_only mis-attribute the base and drop the program's own code -- blinding every static
    detector (zero findings). The entry-point consistency guard now keeps analysis running, so a
    source target gets static SAST (here a corroborated CWE-22) in ADDITION to dynamic sanitizer
    findings."""
    import tempfile
    from pathlib import Path
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.detect import enqueue_detect
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    register()
    src = Path(tempfile.mkdtemp()) / "t.c"
    src.write_text("#include <stdio.h>\nint main(int c,char**v){ if(c<2)return 0;"
                   " FILE*f=fopen(v[1],\"r\"); if(f)fclose(f); return 0; }\n")
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, src, filename="t.c")   # source -> ASan-instrumented binary
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
        enqueue_detect(q, t, force=True); assert pool.wait_idle(90)
        rows = store.conn.execute("SELECT cwe,state FROM finding WHERE target_id=?", (t.id,)).fetchall()
        assert rows, "instrumented source binary produced zero static findings (regression)"
        assert any(cwe == "CWE-22" and state == "corroborated" for cwe, state in rows), rows
    finally:
        pool.stop(grace=3.0)
