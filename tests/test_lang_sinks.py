"""Go / Rust language-aware detection. These languages are memory-safe, so their bugs are
INJECTION / TRAVERSAL / SSRF through the standard library (a runtime command, path, SQL, URL from
untrusted input), not overflows. The C data-flow taint does not apply, but the retained call graph
does: flag the stdlib sink and corroborate when an untrusted-input source reaches it."""
from __future__ import annotations

import shutil
import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import DetectContext, lang_sinks
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest, enqueue_triage
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _edges(*pairs):
    return [types.SimpleNamespace(dst_name=d, src_addr=s, dst_addr=da, site_addr=s)
            for (d, s, da) in pairs]


def test_lang_sinks_unit_go_reachable():
    # main (reads a stdin source) -> handler -> os_exec.Command ; source reaches the sink
    edges = _edges(("runtime.main", "0x1", "0x2"),
                   ("bufio._Reader_.ReadString", "0x10", None),   # source called by main(0x10)
                   ("main.handler", "0x10", "0x20"),              # main -> handler
                   ("os_exec.Command", "0x20", None))             # handler -> Command (sink)
    ctx = DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[], toolchain="go")
    out = lang_sinks(ctx)
    cwe78 = [c for c in out if c["cwe"] == "CWE-78"]
    assert cwe78 and cwe78[0]["state"] == "corroborated"


def test_lang_sinks_unit_go_candidate_when_no_source():
    edges = _edges(("runtime.main", "0x1", "0x2"), ("os_exec.Command", "0x20", None))
    ctx = DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[], toolchain="go")
    out = lang_sinks(ctx)
    assert out and all(c["state"] == "candidate" for c in out)


def test_lang_sinks_skips_non_go_rust():
    edges = _edges(("system", "0x1", None), ("os_exec.Command", "0x20", None))
    ctx = DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[], toolchain="gcc")
    assert lang_sinks(ctx) == []                              # not Go/Rust: no runtime.* either


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("native x86-64 only")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_go_command_injection_e2e(store, case, pool, tmp_path, x86_64_only):
    if not shutil.which("go"):
        pytest.skip("no go toolchain")
    (tmp_path / "m.go").write_text(
        "package main\nimport (\"bufio\"; \"os\"; \"os/exec\"; \"fmt\")\n"
        "func main(){ r:=bufio.NewReader(os.Stdin); line,_:=r.ReadString('\\n');"
        " out,_:=exec.Command(\"sh\",\"-c\",\"echo \"+line).Output(); fmt.Print(string(out)) }\n")
    exe = tmp_path / "gobin"
    if subprocess.run(["go", "build", "-o", str(exe), str(tmp_path / "m.go")],
                      capture_output=True, cwd=str(tmp_path)).returncode != 0:
        pytest.skip("go build failed")
    t = ingest(store, case.id, exe, filename="gobin")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(200)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    rows = store.conn.execute("SELECT state FROM finding WHERE target_id=? AND cwe='CWE-78' "
                              "AND detector='lang_sinks'", (t.id,)).fetchall()
    assert any(state == "corroborated" for (state,) in rows), rows
