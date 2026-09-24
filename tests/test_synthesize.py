"""Phase 6 — directed overflow-PoC synthesis: turn a static CWE-121 (recovered stack frame)
into a reproduced crash + verified L1 PoC without fuzzing."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_synthesize
from lykos.db.dao import FindingDAO, FunctionDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# reads far more than the buffer holds -> a return-address overwrite on return
_VULN = ("#include <unistd.h>\n"
         "void vuln(void){char b[64];read(0,b,400);}\n"
         "int main(void){vuln();return 0;}\n")


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


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="native detonation only")
def test_synthesize_overflow_poc_without_fuzzing(store, case, pool, gcc, tmp_path):
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(b)],
                       capture_output=True, check=False)
    if r.returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    # seed the recovered frame directly (stands in for the Ghidra decompile): a 64-byte
    # stack buffer -> predicted return-address offset ~72 (ret_offset 0, buffer at -72)
    FunctionDAO(store.conn).replace_for_target(target.id, [{
        "addr": "0x1149", "name": "vuln", "size": 60, "blocks": 1, "edges": 0,
        "signature": "void vuln(void)",
        "frame": {"ret_offset": 0, "vars": [
            {"name": "b", "offset": -72, "size": 64, "type": "char[64]", "is_buffer": True}]},
        "cfg": {"blocks": []}}])

    q = JobQueue(store.conn)
    run = enqueue_synthesize(q, target, params={"timeout": 6})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("sandbox/ptrace unavailable: " + str(rec.error))

    # a verified L1 PoC was produced with no fuzzing, and the finding is poc-backed
    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs and pocs[0].verified and pocs[0].level == "L1" and pocs[0].bundle_sha
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed
    assert any("synthesized from static" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or []))
    # The synthesized crash is recorded as a first-class crashing dyn_result, so the autopilot's
    # prove/exploit phase (which selects crashes from dyn_results) can build L2/L3 on it instead of
    # stalling at L1. Regression: synthesis used to file only the Poc + Finding, never the crash row.
    from lykos.db.dao import DynResultDAO
    crashes = [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
    assert crashes and crashes[0].input_sha == pocs[0].input_sha
    assert crashes[0].input_mode == "stdin"        # read(0, ...) overflow: swept to the stdin channel


def test_synthesize_reports_when_no_frame(store, case, pool, gcc, tmp_path):
    """With no recovered stack buffers, the stage says so (doesn't fabricate a PoC)."""
    c = tmp_path / "ok.c"; c.write_text("int main(void){return 0;}\n")
    b = tmp_path / "ok"
    if subprocess.run([gcc, str(c), "-o", str(b)], capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_synthesize(q, target, params={"timeout": 4})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    assert not PocDAO(store.conn).list_by_target(target.id)   # nothing fabricated
