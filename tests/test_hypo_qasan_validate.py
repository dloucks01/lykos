"""The hypothesis loop's validator on a BINARY (no sanitizer build): a solved input that triggers a
silent heap over-read does not crash natively, so it used to be rejected. The QASan lane confirms
it -- but only when the error is attributed to the hypothesis's own function on every replay."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.dynamic import qasan
from lykos.hypo.model import Hypothesis
from lykos.hypo.validate import Target, validate

pytestmark = pytest.mark.skipif(not qasan.available(), reason="needs afl-qemu-trace + libqasan")

_SRC = r"""
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
__attribute__((noinline)) unsigned long parse(const unsigned char *h, int n) {
  char *b = malloc(16); memset(b, 'x', 16);
  volatile unsigned long s = 0; for (unsigned i = 0; i < h[1]; i++) s += b[i];   /* over-read */
  free(b); return s; }
__attribute__((noinline)) int helper(int x) { return x * 3; }
int main(void){ unsigned char h[8]; int n = read(0, h, 8); if (n < 2 || h[0] != 'Q') return 0;
  return (int)parse(h, n) + helper(n); }
"""


def _sym(exe, name):
    for ln in subprocess.run(["nm", "-S", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = ln.split()
        if len(p) == 4 and p[3] == name:
            return int(p[0], 16), int(p[1], 16)
    return None, None


def _hyp(exe, fn):
    a, n = _sym(exe, fn)
    return Hypothesis(id=f"oob-read@{a:#x}", kind="oob-read", cwe="CWE-125", site=a, func=fn,
                      func_addr=a, func_size=n)


@pytest.mark.parametrize("pie", [True, False], ids=["pie", "nopie"])
def test_silent_overread_validates_via_qasan_in_its_own_function_only(pie, tmp_path, gcc):
    c = tmp_path / "v.c"; c.write_text(_SRC)
    exe = tmp_path / "v"
    flags = ["-pie", "-fPIE"] if pie else ["-no-pie"]
    if subprocess.run([gcc, "-O0", "-w", *flags, str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    t = Target(exe=exe, argv=[], mode="stdin", arch="x86-64")
    bad = b"Q\x40AAAAAA"
    assert subprocess.run([str(exe)], input=bad).returncode != 139   # silent natively
    v, _ = validate(t, _hyp(exe, "parse"), bad)
    assert v.confirmed and v.method == "qasan", v.detail
    # the same input, attributed to a function that does NOT err, must not confirm
    v2, _ = validate(t, _hyp(exe, "helper"), bad)
    assert not v2.confirmed
    # an in-bounds input confirms nothing
    v3, _ = validate(t, _hyp(exe, "parse"), b"Q\x08AAAAAA")
    assert not v3.confirmed


def test_hypo_hunt_stage_confirms_a_silent_heap_read_on_a_plain_binary(store, case, tmp_path, gcc):
    """The autopilot stage, end to end, on Tier-0 o04_heap_read built PLAIN (no ASan, no -g): the
    glyph index reads past malloc(n_glyphs) -- silent natively. The loop must propose it, solve an
    input, and validate it by QASan inside `measure`."""
    from pathlib import Path
    from lykos.analyze import register
    from lykos.analyze.hypo_stage import enqueue_hypo_hunt
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import FindingDAO
    from lykos.hypo import engine
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if engine.angr_python() is None:
        pytest.skip("angr not available")
    src = Path(__file__).resolve().parents[1] / "bench" / "tier0" / "o04_heap_read" / "prog.c"
    exe = tmp_path / "o04"
    if subprocess.run([gcc, "-O0", "-w", "-fno-stack-protector", "-no-pie", str(src), "-o",
                       str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build o04")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, lease_seconds=600,
                                                              poll_interval=0.05))
    pool.start()
    try:
        t = ingest(store, case.id, exe)
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(120)
        run = enqueue_hypo_hunt(q, t, params={"input_mode": "file", "argv": ["@@"],
                                              "budget": 150, "mem_mb": 8192})
        assert pool.wait_idle(600)
        rec = q.runs.get(run.id)
        assert rec.status == "done", rec.error
    finally:
        pool.stop(grace=3.0)
    hy = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "hypo"]
    done = store.conn.execute("SELECT payload_json FROM event WHERE type='hypo.done'").fetchall()
    assert hy, f"no hypothesis validated: {[r[0] for r in done]}"
    assert any("measure" in f.title and f.state == "confirmed" for f in hy), [f.title for f in hy]
    for f in hy:
        print("HYPO-FINDING", f.cwe, f.title, [e.get("detail") for e in f.evidence
                                               if e.get("channel") == "validated"])
