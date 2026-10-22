"""(b) buffer-pointer-param taint (doc 46). The daemon-parser gap: a parser reached only through a
callback / dispatch table has NO static call edge from an input source, so the source->sink flow
never reaches it and its sinks are invisible. The engine CAN propagate taint from a seeded
buffer-pointer param (test 1); the stage just never seeded a non-`main` entry -- so the ranked
parser's buffer param is seeded as attacker-controlled (test 2), recovering the injection.
Findings are CANDIDATES (attacker-reachability assumed). Gated by LYKOS_BUFFER_SEED."""
import os
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import bounds, taint
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.harness.rank import rank_functions
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# A packet handler reached through a FUNCTION POINTER (no static call edge main->handle), reading a
# length byte from its pointer-param buffer and using it as a memcpy size -- the classic
# callback-reached daemon parser.
_SRC = r"""
#include <unistd.h>
#include <string.h>
char dst[16];
__attribute__((noinline)) void handle(char *buf){
  unsigned n = (unsigned char)buf[0];   /* length byte read FROM the pointer-param buffer */
  memcpy(dst, buf + 1, n);              /* sink: size from attacker buffer contents */
}
static void (* volatile dispatch)(char *) = handle;   /* registered indirectly */
/* main takes argc/argv, so entry_seeds is non-empty and the stage does NOT fall back to seeding
   every export -- which is what a real daemon looks like, and what makes handle() (a callback-
   reached export) UNSEEDED until the buffer-pointer seed. */
int main(int argc, char **argv){
  (void)argv;
  char pkt[256];
  int k = read(0, pkt, sizeof(pkt));
  if (k <= 0 || argc < 0) return 1;
  dispatch(pkt);                        /* INDIRECT call -> no static edge to handle() */
  return 0;
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _prep(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    c = tmp_path / "d.c"
    c.write_text(_SRC)
    out = tmp_path / "d"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="d")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    arch = TargetDAO(store.conn).get(t.id).arch
    fdao = FunctionDAO(store.conn)
    irs, names = {}, {}
    for f in fdao.list_by_target(t.id):
        full = fdao.get(f.id)
        if full and full.ir:
            irs[f.addr] = full.ir
        names[f.addr] = f.name
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)
    return t, arch, irs, names, edges


def _handle_sites(irs, names, flagged):
    return {ins["addr"]
            for fa, ir in irs.items() if (names.get(fa) or "").endswith("handle")
            for b in (ir or {}).get("blocks", []) for ins in b.get("instructions", [])
            if ins.get("addr") in flagged}


def test_buffer_seed_recovers_a_callback_reached_parser(store, case, pool, tmp_path):
    t, arch, irs, names, edges = _prep(store, case, pool, tmp_path)
    handle_fa = next((fa for fa, nm in names.items() if (nm or "").endswith("handle")), None)
    assert handle_fa is not None, "decompiler did not recover handle()"

    # WITHOUT the buffer seed: handle() is an orphan (reached only indirectly), so the source->sink
    # flow from main never reaches it -- its memcpy is invisible.
    off = taint.analyze_program(irs, edges, arch)
    assert not _handle_sites(irs, names, off), \
        "baseline: a callback-reached parser must NOT be reached by the normal source->sink flow"

    # The ranker finds handle() by its own shape (pointer param + a memcpy sink); seed its buffer
    # param as attacker-controlled -- exactly what _parser_buffer_seeds does under LYKOS_BUFFER_SEED.
    ranked = rank_functions(store.conn, t.id, top=40)
    rf = next((r for r in ranked if (r.name or "").endswith("handle")), None)
    assert rf is not None and rf.sinks, f"ranker should flag handle() as a parser: {ranked[:3]}"
    # recovered pointer param, or arg 0 on a stripped build (what _parser_buffer_seeds does). Key
    # by the IR address (handle_fa) so it matches func_irs keys -- the ranker's int addr would not.
    seeds = {handle_fa: set(rf.ptr_params) if rf.ptr_params else {0}}

    on = taint.analyze_program(irs, edges, arch, entry_seeds=seeds)
    assert _handle_sites(irs, names, on), \
        "buffer-pointer seed must recover the memcpy in the callback-reached parser"
    # the new site is NOT in the baseline -> it is tiered a CANDIDATE by the stage, not corroborated
    assert _handle_sites(irs, names, on) - _handle_sites(irs, names, off)


def test_buffer_seed_stage_files_an_honest_candidate(store, case, pool, tmp_path, monkeypatch):
    """End to end through detect_cwe: with the seed OFF the callback-reached parser files nothing;
    with it ON a CANDIDATE (never corroborated) carries the taint-buffer-param evidence."""
    from lykos.analyze.detect.stage import enqueue_detect
    from lykos.db.dao import FindingDAO
    t, arch, irs, names, edges = _prep(store, case, pool, tmp_path)
    q = JobQueue(store.conn)

    def _buf_param_findings():
        enqueue_detect(q, t, force=True)
        assert pool.wait_idle(120)
        return [f for f in FindingDAO(store.conn).list_by_target(t.id)
                if any((e or {}).get("channel") == "taint-buffer-param" for e in (f.evidence or []))]

    monkeypatch.delenv("LYKOS_BUFFER_SEED", raising=False)
    assert not _buf_param_findings(), "no buffer-param candidate should be filed when the seed is off"

    monkeypatch.setenv("LYKOS_BUFFER_SEED", "1")
    on = _buf_param_findings()
    assert on, "the buffer seed should file a candidate for the callback-reached parser"
    assert all(f.state != "corroborated" for f in on), \
        "buffer-param findings are candidates (attacker-reachability assumed), never corroborated"
