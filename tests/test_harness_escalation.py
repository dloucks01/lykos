"""The harness -> L3 bridge (doc 46 / Agent-C gap): a harness FUNCTION-level crash is replayed
against the WHOLE program and, when the program also faults, recorded as a real DynResult crash so
the existing exploit ladder (root_cause -> build_poc -> poc_primitive -> build_exploit) can escalate
it -- the one non-pipeline capability can now reach L3.

Honesty is the point: the DynResult is written ONLY from a real execution of the program, so L3 is
reached only when the program genuinely crashes; a function that does not reproduce at the program
level leaves a non-crash seed, never a fabricated crash.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.harness.harness_stage import enqueue_harness
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# A drivable internal parser that overflows, reachable from main over stdin, plus a win() so the
# ladder has an L3 to reach. The harness drives parse() directly (ptr+len), faulting at the function
# level; feeding the SAME bytes to stdin makes main() call parse(in, n) with the same n -> the whole
# program faults, which is what the replay must capture as a program-level DynResult crash.
_SRC = r"""
#include <unistd.h>
#include <string.h>
__attribute__((used)) void win(void){ write(1,"LYKOS-WIN\n",10); _exit(7); }
void parse(const char *s, long n){
    char b[32];
    if (n >= 4 && *(const unsigned *)s == 0x4f4b594cu) {   /* a 4-byte "LYKO" magic gate */
        memcpy(b, s, 256);                                 /* fixed oversized copy -> smash b[32] */
        write(1, b, 1);
    } else { write(1, s, n > 1 ? 1 : n); }
}
int main(void){ static char in[1<<12]; long n = read(0, in, sizeof in); if (n > 0) parse(in, n); return 0; }
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


def test_harness_crash_becomes_a_program_level_dynresult(store, case, pool, gcc, tmp_path):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the harness executor + native replay are x86-64 only")
    c = tmp_path / "v.c"
    c.write_text(_SRC)
    out = tmp_path / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    # harness on-demand (the non-pipeline capability), with stdin as the delivery channel
    enqueue_harness(q, t, params={"input_mode": "stdin"}, force=True)
    assert pool.wait_idle(180)

    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "harness"]
    assert hits, "harness filed no function-level finding on an obvious memcpy overflow"

    # The bridge: at least one function-level crash reproduced at the PROGRAM level and was recorded
    # as a real DynResult crash -- the row the prove-ladder consumes (_distinct_crashes).
    crash_rows = [d for d in DynResultDAO(store.conn).list_by_target(t.id)
                  if d.crashed and d.input_sha and "harness-replay" in (d.note or "")]
    assert crash_rows, "harness function-level crash did not reproduce as a program-level DynResult"

    # ...and the finding is raised to confirmed by the program-level channel (a channel can only RAISE).
    confirmed = [f for f in hits if (f.state or "") in ("confirmed", "poc-backed")]
    assert confirmed, "a program-level reproduction must raise the harness finding to >= confirmed"


# A SMALL heap overflow: parse() copies the whole input into a 16-byte heap chunk. Natively the
# program does not crash (glibc's chunk slack absorbs a few bytes), so the native replay alone
# would leave the lead function-level. The redzone heap catches it in the emulator, and QASan
# reproduces it on the WHOLE program inside parse() -- the program-level confirmation channel.
_SRC_HEAP = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void parse(const char *s, long n){
    char *p = malloc(16);
    if (!p) return;
    if (n > 0) memcpy(p, s, n < 40 ? n : 40);   /* bounded at 40: past 16 is a heap overflow */
    write(1, p, 1);
    free(p);
}
int main(void){ static char in[64]; long n = read(0, in, sizeof in); if (n > 0) parse(in, n); return 0; }
"""


def test_small_heap_overflow_is_confirmed_at_program_level_by_qasan(store, case, pool, gcc,
                                                                     tmp_path):
    from lykos.analyze.dynamic import qasan
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the harness executor is x86-64 only")
    if not qasan.available():
        pytest.skip("QASan (afl-qemu-trace + libqasan) not available")
    c = tmp_path / "h.c"
    c.write_text(_SRC_HEAP)
    out = tmp_path / "h"
    if subprocess.run([gcc, "-no-pie", "-O0", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="h")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_harness(q, t, params={"input_mode": "stdin", "sequence": False}, force=True)
    assert pool.wait_idle(240)

    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "harness"]
    heap = [f for f in hits if f.cwe == "CWE-122"]
    assert heap, [(f.cwe, f.title) for f in hits]
    # no native crash row: the program survives the overflow natively...
    assert not [d for d in DynResultDAO(store.conn).list_by_target(t.id)
                if d.crashed and "harness-replay" in (d.note or "")]
    # ...but QASan reproduced it inside parse() on the whole program
    assert any((f.state or "") == "confirmed" for f in heap), [(f.state, f.title) for f in heap]
