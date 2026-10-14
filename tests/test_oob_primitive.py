"""An out-of-bounds ACCESS as an exploitation primitive (chain link 5, doc 35).

On a sanitizer build there is nothing in the registers to find: ASan aborts inside its own
runtime, so the fault-time pc belongs to the reporting machinery, and both register-based steps
of `poc_primitive` -- instruction-pointer control and write-what-where -- can say nothing. The
stage fell through to "crash reproduced but no controllable primitive found", which is
technically true and completely empty: libtiff's `putRGBcontig8bittile` heap out-of-bounds READ,
a real and reachable information disclosure, got no verdict at all because every verdict on
offer was about controlling the instruction pointer.

The primitive for this class is in the REPORT, and the experiment is to vary the input and watch
how far past the end of the object the access goes.
"""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug.rootcause import parse_asan_report
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_primitive
from lykos.analyze.poc import primitive as P
from lykos.db.dao import ArtifactDAO, FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# A real clang 21 report, kept verbatim. The wording of the region line changed across releases
# ("5 bytes after" today, "5 bytes to the right of" in older clang), and a parser that matches
# neither reports an overflow with no magnitude -- which reads exactly like a tool that looked
# and found nothing to say.
_READ_REPORT = """=================================================================
==1801822==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b75737e0059 at pc \
0x563608545b6a bp 0x7ffff201ad00 sp 0x7ffff201acf8
READ of size 1 at 0x7b75737e0059 thread T0
    #0 0x563608545b69 in main /tmp/oob.c:9:12
    #1 0x7f45744bdfb9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:59:16

0x7b75737e0059 is located 5 bytes after 20-byte region [0x7b75737e0040,0x7b75737e0054)
allocated by thread T0 here:
    #0 0x563608501908 in malloc (/tmp/oob+0xd1908)

SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/oob.c:9:12 in main
"""
_WRITE_REPORT = _READ_REPORT.replace("READ of size 1", "WRITE of size 1")
_OLD_WORDING = _READ_REPORT.replace("is located 5 bytes after",
                                    "is located 5 bytes to the right of")


def test_the_report_states_the_direction_and_the_magnitude():
    r = parse_asan_report(_READ_REPORT)
    assert r["access"] == "read" and r["access_size"] == 1
    assert r["distance"] == 5 and r["side"] == "after" and r["region_size"] == 20


def test_both_clang_wordings_of_the_region_line_are_read():
    assert parse_asan_report(_OLD_WORDING)["distance"] == 5
    assert parse_asan_report(_OLD_WORDING)["side"] == "after"


def test_a_read_is_not_reported_as_a_write():
    """`heap-buffer-overflow` is ASan's name for a one-byte READ past the end AND for a wild
    WRITE, and both resolved to CWE-122 at severity CRITICAL. A read discloses or crashes; it
    does not corrupt. Calling it critical spends the reader's attention on the wrong finding."""
    rd, wr = parse_asan_report(_READ_REPORT), parse_asan_report(_WRITE_REPORT)
    assert (rd["cwe"], rd["severity"]) == ("CWE-125", "high")
    assert (wr["cwe"], wr["severity"]) == ("CWE-122", "critical")
    assert "READ of size 1" in rd["detail"] and "WRITE of size 1" in wr["detail"]


def _rep(distance, access="read", cls="heap-buffer-overflow"):
    return {"class": cls, "access": access, "distance": distance, "region_size": 20,
            "access_size": 1}


def test_a_distance_that_moves_with_the_input_is_a_confirmed_primitive():
    prim = P.oob_access_primitive([("orig", _rep(1)), ("byte@0x0=0xff", _rep(7))])
    assert prim["type"] == "controlled-oob-read"
    assert prim["confirmed"] and (prim["distance_min"], prim["distance_max"]) == (1, 7)
    assert "attacker chooses how far to read" in P.oob_effect(prim)


def test_a_fixed_distance_is_reported_as_unproven_not_as_control():
    """The costlier of the two mistakes: claiming the reach is attacker-chosen when the
    experiment did not show it makes every other claim in the report worth less."""
    prim = P.oob_access_primitive([("orig", _rep(5)), ("byte@0x0=0xff", _rep(5))])
    assert prim["type"] == "oob-read" and not prim["confirmed"]
    assert "did not move with the input" in P.oob_effect(prim)


def test_variants_that_provoked_a_different_defect_are_not_averaged_in():
    """A variant that trips a DIFFERENT bug is not evidence about this one; mixing them would
    describe a defect that does not exist."""
    prim = P.oob_access_primitive([
        ("orig", _rep(5)),
        ("byte@0x2=0xff", _rep(80, access="write")),
        ("byte@0x3=0xff", _rep(9, cls="stack-buffer-overflow"))])
    assert prim["access"] == "read" and prim["type"] == "oob-read"
    assert [o["variant"] for o in prim["observations"]] == ["orig"]


def test_a_use_after_free_is_not_an_out_of_bounds_reach():
    """Its distance is an offset INSIDE a freed region, which says nothing about how far an
    attacker can reach."""
    assert P.oob_access_primitive([("orig", _rep(5, cls="heap-use-after-free"))]) is None
    assert P.oob_access_primitive([("orig", {"class": "SEGV"})]) is None
    assert P.oob_access_primitive([]) is None


# ------------------------------------------------------------------- integration
#: The distance past the end is chosen by the FIRST INPUT BYTE, masked into the redzone so every
#: variant still faults. This is the shape the verdict exists for: a value in the input sets how
#: far out of bounds the read goes.
_OOB_READ = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int sink;
int main(void){
    unsigned char hdr[4];
    if (fread(hdr, 1, 4, stdin) != 4) return 0;
    char *p = malloc(20);
    memset(p, 'A', 20);
    sink = p[20 + (hdr[0] & 7)];
    printf("%d\\n", sink);
    return 0;
}
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=180, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_a_controlled_oob_read_becomes_an_l2_primitive_end_to_end(store, case, pool, tmp_path):
    import shutil
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("no clang for a sanitizer build")
    c = tmp_path / "oob.c"; c.write_text(_OOB_READ)
    b = tmp_path / "oob"
    if subprocess.run([clang, "-g", "-O0", "-fsanitize=address", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("sanitizer build failed")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"\x05BBB")          # faults 5 bytes past the end
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 10})
    assert pool.wait_idle(240)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable in this environment: " + str(rec.error))

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "a reproducible out-of-bounds read produced no PoC at all"
    l2 = [p for p in pocs if p.level == "L2" and p.verified]
    assert l2, f"no verified L2 for a controlled out-of-bounds read (got {[p.level for p in pocs]})"

    # the finding says what the defect DOES, not merely that it crashed
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed
    assert any("out-of-bounds read" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or [])), \
        "the primitive was found but the finding never names the effect"
    assert any(f.cwe == "CWE-125" for f in backed), \
        "an out-of-bounds READ was not labelled CWE-125"

    # the bundle has to carry the experiment, not just the claim
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "poc-bundle"]
    assert arts
    import io
    import tarfile
    out = tmp_path / "unpacked"
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(arts[-1].sha256))) as tf:
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
        tf.extractall(out)
    assert "Attacker-controlled distance: True" in txt, txt[:400]
    assert "-> distance" in txt, "the bundle states the claim without the variants behind it"

    # And it has to REPRODUCE somewhere else. A sanitizer build does not die on a signal by
    # default -- ASan prints its report and calls _exit(1) -- so a bundle that does not export
    # abort_on_error hands the operator exit 1 where its own README promises 134, and the PoC
    # reads as broken. The only check that sees this runs the script and reads $?.
    rc = subprocess.run(["sh", "./runner.sh"], cwd=out / "poc", capture_output=True,
                        check=False)
    assert rc.returncode == 134, (rc.returncode, rc.stdout[-400:], rc.stderr[-400:])
    assert b"heap-buffer-overflow" in rc.stderr, "the shipped reproducer lost the report"
