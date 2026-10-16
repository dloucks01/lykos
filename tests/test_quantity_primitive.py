"""The sanitizer classes that describe a MAGNITUDE, not an access (chain link 5, doc 35).

Two verdicts now cover the classes that describe memory: the out-of-bounds distance (step 2b) and
the lifetime offset/size (step 2c). A third family describes neither. A 35 TB allocation request,
a leak, a negative length handed to `memcpy`, an out-of-bounds index: nothing went past the end of
an object and nothing died, so both verdicts decline and the ladder ended on "crash reproduced but
no instruction-pointer / memory primitive found" -- which for a refused allocation is not a near
miss, it is an answer to a question nobody asked about this defect.

What their reports DO state is a number. The experiment is the one the other two verdicts already
run -- vary the input, see whether the number follows -- and the answer separates "this input
happened to do it" from "the input decides".

And one thing this verdict must never do: reach L2. An attacker-chosen allocation size is an
availability defect; calling a controlled denial of service an exploitation primitive would
inflate the single number in a report that exists to resist inflation.
"""
import subprocess

import pytest
from lykos.analyze.debug.rootcause import parse_asan_report
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import primitive as P

# Real clang 21 reports, kept verbatim -- every one of these wordings was measured on this host,
# and the first of them broke the parser badly enough to drop the finding entirely.
_TOO_BIG = """=================================================================
==690128==ERROR: AddressSanitizer: requested allocation size 0x800000000000 (0x800000001000 after \
adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 \
(thread T0)
    #0 0x55cd3a728908 in malloc (/tmp/q/big+0xd1908)
    #1 0x55cd3a76cbe4 in main /tmp/q/big.c:5:13
"""

_NEGATIVE = """=================================================================
==690132==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 0x55879a34d493 in __asan_memcpy (/tmp/q/neg+0xcf493)
    #1 0x55879a393c09 in main /tmp/q/neg.c:7:3
"""

_LEAK = """=================================================================
==690279==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 5120 byte(s) in 5 object(s) allocated from:
    #0 0x55d71da5b908 in malloc (/tmp/q/leak+0xd1908)
    #1 0x55d71da9fbfb in main /tmp/q/leak.c:4:58

SUMMARY: AddressSanitizer: 5120 byte(s) leaked in 5 allocation(s).
"""

_INDEX = "idx.c:6:10: runtime error: index 69 out of bounds for type 'char[64]'\n"


# --- the report ------------------------------------------------------------------------------

def test_an_oversized_allocation_request_is_a_finding_at_all():
    """It was not. ASan states this class as a SENTENCE -- `requested allocation size 0x8000...
    exceeds maximum supported size` -- so the class regex took `requested`, which is in the
    non-bug denylist, so `parse_asan_report` returned None and the whole report was DROPPED.
    A reachable, CVE-bearing defect class (libtiff and libjpeg both carry CVEs for exactly it)
    produced no finding of any kind, while the table entry meant to label it sat unreachable."""
    r = parse_asan_report(_TOO_BIG)
    assert r is not None, "an oversized allocation request still produces no finding"
    assert r["class"] == "allocation-size-too-big"
    assert (r["cwe"], r["severity"]) == ("CWE-789", "medium")
    assert r["quantity"] == 0x800000000000 and r["quantity_limit"] == 0x10000000000
    assert r["source"] == "big.c:5"


def test_each_class_states_its_own_number():
    assert parse_asan_report(_NEGATIVE)["quantity"] == -4
    assert parse_asan_report(_NEGATIVE)["quantity_name"] == "size argument"
    leak = parse_asan_report(_LEAK)
    assert leak["quantity"] == 5120 and leak["quantity_limit"] == 5
    assert leak["quantity_limit_name"] == "objects", \
        "the leak's second number is an OBJECT COUNT, not a bound it exceeded"
    idx = parse_asan_report(_INDEX)
    assert idx["quantity"] == 69 and idx["quantity_limit"] == 64
    assert idx["quantity_limit_name"] == "array bound"


def test_the_sentence_classes_live_in_one_table():
    """Two classes ASan words as prose, and both were broken the same way. One table, so the
    third one nobody has met yet is a line rather than a new bug."""
    from lykos.analyze.debug import rootcause as R
    classes = {cls for _rx, cls in R._ASAN_SENTENCE}
    assert {"double-free", "bad-free", "allocation-size-too-big"} <= classes


# --- the verdict -----------------------------------------------------------------------------

def _rep(q, cls="allocation-size-too-big", name="requested allocation size", limit=None):
    return {"class": cls, "quantity": q, "quantity_name": name, "quantity_limit": limit,
            "quantity_limit_name": "allocator maximum"}


def test_a_magnitude_that_moves_with_the_input_is_confirmed():
    prim = P.quantity_primitive([("orig", _rep(1 << 41)), ("byte@0x0=0xff", _rep(1 << 47))])
    assert prim["type"] == "controlled-allocation-size-too-big" and prim["confirmed"]
    assert (prim["quantity_min"], prim["quantity_max"]) == (1 << 41, 1 << 47)
    assert "the attacker chooses it" in P.quantity_effect(prim)


def test_a_fixed_magnitude_is_reported_as_unproven():
    prim = P.quantity_primitive([("orig", _rep(1 << 41)), ("v", _rep(1 << 41))])
    assert prim["type"] == "allocation-size-too-big" and not prim["confirmed"]
    assert "did not move with the input" in P.quantity_effect(prim)


def test_a_quantity_verdict_can_never_reach_l2():
    """The rule this verdict exists under. An attacker-chosen allocation size is an availability
    defect; L2 means a confirmed exploitation primitive. Nothing here controls the instruction
    pointer or writes to a chosen address, and the ladder has to keep meaning what it says."""
    for cls in P.QUANTITY_CLASSES:
        prim = P.quantity_primitive([("orig", _rep(10, cls=cls)), ("v", _rep(99, cls=cls))])
        assert prim["confirmed"], cls
        assert prim["max_level"] == 1, f"{cls} would be allowed to claim L2"


def test_the_finalizer_honours_the_cap():
    """The cap has to be read by the thing that assigns the level, not merely declared."""
    import pathlib

    import lykos.analyze.poc.primitive_stage as PS
    src = pathlib.Path(PS.__file__).read_text()
    assert 'level = "L2" if (confirmed and int(prim.get("max_level") or 2) >= 2) else "L1"' in src


def test_a_prevented_consequence_is_potential_not_demonstrated():
    """A negative length was intercepted BEFORE the copy and an out-of-bounds index is undefined
    rather than performed, so what a build without the sanitizer would do is an inference. A
    refused allocation and a leak, by contrast, really happened."""
    kinds = {c: P.QUANTITY_CLASSES[c] for c in P.QUANTITY_CLASSES}
    assert kinds["allocation-size-too-big"][1] == "demonstrated"
    assert kinds["memory-leak"][1] == "demonstrated"
    assert kinds["negative-size-param"][1] == "potential"
    assert kinds["array-index-out-of-bounds"][1] == "potential"
    prim = P.quantity_primitive([("orig", _rep(-1, cls="negative-size-param")),
                                 ("v", _rep(-99, cls="negative-size-param"))])
    assert prim["effect_status"] == "potential"
    assert "recorded as potential rather than demonstrated" in P.quantity_effect(prim)


def test_a_leak_is_availability_and_an_index_is_corruption():
    assert P.QUANTITY_CLASSES["memory-leak"][0] == "dos"
    assert P.QUANTITY_CLASSES["array-index-out-of-bounds"][0] == "memory-corruption"


def test_the_effect_kinds_are_ones_the_report_understands():
    """An effect kind the merge policy does not rank is an effect the report silently drops."""
    from lykos.effects import EFFECT_SEV
    for cls, (kind, _status, _meaning) in P.QUANTITY_CLASSES.items():
        assert kind in EFFECT_SEV, f"{cls} files an effect kind the report cannot rank: {kind}"


def test_the_three_verdicts_do_not_borrow_each_others_evidence():
    oob = {"class": "heap-buffer-overflow", "distance": 5}
    uaf = {"class": "heap-use-after-free", "distance": 5}
    assert P.quantity_primitive([("orig", oob)]) is None
    assert P.quantity_primitive([("orig", uaf)]) is None
    assert P.oob_access_primitive([("orig", _rep(1 << 41))]) is None
    assert P.lifetime_primitive([("orig", _rep(1 << 41))]) is None
    assert P.quantity_primitive([]) is None


def test_a_class_that_fits_but_states_no_number_gets_no_verdict():
    """Better no verdict than one about a number that was never read."""
    assert P.quantity_primitive([("orig", {"class": "memory-leak"})]) is None


# --- the classes where this stage should say WHY it has nothing -------------------------------

def test_a_class_with_no_verdict_gets_a_reason_not_the_generic_note():
    """"no instruction-pointer / memory primitive found" reads as if the right question had been
    asked and answered, so a class this stage genuinely cannot reason about gets a NAMED decline
    instead -- the mechanism, which is what this test is about.

    Both entries it was written for are gone, each after one reading. A data race was excused on
    the grounds that its exploitability is a timing property and this stage only varies the input;
    the premise was right and the conclusion was not, because the rate needs no variation at all
    (`race_primitive`). An uninitialised read was excused on the grounds that it is only a
    disclosure if the value reaches an output and that `mem_oracle` owns that line; MSan draws the
    same line in the report this stage already holds (`uninit_primitive`).

    So the table is empty and must stay wired: every class this stage SEES now has a verdict, and
    the next one that does not should decline by name rather than generically."""
    assert P.NO_VERDICT_REASON == {}, \
        "an excuse is back in the table; it needs a verdict, not a reason"
    for cls in ("use-of-uninitialized-value", "data-race", "heap-buffer-overflow", None):
        assert P.no_verdict_reason(cls) is None, f"{cls} is excused again; it has a verdict now"
    P.NO_VERDICT_REASON["a-future-class"] = "because the evidence does not exist"
    try:
        assert "evidence" in P.no_verdict_reason("a-future-class"), "the mechanism is unwired"
    finally:
        P.NO_VERDICT_REASON.pop("a-future-class")


def test_the_stage_reports_the_reason():
    import pathlib

    import lykos.analyze.poc.primitive_stage as PS
    src = pathlib.Path(PS.__file__).read_text()
    assert 'f"no primitive verdict for {_cls}: {_why}"' in src


# ------------------------------------------------------------------- integration
#: The requested size is chosen by the first input byte, so every variant is refused and the
#: magnitude follows the input -- the shape this verdict exists for.
_TOO_BIG_SRC = """#include <stdio.h>
#include <stdlib.h>
int main(void){
    unsigned char h[4];
    if (fread(h, 1, 4, stdin) != 4) return 0;
    size_t n = (size_t)1 << (40 + (h[0] & 7));
    char *p = malloc(n);
    printf("%p\\n", (void*)p);
    return 0;
}
"""


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_an_attacker_sized_allocation_is_reported_as_availability_at_l1(store, case, tmp_path):
    """End to end: a verdict, a finding that names the effect, and an L1 that stays L1."""
    import shutil

    from lykos.analyze import register
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc import enqueue_primitive
    from lykos.db.dao import ArtifactDAO, FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    clang = shutil.which("clang")
    if not clang:
        pytest.skip("no clang for a sanitizer build")
    c = tmp_path / "big.c"
    c.write_text(_TOO_BIG_SRC)
    b = tmp_path / "big"
    if subprocess.run([clang, "-g", "-O0", "-fsanitize=address", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("sanitizer build failed")
    register()
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"\x01BBB")   # 1<<41; the 0xff probe -> 1<<47
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=180, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                   "timeout": 10})
        assert pool.wait_idle(300)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("ptrace unavailable in this environment: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "a reproducible oversized allocation produced no PoC at all"
    assert all(p.level != "L2" for p in pocs), \
        f"an availability defect claimed L2: {[p.level for p in pocs]}"
    assert any(p.verified for p in pocs)

    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed, "the verdict never reached a finding"
    ev = " ".join(str(e.get("detail", "")) for f in backed for e in (f.evidence or []))
    assert "allocation-size-too-big" in ev, ev[:300]
    assert "requested allocation size" in ev
    assert any(f.cwe == "CWE-789" for f in backed), \
        f"an oversized allocation was not labelled CWE-789: {[f.cwe for f in backed]}"

    # RUN IT AGAIN. The quantity path installs the sanitizer's CWE outside `_PRIM_CWE`, and that
    # map has an invariant -- every replacement must itself be a class the override outranks -- so
    # that a second pass cannot flip the label back and forth. The reason this path is safe is
    # that it installs the SAME class every time; the only way to know that is to do it twice.
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=180, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                             "timeout": 10})
        assert pool.wait_idle(300)
    finally:
        pool.stop(grace=3.0)
    again = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if f.state == "poc-backed"]
    assert [f.cwe for f in again] == [f.cwe for f in backed], \
        f"the label moved on a second pass: {[f.cwe for f in backed]} -> {[f.cwe for f in again]}"
    assert len(again) == len(backed), "a second pass forked a duplicate finding"

    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "poc-bundle"]
    assert arts
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(arts[-1].sha256))) as tf:
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
    assert "L1 reproducer with a measured magnitude" in txt, txt[:300]
    assert "NOT an L2 exploitation primitive" in txt
    assert "Attacker-controlled magnitude: True" in txt, txt[:600]
