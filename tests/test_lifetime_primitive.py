"""A use-after-free and a double free as exploitation primitives (chain link 5, doc 35).

The out-of-bounds verdict closed half of this link: on a sanitizer build the registers belong to
the reporting machinery, so the primitive has to come out of the REPORT, and the experiment is to
vary the input and watch how far past the end of the object the access goes.

That question has no meaning for a dead object. A use-after-free's distance is an offset INSIDE a
freed chunk, and a double free has no access to measure at all -- so both classes fell through to
"crash reproduced but no instruction-pointer / memory primitive found", the same empty verdict an
out-of-bounds read used to get, on every sanitizer build. Doc 35 listed it as the second-weakest
link.

Two questions decide whether a lifetime defect is a primitive, and the report answers both: does
the attacker choose WHICH PART of the stale chunk is touched, and HOW BIG the chunk is (the size
class decides what can reclaim it). Neither claims that reuse happened -- ASan quarantines the
chunk, which is how the use is caught in the first place.
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

# Real clang 21 reports, kept verbatim. Both wordings below were measured on this machine, and
# both broke the parser in a way that reads like a tool with nothing to say.
_UAF = """=================================================================
==377088==ERROR: AddressSanitizer: heap-use-after-free on address 0x7c9d467e0045 at pc \
0x5631bf685c36 bp 0x7ffdd4c0d4f0 sp 0x7ffdd4c0d4e8
READ of size 1 at 0x7c9d467e0045 thread T0
    #0 0x5631bf685c35 in main /tmp/lt/uaf.c:11:12
    #1 0x7fdd473c7fb9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:59:16

0x7c9d467e0045 is located 5 bytes inside of 128-byte region [0x7c9d467e0040,0x7c9d467e00c0)
freed by thread T0 here:
    #0 0x5631bf64166a in free (/tmp/lt/uaf+0xd166a)
    #1 0x5631bf685bf4 in main /tmp/lt/uaf.c:10:5
    #2 0x7fdd473c7fb9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:59:16

previously allocated by thread T0 here:
    #0 0x5631bf641908 in malloc (/tmp/lt/uaf+0xd1908)
    #1 0x5631bf685bd4 in main /tmp/lt/uaf.c:8:15

SUMMARY: AddressSanitizer: heap-use-after-free /tmp/lt/uaf.c:11:12 in main
"""

_DOUBLE_FREE = """=================================================================
==377128==ERROR: AddressSanitizer: attempting double-free on 0x7c04e57e0050 in thread T0:
    #0 0x55d28de4166a in free (/tmp/lt/dfree+0xd166a)
    #1 0x55d28de85be9 in main /tmp/lt/dfree.c:8:5

0x7c04e57e0050 is located 0 bytes inside of 37-byte region [0x7c04e57e0050,0x7c04e57e0075)
freed by thread T0 here:
    #0 0x55d28de4166a in free (/tmp/lt/dfree+0xd166a)
    #1 0x55d28de85be0 in main /tmp/lt/dfree.c:7:5

previously allocated by thread T0 here:
    #0 0x55d28de41908 in malloc (/tmp/lt/dfree+0xd1908)
    #1 0x55d28de85bd3 in main /tmp/lt/dfree.c:6:15

SUMMARY: AddressSanitizer: double-free (/tmp/lt/dfree+0xd166a) in free
"""


# --- the report ------------------------------------------------------------------------------

def test_the_lifetime_region_wording_is_read():
    """"is located 5 bytes inside OF 128-byte region" -- with an `of` the overflow wording does
    not have. Without it every use-after-free reported no offset and no chunk size, which are
    the two numbers the verdict for this class turns on."""
    r = parse_asan_report(_UAF)
    assert r["distance"] == 5 and r["side"] == "inside" and r["region_size"] == 128
    assert r["access"] == "read" and r["access_size"] == 1


def test_a_double_free_is_not_classified_as_the_word_attempting():
    """ASan states a free-side defect as a SENTENCE: `attempting double-free on 0x...`. The class
    regex took the first word-like token, so the finding went out as class `attempting` with
    CWE-119 -- a generic memory-corruption label for a defect whose own CWE, 415, was already in
    the table two lines below the one that matched."""
    r = parse_asan_report(_DOUBLE_FREE)
    assert r["class"] == "double-free"
    assert (r["cwe"], r["severity"]) == ("CWE-415", "high")
    assert r["region_size"] == 37


def test_the_report_names_all_three_places_a_lifetime_defect_lives():
    """The use, the free and the allocation. A report naming only the use tells whoever reads it
    the one thing the stack trace already showed them."""
    r = parse_asan_report(_UAF)
    assert (r["source"], r["freed_at"], r["allocated_at"]) == ("uaf.c:11", "uaf.c:10", "uaf.c:8")
    d = parse_asan_report(_DOUBLE_FREE)
    assert (d["source"], d["freed_at"], d["allocated_at"]) == ("dfree.c:8", "dfree.c:7",
                                                               "dfree.c:6")


def test_the_allocator_frame_is_not_mistaken_for_the_site():
    """Frame #0 of each section is inside malloc/free and carries no file:line, so the first
    frame that does is the project's. A parser that took the frame instead of the location would
    report every lifetime defect as living in the allocator."""
    r = parse_asan_report(_UAF)
    assert "uaf+0xd166a" not in str(r["freed_at"])


# --- the verdict -----------------------------------------------------------------------------

def _rep(offset=5, size=128, access="read", cls="heap-use-after-free"):
    return {"class": cls, "access": access, "access_size": 1, "distance": offset,
            "side": "inside", "region_size": size, "source": "u.c:11", "freed_at": "u.c:10",
            "allocated_at": "u.c:8"}


def test_an_offset_that_moves_with_the_input_is_a_confirmed_primitive():
    """The attacker picks WHICH FIELD of whatever reclaims the chunk is touched."""
    prim = P.lifetime_primitive([("orig", _rep(offset=5)), ("byte@0x0=0xff", _rep(offset=63))])
    assert prim["type"] == "controlled-uaf-read" and prim["confirmed"]
    assert prim["offset_controlled"] and not prim["size_controlled"]
    assert (prim["region_offset_min"], prim["region_offset_max"]) == (5, 63)
    assert "chooses which field of the reclaiming object is touched" in P.lifetime_effect(prim)


def test_a_chunk_size_that_moves_with_the_input_is_a_confirmed_primitive():
    """The grooming step: choosing the size class decides what can reclaim the chunk."""
    prim = P.lifetime_primitive([("orig", _rep(size=32)), ("byte@0x0=0xff", _rep(size=159))])
    assert prim["type"] == "controlled-uaf-read" and prim["size_controlled"]
    assert (prim["region_size_min"], prim["region_size_max"]) == (32, 159)
    assert "chooses which size class" in P.lifetime_effect(prim)


def test_a_fixed_offset_and_size_is_reported_as_unproven_not_as_control():
    """The costlier mistake: a claim the experiment did not support makes every other claim in
    the report worth less."""
    prim = P.lifetime_primitive([("orig", _rep()), ("byte@0x0=0xff", _rep())])
    assert prim["type"] == "uaf-read" and not prim["confirmed"]
    assert "neither the offset nor the chunk size moved" in P.lifetime_effect(prim)


def test_a_use_after_free_write_is_named_as_corruption_not_disclosure():
    prim = P.lifetime_primitive([("orig", _rep(access="write", offset=1)),
                                 ("v", _rep(access="write", offset=40))])
    assert prim["type"] == "controlled-uaf-write"
    eff = P.lifetime_effect(prim)
    assert "WRITE" in eff and "corrupting whatever object reclaims the chunk" in eff


def test_a_double_free_has_no_access_and_still_gets_a_verdict():
    """This is the class that had nothing to say about it: no access to measure, so every
    register-based and distance-based step was silent."""
    prim = P.lifetime_primitive([
        ("orig", {"class": "double-free", "distance": 0, "side": "inside", "region_size": 37,
                  "source": "d.c:8", "freed_at": "d.c:7", "allocated_at": "d.c:6"}),
        ("byte@0x0=0xff", {"class": "double-free", "distance": 0, "side": "inside",
                           "region_size": 159})])
    assert prim["type"] == "controlled-double-free" and prim["size_controlled"]
    eff = P.lifetime_effect(prim)
    assert "freed twice" in eff and "free-list entry" in eff


def test_the_other_two_free_side_classes_are_named_as_themselves():
    """`alloc-dealloc-mismatch` and a free of an address the allocator never handed out are
    lifetime defects too, and each says what it is rather than borrowing "double free"."""
    mism = P.lifetime_primitive([("orig", {"class": "alloc-dealloc-mismatch", "distance": 0,
                                           "side": "inside", "region_size": 40})])
    assert mism["type"] == "alloc-dealloc-mismatch"
    assert "through the wrong deallocator" in P.lifetime_effect(mism)
    bad = P.lifetime_primitive([("orig", {"class": "bad-free", "distance": 0, "side": "inside",
                                          "region_size": 40})])
    assert bad["type"] == "bad-free"
    assert "never handed out" in P.lifetime_effect(bad)


def test_an_alloc_dealloc_mismatch_keeps_its_own_cwe():
    """Its class (CWE-762) is not in the family the primitive override may install, and it does
    not need to be: root_cause labels it from the sanitizer's own report, so the verdict relabels
    the title and leaves the class alone. Putting 762 in the override map broke the invariant
    that every replacement is itself a class the override outranks."""
    import lykos.analyze.poc.primitive_stage as PS
    assert "alloc-dealloc-mismatch" not in PS._PRIM_CWE
    assert set(PS._PRIM_CWE.values()) <= PS._MEM_CORRUPTION


def test_the_effect_never_claims_the_chunk_was_reclaimed():
    """`controlled use-after-free write` reads like a completed overwrite. Under ASan the chunk
    is quarantined -- that is HOW the use is caught -- so nothing reclaimed it, and the text has
    to say so where the claim is made rather than leaving the reader to know it."""
    for prim in (P.lifetime_primitive([("orig", _rep(offset=1)), ("v", _rep(offset=9))]),
                 P.lifetime_primitive([("orig", _rep()), ("v", _rep())])):
        assert "quarantine" in P.lifetime_effect(prim)
        assert "not a completed overwrite" in P.lifetime_effect(prim)


def test_variants_that_provoked_a_different_defect_are_not_averaged_in():
    prim = P.lifetime_primitive([
        ("orig", _rep(offset=5)),
        ("a", _rep(offset=90, access="write")),
        ("b", _rep(offset=7, cls="double-free"))])
    assert prim["access"] == "read" and prim["type"] == "uaf-read"
    assert [o["variant"] for o in prim["observations"]] == ["orig"]


def test_an_out_of_bounds_access_is_not_a_lifetime_defect():
    """And the converse, which the out-of-bounds verdict already asserted: the two classes do
    not borrow each other's evidence."""
    assert P.lifetime_primitive([("orig", _rep(cls="heap-buffer-overflow"))]) is None
    assert P.lifetime_primitive([("orig", {"class": "SEGV"})]) is None
    assert P.lifetime_primitive([]) is None
    assert P.oob_access_primitive([("orig", _rep())]) is None


def test_a_use_with_no_access_is_not_evidence():
    """A use-after-free report whose access line did not parse says nothing about direction, and
    a verdict that guesses one would name a disclosure a corruption or the reverse."""
    assert P.lifetime_primitive([("orig", _rep(access=None))]) is None


# ------------------------------------------------------------------- integration
#: The offset inside the freed chunk is chosen by the first input byte, so every variant faults
#: and the offset follows the input. This is the shape the verdict exists for.
_UAF_READ_SRC = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int sink;
int main(void){
    unsigned char hdr[4];
    if (fread(hdr, 1, 4, stdin) != 4) return 0;
    char *p = malloc(128);
    memset(p, 'A', 128);
    free(p);
    sink = p[hdr[0] & 0x3f];
    printf("%d\\n", sink);
    return 0;
}
"""

#: A double free whose chunk SIZE the input picks: no access at all, and the controllable thing
#: is which size class the allocator's free list is corrupted in.
_DOUBLE_FREE_SRC = """#include <stdio.h>
#include <stdlib.h>
int main(void){
    unsigned char hdr[4];
    if (fread(hdr, 1, 4, stdin) != 4) return 0;
    char *p = malloc(32 + (hdr[0] & 0x7f));
    free(p);
    free(p);
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


def _asan_build(tmp_path, src, name):
    import shutil
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("no clang for a sanitizer build")
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    b = tmp_path / name
    if subprocess.run([clang, "-g", "-O0", "-fsanitize=address", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("sanitizer build failed")
    return b


def _run_primitive(store, case, pool, binary, data):
    target = ingest(store, case.id, binary)
    sha, _, _ = store.content.put_bytes(data)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 10})
    assert pool.wait_idle(240)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable in this environment: " + str(rec.error))
    return target


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_a_controlled_use_after_free_becomes_an_l2_primitive_end_to_end(store, case, pool,
                                                                       tmp_path):
    b = _asan_build(tmp_path, _UAF_READ_SRC, "uaf")
    target = _run_primitive(store, case, pool, b, b"\x05BBB")

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "a reproducible use-after-free produced no PoC at all"
    l2 = [p for p in pocs if p.level == "L2" and p.verified]
    assert l2, f"no verified L2 for a controlled use-after-free (got {[p.level for p in pocs]})"

    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed
    assert any("use-after-free" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or [])), \
        "the primitive was found but the finding never names the effect"
    assert any(f.cwe == "CWE-416" for f in backed), \
        f"a use-after-free was not labelled CWE-416: {[f.cwe for f in backed]}"

    # the bundle carries the experiment and the three locations, not just the claim
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "poc-bundle"]
    assert arts
    import io
    import tarfile
    out = tmp_path / "unpacked"
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(arts[-1].sha256))) as tf:
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
        tf.extractall(out)
    assert "attacker-controlled offset: True" in txt, txt[:600]
    assert "-> offset" in txt, "the bundle states the claim without the variants behind it"
    assert "freed at" in txt and "allocated at" in txt
    assert "quarantine" in txt, "the bundle claims a reclaim it did not demonstrate"

    # and it REPRODUCES elsewhere: a sanitizer build exits with a code unless abort_on_error is
    # exported, so a bundle that forgets it hands the operator exit 1 where its README promises
    # 134 and the PoC reads as broken.
    rc = subprocess.run(["sh", "./runner.sh"], cwd=out / "poc", capture_output=True, check=False)
    assert rc.returncode == 134, (rc.returncode, rc.stdout[-400:], rc.stderr[-400:])
    assert b"heap-use-after-free" in rc.stderr, "the shipped reproducer lost the report"


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_a_double_free_gets_a_verdict_end_to_end(store, case, pool, tmp_path):
    """The class with no access to measure. Before this it reached the end of the ladder and
    reported "crash reproduced but no instruction-pointer / memory primitive found"."""
    b = _asan_build(tmp_path, _DOUBLE_FREE_SRC, "dfree")
    target = _run_primitive(store, case, pool, b, b"\x05BBB")

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "a reproducible double free produced no PoC at all"
    assert any(p.verified for p in pocs), f"nothing verified: {[p.level for p in pocs]}"
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert any(f.cwe == "CWE-415" for f in backed), \
        f"a double free was not labelled CWE-415: {[f.cwe for f in backed]}"
    assert any("freed twice" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or [])), \
        "the finding never says what the defect does"
