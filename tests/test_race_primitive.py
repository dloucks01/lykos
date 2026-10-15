"""A concurrency defect as a measured finding (chain link 5, doc 35).

Three verdicts in this stage vary the INPUT and watch a number move: the distance past an object,
the offset inside a dead one, the magnitude a report states. None of them says anything about a
race, whose outcome does not depend on the bytes -- so the stage declined the whole family by
name, with the reason "its exploitability is a TIMING property; varying the input cannot show it,
and this stage only varies the input".

The premise was right and the conclusion was not. A concurrency defect has a property that needs
no input variation at all: how often the SAME input shows it. That number is what whoever acts on
the finding needs, and it decides whether the reproducer can be a one-shot script -- it cannot.
A 1-in-8 race shipped as a single run is a PoC the operator runs once, sees nothing from, and
writes off.
"""
import subprocess

import pytest
from lykos.analyze.debug.rootcause import parse_asan_report
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import bundle
from lykos.analyze.poc import primitive as P

# A real clang 21 ThreadSanitizer report, kept verbatim. Note the frame shape: TSan writes
# `#0 bump /src/race.c:6:66 (race+0xea472)` where ASan writes `#1 0x5a in main /src/x.c:12` --
# no address and no `in`.
_RACE = """==================
WARNING: ThreadSanitizer: data race (pid=805422)
  Write of size 8 at 0x5563a0004718 by thread T2:
    #0 bump /tmp/tr/race.c:6:66 (race+0xea472) (BuildId: 3e378011ed3c4c49)

  Previous write of size 8 at 0x5563a0004718 by thread T1:
    #0 bump /tmp/tr/race.c:6:66 (race+0xea472) (BuildId: 3e378011ed3c4c49)

  Location is global 'counter' of size 8 at 0x5563a0004718 (race+0x1497718)

  Thread T2 (tid=805426, running) created by main thread at:
    #0 pthread_create <null> (race+0x655ce) (BuildId: 3e378011ed3c4c49)
    #1 main /tmp/tr/race.c:13:27 (race+0xea2f1) (BuildId: 3e378011ed3c4c49)

SUMMARY: ThreadSanitizer: data race /tmp/tr/race.c:6:66 in bump
"""

_CLEAN = "200000\n"


# --- the report ------------------------------------------------------------------------------

def test_a_race_report_names_both_accesses_and_the_object():
    """A race has no single site. Naming one frame describes half the defect, and the half it
    names is whichever thread the detector happened to see second."""
    r = parse_asan_report(_RACE)
    assert r["class"] == "data-race" and r["cwe"] == "CWE-362"
    assert r["accesses"] == ["write", "write"]
    assert r["race_sites"] == ["race.c:6", "race.c:6"]
    assert r["location"].startswith("global 'counter' of size 8")


def test_a_tsan_frame_has_no_address_and_still_yields_a_site():
    """TSan omits the `0xADDR in` that ASan prints, so requiring the ASan frame shape left a data
    race with no source location at all -- not the two racing lines, not even one."""
    assert parse_asan_report(_RACE)["source"] == "race.c:6"


def test_the_report_says_which_sanitizer_spoke():
    """Nothing set this, and `libfuzzer_stage` reads it with a default of "AddressSanitizer" --
    so every UBSan and ThreadSanitizer finding ever filed claimed ASan in its evidence. It is
    also the only honest way to tell TSan's `heap-use-after-free` from ASan's: same class name,
    different evidence."""
    assert parse_asan_report(_RACE)["sanitizer"] == "ThreadSanitizer"
    asan = parse_asan_report("ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
                             "READ of size 1 at 0x1 thread T0\n")
    assert asan["sanitizer"] == "AddressSanitizer"
    ub = parse_asan_report("t.c:1:1: runtime error: shift exponent 64 is too large for 32-bit "
                           "type 'int'")
    assert ub["sanitizer"] == "UndefinedBehaviorSanitizer"


# --- the verdict -----------------------------------------------------------------------------

def _rep(reported=True, cls="data-race"):
    if not reported:
        return {}
    return {"class": cls, "sanitizer": "ThreadSanitizer", "cwe": "CWE-362",
            "accesses": ["write", "write"], "race_sites": ["race.c:6", "race.c:6"],
            "location": "global 'counter' of size 8"}


def _runs(hits, total):
    return [(f"run{i + 1}", _rep(i < hits)) for i in range(total)]


def test_an_intermittent_race_reports_its_rate():
    prim = P.race_primitive(_runs(2, 8))
    assert prim["type"] == "intermittent-data-race" and prim["intermittent"]
    assert (prim["hits"], prim["runs"], prim["rate"]) == (2, 8, 0.25)
    assert prim["confirmed"], "it reproduced twice; that is the claim"
    eff = P.race_effect(prim)
    assert "2 of 8 runs of the SAME input" in eff
    assert "a reproducer has to loop" in eff


def test_a_race_that_always_reports_is_not_called_intermittent():
    prim = P.race_primitive(_runs(8, 8))
    assert prim["type"] == "data-race" and not prim["intermittent"]
    eff = P.race_effect(prim)
    assert "all 8 runs" in eff
    assert "a fact about this harness" in eff, \
        "8/8 here is not a guarantee elsewhere, and the text has to say so"


def test_a_rate_decides_how_many_attempts_the_reproducer_makes():
    """Three expected hits, bounded so a 1-in-8 observation does not ask for hundreds of runs."""
    assert P.race_primitive(_runs(8, 8))["retries"] == 3
    assert P.race_primitive(_runs(1, 8))["retries"] == 24
    assert P.race_primitive(_runs(2, 8))["retries"] == 12
    assert P.race_primitive(_runs(1, 8))["retries"] <= 60


def test_a_race_verdict_can_never_reach_l2():
    """Nothing here controls memory or execution. What is measured is whether and how often the
    defect shows itself, and the ladder has to keep meaning what it says."""
    assert P.race_primitive(_runs(4, 8))["max_level"] == 1


def test_the_effect_does_not_claim_what_the_race_causes():
    eff = P.race_effect(P.race_primitive(_runs(4, 8)))
    assert "What the race CAUSES is not shown here" in eff


def test_no_report_on_any_run_is_no_verdict():
    """Not a verdict of "clean": the caller asked about a report it had already seen, and if no
    repeat shows it, this verdict has nothing to say and must not invent a rate of zero."""
    assert P.race_primitive(_runs(0, 8)) is None
    assert P.race_primitive([]) is None


def test_the_race_verdict_keys_on_the_sanitizer_not_the_class_name():
    """TSan reports a `heap-use-after-free` under the same name ASan uses, and only ASan's
    version carries an offset inside a freed chunk to reason about."""
    tsan_uaf = [("run1", {"class": "heap-use-after-free", "sanitizer": "ThreadSanitizer"})]
    asan_uaf = [("run1", {"class": "heap-use-after-free", "sanitizer": "AddressSanitizer",
                          "access": "read", "distance": 5, "side": "inside",
                          "region_size": 128})]
    assert P.race_primitive(tsan_uaf) is not None
    assert P.race_primitive(asan_uaf) is None
    # ...and the lifetime verdict takes the ASan one and refuses the TSan one
    assert P.lifetime_primitive(asan_uaf) is not None
    assert P.lifetime_primitive(tsan_uaf) is None


def test_the_other_verdicts_do_not_take_a_race():
    assert P.oob_access_primitive([("run1", _rep())]) is None
    assert P.quantity_primitive([("run1", _rep())]) is None


# --- the reproducer --------------------------------------------------------------------------

def test_a_race_bundle_loops_instead_of_running_once():
    """The operational half. A one-shot script demonstrates nothing on the runs where the
    interleaving does not happen, and the operator runs it once."""
    prim = P.race_primitive(_runs(2, 8))
    data = bundle.build(b"\x7fELF-not-really", b"\x03AAA", {"level": "L1"}, b"",
                        "stdin", [], "sanitizer-error", primitive=prim)
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        runner = tf.extractfile("poc/runner.sh").read().decode()
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
        readme = tf.extractfile("poc/README.txt").read().decode()
    assert "attempts=12" in runner, runner
    assert "while [ $i -le $attempts ]" in runner
    assert "ThreadSanitizer: data race" in runner, "the loop greps for the detector's own line"
    assert "reproduced on attempt $i" in runner
    assert "did NOT reproduce in $attempts attempts" in runner
    assert "exit 1" in runner, "a reproducer that never reproduced must not exit 0"
    # the claim and its evidence
    assert "Reproduction rate: 2 of 8 runs" in txt
    assert "a race has more than one" in txt
    assert "race.c:6" in txt
    assert "NOT claim: what the race CAUSES" in txt
    assert "2/8 runs of the same input" in readme


def test_a_non_race_bundle_is_unchanged():
    """The loop is for the class that needs it; everything else keeps the one-shot script whose
    exit status the conformance gate asserts on."""
    data = bundle.build(b"\x7fELF", b"A", {"level": "L1"}, b"", "stdin", [], "SIGSEGV")
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        runner = tf.extractfile("poc/runner.sh").read().decode()
    assert "attempts=" not in runner and "exit $rc" in runner


# ------------------------------------------------------------------- integration
#: Two threads incrementing one global, with the INPUT deciding how many threads run -- so the
#: racing code is input-reachable even though the race's outcome is not input-determined.
_RACE_SRC = """#include <pthread.h>
#include <stdio.h>
static long counter;
static void *bump(void *arg){ for (long i = 0; i < 200000; i++) counter++; return 0; }
int main(void){
    unsigned char h[4];
    if (fread(h, 1, 4, stdin) != 4) return 0;
    int n = (h[0] & 3) + 1;
    pthread_t t[4];
    for (int i = 0; i < n; i++) pthread_create(&t[i], 0, bump, 0);
    for (int i = 0; i < n; i++) pthread_join(t[i], 0);
    printf("%ld\\n", counter);
    return 0;
}
"""


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_a_race_is_measured_and_reported_end_to_end(store, case, tmp_path):
    import shutil

    from lykos.analyze import register
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc import enqueue_primitive
    from lykos.db.dao import ArtifactDAO, FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    clang = shutil.which("clang")
    if not clang:
        pytest.skip("no clang for a sanitizer build")
    c = tmp_path / "race.c"
    c.write_text(_RACE_SRC)
    b = tmp_path / "race"
    if subprocess.run([clang, "-g", "-O1", "-fsanitize=thread", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("ThreadSanitizer build failed")
    # ThreadSanitizer needs a very large virtual address reservation; if it cannot start under
    # this host's limits there is nothing to measure.
    probe = subprocess.run([str(b)], input=b"\x03AAA", capture_output=True)
    if b"ThreadSanitizer: data race" not in probe.stderr:
        pytest.skip("ThreadSanitizer did not report here: " + probe.stderr[-200:].decode(
            "utf-8", "replace"))

    register()
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"\x03AAA")
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                   "timeout": 20})
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("ptrace unavailable in this environment: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs, "a reproducible data race produced no PoC at all"
    assert all(p.level != "L2" for p in pocs), \
        f"a concurrency defect claimed L2: {[p.level for p in pocs]}"

    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed, "the verdict never reached a finding"
    ev = " ".join(str(e.get("detail", "")) for f in backed for e in (f.evidence or []))
    assert "data-race" in ev, ev[:400]
    assert "runs of the" in ev, "the finding does not state the reproduction rate"
    assert "race.c:4" in ev or "race.c:" in ev, "the finding does not name a racing site"

    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "poc-bundle"]
    assert arts
    import io
    import tarfile
    out = tmp_path / "unpacked"
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(arts[-1].sha256))) as tf:
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
        tf.extractall(out)
    assert "Reproduction rate:" in txt and "of 8 runs" in txt
    assert "runner.sh loops" in txt

    # and the shipped reproducer actually reproduces -- which for this class means its LOOP does
    rc = subprocess.run(["sh", "./runner.sh"], cwd=out / "poc", capture_output=True, check=False)
    assert b"reproduced on attempt" in rc.stdout, (rc.stdout[-300:], rc.stderr[-300:])
    assert b"ThreadSanitizer: data race" in rc.stdout + rc.stderr


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_a_race_found_by_the_fuzz_stage_reaches_the_ladder(store, case, tmp_path):
    """The autopilot-level half, and the reason it did not work.

    `compile_source_tsan` builds a ThreadSanitizer binary for a SOURCE drop and the fuzz stage
    detonates the corpus against it -- that path existed. What it did was file a `corroborated`
    FINDING and nothing else: the prove loop iterates the dyn_result table, so a real data race
    reached the report and nothing downstream ever touched it. No PoC, no reproduction rate, no
    looping reproducer. The libFuzzer stage had exactly this defect and its own comment says the
    same thing: record it as a RUN, or the ladder cannot see it.

    Measured through the conformance gate first, whose new data-race case found the class and
    demonstrated nothing -- and then found to be unfixable THERE, because every case in that gate
    ingests a compiled binary and the TSan build only exists for a source drop. So the assertion
    lives here, where source can actually be ingested.
    """
    import shutil

    from lykos.analyze import register
    from lykos.analyze.fuzz.stage import enqueue_fuzz
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO, DynResultDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    if not shutil.which("clang"):
        pytest.skip("no clang for a ThreadSanitizer build")
    src = tmp_path / "race.c"
    src.write_text(_RACE_SRC)
    register()
    target = ingest(store, case.id, src, filename="race.c")
    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id)]
    if not any(a.kind == "tsan-blob" for a in arts):
        pytest.skip("no ThreadSanitizer build was produced for this source on this host")

    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        # No seed list: the race fires on any input (the thread count defaults to 2), and
        # `seeds` is not a parameter this stage reads -- passing one silently changed nothing
        # except the time left for the ThreadSanitizer pass, which runs after the campaign.
        run = enqueue_fuzz(q, target, params={"timeout": 20, "input_mode": "stdin"})
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("the fuzz stage could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    races = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if f.detector == "tsan"]
    if not races:
        pytest.skip("ThreadSanitizer did not report on this host within the campaign budget")
    assert any(f.cwe == "CWE-362" for f in races), [f.cwe for f in races]

    # the part that was missing: the ladder can SEE it
    rows = [d for d in DynResultDAO(store.conn).list_by_target(target.id)
            if (d.isolation or "") == "tsan"]
    assert rows, "the race was filed as a finding and recorded as no RUN, so the PoC ladder " \
                 "cannot reach it"
    assert all(d.crashed for d in rows)
    assert all((d.defect_key or "").startswith("tsan:") for d in rows)
    assert all(d.input_sha for d in rows), "a run with no input cannot be replayed"
