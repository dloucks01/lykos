"""The uninitialised-value verdict (chain link 5, doc 35) -- the last class with no verdict.

`use-of-uninitialized-value` was the one sanitizer class this stage declined by name, and the
reason it gave was that an uninitialised read is only a disclosure if the value reaches an output,
which is `mem_oracle`'s verdict and not this stage's to duplicate. True about the line, wrong
about the owner: MemorySanitizer draws exactly that line, in the report the stage already holds,
for the input the ladder is actually holding -- and `mem_oracle` is a bounded triage pass over
inputs it picks for itself, so "some run of this program discloses" and "THIS input discloses"
are different claims and only the second can carry a bundle.

Three facts come from the report, one from the family's shared experiment, and one -- the one this
class really turns on -- from looking at the disclosed bytes:

  * did the value LEAVE THE PROCESS, through which output call, and how much of it;
  * where did it come from: a dead stack frame (with the variable's name) or a recycled chunk;
  * does the volume move with the input;
  * and WHOSE BYTES escaped. That last one is the uninitialised-memory analogue of the reclaim
    experiment: a marker planted in the input coming back out of the program's own output is the
    attacker choosing the contents of memory the program never wrote.

Every report below was measured on this host (clang 21), and the measurement that decided the
design is in `test_a_residue_verdict_declines_on_a_filling_build`: on the ASan build a fresh frame
reads as zeroes and a fresh heap allocation as 0xbe, so a residue verdict taken from THAT binary
measures the sanitizer instead of the program.
"""
import shutil
import subprocess

import pytest
from lykos.analyze.debug.rootcause import parse_asan_report
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import primitive as P

# A value that is only USED -- a branch on an uninitialised int. No `Uninitialized bytes in ...`
# line, because nothing reached an output call.
_INTERNAL = """==2290755==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x55826c21f8f5 in decide /tmp/q/branch.c:4:33
    #1 0x55826c21f5db in main /tmp/q/branch.c:5:29
    #2 0x7f8cabc07fb9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:59:16
    #3 0x55826c182300 in _start (/tmp/q/branch.msan+0x33300)

  Uninitialized value was created by an allocation of 'x' in the stack frame
    #0 0x55826c21f883 in decide /tmp/q/branch.c:4:26

SUMMARY: MemorySanitizer: use-of-uninitialized-value /tmp/q/branch.c:4:33 in decide
"""

# 128 bytes of a dead stack frame reaching write(2). Note where the escape line is: BEFORE the
# WARNING, which is why the parser scans the whole report and not the text after the warning.
_ESCAPE_STACK = """Uninitialized bytes in write at offset 0 inside [0x7ffee21c8e20, 128)
==2290758==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x562a891fd6b9 in leak /tmp/q/escape.c:5:38
    #1 0x562a891fd5db in main /tmp/q/escape.c:6:25

  Uninitialized value was created by an allocation of 'b' in the stack frame
    #0 0x562a891fd6a6 in leak /tmp/q/escape.c:5:25

SUMMARY: MemorySanitizer: use-of-uninitialized-value /tmp/q/escape.c:5:38 in leak
"""

# The same defect with a HEAP origin: a recycled allocation, whose residue is a previously freed
# object. The allocator frame carries no file:line, so the origin site is the caller's.
_ESCAPE_HEAP = """Uninitialized bytes in write at offset 0 inside [0x706000000000, 96)
==2290769==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x55835bfb9736 in main /tmp/q/heaporigin.c:4:70

  Uninitialized value was created by a heap allocation
    #0 0x55835bf5b416 in malloc (/tmp/q/heaporigin.msan+0x72416)
    #1 0x55835bfb96c1 in main /tmp/q/heaporigin.c:4:58

SUMMARY: MemorySanitizer: use-of-uninitialized-value /tmp/q/heaporigin.c:4:70 in main
"""

# An older clang spells the interceptor out. Accepted rather than required, so one release's
# wording is not the difference between a disclosure and a bare uninitialised read.
_ESCAPE_OLD = _ESCAPE_STACK.replace("in write at", "in __interceptor_write at")


# --- the report ------------------------------------------------------------------------------

def test_the_class_alone_cannot_tell_the_two_defects_apart():
    """Both of these are `use-of-uninitialized-value`, and an operator must triage them
    differently: one is a branch on a stale flag, the other is 128 bytes of a dead frame going
    out on a file descriptor. Before `_msan_detail` they were indistinguishable -- same class,
    same CWE, same severity, same title."""
    internal, escaped = parse_asan_report(_INTERNAL), parse_asan_report(_ESCAPE_STACK)
    assert internal["class"] == escaped["class"] == "use-of-uninitialized-value"
    assert internal.get("escape_bytes") is None
    assert (internal["cwe"], internal["severity"]) == ("CWE-457", "medium")
    assert escaped["escape_bytes"] == 128 and escaped["escape_fn"] == "write"
    assert escaped["escape_offset"] == 0
    assert (escaped["cwe"], escaped["severity"]) == ("CWE-200", "high"), \
        "bytes that left the process are an information exposure, not just an uninit read"
    assert "reached `write`" in escaped["detail"]


def test_the_escape_line_is_found_although_it_precedes_the_warning():
    """Measured: clang prints `Uninitialized bytes in write ...` BEFORE the `WARNING:` line. A
    parser that reads only the text after the warning finds no escape and files every disclosure
    as an internal read."""
    assert _ESCAPE_STACK.index("Uninitialized bytes") < _ESCAPE_STACK.index("WARNING")
    assert parse_asan_report(_ESCAPE_STACK)["escape_bytes"] == 128


def test_the_interceptor_prefix_is_accepted_not_required():
    assert parse_asan_report(_ESCAPE_OLD)["escape_fn"] == "write"
    assert parse_asan_report(_ESCAPE_OLD)["escape_bytes"] == 128


def test_the_report_names_where_the_value_came_from_not_only_where_it_was_used():
    """The use site is the line that READS the variable; the line to change is the one that
    declared or allocated it without an initialiser. A report that names only the first sends
    whoever has to fix it to the symptom."""
    stack = parse_asan_report(_ESCAPE_STACK)
    assert stack["origin"] == "stack" and stack["origin_var"] == "b"
    assert stack["origin_site"] == "escape.c:5"
    assert stack["source"] == "escape.c:5"
    heap = parse_asan_report(_ESCAPE_HEAP)
    assert heap["origin"] == "heap" and heap.get("origin_var") is None
    assert heap["origin_site"] == "heaporigin.c:4", \
        "the allocator frame carries no file:line, so the origin is the CALLER's line"


# --- whose bytes escaped ---------------------------------------------------------------------

def test_a_planted_marker_in_the_output_is_the_strongest_residue_verdict():
    marker = bytes.fromhex("5ec0de15ca1dbeef") * 2
    res = P.residue_verdict(b"...." + marker + b"junk", marker)
    assert res["residue"] == "input" and res["marker_offset"] == 4


def test_a_short_marker_is_not_trusted():
    """Eight bytes of a filler run would match residue that merely happens to be filler, so a
    marker below `MARKER_MIN` is not evidence of anything."""
    assert P.residue_verdict(b"AAAA" * 8, b"AAAA")["residue"] != "input"


def test_a_residue_verdict_declines_on_a_filling_build():
    """The measurement that decided where the residue experiment runs. ASan zeroes a fresh frame
    and fills a fresh heap allocation with 0xbe, so the disclosed bytes on that build are the
    sanitizer's and not the program's. A uniform block claims nothing."""
    for byte in (0x00, 0xbe):
        res = P.residue_verdict(bytes([byte]) * 64, b"m" * 16)
        assert res["residue"] == "filled" and res["fill_byte"] == byte
    # and the fill check comes FIRST, so an all-zero block is never read as a null pointer
    assert P.residue_verdict(b"\x00" * 64, b"\x00" * 16)["residue"] == "filled"


def test_unrecognised_residue_says_so_rather_than_guessing():
    res = P.residue_verdict(bytes(range(64)), b"m" * 16)
    assert res["residue"] == "unknown" and res["residue_bytes"] == 64
    assert "not established" in P._RESIDUE_TXT["unknown"]


# --- the verdict -----------------------------------------------------------------------------

def _obs(text, label="orig"):
    return (label, parse_asan_report(text))


def test_a_value_that_never_leaves_claims_no_disclosure():
    prim = P.uninit_primitive([_obs(_INTERNAL)])
    assert prim["type"] == "uninit-read" and not prim["escaped"]
    assert prim["cwe"] == "CWE-457"
    assert prim["effect_status"] == "potential" and prim["effect_kind"] is None
    assert prim["max_level"] == 1
    eff = P.uninit_effect(prim)
    assert "does NOT leave the process" in eff and "consequence is not shown" in eff


def test_an_escape_whose_bytes_are_the_attackers_is_an_l2_disclosure():
    res = {"residue": "input", "marker_offset": 0, "residue_bytes": 128}
    prim = P.uninit_primitive([_obs(_ESCAPE_STACK)], residue=res)
    assert prim["type"] == "controlled-uninit-disclosure"
    assert prim["escaped"] and prim["confirmed"] and prim["max_level"] == 2
    assert prim["cwe"] == "CWE-200" and prim["effect_status"] == "demonstrated"
    assert prim["origin"] == "stack" and prim["origin_var"] == "b"
    assert "the attacker's to choose" in P.uninit_effect(prim)


def test_an_image_base_in_the_residue_is_an_aslr_defeat():
    res = {"residue": "pointer", "pie_base": 0x555555554000, "residue_bytes": 128}
    prim = P.uninit_primitive([_obs(_ESCAPE_HEAP)], residue=res)
    assert prim["max_level"] == 2 and prim["confirmed"]
    assert prim["pie_base"] == 0x555555554000
    assert "defeats ASLR" in P.uninit_effect(prim)


def test_an_escape_with_unaccounted_bytes_stops_at_l1():
    """Bytes left the process and what they were is not shown. That is a real disclosure and not
    a demonstrated primitive, and the two must not be the same number on the ladder."""
    prim = P.uninit_primitive([_obs(_ESCAPE_STACK)],
                              residue={"residue": "unknown", "residue_bytes": 128})
    assert prim["escaped"] and prim["max_level"] == 1 and not prim["confirmed"]
    assert prim["effect_status"] == "demonstrated", \
        "the ESCAPE was observed even where the content was not"
    assert "not established" in P.uninit_effect(prim)


def test_a_filled_residue_cannot_confirm():
    prim = P.uninit_primitive([_obs(_ESCAPE_STACK)],
                              residue={"residue": "filled", "fill_byte": 0xbe})
    assert prim["max_level"] == 1 and not prim["confirmed"]
    assert "measuring the sanitizer" not in P.uninit_effect(prim)
    assert "something FILLED" in P.uninit_effect(prim)


def test_a_volume_that_moves_with_the_input_is_attacker_sized():
    bigger = _ESCAPE_STACK.replace("0x7ffee21c8e20, 128)", "0x7ffee21c8e20, 4096)")
    prim = P.uninit_primitive([_obs(_ESCAPE_STACK), _obs(bigger, "filler+256")],
                              residue={"residue": "unknown"})
    assert (prim["volume_min"], prim["volume_max"]) == (128, 4096)
    assert prim["volume_controlled"] and prim["type"] == "controlled-uninit-disclosure"
    assert "the attacker sizes the disclosure" in P.uninit_effect(prim)


def test_only_a_memorysanitizer_report_gets_this_verdict():
    """The class name is not the test. Another detector's report of the same words would get a
    verdict built for evidence it does not carry."""
    rep = parse_asan_report(_ESCAPE_STACK)
    rep["sanitizer"] = "AddressSanitizer"
    assert P.uninit_primitive([("orig", rep)]) is None


def test_the_no_verdict_table_is_now_empty_and_still_wired():
    """Every class this stage sees has a verdict. The mechanism stays for the next one that
    genuinely does not -- a named decline reads nothing like "no primitive found"."""
    assert P.NO_VERDICT_REASON == {}
    assert P.no_verdict_reason("use-of-uninitialized-value") is None
    P.NO_VERDICT_REASON["a-future-class"] = "because"
    try:
        assert P.no_verdict_reason("a-future-class") == "because"
    finally:
        P.NO_VERDICT_REASON.pop("a-future-class")


def test_the_bundle_states_the_escape_the_origin_and_whose_bytes():
    from lykos.analyze.poc import bundle
    prim = P.uninit_primitive([_obs(_ESCAPE_STACK)],
                              residue={"residue": "input", "marker_offset": 8,
                                       "residue_bytes": 128})
    txt = bundle._primitive_txt(prim).decode()
    assert "L2 information-disclosure primitive" in txt
    assert "reached `write`" in txt and "128..128 bytes" in txt
    assert "declared at  escape.c:5" in txt
    assert "came back" in txt and "offset 8" in txt
    internal = bundle._primitive_txt(P.uninit_primitive([_obs(_INTERNAL)])).decode()
    assert "Left the process: NOTHING" in internal
    assert "no" in internal and "disclosure is claimed" in internal


# --- end to end --------------------------------------------------------------------------------

# The shape this defect takes in real code, and the reason the residue question is worth asking:
# one call reads input into its frame and returns; a later call at the same stack depth reads its
# own frame, which it never wrote, and sends it out. Nothing here is a crash, nothing is out of
# bounds, and the bytes that leave are whatever the previous call left behind -- which is the
# attacker's input.
_UNINIT_SRC = """#include <unistd.h>
static void take(void){ char buf[128]; ssize_t n = read(0, buf, sizeof buf); (void)n; }
static void emit(void){ char b[128]; write(1, b, 128); }
int main(void){ take(); emit(); return 0; }
"""


def _msan_build(tmp_path, src_text, name):
    """An MSan binary built exactly as `compile_source_msan` builds one, or a skip."""
    from lykos.analyze.ingest import compile_source_msan
    if not shutil.which("clang"):
        pytest.skip("no clang for a MemorySanitizer build")
    c = tmp_path / f"{name}.c"
    c.write_text(src_text)
    out = tmp_path / name
    if compile_source_msan(c, c.name, out) is None:
        pytest.skip("the MemorySanitizer build failed on this host")
    probe = subprocess.run([str(out)], input=b"A" * 128, capture_output=True)
    if b"MemorySanitizer: use-of-uninitialized-value" not in probe.stderr:
        pytest.skip("MemorySanitizer did not report here: "
                    + probe.stderr[-200:].decode("utf-8", "replace"))
    return out


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_msan_writes_the_residue_out_which_is_what_makes_this_answerable(tmp_path):
    """The measured fact the residue experiment rests on. MSan's interceptor reports the
    undefined bytes and then PERFORMS the write, so the residue it is complaining about is on the
    same run's stdout. Were that not so, "whose bytes are these" would need a second,
    uninstrumented build -- and for a source drop the pipeline has no such build."""
    exe = _msan_build(tmp_path, _UNINIT_SRC, "uninit")
    r = subprocess.run([str(exe)], input=b"Q" * 128, capture_output=True)
    assert b"MemorySanitizer" in r.stderr, "no report"
    assert r.stdout.startswith(b"Q" * 32), \
        f"the disclosed bytes never reached stdout: {r.stdout[:32]!r}"


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_an_uninitialised_disclosure_is_proved_end_to_end(store, case, tmp_path):
    """The whole link, on a real binary: the class is reported, the escape is parsed, the volume
    is measured, a marker planted in the input comes back out of the program's own output, and the
    bundle says so. Before this the same defect ended on "crash reproduced but no instruction-
    pointer / memory primitive found"."""
    import io
    import tarfile

    from lykos.analyze import register
    from lykos.analyze.ingest import ingest
    from lykos.analyze.poc import enqueue_primitive
    from lykos.db.dao import ArtifactDAO, FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    exe = _msan_build(tmp_path, _UNINIT_SRC, "uninit")
    register()
    target = ingest(store, case.id, exe)
    sha, _, _ = store.content.put_bytes(b"A" * 128)
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
    assert pocs, "an uninitialised-memory disclosure produced no PoC at all"
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed, "the verdict never reached a finding"
    ev = " ".join(str(e.get("detail", "")) for f in backed for e in (f.evidence or []))
    assert "uninitialised-memory disclosure" in ev, ev[:500]
    assert "reach `write`" in ev, "the finding does not name the output call the bytes left by"
    assert "uninit.c:" in ev, "the finding does not name where the value came from"

    arts = [a for a in ArtifactDAO(store.conn).list_by_case(case.id) if a.kind == "poc-bundle"]
    assert arts
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(arts[-1].sha256))) as tf:
        txt = tf.extractfile("poc/PRIMITIVE.txt").read().decode()
    assert "Left the process:" in txt and "`write`" in txt
    assert "Whose bytes escaped:" in txt
    # The strongest residue verdict, on a program shaped the way real ones are: the input lands
    # in a frame that is read again after it dies.
    assert "verdict: input" in txt, txt[:1200]
    assert "L2 information-disclosure primitive" in txt
    assert any(p.level == "L2" for p in pocs), [p.level for p in pocs]


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native sanitizer build")
def test_an_uninitialised_read_found_by_the_fuzz_stage_reaches_the_ladder(store, case, tmp_path):
    """The autopilot-level half, and it had exactly the defect `tsan_detonate` had before it:
    `msan_detonate` filed a `corroborated` FINDING and recorded no run, so the prove loop -- which
    iterates dyn_result -- could never see it. A real uninitialised-memory disclosure reached the
    report and nothing downstream ever touched it: no bundle, no volume, no verdict on whose bytes
    escaped. The isolation tag has to name the MSAN build, because no other build reports this
    class and the ASan one destroys the evidence."""
    from lykos.analyze import register
    from lykos.analyze.fuzz.stage import enqueue_fuzz
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO, DynResultDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    if not shutil.which("clang"):
        pytest.skip("no clang for a MemorySanitizer build")
    src = tmp_path / "uninit.c"
    src.write_text(_UNINIT_SRC)
    register()
    target = ingest(store, case.id, src, filename="uninit.c")
    if not any(a.kind == "msan-blob" for a in ArtifactDAO(store.conn).list_by_case(case.id)):
        pytest.skip("no MemorySanitizer build was produced for this source on this host")

    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_fuzz(q, target, params={"timeout": 20, "input_mode": "stdin"})
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("the fuzz stage could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    uninit = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.detector == "msan"]
    if not uninit:
        pytest.skip("MemorySanitizer did not report within the campaign budget on this host")
    assert any(f.cwe == "CWE-200" for f in uninit), \
        f"the bytes left the process, so this is an exposure: {[f.cwe for f in uninit]}"
    assert any("disclosed to output" in (f.title or "") for f in uninit), \
        f"every uninitialised read was still filed under one title: {[f.title for f in uninit]}"

    rows = [d for d in DynResultDAO(store.conn).list_by_target(target.id)
            if (d.isolation or "") == "msan"]
    assert rows, "the uninitialised read was filed as a finding and recorded as no RUN, so the " \
                 "PoC ladder cannot reach it"
    assert all(d.crashed for d in rows)
    assert all((d.defect_key or "").startswith("msan:") for d in rows)
    assert all(d.input_sha for d in rows), "a run with no input cannot be replayed"

    # ... and the ladder, given that run, earns the L2 -- which is the end-to-end form of the
    # channel defect above. The input the fuzzer recorded here is the EMPTY one (this defect
    # needs no input at all), so a stage that overrides the discovered channel fails silently:
    # the program runs with nothing on stdin, the marker never reaches it, and the residue of a
    # disclosure that is entirely the attacker's comes back `unknown`.
    from lykos.analyze.poc import enqueue_primitive
    from lykos.db.dao import PocDAO
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_primitive(q, target, params={
            "input_sha": rows[0].input_sha, "input_mode": rows[0].input_mode or "stdin",
            "timeout": 20})
        assert pool.wait_idle(420)
        if q.runs.get(run.id).status != "done":
            pytest.skip("ptrace unavailable in this environment")
    finally:
        pool.stop(grace=3.0)
    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert any(p.level == "L2" and p.verified for p in pocs), \
        "the source route reported the disclosure and never proved whose bytes escaped"


def test_the_severity_comes_from_the_verdict_not_from_the_signal():
    """MemorySanitizer HALTS the process, so the signal is SIGABRT and the signal table rates
    that `high`. Applied to this class that is the substrate deciding the severity: the half of
    it where nothing left the process is a medium by the sanitizer's own reckoning, and filing it
    alongside a demonstrated disclosure is how a report stops being able to rank itself."""
    from lykos.analyze.dynamic.stage import _SIG_CWE
    assert _SIG_CWE["SIGABRT"] == ("CWE-787", "high"), "the premise of this test changed"
    internal = P.uninit_primitive([_obs(_INTERNAL)])
    escaped = P.uninit_primitive([_obs(_ESCAPE_STACK)],
                                 residue={"residue": "input", "marker_offset": 0})
    # the verdict carries what the severity must be read off
    assert internal["escaped"] is False and escaped["escaped"] is True
    assert internal["cwe"] == "CWE-457" and escaped["cwe"] == "CWE-200"


def test_a_sanitizer_build_keeps_the_input_channel_a_harness_does_not(store, case, tmp_path):
    """The defect that cost the source route its L2, and it was latent for data races too.

    `replay_exe_for` resolves two different kinds of replacement binary, and both callers forced
    `("file", ["@@"])` on whatever came back. That is right for a libFuzzer harness, which takes a
    file argument whatever the target's own channel was, and wrong for a sanitizer-variant build,
    which is the same program compiled again and reads stdin exactly as before. Measured: an MSan
    build of a stdin-reading program was handed a filename in argv and ran with NO INPUT -- the
    defect still reported, because it needs none, so every experiment that varies the input had
    nothing to vary. The volume could not move and the planted marker never reached the program,
    and the verdict honestly came back `residue: unknown` for a disclosure that is entirely the
    attacker's.
    """
    from lykos.analyze.poc.capture import replay_exe_for

    class _Ctx:
        def __init__(self, conn, content):
            self.conn, self.content = conn, content

    from lykos.analyze.ingest import ingest
    from lykos.db.dao import ArtifactDAO, DynResultDAO

    if not shutil.which("clang"):
        pytest.skip("no clang for a MemorySanitizer build")
    src = tmp_path / "uninit.c"
    src.write_text(_UNINIT_SRC)
    # The real shape: the platform compiles the source to an ASan target AND an MSan sibling.
    target = ingest(store, case.id, src, filename="uninit.c")
    blob = next((a for a in ArtifactDAO(store.conn).list_by_case(case.id)
                 if a.kind == "msan-blob"), None)
    if blob is None:
        pytest.skip("no MemorySanitizer build was produced for this source on this host")
    ctx = _Ctx(store.conn, store.content)
    # Nothing recorded: the ingested binary IS the one to replay, and the kind says so.
    assert replay_exe_for(ctx, target, "deadbeef") == (None, "")

    sha, _, _ = store.content.put_bytes(b"A" * 32)
    DynResultDAO(store.conn).insert(target.id, case.id, run_id=None, input_sha=sha,
                                    input_mode="stdin", argv=[], crashed=True,
                                    signal_name="use-of-uninitialized-value", isolation="msan",
                                    defect_key="msan:uninit.c:3")
    data, kind = replay_exe_for(ctx, target, sha)
    assert kind == "sanitizer", "the caller cannot keep the input channel without knowing this"
    assert data == store.content.get_bytes(blob.sha256)
    assert data != store.content.path(target.sha256).read_bytes(), \
        "the MSan build is a DIFFERENT binary from the ingested ASan one"
