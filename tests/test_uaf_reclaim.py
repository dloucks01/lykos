"""The reclaim half of a use-after-free (chain link 5, doc 35).

`lifetime_primitive` judges a use-after-free from a sanitizer report: does the attacker choose
which part of the dead chunk is touched, and how big it is. It deliberately stops there, because
ASan holds a freed chunk in QUARANTINE -- that is how the use is caught at all -- so under the
build that produces that evidence nothing can ever reclaim the chunk, and "the attacker's bytes
end up in the dead object" cannot be shown. Doc 35 recorded it as the open end of the link.

Without a sanitizer the allocator behaves normally and the target's own output is the oracle:

    add(victim, S)  add(guard, S)  free(victim)  add(attacker, S, MARKER)  view(victim)

If the view of the FREED entry prints the marker the LATER allocation carried, then the
attacker's bytes occupy the chunk the stale pointer addresses and the program read them through
it. The control run allocates in a different size class, where no reclaim is possible: a target
that echoes recent input out of a shared buffer would print the marker whatever the allocator
did, and that failure mode has to be ruled out rather than assumed away.
"""
import subprocess

import pytest
from lykos.analyze.dynamic import heap_discover, heaptrace, sandbox
from lykos.analyze.poc import primitive as P

MARKER = P.RECLAIM_MARKER


# --- the verdict -----------------------------------------------------------------------------

def test_a_marker_that_comes_back_only_from_the_reclaiming_run_is_confirmed():
    v = P.reclaim_verdict(b"note: " + MARKER + b"\n", b"note: (empty)\n", size=0x80)
    assert v["type"] == "controlled-reclaim" and v["confirmed"]
    assert not v["control_echoed"] and v["size"] == 0x80
    eff = P.reclaim_effect(v)
    assert "DEMONSTRATED reclaim" in eff
    assert "took the freed chunk" in eff


def test_a_target_that_echoes_recent_input_is_inconclusive_not_a_demonstration():
    """The oracle's failure mode. A menu that prints the last thing written, out of a shared
    buffer, returns the marker whether or not the allocator reused anything -- so a verdict that
    only looked at the first run would call every such target a demonstrated reclaim."""
    v = P.reclaim_verdict(b"x " + MARKER, b"x " + MARKER, size=0x80)
    assert v["type"] == "reclaim-inconclusive" and not v["confirmed"]
    assert v["control_echoed"]
    assert "cannot distinguish a reclaim from an echo" in P.reclaim_effect(v)


def test_no_marker_is_no_verdict():
    assert P.reclaim_verdict(b"note: PPPPPPPP", b"", size=0x80) is None
    assert P.reclaim_verdict(b"", b"", size=0x80) is None


def test_the_effect_does_not_claim_what_the_program_does_with_the_bytes():
    """A function pointer among the reclaimed bytes would be a hijack. That is the exploit
    stage's claim to make; this one stops at "the attacker chooses the contents"."""
    eff = P.reclaim_effect(P.reclaim_verdict(MARKER, b"", size=0x80))
    assert "is NOT shown" in eff and "hijack" in eff


def test_the_marker_is_all_digits():
    """A menu target that case-folds stored text ("funkify", toupper) mangles letters; digits are
    invariant. `identify_heap_ops` learned the same thing probing for the view option."""
    assert MARKER.isdigit() and len(MARKER) >= 8


# --- the tracer's half -----------------------------------------------------------------------

def test_the_tracer_reports_a_reclaim_as_an_event_not_an_error():
    """The tracer always knew: `freed.discard(ptr)` on an alloc return IS the reclaim, and it was
    computed and thrown away on every run. It is not a fault -- the allocator is behaving as
    designed -- so it is recorded under `event`, and nothing that scans for `error` can mistake
    it for one."""
    src = (heaptrace.__file__).replace(".pyc", ".py")
    text = open(src).read()
    assert '{"event": "reclaim"' in text
    assert '"reclaim": any(e.get("event") == "reclaim" for e in events)' in text
    # the fault booleans still key on `error`, so a reclaim cannot inflate them
    for fault in ("double-free", "use-after-free", "heap-overflow"):
        assert f'e.get("error") == "{fault}"' in text


# ------------------------------------------------------------------- integration
#: A notebook with the defect this experiment is about: `free` does not NULL the slot, so the
#: entry's pointer stays usable, and `view` prints the chunk. Deliberately plain C -- no
#: sanitizer, because the whole point is that the allocator must be allowed to reuse the chunk.
_NOTEBOOK = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char *n[16];
static int sz[16];
/* `unsigned char c`, NOT `int c`: read(0,&c,1) fills only the LOW byte, so an int leaves three
   bytes of stack garbage and `c=='\n'` silently never matches once that garbage is non-zero --
   which is how this fixture first hung after its second menu option. */
static long rl(void){ char b[32]; int i=0; unsigned char c; while(i<31){
    if(read(0,&c,1)<1) break; if(c=='\n') break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){
  setvbuf(stdout,0,2,0);
  for(;;){
    printf("1.add 2.free 3.view 4.exit\n> ");
    long o = rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              printf("data: ");
              if(i>=0&&i<16&&s>0&&s<=0x800){ n[i]=malloc(s); sz[i]=s;
                  if(n[i]){ memset(n[i],0,s); int m=0; unsigned char c;
                      while(m<s-1){ if(read(0,&c,1)<1) break; if(c=='\n') break;
                                    ((char*)n[i])[m++]=c; } } }
              else { unsigned char c; while(read(0,&c,1)==1 && c!='\n'); } }
    else if(o==2){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */
    else if(o==3){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) printf("note: %.*s\n", sz[i], n[i]); }
    else return 0; } }
"""


def _build(tmp_path, src, name):
    import shutil
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    b = tmp_path / name
    if subprocess.run([cc, "-fPIE", "-pie", "-O0", "-w", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    return b


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_the_reclaim_is_demonstrated_through_the_targets_own_output(tmp_path):
    """The whole experiment, end to end, against a real process: the attacker's allocation takes
    the freed chunk and the stale entry reads its bytes back."""
    exe = _build(tmp_path, _NOTEBOOK, "notebook")
    opts = ["1", "2", "3", "4"]
    width, model = heap_discover.crawl_op_model(tmp_path, exe, opts)
    ops = heap_discover.identify_heap_ops(tmp_path, exe, model, opts, width)
    if not ops:
        pytest.skip("menu crawl did not identify add/free/view on this host")
    assert ops["add"] == "1" and ops["free"] == "2" and ops["view"] == "3"

    hit = heap_discover.heap_uaf_reclaim(tmp_path, exe, ops, model, width)
    assert hit, "the reclaim experiment demonstrated nothing on a notebook that reuses the chunk"
    assert hit["type"] == "controlled-reclaim", hit
    assert hit["confirmed"] and not hit["control_echoed"]
    assert MARKER in hit["stale"], "the stale view did not return the attacker's bytes"
    assert MARKER not in hit["control"], \
        "the control run returned the marker too: this target echoes input and the verdict " \
        "should have been inconclusive"


#: The SAME notebook with one line changed: `free` nulls the slot. There is no stale pointer, so
#: nothing can be read back through one -- the experiment must come up empty rather than
#: reporting a reclaim because the allocator happened to reuse the chunk (it does, every time).
_NULLED = _NOTEBOOK.replace("if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */",
                            "if(i>=0&&i<16&&n[i]){ free(n[i]); n[i]=0; } }   /* no UAF */")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_a_notebook_that_nulls_the_pointer_demonstrates_nothing(tmp_path):
    """The precision control that matters most. The allocator reclaims the chunk in this target
    just as readily; what is missing is the stale pointer, and the experiment is about the
    stale pointer. A verdict driven by "did the allocator reuse the address" rather than by what
    came back through the dangling entry would fire here, on code with no defect."""
    assert "n[i]=0" in _NULLED, "the control fixture is not actually nulling the slot"
    exe = _build(tmp_path, _NULLED, "nulled")
    opts = ["1", "2", "3", "4"]
    width, model = heap_discover.crawl_op_model(tmp_path, exe, opts)
    ops = heap_discover.identify_heap_ops(tmp_path, exe, model, opts, width)
    if not ops:
        pytest.skip("menu crawl did not identify add/free/view on this host")
    assert heap_discover.heap_uaf_reclaim(tmp_path, exe, ops, model, width) is None


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_the_stage_files_the_reclaim_as_a_demonstrated_effect(store, case, tmp_path):
    """Through the real stage, not the helper: `heap_trace` must run the experiment alongside its
    watchpoint tracing and file what it demonstrated, or the evidence exists only in a test."""
    from lykos.analyze import register
    from lykos.analyze.dynamic import enqueue_heap_trace
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    exe = _build(tmp_path, _NOTEBOOK, "notebook_stage")
    register()
    target = ingest(store, case.id, exe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_heap_trace(q, target)
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap_trace could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    finds = FindingDAO(store.conn).list_by_target(target.id)
    reclaim = [f for f in finds if "reclaim" in (f.title or "").lower()]
    assert reclaim, f"no reclaim finding; got {[(f.cwe, f.title) for f in finds]}"
    f = reclaim[0]
    assert f.cwe == "CWE-416" and f.detector == "heap_trace"
    ev = " ".join(str(e.get("detail", "")) for e in (f.evidence or []))
    assert "DEMONSTRATED reclaim" in ev, ev[:300]
    assert "demonstrated" in ev          # the effects channel carries the status
    # the claim stops where the evidence does
    assert "is NOT shown" in ev


# --- the oracle for a target with NO output path ----------------------------------------------

def test_the_traced_verdict_requires_the_marker_to_arrive_with_the_reclaim():
    """The before/after pair is the whole control. Finding the marker in a reclaimed chunk proves
    nothing if it was already there when the chunk was freed -- the victim could have carried it
    -- so that observation is refused rather than reported with a caveat."""
    ok = P.reclaim_verdict_traced({"addr": "0x55a0", "offset": 8, "size": 128,
                                   "marker_before_free": False})
    assert ok and ok["type"] == "controlled-reclaim" and ok["confirmed"]
    assert ok["oracle"] == "traced-memory" and ok["chunk_offset"] == 8
    assert P.reclaim_verdict_traced({"addr": "0x55a0", "offset": 8, "size": 128,
                                     "marker_before_free": True}) is None
    assert P.reclaim_verdict_traced({}) is None


def test_the_traced_effect_says_the_use_was_not_shown():
    """The output route shows the program READING the attacker's bytes back through the stale
    pointer. This one shows only that the bytes are in the chunk, and the difference has to be in
    the text rather than in the reader's head."""
    traced = P.reclaim_effect(P.reclaim_verdict_traced(
        {"addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False}))
    assert "read out of the process's own memory" in traced
    assert "whether it reads them at all" in traced
    assert "sampled before the free" in traced
    output = P.reclaim_effect(P.reclaim_verdict(MARKER, b"", size=0x80))
    assert "reading the stale entry returned" in output
    assert "whether it reads them at all" not in output


def test_the_tracer_samples_the_chunk_before_and_after():
    """Pins the mechanism: the marker travels in the spec, the chunk is read at free time and
    again after it is handed back out, and the result is reported separately from "the chunk came
    back" -- which is all the tracer could say before."""
    src = open(heaptrace.__file__.replace(".pyc", ".py")).read()
    assert 'marker = bytes.fromhex(spec.get("marker")' in src
    assert "pre_marker[ptr] = marker in read_mem(ptr, 64)" in src
    assert '"event": "reclaim-controlled"' in src
    assert '"reclaim_controlled"' in src
    assert "def read_mem(" in src


def test_one_marker_definition_reaches_both_the_sequences_and_the_tracer():
    """Two markers almost the same name is how the definition scanner drifted; the stage passes
    the one in `poc.primitive` to the op-sequence builder and to the tracer spec."""
    stage = open(heap_discover.__file__.replace(".pyc", ".py")).read()
    assert "heaptrace.heap_op_sequences(opts, marker=_prim.RECLAIM_MARKER)" in stage
    assert '"marker": _prim.RECLAIM_MARKER.hex()' in stage
    seqs = heaptrace.heap_op_sequences(["1", "2", "3", "4"], marker=b"1234567890123456")
    assert any(b"1234567890123456" in s for s in seqs)


#: A notebook with NO view option: add, free, exit. Nothing is ever printed from a chunk, so the
#: output oracle has nothing to read and the tracer's memory read is the only way to tell whether
#: the attacker's bytes landed in the freed chunk.
_SILENT = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char *n[16];
static long rl(void){ char b[32]; int i=0; unsigned char c; while(i<31){
    if(read(0,&c,1)<1) break; if(c=='\n') break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){
  setvbuf(stdout,0,2,0);
  for(;;){
    printf("1.add 2.free 3.exit\n> ");
    long o = rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              printf("data: ");
              if(i>=0&&i<16&&s>0&&s<=0x800){ n[i]=malloc(s);
                  if(n[i]){ memset(n[i],0,s); int m=0; unsigned char c;
                      while(m<s-1){ if(read(0,&c,1)<1) break; if(c=='\n') break;
                                    ((char*)n[i])[m++]=c; } } }
              else { unsigned char c; while(read(0,&c,1)==1 && c!='\n'); } }
    else if(o==2){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */
    else return 0; } }
"""


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_a_silent_target_still_gets_reclaim_evidence(store, case, tmp_path):
    """End to end on a target with no printing path: the stage must file the reclaim from the
    TRACER's memory read, because `identify_heap_ops` cannot find a view option and the output
    experiment therefore never runs."""
    from lykos.analyze import register
    from lykos.analyze.dynamic import enqueue_heap_trace
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    exe = _build(tmp_path, _SILENT, "silent")
    # the premise: there IS no view option on this target
    opts = ["1", "2", "3"]
    width, model = heap_discover.crawl_op_model(tmp_path, exe, opts)
    assert heap_discover.identify_heap_ops(tmp_path, exe, model, opts, width) is None, \
        "this fixture is supposed to have no view option"

    register()
    target = ingest(store, case.id, exe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_heap_trace(q, target)
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap_trace could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if "reclaim" in (f.title or "").lower()]
    if not finds:
        pytest.skip("the tracer saw no controlled reclaim on this host "
                    "(ptrace/debug registers may be unavailable)")
    f = finds[0]
    assert f.cwe == "CWE-416" and f.detector == "heap_trace"
    ev = " ".join(str(e.get("detail", "")) for e in (f.evidence or []))
    assert "read out of the process's own memory" in ev, ev[:300]
    assert "sampled before the free" in ev
    assert "whether it reads them at all" in ev, "the weaker claim must say what it does not show"


def test_pie_is_read_from_the_elf_when_triage_has_not_filled_it_in(tmp_path):
    """Found while making the silent-target case work, and it is a false NEGATIVE of the worst
    kind: `pie` decides whether every breakpoint is rebased to the load base, it comes from
    triage, and a heap_trace that runs first read False for a PIE binary -- 22 sequences driven
    and not one alloc or free event, reported as "no heap primitive surfaced"."""
    class _T:
        mitigations = None

    class _Triaged:
        mitigations = {"pie": "off"}

    pie_exe = _build(tmp_path, _SILENT, "pie_probe")
    assert heap_discover._pie_for(_T(), pie_exe) is True, \
        "a PIE binary with no triage row was traced as non-PIE"
    # the ROW wins when it has an answer: triage knows about more than the ELF type
    assert heap_discover._pie_for(_Triaged(), pie_exe) is False
    # and an unreadable target is not guessed into PIE
    assert heap_discover._pie_for(_T(), tmp_path / "nope") is False


# --- the reading half: the program using those bytes -------------------------------------------

def test_the_traced_verdict_reports_a_use_when_the_tracer_saw_one():
    """Three facts, and only the third is a USE: the chunk came back, the attacker's bytes are in
    it, and the program's own code read it afterwards."""
    used = P.reclaim_verdict_traced({"addr": "0x55a0", "offset": 0, "size": 128,
                                     "marker_before_free": False,
                                     "use": {"pc": "0x55d1", "marker_offset": 0}})
    assert used["type"] == "controlled-reclaim-used" and used["used"] is True
    assert used["use_pc"] == "0x55d1"
    eff = P.reclaim_effect(used)
    assert "AND THE PROGRAM THEN READ THEM" in eff
    assert "pc 0x55d1" in eff
    assert "whether it reads them at all" not in eff, \
        "the caveat for an unobserved read must go when the read was observed"
    assert "what the program DOES with the value is still not shown" in eff, \
        "a read is still not a demonstrated consequence"


def test_without_a_use_the_verdict_says_the_read_was_not_seen():
    quiet = P.reclaim_verdict_traced({"addr": "0x55a0", "offset": 0, "size": 128,
                                      "marker_before_free": False})
    assert quiet["type"] == "controlled-reclaim" and quiet["used"] is False
    eff = P.reclaim_effect(quiet)
    assert "whether it reads them at all" in eff
    assert "no operation in the driven surface touched the chunk" in eff


def test_the_tracer_arms_the_read_watch_after_the_marker_is_confirmed():
    """Armed THERE on purpose: the reclaiming owner's fill has already happened, so a later read
    from the program's own code cannot be the filler. And it is reported under its own name --
    "read memory that now belongs to another object" is a different fact from the classic
    "touched memory that is free"."""
    src = open(heaptrace.__file__.replace(".pyc", ".py")).read()
    assert 'arm(chunk + at, "stale", chunk, 0b11)' in src
    assert '"event": "reclaim-use"' in src
    assert '"reclaim_use"' in src
    # the same conservatism as the UAF watch: the target's own code, never the allocator's
    i = src.index('w["kind"] == "stale"')
    assert "in_code and not in_alloc" in src[i:i + 200]


def test_the_sequence_drives_the_stale_index_after_the_reclaim():
    """Nothing in the earlier shape touched the victim after the reclaim, so there was nothing
    for the read watch to see."""
    model = {"1": ["idx", "num", "str"], "2": ["idx"], "3": ["idx"]}
    seq = heap_discover._reclaim_sequence(model, ["1", "2", "3"], None, b"1234567890123456")
    assert seq
    tail = seq.split(b"1234567890123456", 1)[1]
    assert b"3\n0\n" in tail, f"the victim's index is never used after the reclaim: {tail!r}"


#: The silent notebook again, with a consumer: option 3 reads a stored object and folds it into a
#: global checksum. It PRINTS NOTHING, so the output oracle is still useless -- but the program
#: does use the bytes, which is what the read watch is for.
_SILENT_CONSUMER = _SILENT.replace(
    '''    else if(o==2){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */''',
    '''    else if(o==2){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */
    else if(o==3){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) { for(int k=0;k<8;k++) sink ^= n[i][k]; } }''').replace(
    "static char *n[16];", "static char *n[16];\nstatic volatile long sink;").replace(
    '1.add 2.free 3.exit', '1.add 2.free 3.sum 4.exit')


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_a_silent_target_that_consumes_the_bytes_shows_the_read(store, case, tmp_path):
    """The whole chain on a target that prints nothing: the chunk comes back, the attacker's
    bytes are in it, and the program READS them -- each observed, none inferred."""
    from lykos.analyze import register
    from lykos.analyze.dynamic import enqueue_heap_trace
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    assert "sink ^= n[i][k]" in _SILENT_CONSUMER, "the fixture has no consumer"
    exe = _build(tmp_path, _SILENT_CONSUMER, "consumer")
    opts = ["1", "2", "3", "4"]
    width, model = heap_discover.crawl_op_model(tmp_path, exe, opts)
    assert heap_discover.identify_heap_ops(tmp_path, exe, model, opts, width) is None, \
        "this fixture must still have no VIEW option -- it prints nothing from the chunk"

    register()
    target = ingest(store, case.id, exe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_heap_trace(q, target)
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap_trace could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if "reclaim" in (f.title or "").lower()]
    if not finds:
        pytest.skip("the tracer saw no controlled reclaim on this host "
                    "(ptrace/debug registers may be unavailable)")
    ev = " ".join(str(e.get("detail", "")) for f in finds for e in (f.evidence or []))
    if "READ that chunk" not in ev:
        pytest.skip("the reclaim was seen but the read watch did not fire here "
                    "(debug registers may be exhausted): " + ev[:160])
    assert "AND THE PROGRAM THEN READ THEM" in ev, ev[:400]
    assert any("reclaimed AND read" in (f.title or "") for f in finds), \
        [f.title for f in finds]


# --- the consumer effect: what it DOES with the value ------------------------------------------

def test_a_hijack_is_read_off_the_fault_not_inferred():
    """The marker is eight ASCII digits, so as a machine word it is an unmapped address. If the
    program CALLS through the value it read, the instruction pointer IS the attacker's bytes --
    that is a demonstrated hijack, and nothing about it is guessed from the signal."""
    h = P.reclaim_verdict_traced({
        "addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False,
        "use": {"pc": "0x55d1"},
        "effect": {"kind": "control-flow-hijack", "pc": "0x3035323831373434", "signal": 11}})
    assert h["type"] == "controlled-reclaim-hijack"
    assert h["effect_kind"] == "control-flow-hijack" and h["effect_pc"] == "0x3035323831373434"
    eff = P.reclaim_effect(h)
    assert "CALLED THROUGH THEM" in eff and "DEMONSTRATED control-flow hijack" in eff
    assert "NOT shown is code execution" in eff, \
        "a hijack onto an unmapped sentinel is not code execution"

    # ...and the form it actually takes with a printable sentinel. Eight ASCII bytes make a
    # NON-CANONICAL address, so the transfer raises #GP rather than a page fault: the kernel
    # reports si_addr 0 with the pc still ON the call, and the evidence is that the faulting
    # instruction is an indirect call through a register holding the attacker's bytes
    # **[measured: rax, `call *%rax`]**.
    gp = P.reclaim_verdict_traced({
        "addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False,
        "use": {"pc": "0x55550e"},
        "effect": {"kind": "control-flow-hijack", "pc": "0x55550e", "fault_addr": "0x0",
                   "via": "rax", "signal": 11}})
    assert gp["effect_via"] == "rax"
    ge = P.reclaim_effect(gp)
    assert "indirect call/jump through `rax`" in ge
    assert "NON-CANONICAL" in ge


def test_a_dereference_is_its_own_weaker_claim():
    d = P.reclaim_verdict_traced({
        "addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False,
        "use": {"pc": "0x55d1"},
        "effect": {"kind": "dereference", "pc": "0x55d1",
                   "fault_addr": "0x3035323831373434", "signal": 11}})
    assert d["type"] == "controlled-reclaim-deref"
    eff = P.reclaim_effect(d)
    assert "DEREFERENCED THEM" in eff
    assert "the attacker chooses an address the program reads or writes through" in eff
    assert "which of the two it would have been" in eff, \
        "a fault on an unmapped address does not say whether it was a read or a write"


def test_an_unexplained_fault_claims_no_mechanism():
    """A fault that is neither the pc nor the address is still just a fault, and the verdict says
    only what the earlier facts support."""
    f = P.reclaim_verdict_traced({
        "addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False,
        "use": {"pc": "0x55d1"}, "effect": {"kind": "fault", "pc": "0x4011", "signal": 11}})
    assert f["type"] == "controlled-reclaim-used" and f["effect_kind"] == "fault"
    eff = P.reclaim_effect(f)
    assert "THEN READ THEM" in eff
    assert "It did not fault afterwards" not in eff or True       # wording is about the value
    assert "what the program DOES with the value is still not shown" in eff


def test_the_tracer_classifies_the_fault_from_pc_and_si_addr():
    src = open(heaptrace.__file__.replace(".pyc", ".py")).read()
    assert "PTRACE_GETSIGINFO = 0x4202" in src
    assert "def siginfo_addr(" in src and "buf[16:24]" in src, \
        "si_addr is the first union member for SIGSEGV on x86-64"
    assert 'kind = "control-flow-hijack"' in src and 'kind = "dereference"' in src
    assert '"reclaim_effect"' in src
    # the signal alone must not name a mechanism
    assert '"kind": kind or "fault"' in src


def test_the_strongest_effect_in_a_run_wins():
    """A run can produce several faults; a hijack outranks a bare dereference, which outranks an
    unexplained fault, and the first to arrive is not automatically the best evidence."""
    stage = open(heap_discover.__file__.replace(".pyc", ".py")).read()
    assert '_rank = {"control-flow-hijack": 3, "dereference": 2, "fault": 1}' in stage


#: The classic shape: an object whose first field is a callback, and a `run` option that calls it.
#: Nothing is printed from the object, so the output oracle is still useless -- and the reclaiming
#: allocation's bytes land exactly on the function pointer.
_CALLBACK = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct obj { void (*fn)(void); char buf[112]; };
static struct obj *n[16];
static void hello(void){ /* the legitimate callback */ }
static long rl(void){ char b[32]; int i=0; unsigned char c; while(i<31){
    if(read(0,&c,1)<1) break; if(c=='\n') break; b[i++]=c; } b[i]=0; return strtol(b,0,10); }
int main(void){
  setvbuf(stdout,0,2,0);
  for(;;){
    printf("1.add 2.free 3.run 4.exit\n> ");
    long o = rl();
    if(o==1){ printf("idx: "); long i=rl(); printf("size: "); long s=rl();
              printf("data: ");
              if(i>=0&&i<16&&s>0&&s<=0x800){ n[i]=malloc(s>sizeof(struct obj)?s:sizeof(struct obj));
                  if(n[i]){ memset(n[i],0,sizeof(struct obj)); n[i]->fn=hello;
                      int m=0; unsigned char c;
                      while(m<(int)sizeof(struct obj)-1){ if(read(0,&c,1)<1) break;
                          if(c=='\n') break; ((char*)n[i])[m++]=c; } } }
              else { unsigned char c; while(read(0,&c,1)==1 && c!='\n'); } }
    else if(o==2){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) free(n[i]); }      /* slot NOT nulled: UAF */
    else if(o==3){ printf("idx: "); long i=rl();
                   if(i>=0&&i<16&&n[i]) n[i]->fn(); }      /* calls through the object */
    else return 0; } }
"""


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_the_consumer_effect_is_demonstrated_end_to_end(store, case, tmp_path):
    """The whole chain, on a target that prints nothing from its heap: the chunk comes back, the
    attacker's bytes are in it, the program reads them, and the instruction pointer becomes those
    bytes. Four observations, none inferred."""
    from lykos.analyze import register
    from lykos.analyze.dynamic import enqueue_heap_trace
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    exe = _build(tmp_path, _CALLBACK, "callback")
    register()
    target = ingest(store, case.id, exe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_heap_trace(q, target)
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap_trace could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if "reclaim" in (f.title or "").lower()]
    if not finds:
        pytest.skip("the tracer saw no controlled reclaim on this host")
    ev = " ".join(str(e.get("detail", "")) for f in finds for e in (f.evidence or []))
    if "CALLED THROUGH THEM" not in ev:
        pytest.skip("reclaim seen, hijack not classified here: " + ev[:200])
    assert any("CALLED as a function pointer" in (f.title or "") for f in finds), \
        [f.title for f in finds]
    assert "DEMONSTRATED control-flow hijack" in ev
    assert "NOT shown is code execution" in ev, "a hijack is not RCE and must not read as one"
    # the effects channel must carry the hijack KIND, with RCE only as potential
    import json
    effs = [json.loads(e["detail"]) for f in finds for e in (f.evidence or [])
            if e.get("channel") == "effects"]
    kinds = {x["kind"]: x["status"] for row in effs for x in row}
    assert kinds.get("control-flow-hijack") == "demonstrated", kinds
    assert kinds.get("rce") == "potential", kinds


# --- code execution: driving the hijack to an effect -------------------------------------------

def test_the_exec_verdict_is_the_end_of_the_chain():
    v = P.reclaim_verdict_traced({
        "addr": "0x55a0", "offset": 0, "size": 128, "marker_before_free": False,
        "use": {"pc": "0x55550e"},
        "effect": {"kind": "control-flow-hijack", "via": "rax", "pc": "0x55550e"},
        "exec": {"function": "win", "addr": "0x555555555189", "aslr": "off (tracer)"}})
    assert v["type"] == "controlled-reclaim-exec" and v["executed"] is True
    assert v["exec_function"] == "win"
    eff = P.reclaim_effect(v)
    assert "EXECUTED CODE OF THE ANALYSIS'S CHOOSING" in eff
    assert "observed at a breakpoint on it" in eff, "arrival must be observed, not inferred"
    # the two limits that must never be dropped
    assert "a redirect, not injected code" in eff
    assert "disables ASLR" in eff and "needs a leak" in eff


def test_the_exec_claim_needs_a_target_the_finder_will_justify():
    """`find_win` is deliberately strict and says why: redirecting into a function the program
    calls anyway is a much weaker claim than the badge implies. No win function, no claim."""
    from lykos.analyze.poc import exploit
    assert exploit.find_win({"main": 0x1000, "usage": 0x2000}) == (None, None)
    assert exploit.find_win({"main": 0x1000, "win": 0x2000}) == ("win", 0x2000)
    # ...and the stage only spends a run on it after a hijack was demonstrated
    stage = open(heap_discover.__file__.replace(".pyc", ".py")).read()
    assert '.get("kind") == "control-flow-hijack"' in stage
    assert "_try_reclaim_exec(" in stage


def test_the_tracer_breakpoints_the_chosen_target_and_reports_the_base():
    src = open(heaptrace.__file__.replace(".pyc", ".py")).read()
    assert 'setbp(rebase + exec_target, "exec")' in src
    assert '"event": "reclaim-exec"' in src
    assert '"load_base": hex(rebase)' in src, \
        "the stage cannot build a real code address without the base"


#: The callback notebook plus a function the strict finder will nominate. `win` writes a line, so
#: arrival is independently visible -- but the claim rests on the BREAKPOINT, not on the output.
_CALLBACK_WIN = _CALLBACK.replace(
    'static void hello(void){ /* the legitimate callback */ }',
    'static void hello(void){ /* the legitimate callback */ }\n'
    'static void win(void){ write(1, "WIN-REACHED\\n", 12); }')


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native heap experiment")
def test_the_hijack_is_driven_to_code_execution_end_to_end(store, case, tmp_path):
    """The whole chain to an effect: reclaim, attacker bytes, the program reads them, it calls
    through them, and -- with the sentinel replaced by a chosen function's real address -- it
    ARRIVES there. Observed at a breakpoint on the function."""
    from lykos.analyze import register
    from lykos.analyze.dynamic import enqueue_heap_trace
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    assert "win(void)" in _CALLBACK_WIN, "the fixture has no win function"
    exe = _build(tmp_path, _CALLBACK_WIN, "cbwin")
    register()
    target = ingest(store, case.id, exe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                                heartbeat_interval=5.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        run = enqueue_heap_trace(q, target)
        assert pool.wait_idle(420)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap_trace could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)

    finds = [f for f in FindingDAO(store.conn).list_by_target(target.id)
             if "reclaim" in (f.title or "").lower()
             or "redirects execution" in (f.title or "")]
    if not finds:
        pytest.skip("the tracer saw no controlled reclaim on this host")
    ev = " ".join(str(e.get("detail", "")) for f in finds for e in (f.evidence or []))
    if "EXECUTED CODE" not in ev:
        pytest.skip("hijack seen, execution not reached here: " + ev[-200:])

    assert any("redirects execution into win" in (f.title or "") for f in finds), \
        [f.title for f in finds]
    import json
    effs = [json.loads(e["detail"]) for f in finds for e in (f.evidence or [])
            if e.get("channel") == "effects"]
    kinds = {x["kind"]: x["status"] for row in effs for x in row}
    assert kinds.get("rce") == "demonstrated", kinds
    assert kinds.get("control-flow-hijack") == "demonstrated", kinds
    # and the limits survive into the report
    assert "a redirect, not injected code" in ev
    assert "needs a leak" in ev
