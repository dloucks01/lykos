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
