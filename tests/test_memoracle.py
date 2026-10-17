"""Binary-only memory-safety oracle: valgrind memcheck classification + dislocator preload."""

from lykos.analyze.dynamic import memoracle as M


def _vg(*body):
    return ("\n".join("==12345== " + b for b in body)).encode()


def test_heap_oob_write_is_cwe122():
    out = _vg("Invalid write of size 4",
              "   at 0x109155: main (t.c:10)",
              " Address 0x4a51048 is 0 bytes after a block of size 8 alloc'd")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "heap-oob-write" and v["cwe"] == "CWE-122" and v["size"] == 4


def test_heap_oob_read_is_cwe125():
    out = _vg("Invalid read of size 1",
              " Address 0x4a51049 is 1 bytes after a block of size 8 alloc'd")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "heap-oob-read" and v["cwe"] == "CWE-125"


def test_use_after_free_is_cwe416():
    out = _vg("Invalid read of size 1",
              " Address 0x4a51040 is 0 bytes inside a block of size 8 free'd")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "use-after-free" and v["cwe"] == "CWE-416"


def test_double_free_is_cwe415():
    out = _vg("Invalid free() / delete / delete[] / realloc()",
              " Address 0x4a51040 is 0 bytes inside a block of size 8 free'd")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "double-free" and v["cwe"] == "CWE-415"


def test_invalid_free_of_non_block_is_cwe590():
    out = _vg("Invalid free() / delete / delete[] / realloc()",
              " Address 0x1fff is on thread 1's stack")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "invalid-free" and v["cwe"] == "CWE-590"


def test_uninitialised_value():
    out = _vg("Conditional jump or move depends on uninitialised value(s)",
              "   at 0x1091aa: main")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "uninitialised" and v["cwe"] == "CWE-457"


def test_leak_only_run():
    out = _vg("HEAP SUMMARY:", "  definitely lost: 24 bytes in 1 blocks")
    v = M.parse_memcheck(out)
    assert v and v["kind"] == "leak" and v["cwe"] == "CWE-401"


def test_clean_run_is_none():
    clean = _vg("HEAP SUMMARY:", "  all heap blocks were freed -- no leaks")
    assert M.parse_memcheck(clean) is None
    assert M.parse_memcheck(b"") is None


def test_worst_error_wins_when_several():
    out = _vg("Invalid read of size 1",
              " Address 0x1 is 1 bytes after a block of size 8 alloc'd",
              "Invalid free() / delete / delete[] / realloc()",
              " Address 0x2 is 0 bytes inside a block of size 8 free'd")
    v = M.parse_memcheck(out)
    assert v["kind"] == "double-free"                    # double-free outranks heap-oob-read


def test_dislocator_preload_env_for_host_arch():
    lib = M.dislocator_lib()
    if lib is None:
        return                                           # libdislocator not installed here
    env = M.dislocator_preload({}, host_arch="x86-64", target_arch="x86-64")
    assert env is not None and str(lib) in env["LD_PRELOAD"]
    # a cross-arch guest gets no host preload object
    assert M.dislocator_preload({}, host_arch="x86-64", target_arch="aarch64") is None
    # an existing LD_PRELOAD is preserved (prepended, not clobbered)
    env2 = M.dislocator_preload({"LD_PRELOAD": "/x.so"}, host_arch="x86-64", target_arch="x86-64")
    assert env2["LD_PRELOAD"].endswith("/x.so") and str(lib) in env2["LD_PRELOAD"]


# --- the oracle nothing turned on -----------------------------------------------------------
# `dislocator_preload` above has existed since the oracle landed, `batch_runner` reads
# LYKOS_PRELOAD in its forked child, and `doctor` reports the library as present. Nothing called
# the first and nothing set the second: `grep -rn LYKOS_PRELOAD core/` found a reader and no
# writer, and doc 29 described the oracle as something an operator exports by hand. So the
# strongest heap oracle available for a stripped, source-less binary was never applied in any
# campaign -- and the defect class it exists for is the one that does not fault on its own.
_SILENT_OOB = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
  char *p = malloc(32);
  memset(p, 'A', 32);
  char buf[64]; size_t n = fread(buf, 1, sizeof buf, stdin);
  size_t far = n ? (size_t)(unsigned char)buf[0] * 64 : 0;   /* the attacker picks the distance */
  volatile char sink = p[far];                                /* heap OOB READ -- silent normally */
  printf("read %c at +%zu\n", sink, far);
  return 0; }"""


def _build_silent_oob(tmp_path, gcc):
    import subprocess
    src = tmp_path / "oob.c"; src.write_text(_SILENT_OOB)
    exe = tmp_path / "oob"
    if subprocess.run([gcc, "-O0", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        return None
    return exe


def test_the_guard_page_turns_a_silent_heap_read_into_a_fault(tmp_path, gcc):
    """The measurement that justifies the whole change.

    A read 64 bytes past a 32-byte allocation lands in the same heap chunk run and the program
    exits 0: nothing in the process notices, so no fuzzer can either. With the guard-page
    allocator the allocation sits at the end of its own page with an unmapped page behind it and
    the same input SIGSEGVs. Asserted on BOTH execution paths, because the campaign uses the
    batch runner where it can and `run` where it cannot, and an oracle present in one of them is
    an oracle that depends on bubblewrap being available.
    """
    import pytest
    from lykos.analyze.dynamic import sandbox
    exe = _build_silent_oob(tmp_path, gcc)
    if exe is None:
        pytest.skip("build failed")
    if M.dislocator_lib() is None:
        pytest.skip("libdislocator not installed here")

    plain = sandbox.run(str(exe), stdin=bytes([1]), timeout=10)
    assert not plain.crashed, "the fixture is supposed to be SILENT without the oracle"
    assert sandbox.GUARD_PAGE_TAG not in plain.isolation

    guarded = sandbox.run(str(exe), stdin=bytes([1]), timeout=10, guard_page=True)
    assert guarded.crashed and guarded.signal_name == "SIGSEGV"
    # The tag is what makes the crash reproducible later: `build_poc` reads it to decide how to
    # replay, and the bundle's runner.sh exports the preload because of it.
    assert sandbox.GUARD_PAGE_TAG in guarded.isolation

    batch = sandbox.run_batch(str(exe), [bytes([1])], timeout=5, guard_page=True)
    if batch is not None:                                # None = no bubblewrap on this host
        assert batch[0].crashed and sandbox.GUARD_PAGE_TAG in batch[0].isolation
        unguarded = sandbox.run_batch(str(exe), [bytes([1])], timeout=5)
        assert unguarded is not None and not unguarded[0].crashed


def test_the_guard_page_declines_where_it_cannot_apply(tmp_path, gcc):
    """A cross-arch guest would need a guest-built preload object, and a sanitizer build already
    instruments every allocation -- layering this on either is how an oracle becomes a crash
    that is not the target's fault."""
    import pytest
    from lykos.analyze.dynamic import sandbox
    if M.dislocator_lib() is None:
        pytest.skip("libdislocator not installed here")
    env, applied = sandbox.guard_page_env(None, exe="/bin/true", arch="mips", host="x86-64",
                                          sanitizer=False)
    assert not applied
    env, applied = sandbox.guard_page_env(None, exe="/bin/true", arch="x86-64", host="x86-64",
                                          sanitizer=True)
    assert not applied
    _env, applied = sandbox.guard_page_env(None, exe="/bin/true", arch="x86-64", host="x86-64",
                                           sanitizer=False)
    assert applied


def test_a_static_binary_is_not_claimed_as_guarded(tmp_path, gcc):
    """LD_PRELOAD is read by the DYNAMIC LOADER, so a statically linked binary ignores it.

    This is not a corner case: every busybox in the multi-architecture corpus is static, as is
    most firmware. Preloading there does nothing, and tagging the run `+guardpage` anyway would
    put a false statement about how a crash was found into the record that `build_poc` reads to
    decide how to replay it.
    """
    import subprocess

    import pytest
    from lykos.analyze.dynamic import sandbox
    src = tmp_path / "s.c"; src.write_text("int main(void){return 0;}")
    static = tmp_path / "s"
    if subprocess.run([gcc, "-static", "-w", str(src), "-o", str(static)],
                      capture_output=True).returncode != 0:
        pytest.skip("no static libc on this host")
    assert sandbox._interp_of(str(static)) == b"", "a static binary has no PT_INTERP"
    _env, applied = sandbox.guard_page_env(None, exe=str(static), arch="x86-64", host="x86-64",
                                           sanitizer=False)
    assert not applied

    dyn = tmp_path / "d"
    subprocess.run([gcc, "-w", str(src), "-o", str(dyn)], capture_output=True, check=False)
    if M.dislocator_lib() is not None and sandbox._interp_of(str(dyn)):
        assert sandbox.guard_page_env(None, exe=str(dyn), arch="x86-64", host="x86-64",
                                      sanitizer=False)[1]


# --- the oracle that HIDES the defect ---------------------------------------------------------
# The guard page makes a heap over-read fault. It also suppresses an overflow the KERNEL
# performs: `read(fd, buf, n)` into a buffer at the end of its page returns EFAULT rather than
# faulting, so the copy never lands and the program runs on undisturbed. Two oracles, two
# classes of overflow, and each hides the other's -- which is why the campaign now runs every
# SEED under both.
_KERNEL_WRITTEN_OVERFLOW = r"""#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct o { char t[32]; void (*f)(void); };
static void ok(void){ printf("ok\n"); }
static long rl(void){ char b[32]; int i=0,c;
  while(i<31){ c=getchar(); if(c<0||c=='\n')break; b[i++]=c; }
  b[i]=0; return strtol(b,0,10); }
struct o *x;
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  while(1){ printf("1.new 2.fill 3.use 4.quit\n> ");
    long c=rl();
    if(c==1){ x=malloc(sizeof *x); if(x) x->f=ok; }
    else if(c==2){ long n=rl(); if(x&&n>0) read(0,x->t,(size_t)n); }  /* the KERNEL writes past t */
    else if(c==3){ if(x) x->f(); }                   /* ...and calling it is what notices */
    else return 0; } }"""


def test_a_kernel_written_overflow_is_hidden_by_the_guard_page(tmp_path, gcc):
    """The measurement that justifies running every seed under both oracles.

    `read(2)` into a buffer at the end of a guarded page cannot fault the process: the kernel
    checks the destination and returns EFAULT, the bytes are never copied, and the function
    pointer the overflow was supposed to overwrite still holds its original value. Measured on
    the heap-notebook conformance fixture, whose crashing SEED is SIGSEGV plain and exit 0 under
    libdislocator: the campaign ran 5,810 executions and reported zero crashes on a target that
    crashes on its own seed.
    """
    import subprocess

    import pytest
    from lykos.analyze.dynamic import sandbox
    src = tmp_path / "kw.c"; src.write_text(_KERNEL_WRITTEN_OVERFLOW)
    exe = tmp_path / "kw"
    if subprocess.run([gcc, "-O0", "-w", "-no-pie", str(src), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("build failed")
    if M.dislocator_lib() is None:
        pytest.skip("libdislocator not installed here")
    # create, overflow the object's buffer with EXACTLY the length we declared, then call it
    data = b"1\n2\n512\n" + b"B" * 512 + b"3\n"

    plain = sandbox.run(str(exe), stdin=data, timeout=10)
    assert plain.crashed and plain.signal_name == "SIGSEGV", \
        "the fixture is supposed to crash WITHOUT the oracle"

    guarded = sandbox.run(str(exe), stdin=data, timeout=10, guard_page=True)
    assert sandbox.GUARD_PAGE_TAG in guarded.isolation
    assert not guarded.crashed, (
        "a kernel-performed write past a guarded page cannot copy the whole payload: the write "
        "stops at the page boundary, the rest of the sequence is read as data, and the operation "
        "that would call the overwritten pointer is never selected -- if this ever starts "
        "crashing, the dual-oracle seed sweep is no longer the reason the class is found")


def test_the_campaign_calibrates_every_seed_under_both_oracles():
    """Structural: the seed queue carries its ORACLE, and both flags are in it. The mutation
    phase keeps the stage's chosen oracle -- only the seeds are doubled, which is a few dozen
    executions."""
    import pathlib

    from lykos.analyze.fuzz import stage as fstage
    src = pathlib.Path(fstage.__file__).read_text()
    assert "[(s, guard) for s in _seeds] + [(s, not guard) for s in _seeds]" in src
    assert "guard_page=guard_eff" in src, "the batch must follow the queue's oracle"


# ---------------------------------------------------------- what the disclosed residue is WORTH
# memcheck proves undefined bytes reached a write syscall -- an effect, and where this stage used
# to stop. Stack residue full of POINTERS defeats ASLR and residue full of padding does not, and
# the whole L2 disclosure ladder hangs off a FAULT (an MSan build aborts inside the read), so on a
# plain binary the class had no path to a primitive however good the bytes were.
_UNINIT_PTR_SRC = '''#include <stdio.h>
#include <string.h>
static void greet(void){ puts("hello"); }
struct session { void (*cb)(void); char name[24]; long id; };
static void setup(void){ struct session s; s.cb=greet; strcpy(s.name,"admin"); s.id=7;
  printf("session %ld ready\\n", s.id); }
static void dump(void){ char b[64]; fwrite(b,1,sizeof b,stdout); }
int main(void){ setvbuf(stdout,0,2,0); setup(); dump(); return 0; }
'''


def test_the_uninit_disclosure_arm_asks_what_the_bytes_were():
    """Pinned at the source level, because the ORDER and the gate are the point: the CWE-200
    finding is filed either way, and the L2 primitive only on a base the leak corroborates."""
    import inspect

    from lykos.analyze.dynamic import uninit_stage
    src = inspect.getsource(uninit_stage.mem_oracle_stage)
    i = src.index('if kind == "uninit-disclosure" and not leaked:')
    j = src.index("_disclosed_bases(", i)
    k = src.index("_file_uninit_l2(", i)
    assert i < j < k
    assert 'disc.get("proved")' in src[j:k], "the L2 claim must be gated on a corroborated base"


def test_an_uninitialised_read_can_disclose_the_image_base(tmp_path, gcc):
    """The rung itself, end to end on a real PIE binary under live ASLR: the dead frame of one
    function holds a code pointer, the next function writes its own uninitialised frame out, and
    `disclosed_bases` recovers the load base from two independent leaked slots. Nothing faults."""
    import subprocess

    import pytest
    from lykos.analyze.poc import leak
    c = tmp_path / "u.c"; c.write_text(_UNINIT_PTR_SRC)
    exe = tmp_path / "u"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w", str(c),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    out = b"".join(subprocess.run([str(exe)], capture_output=True).stdout for _ in range(2))
    d = leak.disclosed_bases(out, exe.read_bytes(), b"")
    assert d["proved"] and d["pie_base"], d.get("note")
    assert d["pie_base"] % 0x1000 == 0
