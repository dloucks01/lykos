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
