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
