"""Unit tests for the validator's report parsers -- the correctness-critical pieces that decide
WHICH source line a confirmation is attributed to. A parser bug here = a mis-attributed finding,
so these run fast (no angr, no execution) against real sanitizer/strace output samples."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from lykos.hypo import validate as V  # noqa: E402


def test_asan_stack_overflow_line_and_func():
    err = (
        "==42==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f..\n"
        "WRITE of size 4 at 0x7f.. thread T0\n"
        "    #0 0x401234 in greet /home/x/prog.c:19\n"
        "    #1 0x401300 in main /home/x/prog.c:30\n"
    )
    kind, func, path, line, alloc = V.parse_sanitizer(err)
    assert kind == "stack-buffer-overflow"
    assert func == "greet" and line == 19 and path.endswith("prog.c")
    assert alloc is None


def test_asan_int_overflow_alloc_frame():
    err = (
        "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..\n"
        "WRITE of size 8 at 0x.. thread T0\n"
        "    #0 0x40a in main /x/prog.c:40\n"
        "0x.. is located 0 bytes to the right of 4-byte region\n"
        "allocated by thread T0 here:\n"
        "    #0 0x.. in malloc ../libsanitizer/asan/asan_malloc_linux.cpp:67\n"
        "    #1 0x40b in main /x/prog.c:38\n"
    )
    kind, func, path, line, alloc = V.parse_sanitizer(err)
    assert "heap-buffer-overflow" in kind
    assert line == 40          # the overflowing write
    assert alloc == 38         # the allocation site (what int-overflow-alloc matches on)


def test_ubsan_vptr_downcast():
    err = ("/x/shapes.cpp:13:22: runtime error: downcast of address 0x.. which does not point to "
           "an object of type 'Square'\n"
           "    #0 0x.. in main /x/shapes.cpp:13:22\n")
    rep = V.parse_sanitizer(err)
    assert rep is not None
    kind, func, path, line, _ = rep
    assert "downcast" in kind          # the type-confusion branch gates on this
    assert line == 13 and path.endswith("shapes.cpp")


def test_ubsan_division_kind():
    err = ("/x/z.c:27:12: runtime error: division by zero\n"
           "    #0 0x401abc in channel_mean /x/z.c:27:12\n")
    kind, func, path, line, _ = V.parse_sanitizer(err)
    assert kind.startswith("ubsan:division") and line == 27 and func == "channel_mean"


def test_msan_use_of_uninitialized_first_program_frame():
    err = (
        "==1==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
        "    #0 0x58f in main /x/u.c:10:15\n"
        "    #1 0x753 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:59:16\n"
    )
    rep = V.parse_msan(err)
    assert rep is not None
    func, path, line = rep
    assert func == "main" and line == 10 and path.endswith("u.c")   # libc frame skipped


def test_msan_none_when_clean():
    assert V.parse_msan("clean exit, nothing here") is None


def test_lsan_leak_allocation_site():
    err = (
        "==9==ERROR: LeakSanitizer: detected memory leaks\n\n"
        "Direct leak of 100 byte(s) in 1 object(s) allocated from:\n"
        "    #0 0x7f1234 in malloc ../libsanitizer/asan/asan_malloc_linux.cpp:67\n"
        "    #1 0x401208 in main /x/l.c:8\n"
        "SUMMARY: AddressSanitizer: 100 byte(s) leaked\n"
    )
    leaks = V.parse_lsan(err)
    assert len(leaks) == 1
    func, path, line = leaks[0]
    assert func == "main" and line == 8 and path.endswith("l.c")    # malloc interceptor skipped


def test_lsan_none_when_clean():
    assert V.parse_lsan("no leaks here") == []


def test_runtime_frame_filter_does_not_swallow_asan_dir():
    # a program legitimately built under a directory literally named "asan/" must NOT be filtered
    err = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x..\n"
           "    #0 0x401455 in use /home/dev/asan/project/src/main.c:55\n")
    kind, func, path, line, _ = V.parse_sanitizer(err)
    assert func == "use" and line == 55 and "asan/project" in path


def test_execve_regex_matches_successful_exec_only():
    log = ('execve("/usr/bin/id", ["id"], 0x..) = 0\n'
           'execve("/nope", ["x"], 0x..) = -1 ENOENT (No such file)\n')
    hits = [os.path.basename(m.group(1)) for m in V._EXECVE.finditer(log)]
    assert hits == ["id"]          # only the `= 0` success, not the ENOENT


def test_openpath_regex_extracts_traversal_path():
    log = ('openat(AT_FDCWD, "/var/lib/drop/../../../../etc/passwd", O_RDONLY) = -1 ENOENT\n'
           'open("conf.d/main.conf", O_RDONLY) = 3\n')
    paths = [m.group(1) for m in V._OPENPATH.finditer(log)]
    assert any("../" in p and "etc/passwd" in p for p in paths)
    assert "conf.d/main.conf" in paths    # benign open captured but lacks ../ + sentinel
