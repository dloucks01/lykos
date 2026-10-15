"""Sanitizer-report classification: UBSan names the check that fired, so the finding must carry
that bug's CWE rather than a blanket "undefined behaviour"."""
from lykos.analyze.debug.rootcause import parse_asan_report


def _cwe(text):
    r = parse_asan_report(text)
    return (r or {}).get("cwe"), (r or {}).get("class")


def test_ubsan_array_index_is_a_bounds_bug_not_generic_ub():
    # An out-of-bounds array write used to classify as CWE-758/medium, which buries a real
    # memory-safety defect. UBSan does not say whether the access was a read or a write, so the
    # bounds PARENT class is the honest answer -- not CWE-125/CWE-787.
    cwe, bug = _cwe("t.c:4:67: runtime error: index 64 out of bounds for type 'char [64]'")
    assert cwe == "CWE-119" and bug == "array-index-out-of-bounds"


def test_ubsan_signed_integer_overflow():
    cwe, bug = _cwe("t.c:7:20: runtime error: signed integer overflow: "
                    "2147483647 + 1 cannot be represented in type 'int'")
    assert cwe == "CWE-190" and bug == "integer-overflow"


def test_ubsan_division_by_zero():
    assert _cwe("t.c:3:5: runtime error: division by zero")[0] == "CWE-369"


def test_ubsan_null_deref():
    cwe, bug = _cwe("t.c:9:3: runtime error: member access within null pointer of type 'struct S'")
    assert cwe == "CWE-476" and bug == "null-pointer-dereference"


def test_ubsan_bad_shift():
    assert _cwe("t.c:4:9: runtime error: shift exponent 64 is too large "
                "for 32-bit type 'int'")[0] == "CWE-1335"


def test_ubsan_unknown_check_falls_back_to_generic_ub():
    # A check nobody has mapped yet must still produce a finding, just an unspecific one.
    cwe, bug = _cwe("t.c:2:1: runtime error: some future check nobody mapped")
    assert cwe == "CWE-758" and bug == "undefined-behavior"


def test_asan_and_msan_classification_unchanged():
    # The UBSan branch is last; adding to it must not shadow the sanitizers ahead of it.
    assert _cwe("ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f")[0] == "CWE-121"
    assert _cwe("ERROR: MemorySanitizer: use-of-uninitialized-value")[0] == "CWE-457"


def test_non_report_text_is_not_a_finding():
    assert parse_asan_report("just some program output\nnothing to see") is None


# --- WHERE the defect is. The site is the dedup key for a sanitizer defect, so a wrong one is
# not a cosmetic label: it merges unrelated bugs into one finding.

_ABORTING_UBSAN = """\
/tmp/lykos-40bc/src/lib/xmltok_impl.c:694:7: runtime error: left shift of 1 by 31 places \
cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior \
/tmp/lykos-40bc/src/lib/xmltok_impl.c:694:7 in
==2951==ERROR: libFuzzer: deadly signal
    #0 0x55e in __sanitizer_print_stack_trace /build/compiler-rt/lib/asan/asan_stack.cpp:87
    #1 0x55e in fuzzer::PrintStackTrace() FuzzerUtil.cpp:210
    #2 0x55e in fuzzer::Fuzzer::CrashCallback() FuzzerLoop.cpp:235
    #3 0x7f1 in __restore_rt libc_sigaction.c:0
    #4 0x7f1 in pthread_kill ./nptl/pthread_kill.c:43
    #5 0x7f1 in raise ../sysdeps/posix/raise.c:26
    #6 0x7f1 in abort ./stdlib/abort.c:79
    #7 0x55e in normal_prologTok /tmp/lykos-40bc/src/lib/xmltok_impl.c:694
    #8 0x55e in XML_Parse /tmp/lykos-40bc/src/lib/xmlparse.c:1577
"""


def test_an_aborting_ubsan_report_is_attributed_to_the_library_not_to_abort():
    """Measured on expat 2.1.0 through the in-process engine: the real left-shift fault at
    `xmltok_impl.c:694` was recorded as `pthread_kill.c:43`. UBSan with halt_on_error aborts,
    libFuzzer catches the deadly signal and prints ITS stack, and glibc ships source file names
    -- so "the first frame naming a real source file" is the file abort() raises from. Every
    UBSan defect in a campaign then shares one site, and the site is the dedup key."""
    r = parse_asan_report(_ABORTING_UBSAN)
    assert r["source"] == "xmltok_impl.c:694", r["source"]
    assert "pthread_kill" not in (r["detail"] or "")


def test_an_asan_report_is_attributed_past_the_interceptor():
    """Same defect, other sanitizer: ASan's frame #0 is its own memcpy interceptor, and
    compiler-rt's own `.cpp` path satisfied the source-file test."""
    r = parse_asan_report(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x604 at pc 0x4f\n"
        "READ of size 4 at 0x604 thread T0\n"
        "    #0 0x4f in __asan_memcpy "
        "/build/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22\n"
        "    #1 0x5a in putRGBcontig8bittile /src/libtiff/tif_getimage.c:1012\n"
        "0x604 is located 5 bytes after 20-byte region [0x600,0x614)\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow\n")
    assert r["source"] == "tif_getimage.c:1012"
    assert r["cwe"] == "CWE-125" and r["access"] == "read"


def test_a_recovered_ubsan_verdict_still_has_a_site():
    """No stack at all -- `-fsanitize-recover`, or a tool that captured only the verdict."""
    assert parse_asan_report(
        "xmltok_impl.c:694:7: runtime error: left shift of 1 by 31 places"
    )["source"] == "xmltok_impl.c:694"


def test_a_stack_of_nothing_but_runtime_frames_reports_no_site():
    """Rather than reporting the sanitizer's own file as the bug's location."""
    r = parse_asan_report(
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x604\n"
        "    #0 0x4f in __asan_memcpy /build/compiler-rt/lib/asan/asan_interceptors.cpp:22\n"
        "    #1 0x7f1 in abort ./stdlib/abort.c:79\n")
    assert r["cwe"] == "CWE-416" and r["source"] is None


def test_a_projects_own_signal_handling_is_not_mistaken_for_libc():
    """The skip list is matched on the DIRECTORY as well as the file name: a project is entitled
    to its own `signal.c`, and a frame in one of those is a frame in the target."""
    from lykos.analyze.debug.rootcause import _is_runtime_frame
    assert _is_runtime_frame("./nptl/pthread_kill.c")
    assert _is_runtime_frame("../sysdeps/posix/raise.c")
    assert _is_runtime_frame("../sysdeps/unix/sysv/linux/libc_sigaction.c")
    assert _is_runtime_frame("/build/compiler-rt/lib/asan/asan_interceptors.cpp")
    assert _is_runtime_frame("FuzzerLoop.cpp")
    assert not _is_runtime_frame("/src/busybox/libbb/signal.c")
    assert not _is_runtime_frame("/src/libtiff/tif_read.c")
