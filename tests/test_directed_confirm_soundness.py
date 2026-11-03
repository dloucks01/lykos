"""The 0-FP memory-fault gate of the confirmation ladder (directed_confirm._memory_fault).

A synthesized STREAM driver reaches a real parser, and a verbose-assert project (FreeRDP's
WINPR_ASSERT, libc assert) aborts on malformed input BY DESIGN. That abort is a reachable-assertion
DoS at most -- never a memory-corruption PoC -- so it must NOT confirm a memory-safety finding. The
bug this guards against: ASan annotates an unrelated SIGABRT with the word "AddressSanitizer", so a
substring test counted every assert-abort as a crash, which would flood false positives across every
parser the driver reaches. Only a genuine `ERROR: AddressSanitizer: <kind>` / UBSan banner (or a
parsed class) may confirm.
"""
from __future__ import annotations

from lykos.analyze.symbolic.directed_confirm import _memory_fault

# A real FreeRDP WINPR_ASSERT abort, as libFuzzer+ASan print it: a "deadly signal", the word
# "AddressSanitizer" present (from ASan's signal annotation / stack-trace helper), and the assertion
# in the stack -- but NO `ERROR: AddressSanitizer: <memory-kind>` banner.
_ASSERT_ABORT_REPORT = """\
==123==ERROR: libFuzzer: deadly signal
    #0 0x55 in __sanitizer_print_stack_trace (/drv+0x4d) (AddressSanitizer runtime)
    #2 0x55 in fuzzer::Fuzzer::CrashCallback()
[FATAL][com.freerdp.winpr.assert] - [winpr_int_assert]: ((Stream_GetRemainingCapacity(s) >= _offset))
    #9 0x7f in winpr_int_assert /freerdp/winpr/libwinpr/crt/assert.c:30:2
SUMMARY: libFuzzer: deadly signal
"""

_HEAP_OVERFLOW_REPORT = """\
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x55 in parse_thing /src/thing.c:42:9
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/thing.c:42:9 in parse_thing
"""

_UAF_REPORT = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60200000
    #0 0x55 in use /src/u.c:10
"""

_UBSAN_REPORT = "src/x.c:5:7: runtime error: signed integer overflow: 2147483647 + 1\n"

_SEGV_REPORT = """\
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x55 in deref /src/d.c:3
"""


def test_assertion_abort_is_not_a_memory_fault():
    # the exact false positive that motivated the gate: assert-abort + the word "AddressSanitizer"
    assert "AddressSanitizer" in _ASSERT_ABORT_REPORT          # the loose substring is present...
    assert _memory_fault(_ASSERT_ABORT_REPORT, {}) is False    # ...but it must NOT count as a fault


def test_genuine_memory_errors_still_confirm():
    assert _memory_fault(_HEAP_OVERFLOW_REPORT, {}) is True
    assert _memory_fault(_UAF_REPORT, {}) is True
    assert _memory_fault(_SEGV_REPORT, {}) is True
    assert _memory_fault(_UBSAN_REPORT, {}) is True


def test_a_parsed_class_is_trusted_even_without_a_rematch():
    # rootcause already classified it -> trust that, independent of the banner regex
    assert _memory_fault("whatever the rootcause parser keyed on", {"class": "heap-buffer-overflow"}) is True


def test_a_real_overflow_that_also_trips_an_assert_still_confirms():
    # an assert on the way down must not mask a genuine memory-error banner
    mixed = _HEAP_OVERFLOW_REPORT + "\n[FATAL] winpr_int_assert: something\n"
    assert _memory_fault(mixed, {}) is True


def test_empty_and_benign_reports_are_not_faults():
    assert _memory_fault("", {}) is False
    assert _memory_fault("Done 1 runs in 0 second(s)\n", {}) is False
    assert _memory_fault("==1==ERROR: LeakSanitizer: detected memory leaks\n", {}) is False
