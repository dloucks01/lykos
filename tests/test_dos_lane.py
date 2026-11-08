"""The DoS confirmation lane (directed_confirm._dos_class) — capability #1.

A reachable assertion / fatal signal driven by attacker input is a real remote DoS (CWE-617/248)
whose reproducer is the input. The thing `_memory_fault` rejects (assert-aborts) must not be thrown
away; it is a valid, weaker finding captured here. Memory faults always take precedence.
"""
from __future__ import annotations
from lykos.analyze.symbolic.directed_confirm import _dos_class, _memory_fault

WINPR = ("[FATAL][com.freerdp.winpr.assert] - [winpr_int_assert]: "
         "((Stream_GetRemainingCapacity(s) >= _offset))\n"
         "==1==ERROR: libFuzzer: deadly signal\n")
LIBC_ASSERT = "app: parse.c:42: do_parse: Assertion `n < max' failed.\n"
SEGV = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
HEAP = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4\n"
STACKCHK = "*** stack smashing detected ***: terminated\n__stack_chk_fail\n"
CLEAN = "Done 2 runs in 0 second(s)\n"


def test_reachable_assert_is_cwe617():
    assert _dos_class(WINPR) == "CWE-617"
    assert _dos_class(LIBC_ASSERT) == "CWE-617"


def test_stack_smash_and_fatal_signal_are_dos():
    assert _dos_class(STACKCHK) == "CWE-248"            # canary abort = detected crash
    assert _dos_class("==1==ERROR: libFuzzer: timeout after 20s\n") == "CWE-248"


def test_clean_output_is_not_a_dos():
    assert _dos_class(CLEAN) is None
    assert _dos_class("") is None


def test_memory_and_dos_are_mutually_exclusive_in_precedence():
    # a genuine heap overflow is a MEMORY fault; the DoS lane must not also claim it (caller checks
    # _memory_fault first, and _asan_replay only sets dos when NOT a mem fault)
    assert _memory_fault(HEAP, {}) is True
    # a SEGV on a bad address is memory (ASan banner), not the DoS lane's assert/abort class
    assert _memory_fault(SEGV, {}) is True
    # ...but a bare assert-abort is NOT a memory fault, and IS a DoS
    assert _memory_fault(WINPR, {}) is False
    assert _dos_class(WINPR) == "CWE-617"
