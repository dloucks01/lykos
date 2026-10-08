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
