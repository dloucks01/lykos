"""One lookup for three runtimes, and why chaining the per-runtime helpers would not do.

Each runtime's own `cwe_for_exception` ends in a catch-all for a name shaped like ITS
exceptions -- `*Error` on both the JVM and in Python -- so whichever ran first would swallow the
other's specific names. Chained in the order (jvm, pyc), `IndexError` comes back as CWE-248
"unknown JVM fault" instead of the CWE-129 unvalidated index it is. Both specific tables are
consulted before either fallback, and this file pins that.
"""
import pytest

from lykos.analyze import jvm, pyc
from lykos.analyze.runtime_fault import managed_fault


@pytest.mark.parametrize("name,cwe,runtime", [
    # the same bug class, in three vocabularies
    ("ArrayIndexOutOfBoundsException", "CWE-129", "the JVM"),
    ("IndexError", "CWE-129", "CPython"),
    ("WASM-TRAP-out-of-bounds-table-index", "CWE-129", "the WebAssembly engine"),
    # and the runtime-specific ones
    ("NullPointerException", "CWE-476", "the JVM"),
    ("AttributeError", "CWE-476", "CPython"),
    ("OutOfMemoryError", "CWE-789", "the JVM"),
    ("MemoryError", "CWE-789", "CPython"),
    ("RecursionError", "CWE-674", "CPython"),
    ("StackOverflowError", "CWE-674", "the JVM"),
    ("WASM-TRAP-uncontrolled-recursion", "CWE-674", "the WebAssembly engine"),
])
def test_each_runtimes_vocabulary_reaches_its_own_mapping(name, cwe, runtime):
    got_cwe, _sev, got_runtime = managed_fault(name)
    assert (got_cwe, got_runtime) == (cwe, runtime)


@pytest.mark.parametrize("name,cwe", [
    ("ArrayIndexOutOfBoundsException", "CWE-129"),
    ("IndexError", "CWE-129"),
    ("ZeroDivisionError", "CWE-369"),
    ("ArithmeticException", "CWE-369"),
])
def test_a_specific_table_always_beats_the_other_runtimes_fallback(name, cwe):
    """The whole reason this module exists rather than two chained calls."""
    assert managed_fault(name)[0] == cwe


def test_the_two_tables_do_not_disagree_about_any_name():
    """If a name ever appears in both tables the answer becomes order-dependent, which is
    exactly the bug this module was written to avoid. Keep them disjoint."""
    assert not (set(jvm.EXCEPTION_CWE) & set(pyc.EXCEPTION_CWE))


def test_an_unknown_exception_is_a_missing_catch_not_memory_corruption():
    """Inheriting the native default would badge it critical memory corruption on a runtime
    that has none."""
    assert managed_fault("SomeVendorLibError") == ("CWE-248", "medium", "a managed runtime")


@pytest.mark.parametrize("name", ["SystemExit", "KeyboardInterrupt", "GeneratorExit",
                                  "SIGSEGV", "", None])
def test_what_is_not_a_managed_fault_at_all(name):
    assert managed_fault(name) is None


def test_the_runtime_itself_dying_is_the_one_real_corruption():
    for name in ("JVM-FATAL-SIGSEGV", "PY-FATAL-SEGMENTATION"):
        cwe, sev, _rt = managed_fault(name)
        assert (cwe, sev) == ("CWE-119", "critical")
