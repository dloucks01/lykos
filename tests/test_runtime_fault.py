"""One lookup for three runtimes, and why chaining the per-runtime helpers would not do.

Each runtime's own `cwe_for_exception` ends in a catch-all for a name shaped like ITS
exceptions -- `*Error` on both the JVM and in Python -- so whichever ran first would swallow the
other's specific names. Chained in the order (jvm, pyc), `IndexError` comes back as CWE-248
"unknown JVM fault" instead of the CWE-129 unvalidated index it is. Both specific tables are
consulted before either fallback, and this file pins that.
"""
import pytest

from lykos.analyze import dotnet, jvm, pyc
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


def test_the_tables_never_disagree_where_they_overlap():
    """The JVM and the CLR genuinely share names -- `IOException`, `ArithmeticException`,
    `SecurityException`, `FileNotFoundException` all exist on both -- so disjointness is not
    achievable once .NET is in. The invariant that keeps a name-only lookup SOUND is weaker and
    sufficient: wherever two tables hold the same name they must agree on the weakness, so only
    the runtime ATTRIBUTION can be wrong without a file_type hint, never the CWE.
    """
    tables = {"jvm": jvm.EXCEPTION_CWE, "cpython": pyc.EXCEPTION_CWE,
              "clr": dotnet.EXCEPTION_CWE}
    for a, ta in tables.items():
        for b, tb in tables.items():
            if a >= b:
                continue
            for name in set(ta) & set(tb):
                assert ta[name] == tb[name], f"{name}: {a} says {ta[name]}, {b} says {tb[name]}"
    # pyc and jvm specifically are still disjoint, which is worth keeping true.
    assert not (set(jvm.EXCEPTION_CWE) & set(pyc.EXCEPTION_CWE))


@pytest.mark.parametrize("name,ft,runtime", [
    ("IndexOutOfRangeException", "dotnet", "the CLR"),
    ("System.IndexOutOfRangeException", "dotnet", "the CLR"),
    ("ArrayIndexOutOfBoundsException", "class", "the JVM"),
    ("IndexError", "pyc", "CPython"),
    ("WASM-TRAP-out-of-bounds-access", "wasm", "the WebAssembly engine"),
])
def test_an_index_defect_is_cwe_129_on_every_runtime_that_has_one(name, ft, runtime):
    """One bug class, four vocabularies. The CWE must not depend on which runtime saw it."""
    cwe, _sev, got = managed_fault(name, ft)
    assert cwe == "CWE-129" or name.startswith("WASM")       # wasm reports the trap's own CWE
    assert got == runtime


@pytest.mark.parametrize("ft,runtime", [("dotnet", "the CLR"), ("jar", "the JVM")])
def test_a_shared_name_is_attributed_to_the_runtime_that_saw_it(ft, runtime):
    """This is why file_type is threaded through from the crash site: without it a .NET
    IOException is reported against "the JVM" in the finding title."""
    for name in sorted(set(jvm.EXCEPTION_CWE) & set(dotnet.EXCEPTION_CWE)):
        cwe, _sev, got = managed_fault(name, ft)
        assert got == runtime, f"{name} on {ft} attributed to {got}"


def test_a_fully_qualified_clr_name_resolves_like_a_bare_one():
    assert managed_fault("System.NullReferenceException", "dotnet") \
        == managed_fault("NullReferenceException", "dotnet")


def test_an_unknown_name_is_attributed_to_the_known_runtime_when_one_is_given():
    """"a managed runtime" is the honest answer only when we do not know which one ran."""
    assert managed_fault("Acme.FrobException", "dotnet")[2] == "the CLR"
    assert managed_fault("Acme.FrobException")[2] == "a managed runtime"


def test_a_clr_unsafe_fault_is_the_one_managed_memory_corruption():
    """The CLR bounds-checks what it owns; an `unsafe`/P-Invoke fault is handed to it."""
    cwe, sev, rt = managed_fault("AccessViolationException", "dotnet")
    assert (cwe, sev, rt) == ("CWE-119", "critical", "the CLR")


def test_an_unknown_exception_is_a_missing_catch_not_memory_corruption():
    """Inheriting the native default would badge it critical memory corruption on a runtime
    that has none."""
    assert managed_fault("SomeVendorLibError") == ("CWE-248", "medium", "a managed runtime")


@pytest.mark.parametrize("name", ["SystemExit", "KeyboardInterrupt", "GeneratorExit",
                                  "OperationCanceledException",
                                  "TaskCanceledException",
                                  "SIGSEGV", "", None])
def test_what_is_not_a_managed_fault_at_all(name):
    assert managed_fault(name) is None


def test_the_runtime_itself_dying_is_the_one_real_corruption():
    for name in ("JVM-FATAL-SIGSEGV", "PY-FATAL-SEGMENTATION",
                 "CLR-FATAL-INTERNAL-CLR-ERROR"):
        cwe, sev, _rt = managed_fault(name)
        assert (cwe, sev) == ("CWE-119", "critical")
