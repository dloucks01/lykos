"""Is the label true? Severity floors, substrate-blind CWEs, and "detected != demonstrated".

Three rules in this platform decide what a finding CLAIMS, as opposed to whether it was found
at all, and each had drifted away from the reason it was written:

  * the poc-backed severity floor, written so a PROVEN memory-safety bug could not be badged
    below an unproven advisory, was promoting every reproduced missing-catch to `high` too;
  * `_SIG_CWE` named only the five native signals, so a Windows PE's `EXCEPTION_*` -- which say
    more about the defect than a signal does -- all fell through to a generic CWE-119;
  * the static-detector filter listed three STAGE names that can never match a finding's
    detector column.

A wrong label on a real finding is worse than a missing one: it survives into the report, it
reorders what an operator looks at first, and nothing downstream can tell it is wrong.
"""
import pathlib
import tempfile

import pytest

from lykos.analyze.dynamic.stage import _SIG_CWE
from lykos.analyze.orchestrate import _STATIC_DETECTORS
from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO
from lykos.db.models import MEMORY_CORRUPTION_CWES, STATIC_DETECTORS


@pytest.fixture()
def store():
    d = pathlib.Path(tempfile.mkdtemp())
    s = CaseStore.open(d / "case")
    c = s.cases.create("lbl")
    t = s.targets.upsert(case_id=c.id, filename="t.bin", sha256="f" * 64, size=1,
                         file_type="elf")
    return s, c, t


def _file(store, cwe, severity, *, state="poc-backed", detector="poc", key=None):
    s, c, t = store
    fd = FindingDAO(s.conn)
    k = key or f"{cwe}:{severity}:{state}"
    fd.upsert(t.id, c.id, {"cwe": cwe, "title": "x", "severity": severity, "state": state,
                           "confidence": 0.95, "detector": detector, "dedup_key": k})
    return next(f for f in fd.list_by_case(c.id) if f.dedup_key == k)


# ---- the severity floor ------------------------------------------------------------------

@pytest.mark.parametrize("cwe", ["CWE-125", "CWE-787", "CWE-416", "CWE-121"])
def test_a_proven_memory_safety_bug_is_never_badged_below_high(store, cwe):
    """The reason the floor exists: jhead's proven out-of-bounds read carried the `low` its
    pattern detector guessed, so the one finding with a verified PoC ranked below advisories."""
    assert _file(store, cwe, "low").severity == "high"


@pytest.mark.parametrize("cwe,sev", [("CWE-248", "info"), ("CWE-248", "low"),
                                     ("CWE-369", "medium"), ("CWE-20", "medium")])
def test_a_reproduced_missing_catch_keeps_its_considered_severity(store, cwe, sev):
    """A managed runtime's tables rank an uncaught FileNotFoundException at info ON PURPOSE --
    a program validating its input by throwing is doing the right thing. Those faults reproduce
    on the first input, so a floor keyed on the STATE alone promoted all of them to `high` and
    buried the findings that matter, which is what those tables were written to prevent."""
    assert _file(store, cwe, sev).severity == sev


def test_the_floor_never_lowers_anything(store):
    assert _file(store, "CWE-787", "critical").severity == "critical"
    assert _file(store, "CWE-248", "critical").severity == "critical"


def test_an_unproven_memory_safety_finding_is_not_floored(store):
    """The floor is about DEMONSTRATED impact; a candidate has demonstrated nothing."""
    assert _file(store, "CWE-125", "low", state="candidate", key="cand").severity == "low"


def test_the_managed_runtime_tables_are_covered_by_this_rule():
    """Pin the actual overlap, so adding a low/info mapping cannot silently re-break it."""
    from lykos.analyze import dotnet, jvm, pyc
    affected = [(m.__name__.rsplit(".", 1)[-1], name, cwe, sev)
                for m in (jvm, pyc, dotnet)
                for name, (cwe, sev) in m.EXCEPTION_CWE.items() if sev in ("low", "info")]
    assert len(affected) > 30, "the overlap this rule protects should be substantial"
    for _mod, _name, cwe, _sev in affected:
        assert cwe not in MEMORY_CORRUPTION_CWES, \
            f"{_name} is ranked {_sev} yet its CWE is a memory-corruption class"


# ---- the Windows exception CWEs -----------------------------------------------------------

def test_every_windows_exception_the_sandbox_can_report_has_its_own_cwe():
    """The wine path sets signal_name to EXCEPTION_<NAME>; each must resolve, or it takes the
    generic memory-corruption fallback and the name's information is thrown away."""
    import ast
    src = pathlib.Path(__file__).resolve().parents[1].joinpath(
        "core/lykos/analyze/dynamic/sandbox.py").read_text()
    blk = src[src.index("_WINE_EXC = {"):]
    names = ast.literal_eval(blk[blk.index("{"):blk.index("}") + 1]).values()
    missing = [n for n in names if f"EXCEPTION_{n}" not in _SIG_CWE]
    assert not missing, f"no CWE for: {missing}"


def test_the_gs_cookie_is_a_stack_overflow_not_a_generic_one():
    """c0000409 is the /GS check firing. It is the most specific stack-overflow evidence any
    substrate here produces, and it was being reported as a generic CWE-119."""
    assert _SIG_CWE["EXCEPTION_STACK_BUFFER_OVERRUN"] == ("CWE-121", "critical")


def test_the_same_defect_gets_the_same_cwe_on_both_substrates():
    """The asymmetry this fixes: a divide-by-zero was CWE-369 natively and CWE-119 under wine,
    so the SUBSTRATE decided the weakness class rather than the bug."""
    assert _SIG_CWE["EXCEPTION_INT_DIVIDE_BY_ZERO"][0] == _SIG_CWE["SIGFPE"][0]
    assert _SIG_CWE["EXCEPTION_ACCESS_VIOLATION"] == _SIG_CWE["SIGSEGV"]
    assert _SIG_CWE["EXCEPTION_ILLEGAL_INSTRUCTION"] == _SIG_CWE["SIGILL"]


def test_a_detected_corruption_check_is_an_assertion_not_a_hijack():
    """__fastfail and int3 mean a check TERMINATED the process. Reporting them as critical
    memory corruption overstates what was observed."""
    for name in ("EXCEPTION_FAIL_FAST_EXCEPTION", "EXCEPTION_NONCONTINUABLE_EXCEPTION",
                 "EXCEPTION_BREAKPOINT"):
        assert _SIG_CWE[name][0] == "CWE-617", name


# ---- "detected is not demonstrated" -------------------------------------------------------

def test_the_static_filter_holds_detector_names_not_stage_names():
    """Three of the four names it used to hold were STAGE names, which can never equal a
    finding's detector column -- so the filter matched one detector out of fourteen."""
    for stage_name in ("detect_cwe", "cwe_scan", "source_sink_scan"):
        assert stage_name not in STATIC_DETECTORS


def test_every_detector_whose_sites_are_re_derived_counts_as_static():
    """detect/stage resets and prunes candidate SITES for its own list of detectors. Anything
    whose sites can be thrown away and recomputed from the image alone is, by construction,
    static -- so that list must be a subset of this one."""
    from lykos.analyze.detect.stage import _STATIC_DETECTORS as REDETECTED
    assert set(REDETECTED) <= STATIC_DETECTORS, sorted(set(REDETECTED) - STATIC_DETECTORS)


def test_neither_the_engine_nor_the_gate_restates_the_set():
    """They held two copies of the same wrong set, and both were wrong in the same way. The
    invariant is not "the copies agree" -- it is that there are no copies."""
    assert _STATIC_DETECTORS is STATIC_DETECTORS
    gate = pathlib.Path(__file__).resolve().parents[1] / "tools" / "pipeline_conformance.py"
    src = gate.read_text()
    assert "STATIC_DETECTORS" in src, "the gate must still filter static evidence"
    assert "_STATIC_DETECTORS = {" not in src and "_STATIC_DETECTORS = frozenset" not in src, \
        "the gate restates the set instead of importing it"
    assert "from lykos.db.models import STATIC_DETECTORS" in src


@pytest.mark.parametrize("detector", ["poc", "primitive", "dynamic", "fuzz", "directed_fuzz",
                                      "root_cause", "multi_debug", "monitor", "msan",
                                      "libfuzzer", "secret_poc", "oob_index", "heap_monitor"])
def test_execution_backed_detectors_are_never_treated_as_static(detector):
    """The costlier mistake of the two: calling a demonstration static HIDES real evidence."""
    assert detector not in STATIC_DETECTORS


@pytest.mark.parametrize("detector", ["tainted_deref", "stack_frame", "weak_crypto",
                                      "embedded_config", "cve_source", "weggli", "jvm_sink",
                                      "pyc_scan", "uaf", "int_overflow"])
def test_the_scanners_that_never_execute_are_treated_as_static(detector):
    assert detector in STATIC_DETECTORS


def test_the_gate_still_executes_the_bundles_it_ships():
    """The gate scored every case by reading our OWN database back, and three defects lived in
    that gap -- including `runner.sh` ending on `echo "exit status: $rc"`, which made every
    bundle ever shipped exit 0 whether the reproducer crashed or ran clean. The only check that
    can see that class of bug unpacks the bundle somewhere else and reads the script's EXIT
    STATUS, so this asserts the gate still does it, on cases spanning the delivery channels.

    This is a source-level invariant for the same reason as the test above it: the gate takes
    minutes per case, so nothing else notices if the assertion quietly stops being made."""
    gate = pathlib.Path(__file__).resolve().parents[1] / "tools" / "pipeline_conformance.py"
    src = gate.read_text()
    assert "def _bundle_reproduces(" in src, "the gate no longer executes a shipped bundle"
    assert "runner.sh" in src and ">= 128" in src, \
        "the bundle check must run runner.sh and judge it by its exit status"
    # Every channel whose carrier the bundle has to get RIGHT -- argv quoting, a file path that
    # must not be a vanished scratch dir, an exported variable, a spawned server, one field per
    # prompt. Each of those has broken a bundle before.
    for case in ("argv_overflow", "file_overflow", "env_overflow", "socket_overflow",
                 "prompt_protocol_overflow"):
        i = src.index('Case("%s"' % case)
        j = src.index('Case("', i + 10) if src.count('Case("', i + 10) else len(src)
        assert "want_bundle=True" in src[i:j], \
            "%s no longer executes its bundle" % case


def _rc_gate():
    """Import the real-corpus gate as a module. It lives in tools/, not on the package path."""
    import importlib.util
    import sys
    path = pathlib.Path(__file__).resolve().parents[1] / "tools" / "real_corpus_gate.py"
    spec = importlib.util.spec_from_file_location("rc_gate", path)
    mod = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: @dataclass resolves its annotations through sys.modules, and a
    # module that is not there yet raises instead of loading.
    sys.modules["rc_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_a_starved_source_run_is_not_reported_as_clean(tmp_path):
    """libtiff at a 200s budget: 6 capabilities worked, 0 crashes, every invariant satisfied -- a
    row that reads exactly like a library with no memory-safety bugs. The SAME tarball at 900s
    produced a heap overflow and a verified L1 PoC. The difference was that the build had eaten
    the budget before the first execution.

    A gate that cannot tell those two runs apart launders a measurement failure into a clean
    bill of health, which is the single most expensive thing this tool can do on an engagement."""
    g = _rc_gate()
    tar = tmp_path / "libfoo-1.0.tar.gz"
    tar.write_bytes(b"")

    # starved: a source project whose engines barely ran, and no crash to prove otherwise
    why = g.unscoreable(tar, search=12.0, budget=200.0, crashes=0)
    assert why, "a source project searched for 12s of 200s was reported as scoreable"
    assert "starved" in why and "200s budget" in why and "larger --budget" in why

    # not starved: the engines held a real slice
    assert g.unscoreable(tar, search=600.0, budget=900.0, crashes=0) == ""
    # not starved: it found something, so the search demonstrably reached the code
    assert g.unscoreable(tar, search=12.0, budget=200.0, crashes=1) == ""
    # a prebuilt binary has nothing to build, so the floor does not apply to it
    exe = tmp_path / "xxd"
    exe.write_bytes(b"\x7fELF")
    assert g.unscoreable(exe, search=12.0, budget=200.0, crashes=0) == ""


def test_an_unscoreable_corpus_fails_the_gate():
    """Printing INVALID and then exiting 0 would be the same false clean one layer up: whatever
    runs the gate in CI reads the exit status, not the table."""
    gate = pathlib.Path(__file__).resolve().parents[1] / "tools" / "real_corpus_gate.py"
    src = gate.read_text()
    assert "return 1 if (bad or starved) else 0" in src, \
        "a starved target no longer fails the gate's exit status"
