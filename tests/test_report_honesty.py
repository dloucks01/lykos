"""The DELIVERABLE has to be able to say "nothing was run".

The engine is careful about this: every substrate returns a sentinel isolation when the target
never executed, the managed paths append a `/not-runnable` suffix, and stage failures are recorded
as run statuses. All of it used to die at the report boundary. A target nothing could execute
produced an empty crash list, which is byte-identical in the report to a target that ran cleanly
and had no defect -- the one confusion this platform exists to avoid, surviving into the only
artefact a reader actually sees.

Three separate places were blind, and each had a hand-kept table where a derived answer belonged:

  * `_DID_NOT_RUN` listed four of eight exact sentinels and could not match the suffix at all;
  * `_runtime` knew jar/class/pe and called everything else "native machine code" at ceiling L3;
  * `_engines` listed the tools used for reproducibility and discarded run status entirely.
"""
import pathlib
import tempfile

import pytest
from lykos.analyze import substrate
from lykos.analyze.dynamic import sandbox
from lykos.report.model import _engines, _runtime, build_report


class T:
    def __init__(self, file_type, arch="x86-64"):
        self.file_type, self.arch, self.linking, self.bits = file_type, arch, "dynamic", 64


# ---- did it run? --------------------------------------------------------------------------

@pytest.mark.parametrize("iso", [
    "unsupported-arch", "unsupported-windows", "wine-launch-failed",
    "jvm-missing", "python-missing", "node-missing", "dotnet-missing", "not-runnable",
    "bwrap+netns+cpython/not-runnable", "bwrap+netns+clr/not-runnable",
    "bwrap+netns+wasm/not-runnable", "rlimits-only+jvm/not-runnable",
    "bwrap+netns/not-runnable", "",
])
def test_every_isolation_that_means_it_never_ran_is_recognised(iso):
    assert sandbox.did_not_run(iso), f"{iso!r} read as a run that happened"


@pytest.mark.parametrize("iso", ["bwrap+netns", "bwrap+netns+qemu", "rlimits-only",
                                 "rlimits-only+jvm", "bwrap+netns+clr", "wine",
                                 "bwrap+netns+batch"])
def test_a_real_isolation_is_not_mistaken_for_a_non_run(iso):
    assert not sandbox.did_not_run(iso), f"{iso!r} read as a non-run"


def test_the_rule_is_structural_so_a_new_runtime_needs_no_second_table():
    """The failure mode being closed: sentinels were added for .pyc, .wasm and .NET and the
    consumer's set was never updated, so three formats reported a clean exit after not running."""
    assert sandbox.did_not_run("mono-missing")            # a runtime nobody has added yet
    assert sandbox.did_not_run("bwrap+netns+mono/not-runnable")
    assert sandbox.did_not_run("unsupported-something")


def test_no_module_keeps_a_second_list_of_the_non_run_isolations():
    """The drift this closes: the sandbox grew sentinels for .pyc, .wasm and .NET and a hand-kept
    set elsewhere was never updated. One predicate, no copies -- and no alias either, since a
    name that changes from a container to a callable breaks `in` at the call site."""
    import pathlib as _p
    root = _p.Path(__file__).resolve().parents[1] / "core"
    offenders = [f for f in root.rglob("*.py")
                 if "_DID_NOT_RUN" in f.read_text()]
    assert not offenders, [str(f) for f in offenders]
    src = (root / "lykos/analyze/dynamic/stage.py").read_text()
    assert "sandbox.did_not_run(res.isolation)" in src
    # The fuzz campaign is the main crash finder; a target that never executed (noexec staging,
    # unsupported arch, a guest that could not load) must record a did-not-run row and bail, not
    # spin the budget and report a clean empty campaign. Guard both halves of that here.
    fz = (root / "lykos/analyze/fuzz/stage.py").read_text()
    assert "sandbox.did_not_run(res.isolation)" in fz, "fuzz campaign must detect a non-run"
    assert '"did_not_run": True' in fz, "fuzz campaign must record/report the non-run"


# ---- what does this target run on? ---------------------------------------------------------

@pytest.mark.parametrize("ftype", ["class", "jar", "pyc", "wasm", "dotnet"])
def test_a_managed_target_is_never_described_as_a_processor(ftype):
    """`Arch: cpython` / `Arch: cil` is triage recording the RUNTIME, not hardware. Printing it
    as a CPU is the exact bug `_runtime` was written to fix -- for the JVM only, as it turned
    out, so it came straight back for every format added afterwards."""
    r = _runtime(T(ftype, substrate.managed_runtime(ftype) or "x"))
    assert not r["describes_cpu"]
    assert r["ceiling"] == "L1"
    assert r["ceiling_why"], "a reader must be told WHY no exploit appears"
    assert substrate.managed_runtime(ftype).lstrip("the ") in r["ceiling_why"]
    assert r["label"] != "Native machine code"


@pytest.mark.parametrize("ftype", ["elf", "pe"])
def test_a_native_target_still_claims_the_full_ladder(ftype):
    r = _runtime(T(ftype))
    assert r["describes_cpu"] and r["ceiling"] == "L3"


@pytest.mark.parametrize("ftype", ["macho", "raw", "other"])
def test_an_image_nothing_here_can_execute_claims_no_level_at_all(ftype):
    """L1 means a VERIFIED, reproducible fault. Claiming it for an image that cannot be started
    promises a reproducer the platform is unable to build."""
    r = _runtime(T(ftype))
    assert r["ceiling"] == "L0"
    assert r["ceiling_why"]


def test_the_ceiling_reason_reads_as_a_sentence():
    assert _runtime(T("pyc", "cpython"))["ceiling_why"][0].isupper()


def test_every_file_type_triage_can_emit_gets_a_reader_facing_label():
    from lykos.analyze import triage
    for ftype in triage._FILE_TYPES:
        label = _runtime(T(ftype))["label"]
        assert label and label != "", ftype


# ---- was the engine actually used, or merely invoked? --------------------------------------

class _Run:
    def __init__(self, tool, status, stage="fuzz", version="1"):
        self.tool, self.status, self.stage, self.tool_version = tool, status, stage, version
        self.target_id = "t"


class _RDAO:
    def __init__(self, runs):
        self._runs = runs

    def list_by_case(self, _case_id):
        return self._runs


def test_an_engine_that_aborted_is_not_reported_as_one_that_ran():
    """afl-fuzz failing its dry run executed NOTHING, and the report listed AFL++ under
    "engines actually used" regardless -- indistinguishable from AFL finding no crash."""
    out = _engines(_RDAO([_Run("aflpp", "error")]), "c")
    assert out[0]["ran"] is False and out[0]["failed"] == 1 and out[0]["completed"] == 0


def test_an_engine_that_completed_says_so():
    out = _engines(_RDAO([_Run("aflpp", "done")]), "c")
    assert out[0]["ran"] is True and out[0]["completed"] == 1


def test_an_engine_with_one_good_run_among_failures_counts_as_having_run():
    out = _engines(_RDAO([_Run("aflpp", "error"), _Run("aflpp", "done"),
                          _Run("aflpp", "timeout")]), "c")
    e = out[0]
    assert e["runs"] == 3 and e["completed"] == 1 and e["failed"] == 2 and e["ran"] is True


def test_the_reproducibility_fields_are_still_there():
    """Existing consumers read tool/version; the status fields are additive."""
    e = _engines(_RDAO([_Run("ghidra", "done", version="11.0")]), "c")[0]
    assert e["tool"] == "ghidra" and e["version"] == "11.0"


# ---- end to end: the report carries the execution evidence ---------------------------------

def test_the_report_states_that_a_target_never_executed():
    from lykos.casestore import CaseStore
    d = pathlib.Path(tempfile.mkdtemp())
    s = CaseStore.open(d / "case")
    c = s.cases.create("rep")
    t = s.targets.upsert(case_id=c.id, filename="x.dll", sha256="a" * 64, size=4,
                         file_type="dotnet", arch="cil")
    from lykos.db.dao import DynResultDAO
    DynResultDAO(s.conn).insert(
        t.id, c.id, run_id=None, input_sha=None, input_mode="stdin", argv=[],
        exit_code=1, signal=None, signal_name=None, crashed=False, timed_out=False,
        isolation="dotnet-missing", duration_ms=1, stdout_sha=None, stderr_sha=None,
        note="no `dotnet` found to run a .NET assembly", fault_pc=None)
    rep = build_report(s, c.id)
    tgt = rep["targets"][0]
    ex = tgt["execution"]
    assert ex["did_not_run_count"] == 1
    assert ex["did_not_run"][0]["isolation"] == "dotnet-missing"
    assert "dotnet" in ex["did_not_run"][0]["reason"]
    # ...and the runtime block must not call a .NET assembly native machine code
    assert tgt["runtime"]["describes_cpu"] is False
    assert tgt["runtime"]["ceiling"] == "L1"


# ---- round 4: a model field is not a DELIVERED field ---------------------------------------

def _rep_with_gap():
    """A report whose target never executed and whose engine aborted."""
    return {
        "case": {"id": "c", "name": "n"}, "generated_at": "t", "summary": {},
        "engines": [{"tool": "aflpp", "version": "4.0", "runs": 1, "completed": 0,
                     "failed": 1, "ran": False}],
        "targets": [{
            "id": "t", "filename": "x.dll", "sha256": "a" * 64, "file_type": "dotnet",
            "arch": "cil", "bits": 64, "endianness": "little", "mitigations": {},
            "runtime": {"substrate": "clr", "label": ".NET assembly (CIL)",
                        "describes_cpu": False, "ceiling": "L1",
                        "ceiling_why": "The CLR owns the instruction pointer.",
                        "unavailable": {}},
            "execution": {"executions_recorded": 1, "did_not_run_count": 1,
                          "did_not_run": [{"isolation": "dotnet-missing", "mode": "stdin",
                                           "reason": "no `dotnet` found"}],
                          "failed_stages": ["coverage_fuzz"]},
            "findings": [],
        }],
    }


def test_the_html_says_nothing_ran_rather_than_showing_an_empty_list():
    """R2/R3 put this in the report MODEL and no renderer showed it, so the artefact a human
    opens still could not tell "found nothing" from "ran nothing". A model field is not a
    delivered field."""
    from lykos.report.html import to_html
    out = to_html(_rep_with_gap())
    assert "Execution gaps" in out
    assert "no `dotnet` found" in out or "dotnet-missing" in out
    assert "coverage_fuzz" in out
    assert "not a clean result" in out, "the empty finding list must be qualified"
    assert "did not complete" in out, "an engine that aborted must not read as one that ran"


def test_the_pdf_says_the_same():
    from lykos.report.pdf import to_pdf
    data = to_pdf(_rep_with_gap())
    assert data[:4] == b"%PDF"
    assert b"Execution gaps" in data
    assert b"did not complete" in data


def test_the_pdf_does_not_print_a_runtime_as_a_processor():
    """`Arch: jvm/64 big` is the bug the HTML learned to drop and this renderer never did."""
    from lykos.report.pdf import to_pdf
    data = to_pdf(_rep_with_gap())
    assert b"Arch: cil" not in data
    assert b"Runs on" in data and b".NET assembly" in data
    assert b"Analysis ceiling" in data


def test_a_clean_target_is_still_reported_as_clean():
    """The qualification must appear ONLY when something actually did not run."""
    from lykos.report.html import to_html
    rep = _rep_with_gap()
    rep["targets"][0]["execution"] = {"executions_recorded": 3, "did_not_run_count": 0,
                                      "did_not_run": [], "failed_stages": []}
    rep["engines"][0].update({"completed": 1, "failed": 0, "ran": True})
    out = to_html(rep)
    assert "Execution gaps" not in out
    assert "not a clean result" not in out
    assert "did not complete" not in out


def test_structured_evidence_never_reaches_the_line_a_reader_sees():
    """The `effects` channel carries a JSON blob and every surface printed `detail` verbatim, so
    it landed raw in a SARIF message -- i.e. in a GitHub code-scanning alert."""
    import json as _json

    from lykos.report.model import _split_evidence
    from lykos.report.sarif import to_sarif
    effs = [{"kind": "rce", "title": "Arbitrary code execution", "status": "potential"}]
    prose, struct = _split_evidence([{"channel": "root-cause", "detail": "wrote past b[64]"},
                                     {"channel": "effects", "detail": _json.dumps(effs)}])
    assert [e["channel"] for e in prose] == ["root-cause"]
    assert struct["effects"] == effs

    rep = _rep_with_gap()
    rep["targets"][0]["findings"] = [{
        "cwe": "CWE-121", "cwe_name": "Stack overflow", "severity": "high",
        "state": "confirmed", "title": "Arbitrary code execution (potential)",
        "evidence": prose, "effects": effs, "pocs": [], "crashes": []}]
    res = to_sarif(rep)["runs"][0]["results"][0]
    assert '{"kind"' not in res["message"]["text"], "raw JSON in the alert a reader sees"
    assert "wrote past b[64]" in res["message"]["text"]
    assert res["properties"]["effects"] == effs, "the data must still be there, structured"


def test_the_report_names_the_image_the_exploit_was_built_against(tmp_path):
    """The target header prints the INGESTED sha; for a source drop that is not what was exploited.

    `compile_source` builds ASan+UBSan and that build IS the ingested target, which is right for
    finding the defect and makes L3 impossible on it -- AddressSanitizer abort()s at the overflow
    copy before the corrupted return is reached. So `build_exploit` works against the
    uninstrumented build of the same source. Every offset in the findings then belongs to an
    image whose hash appears nowhere in the report, and a reader taking the two to be the same
    binary is misled by omission. The PoC bundle's own meta.json already carried
    `exploited_sha256`; the report was the last place that did not say it.
    """
    from lykos.casestore import CaseStore
    from lykos.report.html import to_html
    from lykos.report.model import _exploited_build, build_report

    store = CaseStore.open(tmp_path / "case")
    try:
        c = store.cases.create("x")
        t = store.targets.upsert(c.id, "prog.c", "a" * 64, size=100)
        # no swap recorded -> nothing claimed, which is the normal case for an ingested binary
        assert _exploited_build(store, c.id, t.id) == {}
        assert "Exploited build" not in to_html(build_report(store, c.id))

        run = store.runs.create(c.id, "build_exploit", target_id=t.id, status="done")
        store.events.append("exploit.build_choice", case_id=c.id, run_id=run.id, payload={
            "build": "uninstrumented", "bytes": 22384,
            "note": "the ingested binary is the ASan+UBSan build, which aborts inside the "
                    "overflow before the corrupted return is reached"})
        got = _exploited_build(store, c.id, t.id)
        assert got["build"] == "uninstrumented" and got["bytes"] == 22384

        html = to_html(build_report(store, c.id))
        assert "Exploited build" in html
        # and it must say WHICH WAY ROUND, not merely that two builds exist
        assert "not the" in html and "SHA-256 above" in html
    finally:
        store.close()


def test_every_crash_finding_filer_uses_the_whole_dedup_key():
    """A finding key has THREE parts and seven call sites were each building two of them.

    `crash_dedup_key(signal, fault_pc, discriminator)` separates two sanitizer defects that both
    SIGABRT -- that is the only thing keeping them apart, because an ASan abort's fault PC is in
    the sanitizer's own machinery and identical for every defect. The fuzz stage passed the
    discriminator; the poc, primitive, exploit, synthesize, root_cause and multidebug sites did
    not, so each filed or looked up `dynamic-crash:SIGABRT` while the fuzz stage had filed
    `dynamic-crash:SIGABRT:<class>@<file>:<line>`.

    Measured on a program with four demonstrated defects: three correctly separated findings from
    the fuzz stage, plus ONE more holding all four defects' evidence -- 20 entries, titled after
    whichever verdict ran last, with a CWE from a different defect than its title and a severity
    from neither. Several of those sites carry a comment promising they merge into the crash
    finding; they were doing the opposite.

    Read as an AST so a comment mentioning the discriminator cannot satisfy it.
    """
    import ast

    checked = 0
    for mod in ("analyze/poc/stage.py", "analyze/poc/synthesize_stage.py",
                "analyze/poc/primitive_stage.py", "analyze/poc/exploit_stage.py",
                "analyze/debug/stage.py", "analyze/debug/multidebug.py"):
        src = pathlib.Path("core/lykos") / mod
        tree = ast.parse(src.read_text())
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
            fname = getattr(call.func, "id", None) or getattr(call.func, "attr", None)
            if fname == "crash_dedup_key":
                # positional (signal, pc, disc) or keyword; a two-arg call is the bug
                has_disc = len(call.args) >= 3 or any(k.arg == "discriminator"
                                                     for k in call.keywords)
                # the managed-runtime key is NOT a signal bucket: `kind` is an exception name, so
                # the fault pc already separates those and no sanitizer class exists for them
                managed = (call.args and getattr(call.args[0], "id", "") == "kind")
                assert has_disc or managed, (
                    f"{mod}:{call.lineno} keys a crash finding without the discriminator")
                checked += 1
            if fname == "crash_finding_candidate":
                kw = {k.arg for k in call.keywords}
                if "fault_pc" in kw:          # a crash-keyed filing, so it needs the third part
                    assert "discriminator" in kw, (
                        f"{mod}:{call.lineno} files a crash finding without the discriminator")
                    checked += 1
    assert checked >= 6, f"only {checked} key site(s) found; did they move?"
