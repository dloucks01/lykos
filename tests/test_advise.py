"""What to do next with a target -- the logic that used to live in the GUI.

Keeping it in index.html meant the API and CLI could not reach it, and a scripted run
against jhead consequently picked plain black-box fuzzing: 98,500 executions, `unique: 0`,
nothing found -- while the GUI panel was recommending a seed and a structure model.
"""
from lykos.analyze import advise as A

_FILE_IMPORTS = ["fopen", "fread", "fclose", "printf"]
_STDIN_IMPORTS = ["fgets", "printf", "strlen"]
_NEITHER = ["printf", "strlen", "exit"]


def _advise(**kw):
    base = dict(imports=_FILE_IMPORTS, functions=100, findings=5, seeds=1,
                has_format=True, afl_usable=False)
    base.update(kw)
    return A.advise(**base)


def test_coverage_guided_is_preferred_whenever_it_is_usable():
    """The GUI recommended `directed` whenever static findings existed and never mentioned
    coverage-guided fuzzing at all. But `directed` is still BLIND mutation biased toward sink
    addresses: measured on jhead it managed ~195 execs/sec with no coverage feedback and
    found nothing in 505 seconds, where AFL++ on the same program sustained ~15,000 execs/sec
    with edge coverage and found five SIGSEGV crashes in 60.
    """
    a = _advise(afl_usable=True, findings=27)
    assert a["backend"] == "coverage_fuzz"
    assert "coverage" in a["backend_why"].lower()


def test_directed_only_when_there_is_no_coverage_backend():
    a = _advise(afl_usable=False, findings=27)
    assert a["backend"] == "directed_fuzz"
    assert "27" in a["backend_why"]


def test_blackbox_is_the_last_resort_and_says_so():
    a = _advise(afl_usable=False, findings=0)
    assert a["backend"] == "fuzz"
    assert "low yield" in a["backend_why"]


def test_input_mode_comes_from_the_import_table():
    assert _advise(imports=_FILE_IMPORTS)["input_mode"] == "file"
    assert _advise(imports=_STDIN_IMPORTS)["input_mode"] == "stdin"
    assert _advise(imports=_NEITHER)["input_mode"] == "arg"
    assert _advise(imports=_FILE_IMPORTS)["file_parser"] is True


def test_plan_is_dynamic_first():
    """Decompile -> detect -> maybe-fuzz produces a wall of undemonstrated findings: on jhead
    that was 27 findings, 0 confirmed, 0 poc-backed. Execution has to come first so that
    static analysis arrives to EXPLAIN something real."""
    plan = [p["stage"] for p in _advise(afl_usable=True)["plan"]]
    assert plan[0] == "coverage_fuzz", "the first step must produce evidence"
    assert plan.index("coverage_fuzz") < plan.index("disassemble")
    assert plan.index("coverage_fuzz") < plan.index("detect_cwe")
    # static work is still in the plan -- demoted, not dropped
    assert "disassemble" in plan and "detect_cwe" in plan


def test_the_poc_ladder_appears_once_a_crash_exists():
    dry = _advise(afl_usable=True, crashes=0)
    assert not any(p["stage"] == "build_poc" for p in dry["plan"])
    rc = next(p for p in dry["plan"] if p["stage"] == "root_cause")
    assert rc["ready"] is False and "once a crashing input exists" in rc["why"]

    wet = _advise(afl_usable=True, crashes=3)
    stages = [p["stage"] for p in wet["plan"]]
    for s in ("root_cause", "build_poc", "poc_primitive"):
        assert s in stages, f"{s} should be planned once a crash exists"
    assert all(p["ready"] for p in wet["plan"] if p["stage"] in
               ("root_cause", "build_poc", "poc_primitive"))
    assert "3 crashes already found" in wet["headline"]


def test_completed_steps_are_marked_done_not_repeated():
    a = _advise(afl_usable=True, functions=165, findings=231)
    by = {p["stage"]: p for p in a["plan"]}
    assert by["disassemble"].get("done") is True
    assert by["detect_cwe"].get("done") is True


def test_a_parser_without_seeds_is_told_why_that_matters():
    a = _advise(imports=_FILE_IMPORTS, seeds=0, afl_usable=True)
    seed_check = next(c for c in a["checks"] if c["text"].startswith("seeds"))
    assert seed_check["ok"] is False
    assert "rejects random bytes" in seed_check["text"]


def test_afl_usable_requires_the_qemu_helper_too(monkeypatch):
    """afl-fuzz alone is not enough for binary-only mode: `-Q` needs afl-qemu-trace, which
    ships separately and is absent from Ubuntu's afl++ package."""
    from lykos.analyze.fuzz import aflpp
    monkeypatch.setattr(aflpp, "locate_afl", lambda *a, **k: None)
    assert A.afl_usable() is False
    monkeypatch.setattr(aflpp, "locate_afl", lambda *a, **k: "/usr/bin/afl-fuzz")
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda *a, **k: None)
    assert A.afl_usable() is False
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda *a, **k: "/usr/bin/afl-qemu-trace")
    assert A.afl_usable() is True


def test_an_empty_import_table_is_not_evidence_of_argv():
    """A statically linked binary has no import table, and falling through to "argv/none" made
    a config-driven daemon -- whose entire input is a file -- report as argv-driven with full
    confidence. Absence of evidence is not evidence."""
    from lykos.analyze.advise import _input_mode, advise
    assert _input_mode([])[0] is None
    assert _input_mode(None)[0] is None
    assert "not determinable" in _input_mode([])[1]
    # the same names from a symbol table still work
    assert _input_mode(["fopen", "fgets", "malloc"])[0] == "file"
    assert _input_mode(["read", "memcpy"])[0] == "stdin"
    assert _input_mode(["getpid", "malloc"])[0] == "arg"

    out = advise(imports=[], functions=900, findings=2, seeds=0, has_format=False,
                 afl_usable=True, executable=True)
    assert out["input_unknown"] is True and out["input_mode"] is None
    assert "@@" in out["headline"], "tell the operator how to supply the invocation"


def test_a_required_config_flag_says_what_the_input_is():
    """A statically linked daemon has no import table, so the import-based guess returns
    "not determinable" and the operator is told to work it out themselves. But the binary
    documents `-c <config>` in its own usage line, which survives stripping and static linking
    -- and a required config path IS the input channel."""
    from lykos.analyze.advise import advise
    inv = {"flags": [{"flag": "-c", "kind": "config", "takes_value": True, "optional": False}],
           "proposed_argv": ["-c", "@@"]}
    out = advise(imports=[], functions=0, findings=0, seeds=0, has_format=False,
                 afl_usable=False, executable=True, invocation=inv)
    assert out["input_mode"] == "file"
    assert "-c" in out["shape"]
    assert out["plan"][0]["params"]["argv"] == ["-c", "@@"], \
        "the plan has to carry the argv, or running it repeats the failure"
    assert any("required -c" in c["text"] for c in out["checks"])


def test_an_optional_flag_is_not_evidence_of_anything():
    """unzip documents `[-d exdir]`; reading that as a requirement produced a command line
    unzip refuses."""
    from lykos.analyze.advise import advise
    inv = {"flags": [{"flag": "-d", "kind": "path", "takes_value": True, "optional": True}],
           "proposed_argv": []}
    out = advise(imports=[], functions=0, findings=0, seeds=0, has_format=False,
                 afl_usable=False, executable=True, invocation=inv)
    assert out["input_mode"] is None and out.get("input_unknown")


def test_coverage_fuzz_is_not_recommended_where_afl_cannot_run():
    """"AFL++ is installed" and "AFL++ can run this target" are different questions, and
    conflating them made coverage_fuzz the first recommendation for every one of the eleven
    non-host architectures in the corpus. Measured on an aarch64 target: the campaign ran to
    completion and reported crash_inputs 0, unique 0, status done -- which reads exactly like
    a thorough campaign that found nothing."""
    from lykos.analyze.advise import advise, fuzz_backend
    blocked = "afl-qemu-trace is built for the host (x86-64); it cannot execute aarch64."
    assert fuzz_backend(True, 3, blocked)[0] == "fuzz"
    assert "not available for this target" in fuzz_backend(True, 3, blocked)[1]
    # unchanged where it CAN run
    assert fuzz_backend(True, 3, None)[0] == "coverage_fuzz"
    assert fuzz_backend(False, 3, None)[0] == "directed_fuzz"
    out = advise(imports=["fopen"], functions=10, findings=1, seeds=0, has_format=False,
                 afl_usable=True, executable=True, coverage_blocked=blocked)
    assert out["backend"] == "fuzz"
    assert out["plan"][0]["stage"] == "fuzz"


def test_macho_is_static_only_on_a_non_macos_host():
    """A Mach-O has no loader on Linux: advise must say analysis is static-only and NOT
    recommend a dynamic backend that cannot run."""
    from lykos.analyze.advise import advise
    a = advise(imports=[], functions=12, findings=3, seeds=0, has_format=False,
               afl_usable=True, file_format="macho")
    assert a["backend"] == "synthesize_poc"              # not a fuzzing backend
    assert "static only" in a["headline"].lower()
    assert any("execution" in c["text"] and not c["ok"] for c in a["checks"])
    # the plan must be the static chain, with no fuzz/dynamic stage
    stages = {s["stage"] for s in a["plan"]}
    assert "coverage_fuzz" not in stages and "directed_fuzz" not in stages
    assert {"disassemble", "detect_cwe", "cve_scan"} <= stages
