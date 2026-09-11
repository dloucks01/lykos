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
