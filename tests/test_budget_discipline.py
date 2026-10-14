"""The case has a wall clock, and the stages have to share it.

Measured on four stock /usr/bin binaries before any of this existed, 420s of budget each:

    /usr/bin/cat        1,511 executions   27 of ~40 stages   ended inside directed_fuzz
    /usr/bin/xxd        2,756 executions   30 stages (done)   --
    /usr/bin/readelf    1,473 executions   26 stages          ended inside concolic
    /usr/bin/jpegtran           0          15 stages          ended inside build_exploit

Three defects in that table, none of them about analysis quality:

  * the campaign was never budgeted, so every target got the stage default of `max_seconds=30`
    and `max_execs=3000` -- a smoke test, at a fraction of the 174 exec/s measured achievable
    on /usr/bin/cat;
  * a single stage could outlast the whole run (`directed_fuzz` and `concolic` are registered at
    3600s, the queue default is 3600, the case had 420), so which stages you got depended on
    where the clock stopped;
  * and jpegtran, the one real file-format parser in the sample, was executed ZERO times because
    `build_exploit` spent its full registered 300s on a target with no crash yet.

Both of the binaries that produced no findings also produced a report that looked identical --
one after 2,756 executions, one after none. That is what the scorecard is for.
"""
import re
from pathlib import Path

import pytest
from lykos.analyze import budget as B
from lykos.analyze import orchestrate as O

_SRC = Path(O.__file__).read_text()


# ---- the clock, divided --------------------------------------------------------------------

def test_a_phase_cannot_spend_what_a_later_phase_is_owed():
    """The core rule. `recover` keeps 70% back, so everything before the campaigns -- including
    the crashless weaponization that deliberately runs early -- is bounded by the remaining 30%."""
    b = B.CaseBudget(900)
    assert b.available() == pytest.approx(270.0)          # 30% of 900
    b.phase("search")
    assert b.available() == pytest.approx(675.0)          # 900 - 25% reserved for proving
    b.phase("prove")
    assert b.available() == pytest.approx(900.0)          # last phase keeps nothing back


def test_no_single_stage_takes_its_whole_phase():
    """Without this the first expensive stage in a phase takes the lot, which is exactly how one
    `build_exploit` consumed a whole case."""
    b = B.CaseBudget(900)
    assert b.slice("build_exploit") == pytest.approx(135.0)   # half of the recover allowance
    b.phase("search")
    # a SAMPLER gets half of what the phase has left for samplers -- the allowance less the
    # share the solver is owed (900 * 0.10): (675 - 90) / 2
    assert b.slice("fuzz") == pytest.approx(292.5)
    # a stage that SOLVES rather than samples gets half of the full allowance: 675 / 2
    assert b.slice("concolic") == pytest.approx(337.5)


def test_a_caller_may_ask_for_less_but_never_for_more():
    b = B.CaseBudget(900)
    b.phase("search")
    assert b.slice("env_fuzz", want=45.0) == pytest.approx(45.0)
    assert b.slice("fuzz", want=10_000.0) == pytest.approx(292.5)


def test_a_slice_too_small_to_measure_anything_is_refused_outright():
    """"Ran out of time before this stage" is a result; a two-second campaign pretending to be
    one is not. 0.0 is the signal the orchestrator turns into a `skipped` plan entry."""
    b = B.CaseBudget(20)
    assert b.slice("fuzz") == 0.0
    assert B.CaseBudget(900, clock=lambda: 0).slice("fuzz") > 0


def test_an_exhausted_clock_refuses_every_slice():
    ticks = iter([0.0] + [10_000.0] * 20)
    b = B.CaseBudget(900, clock=lambda: next(ticks))
    assert b.expired()
    assert b.slice("fuzz") == 0.0


def test_the_budget_records_where_the_time_went():
    b = B.CaseBudget(900)
    b.record("fuzz", 120.0)
    b.record("fuzz", 30.0)
    b.record("disassemble", 2.0)
    b.skipped("concolic", "no budget left in the search phase")
    sp = b.spent()
    assert sp["by_stage"] == {"fuzz": 150.0, "disassemble": 2.0}   # dearest first
    assert list(sp["by_stage"]) == ["fuzz", "disassemble"]
    assert sp["skipped_for_budget"] == [{"stage": "concolic",
                                         "why": "no budget left in the search phase"}]


def test_an_unknown_phase_is_a_programming_error_not_a_default():
    with pytest.raises(ValueError):
        B.CaseBudget(900).phase("exploit")


def test_the_spent_record_is_json_serializable():
    """It goes into the autopilot's status dict, which the API serializes wholesale to the UI."""
    import json
    json.dumps(B.CaseBudget(900).spent())


# ---- the worker honours a per-run budget ---------------------------------------------------

class _SD:
    def __init__(self, timeout):
        self.timeout = timeout


class _Run:
    def __init__(self, params):
        self.params = params


class _Cfg:
    default_timeout = 3600.0


def _t(params, stage_timeout=3600.0):
    from lykos.jobs.worker import _run_timeout
    return _run_timeout(_Run(params), _SD(stage_timeout), _Cfg())


def test_a_per_run_budget_tightens_the_stages_own_ceiling():
    """The measured failure: `directed_fuzz` is registered at 3600s and the case had 420."""
    assert _t({"max_seconds": 120.0}) < 3600.0
    assert _t({"max_seconds": 120.0}) < _t({"max_seconds": 600.0})


def test_the_kill_deadline_sits_just_BEYOND_the_campaign_length():
    """The budget is the stage's own campaign length as well as the worker's kill deadline, and
    making them the same number kills every campaign at the instant it would have returned.

    Measured after the first version of this: `directed_fuzz` ended in `timeout` on all four
    channels it was driven over -- the work was done, the run was marked `error`, its summary
    was never written, and the scorecard counted a success as a failure.
    """
    for want in (30.0, 120.0, 600.0):
        hard = _t({"max_seconds": want})
        assert hard > want, "a stage killed at its own deadline never finishes cleanly"
        assert hard < want * 2, "the margin is a handover, not a second budget"


def test_a_per_run_budget_can_never_raise_the_ceiling():
    """A stage author's timeout is a safety limit. A caller may ask for less, never for more."""
    assert _t({"max_seconds": 9999.0}, stage_timeout=300.0) == 300.0


@pytest.mark.parametrize("params", [{}, {"max_seconds": None}, {"max_seconds": "soon"},
                                    {"max_seconds": 0}, {"max_seconds": -5}, None])
def test_without_a_usable_budget_the_stage_default_still_applies(params):
    """Nothing here may make a stage launched on its own from the API lose its timeout."""
    assert _t(params) == 3600.0


def test_an_intentionally_unbounded_stage_stays_unbounded_without_a_budget():
    assert _t({}, stage_timeout=None) == 3600.0           # falls back to the queue default
    assert 60.0 < _t({"max_seconds": 60.0}, stage_timeout=None) < 120.0


# ---- the operator's facts reach the stages -------------------------------------------------

def test_argv_reaches_every_stage_and_seeds_only_the_fuzzers():
    """`dynamic_run` is the one stage that VALIDATES its params, and it declares argv but not
    seed_files -- handing it the latter would fail the run outright."""
    over = {"argv": ["-r", "@@"], "seed_files": ["/tmp/a.jpg"]}
    assert O._apply_overrides("dynamic_run", None, over) == {"argv": ["-r", "@@"]}
    assert O._apply_overrides("fuzz", None, over) == over
    assert O._apply_overrides("disassemble", None, over) == {"argv": ["-r", "@@"]}


def test_what_the_operator_knows_beats_what_the_pipeline_inferred():
    """The channel ranking is a guess from the imported symbols; an explicit mode is knowledge.
    A program handed its input on the wrong channel looks exactly like one with no bugs."""
    got = O._apply_overrides("fuzz", {"input_mode": "stdin"}, {"input_mode": "file"})
    assert got["input_mode"] == "file"


def test_empty_overrides_change_nothing():
    base = {"input_mode": "stdin"}
    assert O._apply_overrides("fuzz", base, None) == base
    assert O._apply_overrides("fuzz", base, {"argv": [], "seed_files": None}) == base


def test_the_seed_scope_lists_only_stages_that_read_seeds():
    for stage in O._OVERRIDE_SCOPE["seed_files"]:
        assert stage in O._TARGET, stage


# ---- the ordering invariant ---------------------------------------------------------------

def _pos(needle):
    i = _SRC.index("def run_case_autopilot(")
    return _SRC.index(needle, i)


def test_the_baseline_execution_comes_before_any_analysis():
    """`dynamic_run`'s own capability description is "Run once, to see the target work". It was
    registered, wired to the API and offered in the UI, and the autopilot never called it -- so
    the pipeline's first execution of an arbitrary target happened inside a fuzzer twenty stages
    later, and a run whose budget went elsewhere never ran the program at all."""
    assert _pos('"dynamic_run"') < _pos('"disassemble"')
    assert "dynamic_run" in O._TARGET
    # In the PLAN (the display order) only the steps that decide WHAT the target is may precede
    # it: a firmware image has to be carved and a packed stub unpacked before executing either
    # one means anything, and triage is what tells them apart. Every ANALYSIS stage comes after.
    _plan = [s for s, _ in O._PLAN_STAGES]
    _before = _plan[:_plan.index("dynamic_run")]
    assert set(_before) <= {"ingest_triage", "unpack", "firmware_carve", "firmware_rehost"}, \
        f"analysis is planned before the baseline execution: {_before}"


def test_every_autopilot_stage_call_carries_the_budget():
    """A stage added to the pipeline without a budget would silently get its registered
    timeout -- up to an hour -- and could consume the run. The autopilot's calls are spelled
    `_staged` precisely so that this check can be made mechanically."""
    body = _SRC[_SRC.index("def run_case_autopilot("):]
    direct = re.findall(r"_run_target_stage\(store, t,", body)
    assert not direct, f"{len(direct)} autopilot call(s) bypass the budget; use _staged"
    assert len(re.findall(r"_staged\(bud, store, t,", body)) > 30


def test_the_phases_are_entered_in_order():
    assert _pos('bud.phase("recover")') < _pos('bud.phase("search")') < _pos('bud.phase("prove")')


def test_the_campaigns_are_inside_the_search_phase():
    """If a campaign were left in `recover` it would be capped by the 30% allowance, and if it
    were in `prove` it would spend the reserve that exists to prove what it finds.

    `libfuzzer` WAS left in recover, beside `disassemble` and `detect_cwe`. Measured on the
    libtiff tarball at 600s per target: `disassemble` took 138s and `detect_cwe` 237s (and was
    cancelled anyway), the allowance was gone, and the autopilot skipped the one engine that
    finds this library's bug -- "libfuzzer: skipped, no budget left in the recover phase", in the
    run's own words. The same tarball at 900s had enough slack for it to run, found the heap
    overflow and produced a verified PoC. That difference was budget luck, not design, and no
    test said anything because this list did not name the strongest engine in the pipeline."""
    s, p = _pos('bud.phase("search")'), _pos('bud.phase("prove")')
    for stage in ('"coverage_fuzz"', '"fuzz"', '"directed_fuzz"', '"libfuzzer"'):
        assert s < _pos(stage) < p, stage


def test_in_process_fuzzing_leads_the_campaigns():
    """On a library it outproduces out-of-process mutation by orders of magnitude -- libtiff
    4.0.3: a sanitizer finding in 36 executions, where 14,821 external file-channel executions
    found none. Ordered last among the campaigns it is the first thing a tight budget drops."""
    assert _pos('"libfuzzer"') < _pos('"coverage_fuzz"')
    assert _pos('"libfuzzer"') < _pos('"directed_fuzz"')


def test_a_campaign_is_bounded_by_time_and_not_by_an_arbitrary_count():
    """The stage default of 3,000 executions turned a 200-second slice into a 17-second
    campaign on a fast target. Time is the bound the operator actually has."""
    assert "fuzz" in O._EXEC_BOUNDED and "coverage_fuzz" in O._EXEC_BOUNDED
    assert B.EXEC_CEILING > 100_000


# ---- the scorecard ------------------------------------------------------------------------

def test_the_scorecard_event_is_what_the_report_reads():
    """One derivation of "how much work was done", not two: the report reads the autopilot's own
    record rather than re-deriving it, so the deliverable cannot disagree with what the operator
    watched happen."""
    from lykos.report import model
    assert O.SCORECARD_EVENT == "autopilot.scorecard"
    assert "SCORECARD_EVENT" in Path(model.__file__).read_text()


def test_the_report_states_the_work_behind_a_null_result():
    """The two stock binaries that found nothing -- one after 2,756 executions and one after
    none -- rendered identically. These are the fields that separate them."""
    html = Path(__import__("lykos.report.html", fromlist=["x"]).__file__).read_text()
    for field in ("baseline", "executions_attempted", "stages_skipped_for_budget"):
        assert field in html, field
    assert "DID NOT RUN" in html


def test_a_stage_skipped_for_budget_is_an_execution_gap_in_the_report():
    """"We ran out of time before this stage" must reach the same prominence as "this stage
    found nothing", or a short run reads as a clean one."""
    html = Path(__import__("lykos.report.html", fromlist=["x"]).__file__).read_text()
    i = html.index("Execution gaps")
    assert "Ran out of time before" in html[i:i + 2500]


# ---- the front door ------------------------------------------------------------------------

def test_the_cli_can_analyse_a_binary():
    """There was no CLI path to the pipeline at all: `serve`, `eval`, `archgate`, `realgate`,
    `doctor` -- nothing that takes a file. So the only ways in were the browser console and
    importing the orchestrator, which is why nobody had ever watched it run on an arbitrary
    binary."""
    from lykos.cli import build_parser
    args = build_parser().parse_args(["analyze", "/bin/ls", "--budget", "120",
                                      "--argv", "-l @@", "--input-mode", "file"])
    assert args.binary == "/bin/ls" and args.budget == 120.0
    assert args.input_mode == "file"
    # One shell-quoted string, not a list: argparse reads a leading-dash list element as an
    # unknown option, so `--argv -c @@` -- the shape every real invocation has -- cannot parse.
    import shlex
    assert shlex.split(args.argv) == ["-l", "@@"]


def test_the_cli_passes_the_budget_and_the_overrides_to_the_autopilot():
    import inspect

    from lykos.cli import _cmd_analyze
    src = inspect.getsource(_cmd_analyze)
    assert "args.budget" in src and "over" in src
    sig = inspect.signature(O.run_case_autopilot)
    assert list(sig.parameters)[-2:] == ["budget_seconds", "overrides"]


def test_nothing_that_consumes_a_crash_runs_before_the_stages_that_produce_one():
    """The ordering invariant. `root_cause`, `build_poc` and `poc_primitive` all require
    `params.input_sha` -- a crash -- so running them before the campaigns would be asking for
    evidence that cannot exist yet.

    `build_exploit` is the deliberate exception and stays early: its `auto` strategy provokes
    its OWN leak and needs no crash, and placing it early was itself an earlier fix for a
    budget it could never reach at the end of the pass. What was wrong was not its position but
    that it could spend the search phase's share -- which the phase reserve now prevents.
    """
    first_campaign = min(_pos('"coverage_fuzz"'), _pos('"fuzz"'))
    for stage in ('"root_cause"', '"build_poc"', '"poc_primitive"'):
        assert _pos(stage) > first_campaign, f"{stage} needs a crash that does not exist yet"


def test_the_crashless_weaponizer_is_bounded_where_it_sits():
    """Measured: unbounded in that slot it took its full registered 300s on a jpegtran with no
    crash, and the run ended before any fuzzer started."""
    body = _SRC[_SRC.index("def run_case_autopilot("):]
    m = re.search(r'_staged\(bud, store, t, "build_exploit", status, stop,[^)]*?\)', body, re.S)
    assert m and "want=" in m.group(0), "build_exploit must declare what it is worth"


def test_a_sampler_cannot_spend_what_the_solver_is_owed():
    """The phase reserve stops an earlier PHASE eating a later one; this is the same principle
    inside the search phase, and it was measured as a real loss rather than anticipated.

    On the HTB target quack_quack at a 600 s budget: `fuzz` 211.4 s + `directed_fuzz` 185.0 s
    spent 396 s on 91,896 executions and found NOTHING, while `concolic` -- which reaches that
    target's defect in 19.8 s when allowed to finish -- was handed 19.2 s of the 120 s it asked
    for, and was cancelled before it could validate what it had already found. A blind campaign
    cannot construct the input behind a `strstr(input, "Quack Quack")` gate at any budget.
    """
    t = [0.0]
    b = B.CaseBudget(600.0, clock=lambda: t[0])
    t[0] = 30.0
    b.phase("search")
    # The REAL order, which is what exposed the first version of this: several non-sampler
    # stages run in the search phase BEFORE the campaigns, and releasing the reserve on any
    # non-sampler therefore released it before `fuzz` even started.
    for stage, want in (("build_exploit", 60.0), ("mem_oracle", 60.0),
                        ("chain_primitive", 45.0), ("synthesize_poc", 45.0)):
        t[0] += b.slice(stage, want)
    t[0] += b.slice("fuzz", want=180.0)
    t[0] += b.slice("directed_fuzz", want=120.0)
    solver = b.slice("concolic", want=120.0)
    # twice the 18.52 s + validation that reached quack_quack's defect, where the measured
    # before-state was 21.0 s with the reserve released early, and 19.2 s with none at all
    assert solver > 40.0


def test_the_reserve_is_released_once_the_solver_has_been_served():
    """A reserve protects a stage that has not run yet. Held past that, the campaign that closes
    the coverage loop -- re-fuzzing AROUND the branches concolic just unlocked, which is why it
    is ordered there -- would be permanently denied the time to do it."""
    t = [0.0]
    b = B.CaseBudget(600.0, clock=lambda: t[0])
    t[0] = 30.0
    b.phase("search")
    t[0] += b.slice("fuzz", want=180.0)
    t[0] += b.slice("directed_fuzz", want=120.0)
    t[0] += b.slice("concolic", want=120.0)
    assert b.slice("directed_fuzz", want=120.0) > B.FLOOR_SECONDS


def test_only_the_stage_the_reserve_is_FOR_releases_it():
    """`build_exploit`, `mem_oracle`, `chain_primitive` and `synthesize_poc` all run in the
    search phase BEFORE the campaigns. Releasing the reserve on any non-sampler therefore
    released it before `fuzz` started, and the solver was barely better off: 21.0 s on
    quack_quack where the model said 97.5, and 3.0 s on replaceme."""
    t = [0.0]
    b = B.CaseBudget(600.0, clock=lambda: t[0])
    t[0] = 30.0
    b.phase("search")
    b.slice("mem_oracle", want=60.0)
    b.slice("chain_primitive", want=45.0)
    assert not b._solver_served, "a discovery stage must not release the solver's share"
    b.slice("concolic", want=120.0)
    assert b._solver_served


def test_an_unused_solver_reserve_is_not_wasted():
    """A target whose search finds a crash early never runs concolic. The reserve must then flow
    to the `prove` phase rather than sitting idle."""
    def prove_gets(reserve):
        was = B.SOLVER_RESERVE
        B.SOLVER_RESERVE = reserve
        try:
            t = [0.0]
            b = B.CaseBudget(600.0, clock=lambda: t[0])
            t[0] = 30.0
            b.phase("search")
            for stage, want in (("fuzz", 180.0), ("coverage_fuzz", 180.0),
                                ("directed_fuzz", 120.0)):
                t[0] += b.slice(stage, want)
            b.phase("prove")
            return b.available()
        finally:
            B.SOLVER_RESERVE = was

    # Relational, not a magic number: the share the solver never claimed is still there for the
    # next phase rather than having been spent by the samplers.
    assert prove_gets(B.SOLVER_RESERVE) > prove_gets(0.0)
    assert prove_gets(B.SOLVER_RESERVE) > 600.0 * B.RESERVE_AFTER["search"]


def test_a_stage_that_ran_and_refused_is_not_counted_as_work():
    """Elapsed seconds are not evidence of work, and the scorecard only had seconds.

    Measured on an ASan libtiff build: `libfuzzer` -- the one engine built for fuzzing a
    library -- emitted `supported: false, "libFuzzer build failed: fatal error: 'tiffio.h' file
    not found"`, and the scorecard showed `libfuzzer: 9.0` among the stages that completed. Nine
    seconds of elapsed time reads as work, so a capability that had built nothing and fuzzed
    nothing was indistinguishable from one that worked, in the run's own report. That is how a
    broken engine survives a session of measurement.
    """
    from types import SimpleNamespace as NS
    from lykos.analyze import orchestrate
    declines = orchestrate._declines_from_events([
        NS(type="libfuzzer.done", payload={"supported": False,
           "note": "libFuzzer build failed: fatal error: 'tiffio.h' file not found"}),
        NS(type="heap.done", payload={"ok": True, "errors": 0, "findings": 0}),
        NS(type="poc.done", payload={"verified": True, "level": "L1"}),
    ])
    assert "libfuzzer" in declines and "tiffio.h" in declines["libfuzzer"]
    # A stage that ran, applied, and found nothing is NOT a decline -- that distinction is the
    # whole point: "clean" and "could not look" must never collapse into one row again.
    assert "heap_check" not in declines, declines
    assert "build_poc" not in declines, declines


def test_every_event_prefix_maps_to_a_stage_that_exists():
    """The declines are keyed by STAGE, while stages emit events under their own prefixes
    (`heaptrace.done` for `heap_trace`, `re.done` for `disassemble`). A typo here does not fail
    loudly -- it files the decline against a stage name nobody schedules, and the capability
    goes quiet again, which is the exact failure this ledger exists to end."""
    from lykos.analyze import orchestrate, register
    from lykos.jobs.registry import list_stages
    register()
    names = set(list_stages())
    unknown = sorted(v for v in orchestrate._EVENT_STAGE.values() if v not in names)
    assert not unknown, f"event map points at non-existent stages: {unknown}"


def test_the_card_says_which_capabilities_were_never_scheduled():
    """"Is the pipeline using everything it has" must be answerable from a run, not from
    reading the orchestrator. Case-level stages are excluded because they are not per-target
    work, so their absence from a target's pass is correct rather than a gap."""
    from lykos.analyze import orchestrate
    assert "link_case" in orchestrate._NOT_PER_TARGET
    assert "whole_system" in orchestrate._NOT_PER_TARGET
    assert "fuzz" not in orchestrate._NOT_PER_TARGET, "fuzz is per-target work"


def test_the_rate_is_divided_by_the_stages_that_actually_executed():
    """A fabricated rate is worse than no rate.

    The divisor was a fixed list of stage names that does not contain `libfuzzer`, so on a target
    whose executions all came from in-process fuzzing it fell back to its 1e-3 floor and the card
    reported **23,642,000.0/s** for 23,642 executions. That is the one field a reader uses to
    judge whether a campaign was real, and nothing else in the card contradicted it.

    Execution counts are keyed by EVENT prefix and timings by STAGE name, which is why this needs
    a resolver rather than a dict lookup: `directed` is `directed_fuzz`.
    """
    from lykos.analyze.orchestrate import _engine_seconds
    by_stage = {"fuzz": 162.9, "directed_fuzz": 126.1, "libfuzzer": 180.0, "disassemble": 78.2}
    assert _engine_seconds(by_stage, ["libfuzzer"]) == 180.0
    assert _engine_seconds(by_stage, ["directed"]) == 126.1, "event prefix must resolve to a stage"
    assert _engine_seconds(by_stage, ["fuzz", "directed", "libfuzzer"]) == 469.0
    # a stage that contributed nothing must not be counted, and an unknown engine adds no time
    assert _engine_seconds(by_stage, ["nosuch"]) == 0.0
    assert "disassemble" not in ("fuzz", "directed", "libfuzzer")
