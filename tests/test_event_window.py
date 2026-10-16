"""Terminal events must not be read through a fixed window into a case's event log.

`EventDAO.list` is `ORDER BY id ASC LIMIT ?`. A caller that passes a fixed `limit=` therefore
reads the OLDEST events, which is the opposite of what every one of these callers wanted: they
all want a stage's `.done` event, and that is by construction near the end.

Measured on one 420-second run against one small ELF: 2,124 events in the case.

  reader                                  window   the event it wanted
  orchestrate._last_done_payload          400      primitive.done, first at index 459
  orchestrate._all_done_payloads          400      monitor/taint/behavior/multidebug .done, >2000
  orchestrate._stage_decline              400      exploit.done, spanning 216..2077
  exploit_stage._l2_offset                60       primitive.done, index ~128 of ~131 per run
  realgate._done_field                    60       primitive.done / poc.done / rootcause.done
  archgate (l2_note/l3_note)              40       primitive.done, exploit.done
  report._scorecard                       8000     the scorecard, emitted LAST of all

The sharpest consequence was that build_exploit could never inherit the control offset
poc_primitive had verified, so L3 was unreachable on any target whose input needs structure.
`realgate._last_done_field` had already worked around the same thing for `fuzz` and said so in
its docstring, which is how we know the class was known and fixed in exactly one place.

These tests pin the mechanism, because a test with a small event count passes either way.
"""
from __future__ import annotations

import ast
import inspect
import textwrap

from lykos.analyze import orchestrate
from lykos.db.dao import AnalysisRunDAO, EventDAO, TargetDAO

#: More events than any of the windows above.
_NOISE = 450


def _code(fn):
    """A function's executable source only: no comments, no docstring. Several of these carry a
    docstring that quotes the old `limit=400`, and prose about a bug must not read as the bug."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    body = tree.body[0].body                                  # type: ignore[attr-defined]
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]                                       # drop the docstring
    return "\n".join(ast.unparse(n) for n in body)


#: Every reader of a stage's terminal event. Adding one here is the point: the list is the
#: inventory the invariant below is checked against.
_READERS = (
    "lykos.analyze.orchestrate:_done_payloads",
    "lykos.analyze.orchestrate:_last_done_payload",
    "lykos.analyze.orchestrate:_all_done_payloads",
    "lykos.analyze.orchestrate:_stage_decline",
    "lykos.analyze.orchestrate:_scorecard",
    "lykos.analyze.poc.exploit_stage:_confirmed_l2",
    "lykos.analyze.poc.exploit_stage:_l2_offset",
    "lykos.analyze.poc.exploit_stage:_l2_mode",
    "lykos.eval.realgate:_done_field",
    "lykos.eval.realgate:_last_done_field",
    "lykos.eval.archgate:_all_events",
    "lykos.report.model:_scorecard",
)


def _resolve(spec):
    import importlib
    mod, name = spec.split(":")
    return getattr(importlib.import_module(mod), name, None)


def test_no_reader_of_a_done_event_uses_a_fixed_window():
    """The invariant. A fixed `limit=` with no `after_id` is a window; a terminal event needs
    either a type-filtered query or pagination to the end."""
    offenders = []
    for spec in _READERS:
        fn = _resolve(spec)
        if fn is None:
            continue                                      # covered by the inventory test below
        code = _code(fn)
        if "limit=" in code and "after_id" not in code:
            offenders.append(spec)
    assert not offenders, ("these read a terminal event through a fixed window: %s" % offenders)


def test_every_reader_in_the_inventory_still_exists():
    """A reader that is renamed or deleted must not silently drop out of the check above."""
    missing = [spec for spec in _READERS if _resolve(spec) is None]
    assert not missing, ("the window invariant is no longer checked for: %s -- update _READERS"
                         % missing)


def test_the_readers_go_through_the_dao_rather_than_hand_rolled_sql():
    """Seven call sites each got this wrong independently, and my first pass fixed them with
    seven hand-written queries -- which is the same mistake one layer up. The safe reads live on
    EventDAO (`walk`, `payloads_of_type`), neither of which takes a limit, so routing through
    them is what makes the class closed rather than merely fixed."""
    offenders = []
    for spec in _READERS:
        fn = _resolve(spec)
        if fn is None:
            continue
        code = _code(fn)
        if "SELECT" in code.upper() and "payload_json" in code:
            offenders.append(spec)
    assert not offenders, ("these hand-roll event SQL instead of using EventDAO.walk / "
                           "payloads_of_type: %s" % offenders)


def test_the_dao_reads_that_cannot_truncate_take_no_limit():
    """The property that makes them safe, asserted on the primitives themselves."""
    import inspect

    from lykos.db.dao import EventDAO
    for fn in (EventDAO.walk, EventDAO.payloads_of_type):
        params = inspect.signature(fn).parameters
        assert "limit" not in params, f"{fn.__name__} must not offer a limit"
    # ...and `list`, which does take one, must keep its cursor so a caller CAN page safely.
    assert "after_id" in inspect.signature(EventDAO.list).parameters


def test_the_autopilot_sees_a_done_event_past_the_old_window(store, case):
    """`_last_done_payload` returned None for any stage whose `.done` landed past event 400 --
    which included poc_primitive on every real run."""
    t = TargetDAO(store.conn).upsert(case.id, "vuln", "b" * 64, size=100)
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(case.id, "poc_primitive", target_id=t.id, params={}, tool="poc",
                      tool_version="1")
    for i in range(_NOISE):
        events.append("job.exec", case_id=case.id, run_id=run.id, payload={"i": i})
    events.append("primitive.done", case_id=case.id, run_id=run.id,
                  payload={"confirmed": True, "offset": 41, "supported": True})
    runs.set_status(run.id, "done")

    assert orchestrate._last_done_payload(store, t, "poc_primitive") == {
        "confirmed": True, "offset": 41, "supported": True}
    assert len(orchestrate._all_done_payloads(store, t, "poc_primitive")) == 1


def test_a_decline_past_the_window_is_still_reported(store, case):
    """`_stage_decline` is what turns a green-looking plan line into "ran, but could not apply
    here". Past the window it reported nothing, i.e. "worked"."""
    t = TargetDAO(store.conn).upsert(case.id, "vuln", "c" * 64, size=100)
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(case.id, "libfuzzer", target_id=t.id, params={}, tool="lf",
                      tool_version="1")
    for i in range(_NOISE):
        events.append("job.exec", case_id=case.id, run_id=run.id, payload={"i": i})
    events.append("libfuzzer.done", case_id=case.id, run_id=run.id,
                  payload={"supported": False, "note": "no source for this target"})
    runs.set_status(run.id, "done")

    assert orchestrate._stage_decline(store, t, "libfuzzer") == "no source for this target"


def test_the_newest_done_wins_when_a_stage_ran_several_times(store, case):
    """`exploit.done` spans index 216..2077 on a real run: the pre-fuzz refusal and then three
    attempts with the crash in hand. Reporting the first one describes a stage that has since
    moved on."""
    t = TargetDAO(store.conn).upsert(case.id, "vuln", "d" * 64, size=100)
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    for n, payload in enumerate(({"supported": False, "note": "run fuzz/L2 first"},
                                 {"supported": True, "confirmed": True, "level": "L3"})):
        run = runs.create(case.id, "build_exploit", target_id=t.id, params={}, tool="x",
                          tool_version="1")
        for i in range(_NOISE):
            events.append("job.exec", case_id=case.id, run_id=run.id, payload={"n": n, "i": i})
        events.append("exploit.done", case_id=case.id, run_id=run.id, payload=payload)
        runs.set_status(run.id, "done")

    last = orchestrate._last_done_payload(store, t, "build_exploit")
    assert last and last.get("level") == "L3", last
    assert orchestrate._stage_decline(store, t, "build_exploit") is None, \
        "the stage succeeded on its second run; the first refusal must not be its verdict"
    assert len(orchestrate._all_done_payloads(store, t, "build_exploit")) == 2


# ------------------------------------------------------------- the card must not close its books
# while work is still landing. Found on the HTB binary `zigzag` in a real-corpus run: the budget
# ran out, `_staged` cancelled the pending runs and returned, and `directed_fuzz` -- still inside
# its stage function -- emitted `directed.done {"execs": 64}` six events AFTER the scorecard. The
# card recorded `executions.total = 0`, and the gate failed the target with "ran once but the
# campaigns executed it zero times", which was simply untrue.
#
# Neither the row status nor the pending set shows this: `q.cancel()` has already marked the row
# `cancelled` while the thread runs on.


def test_the_scorecard_waits_for_every_run_to_report(store, case):
    """`_settle` returns only once every run has emitted a terminal job event. A quiet-window
    heuristic was tried first and could not work: on `zigzag` the log was genuinely quiet when
    the card was built and `directed.done {"execs": 64}` landed 50 seconds later, because the
    stage was stuck in a non-cooperative afl/qemu call."""
    from lykos.analyze import orchestrate
    from lykos.db.dao import AnalysisRunDAO, EventDAO
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    r1 = runs.create(case.id, "fuzz", params={}, tool="f", tool_version="1")
    r2 = runs.create(case.id, "directed_fuzz", params={}, tool="f", tool_version="1")

    events.append("job.done", case_id=case.id, run_id=r1.id, payload={})
    # r2 has NOT reported -- even though its row says cancelled, which is the whole trap.
    runs.set_status(r2.id, "cancelled")
    assert orchestrate._settle(store, case.id, limit=0.5) is False, \
        "settled while a cancelled run was still working"

    events.append("job.cancelled", case_id=case.id, run_id=r2.id, payload={})
    assert orchestrate._settle(store, case.id, limit=5.0) is True


def test_a_cancelled_row_is_not_a_finished_thread(store, case):
    """The precise trap: `q.cancel()` marks the row `cancelled` immediately while the worker
    thread runs on inside the stage function for another minute. Row status cannot be the signal
    and the pending set is already empty, which is why this waits on the worker's own event."""
    import inspect

    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate._settle)
    assert "_JOB_TERMINAL" in src, "the wait must key on the worker's terminal job events"
    assert "analysis_run" in src and "e.type IN" in src
    assert "status" not in src.split('"""')[-1], \
        "the wait must not trust the run's row status"


def test_the_card_says_whether_it_settled(store, case):
    """A card built while a stage was still finishing reports a FLOOR, not a total. A reader
    weighing "0 executions" has to know which they are looking at -- that is exactly how a wrong
    zero gets believed."""
    import inspect

    from lykos.analyze import orchestrate
    assert "settled" in inspect.signature(orchestrate._scorecard).parameters
    src = inspect.getsource(orchestrate._scorecard)
    assert 'card["settled"]' in src


def test_the_settle_wait_is_capped(store, case):
    """A wedged stage may never report at all, and must not hold a run open forever."""
    import time

    from lykos.analyze import orchestrate
    from lykos.db.dao import AnalysisRunDAO
    AnalysisRunDAO(store.conn).create(case.id, "fuzz", params={}, tool="f", tool_version="1")
    t0 = time.monotonic()
    assert orchestrate._settle(store, case.id, limit=1.0) is False
    assert time.monotonic() - t0 < 3.0


def test_the_autopilot_settles_before_it_scores():
    """Source-level: the wait has to happen on the path that builds the card."""
    import inspect

    from lykos.analyze import orchestrate
    src = inspect.getsource(orchestrate.run_case_autopilot)
    i, j = src.index("_settle(store, t.case_id)"), src.index("_scorecard(store, t, bud, status")
    assert i < j, "the scorecard is built before the runs have reported"
    assert "settled=_settled" in src, "the card is not told whether everything reported"


def test_an_unsettled_card_says_so_everywhere_it_is_shown():
    """The flag is only worth recording if a reader sees it. `0 executions` from a complete run
    and `0 executions` from a card built early are opposite conclusions -- the first says the
    target was not exercised, the second says the accounting closed early -- and on `zigzag` the
    second was reported as the first, all the way out to a gate FAIL."""
    import inspect
    import pathlib as _p

    from lykos.report import html, model
    assert '"settled"' in inspect.getsource(model._scorecard), \
        "the report model drops the settled flag"
    assert 'settled' in inspect.getsource(html.render) if hasattr(html, "render") else True
    assert "Incomplete" in (_p.Path(html.__file__).read_text()), \
        "the HTML report never shows it"
    from lykos import cli
    assert "INCOMPLETE" in inspect.getsource(cli._print_scorecard), \
        "the CLI never shows it"
    spa = (_p.Path(__file__).resolve().parents[1]
           / "core/lykos/api/static/app/components.js").read_text()
    assert "card.settled === false" in spa, "the workbench panel never shows it"
