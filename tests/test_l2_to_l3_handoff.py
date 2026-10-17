"""The L2 -> L3 handoff: build_exploit must be able to read the offset poc_primitive confirmed.

This is the join between two stages, and it was broken in a way neither stage's own tests could
see. `_l2_offset` listed a poc_primitive run's events with `EventDAO.list(run_id=..., limit=60)`.
That call is `ORDER BY id ASC LIMIT ?`, a real poc_primitive run emits ~131 events, and
`primitive.done` -- the one carrying the confirmed offset -- is second-to-last. So the lookup
returned None every time, the "prefer the confirmed L2 control offset" branch in
build_exploit_stage was unreachable, and the stage always fell back to its own cyclic-pattern
probe. On a target whose input needs structure (a `key=` prefix, a length field, a menu choice)
that probe cannot fault at all, so L3 was unreachable on precisely the targets where L2 had
already found and verified the exact offset.

It was invisible because all three of the things that should have caught it were absent: the
lookup swallowed every exception silently, nothing asserted the handoff, and the end-to-end
harness that exercises it (tools/pipeline_conformance.py) exited 0 regardless of its own results.
"""
from __future__ import annotations

from lykos.analyze.poc.exploit_stage import _l2_frame, _l2_mode, _l2_offset
from lykos.db.dao import AnalysisRunDAO, EventDAO, TargetDAO

#: More events than any single-window read would return. The real runs emit ~131.
_NOISE = 140
_OFFSET = 41


class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "vuln", "a" * 64, size=16376)


def _primitive_run(store, target, *, confirmed, offset, mode="stdin", frame=None,
                   noise=_NOISE):
    """A finished poc_primitive run that emits `noise` events before its primitive.done."""
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(target.case_id, "poc_primitive", target_id=target.id,
                      params={}, tool="poc", tool_version="1")
    for i in range(noise):
        events.append("job.exec", case_id=target.case_id, run_id=run.id,
                      payload={"tool": "python3", "cmd": "ptrace_capture.py", "i": i})
    payload: dict = {"primitive": "instruction-pointer-control", "supported": True}
    if confirmed:
        payload.update({"confirmed": True, "offset": offset, "level": "L2",
                        "mode": mode})
        if frame is not None:
            payload["frame_prefix"] = frame[0].hex()
            payload["frame_suffix"] = frame[1].hex()
    else:
        payload.update({"note": "no L2", "input_modes_tried": ["stdin"]})
    events.append("primitive.done", case_id=target.case_id, run_id=run.id, payload=payload)
    runs.set_status(run.id, "done")
    return run


def test_the_confirmed_offset_is_found_behind_a_full_run_of_events(store, case):
    """The regression itself: the offset is readable even though ~140 events precede it."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET)
    assert _l2_offset(_Ctx(store.conn), t) == _OFFSET


def test_a_later_unconfirmed_run_does_not_mask_an_earlier_confirmed_one(store, case):
    """The autopilot re-runs poc_primitive once per distinct crash, and most of those runs do NOT
    confirm. The newest event is therefore usually an unconfirmed one; the lookup has to keep
    scanning back rather than stop at it."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET)
    for _ in range(3):
        _primitive_run(store, t, confirmed=False, offset=None)
    assert _l2_offset(_Ctx(store.conn), t) == _OFFSET


def test_no_confirmed_primitive_means_no_offset(store, case):
    """With nothing confirmed there is no offset to inherit, and build_exploit must fall back to
    its own recovery rather than be handed a wrong number."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=False, offset=None)
    assert _l2_offset(_Ctx(store.conn), t) is None


def test_the_offset_must_be_an_integer(store, case):
    """A payload whose offset is a string or null is not a usable offset."""
    t = _target(store, case)
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(t.case_id, "poc_primitive", target_id=t.id,
                      params={}, tool="poc", tool_version="1")
    events.append("primitive.done", case_id=t.case_id, run_id=run.id,
                  payload={"confirmed": True, "offset": "41"})
    runs.set_status(run.id, "done")
    assert _l2_offset(_Ctx(store.conn), t) is None


def test_the_lookup_does_not_depend_on_a_window_into_a_runs_events():
    """A source-level guard on the shape of the bug: the result is asked of the database, not
    filtered out of a capped list. A re-introduced `limit=` would pass every test above, because
    they all use a small event count -- so pin the mechanism, not just the behaviour.

    All three readers go through one `_confirmed_l2`, which is itself the point: the offset, the
    channel and the framing are only meaningful together, and three separate lookups could
    answer from three different runs."""
    import inspect

    from lykos.analyze.poc import exploit_stage

    def code(fn):
        return "\n".join(ln for ln in inspect.getsource(fn).splitlines()
                          if not ln.lstrip().startswith("#"))

    shared = code(exploit_stage._confirmed_l2)
    assert "limit=" not in shared, "the shared L2 read must not take a window"
    assert "payloads_of_type(" in shared, \
        "it must ask EventDAO for the event type, not page a run's events"
    assert 'stage="poc_primitive"' in shared and 'status="done"' in shared
    # Each selector must reach the shared lookup -- directly, or through `_l2_control_run`,
    # which is the one that picks the payload carrying the offset. The delegation exists because
    # the three have to answer from ONE payload: a second verdict family (address-control)
    # confirms an L2 with no offset and empty framing, and when `_l2_frame` answered from
    # whichever payload had the keys first it handed L3 "unstructured" for a target whose smash
    # only lands behind `name=`.
    assert "_confirmed_l2(ctx, target)" in code(exploit_stage._l2_control_run)
    for fn in (_l2_offset, _l2_mode, _l2_frame):
        body = code(fn)
        assert ("_confirmed_l2(ctx, target)" in body
                or "_l2_control_run(ctx, target)" in body), \
            f"{fn.__name__} must read through the shared, unwindowed lookup"
        assert "SELECT" not in body.upper(), f"{fn.__name__} hand-rolls its own query"


# --------------------------------------------------------------------- the channel, not just the
# offset. build_exploit inherited the offset and then re-guessed the channel from the import
# table. how_to_feed ranks a `file` parser first whenever the binary imports fopen, so a stdin
# smash in a program that also opens a config file was delivered as argv -- where a NUL inside a
# non-PIE win address truncates the copy, and the stage reported "the hijack was not reached".
# Its own re-probe cannot correct it: that probe is a bare cyclic, which never faults at all on a
# target whose input needs structure. poc_primitive does not guess -- it retries the crashing
# input on every channel until one faults -- so it is the one that knows.


def test_the_confirmed_channel_is_inherited(store, case):
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, mode="file")
    assert _l2_mode(_Ctx(store.conn), t) == "file"


def test_an_unconfirmed_run_contributes_no_channel(store, case):
    """An unconfirmed primitive never resolved a channel, so there is nothing to inherit and
    build_exploit must keep its own guess rather than be handed a default."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=False, offset=None)
    assert _l2_mode(_Ctx(store.conn), t) is None


def test_the_channel_and_the_offset_come_from_the_same_confirmed_run(store, case):
    """Taking the offset from one run and the channel from another would build a payload for a
    frame that channel never produced."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, mode="file")
    for _ in range(3):
        _primitive_run(store, t, confirmed=False, offset=None)
    ctx = _Ctx(store.conn)
    assert (_l2_offset(ctx, t), _l2_mode(ctx, t)) == (_OFFSET, "file")


def test_the_confirmed_channel_only_overrides_the_import_table_guess():
    """Precedence, which is the whole subtlety. how_to_feed answers in three tiers, and only its
    last one is a guess:

        params.input_mode                                  -- the analyst said so
        the channel the run that FOUND this input recorded  -- authoritative for THIS input
        a ranking of the channels by the import table       -- "a starting guess", its own words

    L2's measured channel beats the third and must not beat the first two: it was resolved
    against whichever crash L2 confirmed, which need not be the input being exploited now.
    Getting this backwards substitutes a channel for one the recording run had already measured
    for this exact input -- which is how the first version of this override was written."""
    import inspect

    from lykos.analyze.poc import exploit_stage
    src = inspect.getsource(exploit_stage.build_exploit_stage)
    assert "_l2_mode(ctx, target)" in src, "build_exploit does not inherit the confirmed channel"
    i, j = src.index("how_to_feed("), src.index("_l2_mode(ctx, target)")
    assert i < j, "the L2 channel is consulted after how_to_feed, not instead of it"
    assert "FEED_AUTHORITATIVE" in src, \
        "the override must be gated on how_to_feed having fallen back to its import-table guess"


def test_the_authoritative_feed_reasons_are_the_ones_how_to_feed_actually_returns():
    """The gate above is only as good as this set. `how_to_feed` returns a sentence, and the two
    sentences that mean "established, not inferred" used to be restated as literals at the call
    site -- so rewording either would have failed the gate OPEN, silently letting L2's channel
    override a mode the recording run had measured for this exact input. One definition, and
    this pins it to the function's real returns."""
    import ast
    import inspect
    import textwrap

    from lykos.analyze.poc import capture
    tree = ast.parse(textwrap.dedent(inspect.getsource(capture.how_to_feed)))
    returned = {ast.unparse(r.value.elts[2]) for r in ast.walk(tree)
                if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple)}
    named = {"FEED_GIVEN", "FEED_RECORDED"}
    assert named <= returned, (
        "how_to_feed no longer returns the named authoritative reasons: %s" % sorted(returned))
    assert capture.FEED_AUTHORITATIVE == {capture.FEED_GIVEN, capture.FEED_RECORDED}
    # ...and the third return is the guess, which must NOT be in the authoritative set.
    guesses = returned - named
    assert guesses, "how_to_feed must still have an inferring fallback"


def test_a_nul_in_the_slot_is_only_blamed_on_truncation_where_truncation_happens():
    """The note read "so an argv-delivered copy is truncated" whenever the address contained a
    NUL -- on every channel, because the check reads the payload bytes and never `mode`. It was
    emitted on a run delivering through a FILE, where a zero byte travels intact, so it named a
    cause that was not there and sent the reader after the wrong thing. Only argv and env are
    NUL-terminated."""
    import inspect

    from lykos.analyze.poc import exploit_stage
    src = inspect.getsource(exploit_stage.build_exploit_stage)
    window = src[src.index("_nul_cuts_the_slot("):][:1600]
    assert 'mode in ("arg", "env")' in window, \
        "the truncation claim must be conditional on a NUL-terminated channel"
    assert "landing beside the slot" in window, \
        "on a byte-safe channel the note must say what IS happening, not what is not"


def test_poc_primitive_records_the_channel_it_resolved():
    """The producer side. Every test above builds the `primitive.done` payload itself, so none of
    them notices if the real stage stops putting `mode` in it -- and then `_l2_mode` returns None
    forever and build_exploit silently goes back to guessing. Driving the real stage needs a
    compiled target and minutes, so this pins the emit instead, which is the same reason the rest
    of this suite uses source-level invariants for things only a full run would otherwise show."""
    import inspect

    from lykos.analyze.poc import primitive_stage
    src = inspect.getsource(primitive_stage._finalize)
    assert '"primitive.done"' in src, "the confirmed L2 result is emitted here"
    assert '"mode": mode' in src, \
        "primitive.done must carry the channel L2 resolved -- build_exploit inherits it"
    assert '"offset": prim.get("offset")' in src, \
        "primitive.done must carry the confirmed offset -- build_exploit inherits it too"


# ------------------------------------------------------------------- the framing. The third thing
# an L2 result carries, and the one whose absence kept L3 out of reach on structured targets even
# after the offset was being inherited correctly. An offset is measured AGAINST a framing: given
# the right number and the wrong prefix, the payload lands beside the control slot and the stage
# reports "payload built but the hijack was not reached".
#
# build_exploit re-derived its own framing with `_overflow_frame`, which needs a long single-byte
# filler run to see any structure at all. A fuzzer-found crash routinely has none -- even on a
# target whose sink is behind a `key=value` parse -- so the answer was (b"", b""), every probe went
# out as a bare cyclic, and nothing faulted.


def test_the_confirmed_framing_is_inherited(store, case):
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, frame=(b"name=", b"\n"))
    assert _l2_frame(_Ctx(store.conn), t) == (b"name=", b"\n")


def test_an_l2_with_no_recorded_framing_leaves_the_derivation_alone(store, case):
    """None and (b"", b"") mean different things. An older L2 -- recorded before the framing was
    carried at all -- must not be read as "this target is unstructured", because that would
    silently replace a framing this stage had correctly derived for itself."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, frame=None)
    assert _l2_frame(_Ctx(store.conn), t) is None


def test_an_empty_framing_is_an_answer_not_a_missing_one(store, case):
    """An unstructured target genuinely has no framing, and L2 saying so is information."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, frame=(b"", b""))
    assert _l2_frame(_Ctx(store.conn), t) == (b"", b"")


def test_offset_channel_and_framing_all_come_from_the_same_run(store, case):
    """They are only meaningful together: an offset measured in one framing, applied in another,
    builds a payload for a frame that never existed. One read, one run."""
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, mode="file",
                   frame=(b"cfg=", b"\n"))
    for _ in range(3):
        _primitive_run(store, t, confirmed=False, offset=None)
    ctx = _Ctx(store.conn)
    assert (_l2_offset(ctx, t), _l2_mode(ctx, t), _l2_frame(ctx, t)) == (
        _OFFSET, "file", (b"cfg=", b"\n"))


def test_a_later_l2_without_an_offset_does_not_shadow_the_framing(store, case):
    """The regression that cost an L3. A second verdict family -- address-control, which measures
    the faulting ADDRESS rather than the instruction pointer -- confirms an L2 that has no
    control offset and no framing, and it is the NEWER event. `_l2_frame` scanned for the first
    payload carrying the framing keys, found two empty strings, and told build_exploit the target
    was unstructured: the `name=` prefix was dropped, the relocated win address landed in a line
    the program rejects, and the run reported "leak worked but the success marker was not
    observed" while holding a correct base and a correct offset **[measured 2026-10-16]**.
    """
    t = _target(store, case)
    _primitive_run(store, t, confirmed=True, offset=_OFFSET, mode="stdin",
                   frame=(b"name=\n", b"\n"))
    # ...and then the address-control verdict lands, newer, with neither
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(case.id, "poc_primitive", target_id=t.id, params={}, tool="poc",
                      tool_version="1")
    events.append("primitive.done", case_id=case.id, run_id=run.id,
                  payload={"primitive": "address-control", "confirmed": True, "offset": None,
                           "mode": "stdin", "frame_prefix": "", "frame_suffix": ""})
    runs.set_status(run.id, "done")
    ctx = _Ctx(store.conn)
    assert _l2_offset(ctx, t) == _OFFSET
    assert _l2_frame(ctx, t) == (b"name=\n", b"\n"), \
        "the framing must come from the run that measured the offset"


def test_a_corrupt_framing_does_not_raise(store, case):
    """The payload crosses a database, so a non-hex value must degrade to "no framing" rather
    than take the stage down."""
    t = _target(store, case)
    runs, events = AnalysisRunDAO(store.conn), EventDAO(store.conn)
    run = runs.create(case.id, "poc_primitive", target_id=t.id, params={}, tool="poc",
                      tool_version="1")
    events.append("primitive.done", case_id=case.id, run_id=run.id,
                  payload={"confirmed": True, "offset": 41, "frame_prefix": "zzz",
                           "frame_suffix": ""})
    runs.set_status(run.id, "done")
    assert _l2_frame(_Ctx(store.conn), t) is None


def test_poc_primitive_records_the_framing_it_confirmed():
    """Producer side, pinned at the emit for the same reason as the channel above: every test
    here builds the payload itself, so none would notice the real stage dropping the field."""
    import inspect

    from lykos.analyze.poc import primitive_stage
    src = inspect.getsource(primitive_stage._finalize)
    assert '"frame_prefix"' in src and '"frame_suffix"' in src, \
        "primitive.done must carry the framing L2 confirmed -- build_exploit inherits it"
    stage = inspect.getsource(primitive_stage.primitive_stage)
    assert "_frame_bytes" in stage, "the stage does not capture which framing actually faulted"
    assert "active_frame is not identity" in stage, \
        "the recorded framing must be the one that faulted, not the one that was derived"


def test_build_exploit_prefers_the_confirmed_framing_over_its_own_derivation():
    import inspect

    from lykos.analyze.poc import exploit_stage
    src = inspect.getsource(exploit_stage.build_exploit_stage)
    # The OFFSET path's own derivation runs first and L2's answer overrides it. Matched on the
    # ASSIGNMENT (`_l2f = `) rather than on any call to `_l2_frame`, because the PIE recipes above
    # the ladder read the same measured framing for their own detonations -- they build their
    # payloads themselves, so a framing they cannot see is a payload that never reaches the sink.
    i, j = src.index("_overflow_frame("), src.index("_l2f = _l2_frame(ctx, target)")
    assert i < j, "L2's framing must override the local derivation, not precede it"
    assert "_pre, _post = _l2f" in src
    # ...and the early read is for the recipes that detonate on their own, with the same source.
    assert "_measured_frame" in src and "frame=_measured_frame" in src
