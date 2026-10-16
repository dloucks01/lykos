"""The budget divides EXECUTIONS, not just seconds.

Time is the operator's unit, so the case clock stays in seconds. But what a second BUYS is not
constant, and the spread is not small -- measured on this platform:

    plain x86-64 ELF        ~580 exec/s (substrate table) / ~105 exec/s on /usr/bin-class tools
    the same build + ASan    5.1x slower
    a jar                     ~36 exec/s
    a .pyc                    ~19 exec/s
    a .NET assembly            ~8 exec/s
    a rehosted firmware image  ~5 exec/s

Dividing seconds handed the same campaign a 5x smaller search on the instrumented build -- and
the instrumented build is the ONLY configuration whose oracle can see a heap out-of-bounds
access at all. Measured: ASan `tiffcrop` got 2,761 executions from a 420-second case, 11 stages
done, 14 skipped, and `coverage_fuzz` never started. The configuration that can find the bug is
the one the clock starves.

Three things follow, and each is tested here: a sampler asks in executions and the budget
converts at this target's rate; a slice too small to mean anything is REFUSED with that reason
rather than spread into uselessness; and the shortfall is stated as a budget the operator can
actually pass.
"""
from __future__ import annotations

from lykos.analyze import budget as B


# ---------------------------------------------------------------------------- the rate model
def test_a_measured_rate_always_wins():
    """An estimate is a prior; a rate a campaign actually achieved is evidence."""
    assert B.exec_rate(580.0, sanitizer=True, measured=20.5) == 20.5
    assert B.exec_rate(None, measured=3780.0) == 3780.0


def test_the_sanitizer_penalty_applies_to_the_estimate_only():
    plain = B.exec_rate(105.0)
    san = B.exec_rate(105.0, sanitizer=True)
    assert plain == 105.0
    assert abs(san - 105.0 / B.SANITIZER_SLOWDOWN) < 0.01
    # ...and not on top of a measured figure, which already includes it
    assert B.exec_rate(105.0, sanitizer=True, measured=20.5) == 20.5


def test_the_rate_is_floored():
    """A rate near zero would turn a modest execution request into the whole case clock."""
    assert B.exec_rate(0.0001) >= B.MIN_EXEC_RATE
    assert B.exec_rate(None, measured=0.0) == B.DEFAULT_EXEC_RATE


# -------------------------------------------------------------------------- the conversion
def test_a_slow_target_is_given_the_seconds_its_search_costs():
    """The same execution request costs more seconds on a slower target. That is the whole
    point: before this, both got the same seconds and the slow one got a fifth of the search."""
    fast = B.CaseBudget(900.0); fast.phase("search"); fast.set_exec_rate(105.0)
    slow = B.CaseBudget(900.0); slow.phase("search"); slow.set_exec_rate(20.6)
    s_fast = fast.slice("fuzz", want_execs=5_000)
    s_slow = slow.slice("fuzz", want_execs=5_000)
    assert s_slow > s_fast, f"slow target got {s_slow}s, fast got {s_fast}s"
    # and each is sized from its own rate
    assert abs(s_fast - 5_000 / 105.0) < 1.0
    assert abs(s_slow - 5_000 / 20.6) < 1.0


def test_the_seconds_path_is_unchanged():
    """A stage that asks in seconds must get exactly what it got before -- most stages are a
    single detonation or a static pass, and executions are not their unit."""
    b = B.CaseBudget(900.0); b.phase("search")
    assert b.slice("fuzz", want=180.0) == 180.0
    r = B.CaseBudget(900.0); r.phase("recover")
    assert r.slice("disassemble", want=600.0) == 135.0      # the phase reserve still binds


def test_the_phase_reserve_still_bounds_an_execution_request():
    """Execution-sizing may not become a way around the reserve: a later phase is still owed
    what it is owed, and a huge request is capped rather than granted."""
    b = B.CaseBudget(100.0); b.phase("search"); b.set_exec_rate(1.0)
    s = b.slice("fuzz", want_execs=1_000_000)
    assert s <= b.available() + 0.05, f"{s} exceeds the phase's {b.available()}"
    assert b.sizing()["capped"] is True


def test_a_slice_too_small_to_mean_anything_is_refused_with_the_reason():
    """Five pointless campaigns are worth less than one real one, so a sub-floor slice is
    refused and its budget stays for a stage that can clear the floor. The reason names the
    rate, which is what makes it actionable rather than a bare skip."""
    b = B.CaseBudget(60.0); b.phase("search"); b.set_exec_rate(2.0)
    s = b.slice("fuzz", want_execs=30_000)
    assert s == 0.0, f"handed out {s}s for a campaign that cannot clear the floor"
    z = b.sizing()
    assert z["refused"], "refused with no reason"
    assert "floor" in z["refused"] and "exec/s" in z["refused"]
    assert z["affords_execs"] < B.FLOOR_EXECS


def test_the_floor_may_exceed_the_single_stage_share_when_that_is_what_it_costs():
    """`MAX_SINGLE_SHARE` exists to stop ONE stage eating a case with many stages to serve. On
    a slow target it starts doing the opposite -- half the clock buys too little to be worth
    anything -- so an execution-sized request may exceed the share, still bounded by the phase.

    The rate is DERIVED from the constants rather than guessed: the window where this applies
    is where the floor costs more than the share but no more than the phase has, and a
    hand-picked number lands outside it the moment a constant moves."""
    total = 600.0
    b0 = B.CaseBudget(total); b0.phase("search")
    avail = b0.available()
    share = avail * B.MAX_SINGLE_SHARE
    # floor_cost = FLOOR_EXECS / rate, and we want share < floor_cost < avail
    rate = B.FLOOR_EXECS / ((share + avail) / 2.0)
    b = B.CaseBudget(total); b.phase("search"); b.set_exec_rate(rate)
    s = b.slice("fuzz", want_execs=B.FLOOR_EXECS)
    assert s > 0.0, f"refused at {rate:.2f} exec/s where the phase can afford the floor"
    assert s > share, f"the floor ({s}s) was not allowed to exceed the share ({share}s)"
    assert s <= avail + 0.05, "and it must still not exceed what the phase has"
    assert b.sizing()["affords_execs"] >= B.FLOOR_EXECS


def test_the_sizing_is_reported_so_a_starved_campaign_is_not_mistaken_for_a_thorough_one():
    b = B.CaseBudget(900.0); b.phase("search"); b.set_exec_rate(20.6)
    b.slice("fuzz", want_execs=30_000)
    z = b.sizing()
    assert z["stage"] == "fuzz" and z["want_execs"] == 30_000
    assert z["rate"] == 20.6 and z["measured_rate"] is True
    assert z["affords_execs"] > 0 and z["capped"] is True


# ------------------------------------------------------------------------------- the advice
def test_the_shortfall_is_stated_as_a_budget_the_operator_can_pass():
    """A number nobody can act on is barely better than no number. ASan `tiffcrop` reported
    2,761 executions and nothing said the same case would have bought ~44,000 uninstrumented,
    or what budget a comparable search needed."""
    b = B.CaseBudget(420.0); b.set_exec_rate(B.exec_rate(105.0, sanitizer=True))
    a = b.advice(want_execs=30_000)
    assert a["short_by"] > 0
    assert a["budget_for_want"] > 420.0
    assert "--budget" in a["note"]
    # the measured complaint, reproduced: ~2,600 executions at this rate in a 420s case
    assert 2_000 < a["affords_execs"] < 3_500, a["affords_execs"]


def test_the_advice_says_so_when_the_budget_is_enough():
    b = B.CaseBudget(900.0); b.set_exec_rate(580.0)
    a = b.advice(want_execs=18_000)
    assert a["short_by"] == 0
    assert "covers" in a["note"]


def test_an_estimated_rate_is_labelled_as_one():
    b = B.CaseBudget(420.0)                               # nothing set
    a = b.advice()
    assert a["measured"] is False
    assert b.rate == B.DEFAULT_EXEC_RATE
