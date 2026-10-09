"""The case's wall clock, and how it is divided among the stages.

Measured on four stock binaries from /usr/bin before this existed, 420s of budget each:

    /usr/bin/cat        1,511 executions   27 of ~40 stages   ended inside directed_fuzz
    /usr/bin/xxd        2,756 executions   30 stages (done)   --
    /usr/bin/readelf    1,473 executions   26 stages          ended inside concolic
    /usr/bin/jpegtran           0          15 stages          ended inside build_exploit

Three facts in that table, and none of them is about analysis quality:

  * **The campaign was never budgeted.** The autopilot passed no time or execution bound, so
    every campaign on every target took the stage default: `max_seconds=30`, `max_execs=3000`.
    Thirty seconds is a smoke test. Measured achievable rate on /usr/bin/cat is 174 exec/s
    batched, so even those 30 seconds were spent at a fraction of the host's capability.

  * **A single stage could consume the whole run.** `directed_fuzz` and `concolic` are
    registered at `timeout=3600` and the queue default is also 3600 -- against a case that had
    420 seconds in total. One stage could claim eight times the entire budget, and everything
    ordered after it never ran at all. Which stages you got depended on where the clock stopped.

  * **So jpegtran -- the one real file-format parser in the sample -- got zero executions**,
    because `build_exploit` (ordered early on purpose, for crashless weaponization) spent its
    full 300s on a target that had no crash yet, and the run ended before any fuzzer started.

The fix is not a different order; the early placement of crashless weaponization was itself a
previous fix for this same problem, and moving it back would undo that. The fix is that NO stage
may spend budget that a later PHASE is owed.

So the budget is divided by phase, and each phase keeps a reserve for the ones after it:

    recover   static recovery and detection -- cheap, and must not eat the search
    search    the campaigns that actually execute the target; the largest share
    prove     root-cause, PoC, primitive and weaponization of what search found

A stage is handed its slice as `max_seconds`, which `registry._COMMON_PARAMS` permits on every
stage. That single value does three jobs: it caps the orchestrator's wait, it becomes the
worker's per-run deadline (so `ctx.should_cancel()` fires and the pipeline moves on instead of
blocking), and for the four stages that read `max_seconds` themselves it IS the campaign length.
"""
from __future__ import annotations

import time
from typing import Optional

#: Phases, in the order the autopilot enters them.
PHASES = ("recover", "search", "prove")

#: Fraction of the TOTAL budget that must still be AVAILABLE when each phase ends -- i.e. what
#: the phase is forbidden to spend because later phases are owed it. `search` keeps a quarter
#: back for proving whatever it finds; `prove` is last and keeps nothing.
RESERVE_AFTER = {"recover": 0.70, "search": 0.25, "prove": 0.0}

#: No single stage may take more than this fraction of what its phase has available. Without it
#: the first expensive stage in a phase takes the lot -- which is exactly how one `build_exploit`
#: consumed a whole case.
MAX_SINGLE_SHARE = 0.5

#: Below this a slice is not worth handing out: a two-second campaign measures nothing, and
#: saying "no budget left" is more useful than pretending to run. Returned as 0.0 instead.
FLOOR_SECONDS = 12.0

#: Default per-target wall clock when the caller names none. Chosen so the search phase gets a
#: few hundred seconds -- enough for tens of thousands of executions at the measured rate --
#: rather than the 30 seconds the stage defaults gave it.
DEFAULT_TARGET_BUDGET = 900.0

#: Execution ceilings exist to stop a runaway loop, not to size a campaign. Sizing is TIME's
#: job, because time is what the operator actually has; a 3,000-exec cap turned a 200-second
#: slice into a 17-second one on a fast target.
EXEC_CEILING = 2_000_000


class CaseBudget:
    """One target's wall clock, divided by phase and handed out in slices.

    Not a scheduler: nothing here can preempt a running stage. It decides what each stage is
    ALLOWED, hands that over as the stage's own deadline, and records what was actually spent so
    the report can say where the time went (`spent()`).
    """

    def __init__(self, total: Optional[float] = None, *, clock=time.monotonic,
                 overrides: Optional[dict] = None):
        #: The operator's invocation facts (argv, seed files, input mode), carried here because
        #: this object is already the per-target run context threaded to every stage call --
        #: `orchestrate._OVERRIDE_SCOPE` decides which stage may be handed which key. They are
        #: knowledge rather than inference, so they win over what the pipeline guesses.
        self.overrides = dict(overrides or {})
        self.total = float(DEFAULT_TARGET_BUDGET if total is None else total)
        self._clock = clock
        self._start = clock()
        self._phase = PHASES[0]
        self._spent: dict = {}
        self._skipped: list = []

    # ---- the clock ------------------------------------------------------------------------
    def elapsed(self) -> float:
        return max(0.0, self._clock() - self._start)

    def remaining(self) -> float:
        return max(0.0, self.total - self.elapsed())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    # ---- phases ---------------------------------------------------------------------------
    def phase(self, name: str) -> None:
        if name not in RESERVE_AFTER:
            raise ValueError(f"unknown phase {name!r}; expected one of {PHASES}")
        self._phase = name

    @property
    def current_phase(self) -> str:
        return self._phase

    def available(self) -> float:
        """What the CURRENT phase may still spend: the clock, less what later phases are owed."""
        return max(0.0, self.remaining() - self.total * RESERVE_AFTER[self._phase])

    # ---- slices ---------------------------------------------------------------------------
    def slice(self, stage: str, want: Optional[float] = None) -> float:
        """Seconds this stage may have, or 0.0 when there is no room left for it.

        `want` is the caller's own idea of enough (a cheap probe does not need the phase's
        half); the slice is never more than that and never more than the phase allows.
        """
        avail = self.available()
        if avail < FLOOR_SECONDS:
            return 0.0
        cap = max(FLOOR_SECONDS, avail * MAX_SINGLE_SHARE)
        s = cap if want is None else min(float(want), cap)
        return 0.0 if s < FLOOR_SECONDS else round(s, 1)

    # ---- what actually happened -----------------------------------------------------------
    def record(self, stage: str, seconds: float) -> None:
        self._spent[stage] = round(self._spent.get(stage, 0.0) + max(0.0, seconds), 1)

    def skipped(self, stage: str, why: str) -> None:
        self._skipped.append({"stage": stage, "why": why})

    def spent(self) -> dict:
        """Where the time went, for the run's scorecard. Ordered dearest first."""
        return {
            "total": round(self.total, 1),
            "elapsed": round(self.elapsed(), 1),
            "remaining": round(self.remaining(), 1),
            "phase": self._phase,
            "by_stage": dict(sorted(self._spent.items(), key=lambda kv: -kv[1])),
            "skipped_for_budget": list(self._skipped),
        }
