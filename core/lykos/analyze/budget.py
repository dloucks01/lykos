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

#: Stages that SAMPLE the input space -- the blind and coverage-guided campaigns. They are the
#: reason a phase needs an INTERNAL reserve as well as one for the phases after it: each takes
#: the largest share it is allowed, and with two of them running in sequence the stages that
#: SOLVE rather than sample run on what is left over.
SAMPLER_STAGES = frozenset({"fuzz", "coverage_fuzz", "directed_fuzz", "net_fuzz", "env_fuzz",
                            "boundary_fuzz", "libfuzzer"})

#: The stages the reserve exists FOR. Releasing it on ANY non-sampler was wrong and measurably
#: so: `build_exploit`, `mem_oracle`, `chain_primitive` and `synthesize_poc` all run in the
#: search phase BEFORE the campaigns, so the reserve was released before `fuzz` even started and
#: the solver was barely better off -- `concolic` got 21.0 s of a 600 s case where the model
#: predicted 97.5 s, and on `replaceme` it got 3.0 s.
SOLVER_STAGES = frozenset({"concolic"})

#: What the SEARCH phase keeps back from its samplers for the stages that solve instead of
#: sample (`concolic`). Measured on the HTB target quack_quack at a 600 s budget: `fuzz` 211.4 s
#: plus `directed_fuzz` 185.0 s spent 396 s of the clock on 91,896 executions and found NOTHING,
#: while `concolic` -- which reaches that target's defect in 19.8 s when it is allowed to finish
#: -- was handed 19.2 s of the 120 s it asked for and was cancelled before it could validate
#: what it had already found.
#:
#: The asymmetry is not a tuning preference. A blind campaign cannot construct the input behind
#: a `strstr(input, "Quack Quack")` gate at any budget -- it has to invent the token byte by byte
#: -- and the solver constructs it in seconds. So the solver's share is not the samplers' to
#: spend, exactly as a phase's share is not an earlier phase's to spend.
#:
#: SIZED FROM THE MEASURED NEED, not from a preference: `concolic` reached quack_quack's defect
#: with 18.52 s of exploration plus a validation run, and 0.10 of a 600 s case leaves it 48.8 s
#: -- about twice that, with headroom for a harder gate -- while the samplers keep 137 s, some
#: 30,000 executions at the 220 exec/s measured on these targets. The larger reserve this started
#: at (0.20) gave the solver 71 s it does not need and cut the blind campaign to 45 s, which is
#: the wrong trade for any target whose defect a campaign CAN reach.
SOLVER_RESERVE = 0.10

#: Below this a slice is not worth handing out: a two-second campaign measures nothing, and
#: saying "no budget left" is more useful than pretending to run. Returned as 0.0 instead.
FLOOR_SECONDS = 12.0

#: The same floor in the unit a sampler actually spends. A slice of seconds that buys fewer than
#: this many executions is not a small campaign, it is no campaign: a mutation loop that has
#: barely finished replaying its seed corpus has tested the seeds, not the program.
#:
#: This is what makes execution-sizing change outcomes rather than just reporting them. Dividing
#: seconds on a slow target gave every sampler a slice that LOOKED reasonable and bought almost
#: nothing: measured on ASan `tiffcrop`, 420 s produced 2,761 executions spread across the
#: campaigns, 11 stages done, 14 skipped, and `coverage_fuzz` never started. Five starved
#: searches is a worse use of a slow target's clock than two real ones, so a slice that cannot
#: clear this floor is refused with that reason and its budget stays for a stage that can.
#:
#: 1,000 is a judgement, not a measurement -- it is roughly where a mutator gets past the corpus
#: on the formats here. Lower it if a stage demonstrably finds things below it.
FLOOR_EXECS = 1_000

#: Default per-target wall clock when the caller names none. Chosen so the search phase gets a
#: few hundred seconds -- enough for tens of thousands of executions at the measured rate --
#: rather than the 30 seconds the stage defaults gave it.
DEFAULT_TARGET_BUDGET = 900.0

#: Execution ceilings exist to stop a runaway loop, not to size a campaign.
EXEC_CEILING = 2_000_000

# ---------------------------------------------------------------------------------------------
# EXECUTIONS, not seconds.
#
# Time is what the operator has, so the case clock stays in seconds. But what a SAMPLER buys with
# a second is not a constant, and the variation is not small:
#
#     plain x86-64 ELF        ~105 exec/s      (measured, /usr/bin class)
#     the same build + ASan   ~20.5 exec/s     (measured, tiffcrop)
#     a jar                    ~36 exec/s
#     a .pyc                   ~19 exec/s
#     a .NET assembly           ~8 exec/s
#     a rehosted firmware img   ~5 exec/s
#
# Dividing SECONDS therefore hands the same campaign a 5x smaller search on the instrumented
# build -- and the instrumented build is the ONLY configuration whose oracle can see a heap
# out-of-bounds access at all. Measured: ASan `tiffcrop` got 2,761 executions from the same 420 s
# that gave the plain build 14,000+, with 11 stages done and 14 skipped, and `coverage_fuzz`
# never ran. The configuration that can find the bug is the one the clock starves.
#
# So a sampler now asks for EXECUTIONS and the budget converts, using this target's own rate.
# Nothing else changes: the conversion is bounded by exactly the same phase reserves and
# single-stage cap as before, so a slow target cannot eat the case -- it is told, honestly, that
# the phase affords fewer executions than it asked for.

#: Measured penalty for an ASan/UBSan build: 105 / 20.5 on the same binary. A sanitizer build is
#: not a different target, so this is a property of the BUILD, applied on top of the substrate's
#: own rate rather than replacing it.
SANITIZER_SLOWDOWN = 5.1

#: Fallback when nothing is known -- the substrate table's own figure for a native ELF.
DEFAULT_EXEC_RATE = 105.0

#: A conversion is only as good as the rate, so it is floored: a rate below this would turn a
#: modest execution request into the entire case clock.
MIN_EXEC_RATE = 0.5


def exec_rate(execs_per_sec: Optional[float] = None, *, sanitizer: bool = False,
              measured: Optional[float] = None) -> float:
    """Executions per second to assume for this target, best evidence first.

    `measured` is what a campaign on THIS target actually achieved and always wins -- a measured
    rate is not an estimate. `execs_per_sec` is the substrate table's per-format figure (itself
    measured on this platform, but for the format rather than the binary). `sanitizer` applies
    the build penalty, and only to the estimate: a measured rate already includes it.
    """
    if measured is not None and measured > 0:
        return max(MIN_EXEC_RATE, float(measured))
    rate = float(execs_per_sec) if execs_per_sec else DEFAULT_EXEC_RATE
    if sanitizer:
        rate /= SANITIZER_SLOWDOWN
    return max(MIN_EXEC_RATE, rate)


class CaseBudget:
    """One target's wall clock, divided by phase and handed out in slices.

    Not a scheduler: nothing here can preempt a running stage. It decides what each stage is
    ALLOWED, hands that over as the stage's own deadline, and records what was actually spent so
    the report can say where the time went (`spent()`).
    """

    def __init__(self, total: Optional[float] = None, *, clock=time.monotonic,
                 overrides: Optional[dict] = None, skip_stages=None, pause=None):
        #: The operator's invocation facts (argv, seed files, input mode), carried here because
        #: this object is already the per-target run context threaded to every stage call --
        #: `orchestrate._OVERRIDE_SCOPE` decides which stage may be handed which key. They are
        #: knowledge rather than inference, so they win over what the pipeline guesses.
        self.overrides = dict(overrides or {})
        #: Stages the operator switched OFF for this run (e.g. the black-box `fuzz` stage). The
        #: autopilot's scheduling chokepoints (`_staged`, `_run_target_stages`) skip these before
        #: spending any budget, so an operator can drop a stage they do not want on a given run
        #: without editing the plan. A deliberate operator choice, recorded as a `skipped` plan row
        #: with that reason -- not a silent omission.
        self.skip_stages = set(skip_stages or ())
        #: An optional threading.Event the operator can SET to pause the run BETWEEN stages (no
        #: work is lost -- the stage in flight finishes, then the autopilot waits here until the
        #: event is cleared or the run is stopped). None = never pauses.
        self.pause = pause
        self.total = float(DEFAULT_TARGET_BUDGET if total is None else total)
        self._clock = clock
        self._start = clock()
        self._phase = PHASES[0]
        self._spent: dict = {}
        self._skipped: list = []
        #: set once a non-sampler search stage has had its slice; see `slice`
        self._solver_served = False
        #: Executions per second for THIS target, so an execution request can be converted to
        #: seconds. None until something knows; `slice(want_execs=...)` then falls back to the
        #: default rate and says so in `sizing()`.
        self._rate: Optional[float] = None
        #: What the last conversion decided, for the scorecard and the stage's own event.
        self._sizing: dict = {}

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
    def set_exec_rate(self, rate: Optional[float]) -> None:
        """Record this target's executions-per-second. See `exec_rate`."""
        if rate and rate > 0:
            self._rate = max(MIN_EXEC_RATE, float(rate))

    @property
    def rate(self) -> float:
        return self._rate if self._rate else DEFAULT_EXEC_RATE

    def sizing(self) -> dict:
        """How the last execution-sized slice was converted, for the event and the scorecard."""
        return dict(self._sizing)

    def seconds_for(self, execs: float) -> float:
        """Seconds this target needs to perform `execs` executions, at its measured rate."""
        return max(0.0, float(execs) / self.rate)

    def affordable_execs(self) -> int:
        """Executions a single search campaign's TIME-SHARE can buy at this target's rate, so a
        campaign can be SIZED to the operator's budget instead of a fixed count. Passed back as
        `want_execs`: a large --budget then buys a longer search, while `slice()` still enforces the
        same single-stage share (MAX_SINGLE_SHARE) and phase reserve, so one campaign cannot eat the
        case. Read-only -- no `_solver_served` side effect; `slice()` does the authoritative
        accounting. Fixes the "raising --budget did nothing, fuzzing still stops at ~30s" an operator
        hit: a fixed 12-18k execs ran ~30s no matter how large the budget was."""
        return int(max(0.0, self.available() * MAX_SINGLE_SHARE) * self.rate)

    def slice(self, stage: str, want: Optional[float] = None,
              *, want_execs: Optional[float] = None) -> float:
        """Seconds this stage may have, or 0.0 when there is no room left for it.

        `want` is the caller's own idea of enough in SECONDS (a cheap probe does not need the
        phase's half). `want_execs` states it in EXECUTIONS instead, which is the honest unit for
        a sampler: the budget converts at this target's own rate, so an ASan build -- 5x slower
        and the only one whose oracle sees a heap overflow -- is given the seconds its search
        actually costs rather than the same seconds as a plain build. The result is bounded by
        the identical phase reserve and single-stage cap either way, so a slow target cannot eat
        the case; it is told how many executions the phase could afford.
        """
        if want_execs is not None:
            needed = self.seconds_for(want_execs)
            want = needed if want is None else max(float(want), needed)
        avail = self.available()
        # A sampler may not spend what the solver is owed: the phase-reserve principle, applied
        # WITHIN the search phase. Without it the first campaign takes half of everything, the
        # second takes half of the rest, and `concolic` -- ordered after them on purpose, so it
        # can aim at what they left uncovered -- gets the dregs of its own phase.
        if (self._phase == "search" and stage in SAMPLER_STAGES
                and not self._solver_served):
            avail = max(0.0, avail - self.total * SOLVER_RESERVE)
        if avail < FLOOR_SECONDS:
            return 0.0
        cap = max(FLOOR_SECONDS, avail * MAX_SINGLE_SHARE)
        if want_execs is not None:
            # The single-stage share exists to stop ONE stage eating a case that has many
            # stages to serve. On a slow target it starts doing the opposite: half of the
            # available clock buys so few executions that every campaign is pointless, and
            # five pointless campaigns are worth less than one real one. So an
            # execution-sized request may exceed the share when that is simply what the
            # floor COSTS at this rate -- still bounded by what the phase actually has.
            cap = min(avail, max(cap, self.seconds_for(FLOOR_EXECS)))
        s = cap if want is None else min(float(want), cap)
        if s < FLOOR_SECONDS:
            return 0.0
        # The reserve protects a stage that has NOT RUN YET. Once the solver has been served it
        # is ordinary budget again, or the campaign that closes the coverage loop afterwards --
        # re-fuzzing AROUND the branches concolic just unlocked, which is the whole point of
        # running it there -- would be permanently denied the time to do it.
        if self._phase == "search" and stage in SOLVER_STAGES:
            self._solver_served = True
        s = round(s, 1)
        if want_execs is not None:
            afforded = int(s * self.rate)
            if afforded < FLOOR_EXECS:
                # Refuse rather than starve. The budget stays available for a stage that can
                # clear the floor, and the caller gets a reason instead of a tiny campaign whose
                # "0 crashes" means nothing.
                self._sizing = {
                    "stage": stage, "want_execs": int(want_execs), "rate": round(self.rate, 1),
                    "seconds": 0.0, "affords_execs": afforded,
                    "measured_rate": self._rate is not None, "capped": True,
                    "refused": (f"{afforded} executions is below the {FLOOR_EXECS}-execution "
                                f"floor at {self.rate:.1f} exec/s -- a campaign this small "
                                f"tests the seed corpus, not the program"),
                }
                return 0.0
            self._sizing = {
                "stage": stage, "want_execs": int(want_execs), "rate": round(self.rate, 1),
                "seconds": s, "affords_execs": afforded,
                "measured_rate": self._rate is not None,
                # The honest line when the phase cannot pay for what was asked. Without it a
                # starved instrumented campaign looks identical to a thorough one.
                "capped": afforded < int(want_execs),
            }
        return s

    # ---- what actually happened -----------------------------------------------------------
    def record(self, stage: str, seconds: float) -> None:
        self._spent[stage] = round(self._spent.get(stage, 0.0) + max(0.0, seconds), 1)

    def skipped(self, stage: str, why: str) -> None:
        self._skipped.append({"stage": stage, "why": why})

    def advice(self, *, want_execs: float = 30_000.0) -> dict:
        """What this case's clock is worth at this target's rate, and what it would need.

        The starvation this file exists to fix is invisible from the inside: ASan `tiffcrop`
        reported 2,761 executions from a 420-second case and nothing said that the same case
        would have bought 44,000 on the uninstrumented build, or that a comparable search needed
        roughly 1,500 seconds. A number nobody can act on is not much better than no number, so
        this is the recommendation -- surfaced in the scorecard, next to the count.
        """
        rate = self.rate
        search_seconds = max(0.0, self.total * (1.0 - RESERVE_AFTER["recover"]))
        affordable = int(search_seconds * rate)
        needed = self.seconds_for(want_execs) / max(1e-9, (1.0 - RESERVE_AFTER["recover"]))
        return {
            "exec_rate": round(rate, 1),
            "measured": self._rate is not None,
            "search_seconds": round(search_seconds, 1),
            "affords_execs": affordable,
            "want_execs": int(want_execs),
            "budget_for_want": round(needed, 1),
            "short_by": max(0, int(want_execs) - affordable),
            "note": (
                f"at {rate:.1f} exec/s this target's search phase affords ~{affordable:,} "
                f"executions; {int(want_execs):,} would need a case budget of about "
                f"{needed:.0f}s (--budget {int(needed)})"
                if affordable < want_execs else
                f"at {rate:.1f} exec/s the search phase affords ~{affordable:,} executions, "
                f"which covers the {int(want_execs):,} a campaign asks for"),
        }

    def spent(self) -> dict:
        """Where the time went, for the run's scorecard. Ordered dearest first."""
        return {
            "total": round(self.total, 1),
            "elapsed": round(self.elapsed(), 1),
            "remaining": round(self.remaining(), 1),
            "phase": self._phase,
            "by_stage": dict(sorted(self._spent.items(), key=lambda kv: -kv[1])),
            "skipped_for_budget": list(self._skipped),
            "exec_rate": round(self.rate, 1),
            "exec_rate_measured": self._rate is not None,
            "last_sizing": dict(self._sizing),
        }
