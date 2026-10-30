# 58 — The PoC engine redesign: constructed PoCs, every class, deps-tolerant (2026-10-30)

Operator verdict that forced this (see memory `validated-poc-or-nothing`): across real engagements,
lykos has only ever produced **candidates and corroborations, never PoCs** — "just useless
information." This doc is the architecture we build against to fix that, settled over a design
dialogue. It supersedes the fuzz-led framing this session drifted into.

## The job (unchanged, restated)
Look at a binary **or** source tree pulled off some other system → for **every** bug/vuln class →
produce a **validated PoC** (a concrete triggering input / payload) with a **soundness argument**,
or an **honest, actionable dead-end**. Never "a recipe, good luck."

## Four operator constraints that fix the architecture
1. **Fuzzing is not the primary engine.** Most classes (format string, cmd/path injection,
   int-overflow→alloc, UAF, auth/logic, type confusion, …) are found by dataflow + reachability +
   a class trigger, and the PoC is a *constructed payload*, not a lucky mutation.
2. **Time budget is 30–60 min/target** (a bit more for large). A fuzz campaign that needs hours to
   maybe hit the bug is useless. Constructed PoCs are minutes.
3. **Targets are pulled off other systems** — often missing libs / configs / args, so they frequently
   **won't execute locally**. Execution therefore **cannot be the gate**.
4. **But missing deps are recoverable** — if we tell the operator *exactly* what's missing, they
   usually bring it from the origin system. So "won't run" is a precise question to answer, not a
   blocker.

## The engine
- **Primary: static + symbolic constructed PoCs.** Static dataflow finds a reachable sink with a
  controllable argument; the class trigger gives the violation predicate; a directed symbolic solve
  (angr/claripy) returns a concrete triggering input as the *byproduct of proving reachability* — no
  execution, no real libs needed (externals are modelled/stubbed). For non-symbolic classes the PoC
  is a class payload template instantiated against the solved constraints.
- **The gate is a SOUND reach+trigger+payload argument**, not a detonation. 0-false-confirmation
  discipline now applies to the *argument*: an unsound reach/trigger claim is a false confirmation to
  hunt down. (Resolves the "can't certify static without execution / self-referential" tension:
  certification is the argument, which is checkable without running the target.)
- **"Static working properly" is redefined.** Not "precise candidate lines" — it is *"emits a
  constructed PoC: concrete payload + reach + trigger + input-channel soundness argument."* That bar
  is the difference between the useless corroboration and a real PoC. Static leads in dependency
  order because it **is** most of the PoC engine, not because it's a separate phase.
- **Execution/fuzzing is optional bonus confirmation**, attempted when the target runs (or once the
  operator supplies the missing deps). It upgrades a constructed PoC from "sound by argument" to
  "detonated," but is never required for a deliverable.

## What a PoC *is* (the artifact format)
A PoC is a **minimal, immediately-usable artifact**, not a package:
- the concrete payload (the bytes / string / argv / env that triggers it), and
- a **few lines** that reproduce it — a short script, a one-line command, or a code snippet an
  operator can read, adapt, and run in seconds, plus
- the soundness argument (why it reaches the sink and satisfies the trigger).

A single committed input file + a one-line run command IS a complete PoC. The multi-file
`bundle.py` package is retired as the default — offered only if the operator explicitly wants the
full harness. Lightweight is also more portable for air-gap/offline reuse.

## Target environment pre-flight (first-class output)
Statically derive what the target needs to run and report it as an actionable manifest:
- binary: unresolved `DT_NEEDED` libs, interpreter, config paths it `open()`s, env it reads, expected
  argv shape; source: headers / `-l` / pkg-config / configs read.
- Foundation exists: `analyze/dep_preflight.py` (today: lykos's own deps) and `analyze/fuzz/health.py`
  (already distinguishes "handshake failed: missing libfoo.so.1" from other failures) — surface it to
  the operator instead of swallowing it. Relates to memory `offline-dep-coverage`.

## When fuzzing is used it must be smart + targeted (never the blind discovery run)
A *within-a-finding bridge* the symbolic solver calls for one hard constraint it couldn't close:
- directed at the one static sink (distance-to-target / directed greybox), not whole-program coverage;
- concolic-seeded from the solver's partial path (+ real corpus), never random / one hand seed;
- input-to-state (CmpLog) on, so comparisons/magic bytes solve in seconds;
- reach-gated + plateau-bail (bail the instant distance stops shrinking; fail open, no tuned
  thresholds) — ends the 44%-compute / 0-yield waste;
- execution-gated — if the target won't start here, detect it up front and fall back to symbolic
  (and emit the missing-deps manifest); do **not** spin on blocked execs;
- instrumented-first (source → afl-clang-fast; bare binary only if it runs — **not** qemu-by-default),
  short, and with a **live progress window** (exec/s, distance-to-target, crashes) so it's visibly
  working or killable. Fixes the observed "no I/O window, spinning on blocked execs." Ties to memory
  `fuzzing-reach-gate-policy`.

## Build order
One bug class at a time, each taken end-to-end to a constructed PoC + soundness argument, on **both**
a source and a binary, execution optional:
1. **CWE-134 format string** — purest demonstration (payload constructed, no execution/libs, ladders
   to arbitrary write), fmt machinery already exists.
2. a light-symbolic class (CWE-190→787 int-overflow→overflow) to prove directed-solve-without-execution.
3. UAF/double-free, then injection/traversal, then auth/logic, type confusion, … across the 20 classes.
Each slice's "done" = a produced PoC on a target where we know the ground truth (e.g. the stb Tier-2
sources / planted Tier-0), plus a red-run diagnosis that names which stage failed (static missed the
site / no trigger hypothesis / solver stalled / target wouldn't execute).

## What this explicitly retires
The fuzz-led benchmark framing as a proxy for the product; "corroborated recipe, nothing further" as
a terminal output; execution as the confirmation gate; the giant multi-file `bundle.py` package as
the default PoC shape (a script / payload + a few lines is the deliverable).
